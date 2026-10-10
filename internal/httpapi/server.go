// Package httpapi 实现对外 HTTP API：路由、处理函数与中间件。
package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"

	"risky_ip_filter/internal/cache"
	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/geo"
	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/netlists"
)

// Deps Server 的依赖
type Deps struct {
	Config    config.Config
	Version   string
	Log       *slog.Logger
	Risk      *feeds.Store
	Lists     *netlists.Lists
	Geo       *geo.Service
	InfoCache *cache.Cache
	Trap      *honeytrap.Trap
	// ParseClient 转发 /api/v1/parse 使用的 HTTP 客户端；为 nil 时使用 30s 超时的默认客户端
	ParseClient *http.Client
	// TracerProvider 非 nil 时为入站请求创建 span（OPENTELEMETRY=1）
	TracerProvider trace.TracerProvider
}

// Server 持有全部依赖，处理函数为其方法
type Server struct {
	cfg       config.Config
	version   string
	log       *slog.Logger
	risk      *feeds.Store
	lists     *netlists.Lists
	geo       *geo.Service
	infoCache *cache.Cache
	trap      *honeytrap.Trap

	trustedProxies []netip.Prefix
	parseClient    *http.Client
	forbiddenPage  []byte
	tracerProvider trace.TracerProvider
}

// New 创建 Server
func New(d Deps) *Server {
	s := &Server{
		cfg:            d.Config,
		version:        d.Version,
		log:            d.Log,
		risk:           d.Risk,
		lists:          d.Lists,
		geo:            d.Geo,
		infoCache:      d.InfoCache,
		trap:           d.Trap,
		trustedProxies: parsePrefixes(d.Config.TrustedProxies, d.Log),
		parseClient:    d.ParseClient,
		tracerProvider: d.TracerProvider,
		forbiddenPage:  loadForbiddenPage(filepath.Join(d.Config.DataDir, "pages", "403.html"), d.Log),
	}
	if s.parseClient == nil {
		s.parseClient = &http.Client{Timeout: 30 * time.Second}
	}
	return s
}

// Handler 构建带完整中间件链与路由的 gin.Engine
func (s *Server) Handler() *gin.Engine {
	r := gin.New()
	// 客户端 IP 统一由 clientIP 按可信代理规则解析，禁用 gin 自带的转发头信任
	_ = r.SetTrustedProxies(nil)

	r.Use(gin.Recovery())
	if s.tracerProvider != nil {
		r.Use(s.tracing())
	}
	r.Use(cors.New(s.corsConfig()))
	r.Use(crossOriginResourcePolicy())
	r.Use(correlation())
	r.Use(s.requestLogger())
	r.Use(s.trap.Middleware(s.clientIP))
	r.Use(s.sensitivePath())

	s.routes(r)
	s.trap.RegisterDecoys(r)
	return r
}

func (s *Server) routes(r *gin.Engine) {
	r.NoRoute(s.notFound)
	r.GET("/", s.home)

	// IP 风险检测
	r.GET("/api/v1/ip/:ip", s.checkIP)
	r.POST("/api/v1/ip/:ip", s.checkIP)
	r.GET("/api/v1/ip", s.checkRequestIP)
	r.POST("/filter-proxies", s.filterProxies)
	r.POST("/api/v1/webrtc", s.webrtcCheck)
	r.GET("/api/v1/webrtc", s.webrtcScriptHandler)
	r.HEAD("/api/v1/webrtc", s.webrtcScriptHandler)

	// 地理位置
	r.GET("/api/v1/info", s.ipInfo)
	r.GET("/api/v1/info/:ip", s.ipInfo)
	r.GET("/api/qqwry/stats", s.qqwryStats)

	// 链接解析转发
	r.GET("/api/v1/parse", rateLimit(s.cfg.ParseRateLimitPerMin, time.Minute, s.clientIP), s.parseProxy)

	// CDN 列表
	r.GET("/cdn/:name", s.cdnList)
	r.GET("/cdn/all", s.cdnAll)

	// 状态与监控
	r.GET("/api/status", s.status)
	r.GET("/api/ready", s.ready)
	r.GET("/version", s.versionInfo)
	r.GET("/api/metrics", s.metricsJSON)
	r.GET("/metrics", s.metricsPrometheus)
	r.GET("/api/export", s.exportCIDRs)

	// 管理接口：需 Authorization: Bearer <ADMIN_TOKEN>
	admin := r.Group("/api/cache", adminAuth(s.cfg.AdminToken))
	{
		admin.GET("/flush", s.flushIndex)
		admin.POST("/flush/:method/*range", s.flush)
	}
}

// corsConfig 仅允许 https 下的白名单域名及其子域名
func (s *Server) corsConfig() cors.Config {
	allowed := s.cfg.AllowedCORS
	return cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if !strings.HasPrefix(origin, "https://") {
				return false
			}
			for _, domain := range allowed {
				if origin == "https://"+domain || strings.HasSuffix(origin, "."+domain) {
					return true
				}
			}
			return false
		},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
}
