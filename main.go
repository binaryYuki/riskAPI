package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// shutdownTimeout 收到停机信号后等待进行中请求完成的最长时间
const shutdownTimeout = 15 * time.Second

func main() {
	// SIGINT / SIGTERM（容器平台停止实例时发送）触发优雅停机
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set GOMAXPROCS to use all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Printf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))

	// Initialize cache and data structures
	appCache = NewBoundedRadixCache(getEnvInt("INFO_CACHE_MAX_ENTRIES", defaultInfoCacheMaxEntries), infoCacheExpiry)
	storeRiskySet(newPrefixSet())

	// Initialize QQWry database
	log.Printf("Initializing QQWry database...")
	if err := InitQQWryDatabase(); err != nil {
		log.Printf("Warning: Failed to initialize QQWry database: %v", err)
	} else {
		log.Printf("QQWry database initialized successfully")
	}

	// Get configuration
	allowedDomains := getAllowedDomains()
	config := getDefaultConfig()

	// Setup CORS configuration
	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if !strings.HasPrefix(origin, "https://") {
				// Allow localhost for development if needed
				// return strings.HasPrefix(origin, "http://localhost")
				return false
			}
			for _, domain := range allowedDomains {
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

	// Setup router
	router := gin.New()
	// 客户端 IP 统一由 getClientIPFromCDNHeaders 按可信代理规则解析，禁用 gin 自带的转发头信任
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("Failed to disable gin trusted proxies: %v", err)
	}
	router.Use(gin.Recovery())
	router.Use(cors.New(corsConfig))
	router.Use(CrossOriginResourcePolicyMiddleware())
	router.Use(CorrelationMiddleware())
	router.Use(LoggingMiddleware())
	// 蜜罐中间件：从环境变量读取配置
	router.Use(Honeytrap(HoneytrapConfigFromEnv()))
	router.Use(SensitivePathMiddleware())

	// Start background services
	// CDN/IDC 列表随镜像发布、运行期不变，启动时加载一次即可（/api/cache/flush/all 可手动重载）
	initCDNIDCCache()
	go updateIPListsPeriodically(ctx, config)

	// Setup routes
	setupRoutes(router)
	// 可选诱饵路由（通过 HONEYTRAP_DECOYS=true 启用）
	registerDecoys(router)

	// Start server with optimized settings for high concurrency
	log.Printf("Starting server on port 8080...")
	srv := &http.Server{
		Addr:           ":8080",
		Handler:        router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Configure transport for better concurrency
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 1000
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 100
	http.DefaultTransport.(*http.Transport).IdleConnTimeout = 90 * time.Second

	log.Printf("Server configured for high concurrency with optimized timeouts and connection limits")

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	case <-ctx.Done():
		log.Printf("Shutdown signal received, draining in-flight requests (timeout %s)...", shutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Graceful shutdown incomplete: %v", err)
		}
		log.Printf("Server stopped")
	}
}

// setupRoutes configures all application routes
func setupRoutes(router *gin.Engine) {
	// Default route handlers
	router.NoRoute(notFoundHandler)
	router.GET("/", homeHandler)

	// API routes
	ipCheckGroup := router.Group("/api/v1/ip")
	{
		ipCheckGroup.GET("/:ip", checkIPHandler)
		ipCheckGroup.POST("/:ip", checkIPHandler)
	}
	router.GET("/api/v1/ip", checkRequestIPHandler)
	router.GET("/api/status", statusHandler)
	router.GET("/api/ready", readyHandler)

	router.GET("/api/v1/info", ipInfoHandler)
	router.GET("/api/v1/parse",
		RateLimitMiddleware(getEnvInt("PARSE_RATE_LIMIT_PER_MIN", 30), time.Minute),
		parseProxyHandler)
	infoGroup := router.Group("/api/v1/info")
	{
		infoGroup.GET("/:ip", ipInfoHandler)
	}

	// Version route
	router.GET("/version", versionHandler)

	// Proxy filtering
	router.POST("/filter-proxies", filterProxiesHandler)

	// CDN routes
	router.GET("/cdn/:name", cdnHandler)
	router.GET("/cdn/all", cdnAllHandler)

	router.GET("/api/metrics", metricsHandler)

	// 管理接口：需 Authorization: Bearer <ADMIN_TOKEN>
	adminGroup := router.Group("/api/cache", AdminAuthMiddleware(os.Getenv("ADMIN_TOKEN")))
	{
		adminGroup.GET("/flush", flushCacheIndexHandler)
		adminGroup.POST("/flush/:method/*range", flushCacheHandler)
	}

	// 纯真数据库状态路由
	router.GET("/api/qqwry/stats", qqwryStatsHandler)

	// 新增：导出所有 CIDR
	router.GET("/api/export", exportCIDRsHandler)
}
