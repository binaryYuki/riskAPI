package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/telemetry"
)

// correlation 为请求分配 correlation ID（优先沿用 X-Correlation-ID），并写入 X-Request-ID 响应头
func correlation() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Correlation-ID")
		if id == "" {
			if v7, err := uuid.NewV7(); err == nil {
				id = v7.String()
			} else {
				id = uuid.New().String() + "vtc" // V7 不可用时回退为随机 UUID
			}
		}
		id = strings.ReplaceAll(id, "-", "")
		c.Set("correlation_id", id)
		c.Header("X-Request-ID", id)
		c.Header("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate")
		c.Next()
	}
}

func correlationID(c *gin.Context) string {
	id, _ := c.Get("correlation_id")
	s, _ := id.(string)
	return s
}

// requestLog 返回携带 correlation_id 的请求级 logger
func (s *Server) requestLog(c *gin.Context) *slog.Logger {
	return s.log.With("correlation_id", correlationID(c))
}

// requestLogger 记录访问日志；/.well-known/ 直接 404 且不记录。
// 命中蜜罐规则的请求整行封存为一个字符串（sealed），日志里不留明文地址和路径
func (s *Server) requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		start := time.Now()
		s.annotateSpan(c)
		c.Next()
		// 带 ctx 记录，开启追踪时日志自动关联 trace_id / span_id
		ctx := c.Request.Context()
		if telemetrySkipPaths[c.Request.URL.Path] {
			ctx = telemetry.SkipExport(ctx)
		}
		if honeytrap.Hit(c) {
			line, _ := json.Marshal(accessLine{
				Method:        c.Request.Method,
				Path:          c.Request.URL.Path,
				Status:        c.Writer.Status(),
				Latency:       time.Since(start).String(),
				ClientIP:      s.clientIP(c),
				CorrelationID: correlationID(c),
			})
			s.log.InfoContext(ctx, "request", "sealed", s.trap.Seal(string(line)))
			return
		}
		s.log.InfoContext(ctx, "request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency", time.Since(start),
			"client_ip", s.clientIP(c),
			"correlation_id", correlationID(c),
		)
	}
}

// accessLine 被封存的访问日志行的内容，字段与明文访问日志一致
type accessLine struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	Latency       string `json:"latency"`
	ClientIP      string `json:"client_ip"`
	CorrelationID string `json:"correlation_id"`
}

// sensitivePath 拦截蜜罐规则表中标记为 Forbidden 的敏感路径：GET 返回 403 页面，其余方法返回 JSON。
// 蜜罐关闭或未返回伪造内容时，这些路径由这里兜底
func (s *Server) sensitivePath() gin.HandlerFunc {
	rules := s.trap.Rules()
	return func(c *gin.Context) {
		if rule, ok := rules.Match(c.Request.URL.Path); !ok || !rule.Forbidden {
			return
		}
		if c.Request.Method == http.MethodGet {
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
			// 不用 c.File：http.ServeFile 会把已设置的 403 覆盖为 200
			c.Data(http.StatusForbidden, "text/html; charset=utf-8", s.forbiddenPage)
		} else {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		}
		c.Abort()
	}
}

// loadForbiddenPage 读取 403 页面，失败时回退为纯文本
func loadForbiddenPage(path string, log *slog.Logger) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("failed to read 403 page", "path", path, "err", err)
		return []byte("403 Forbidden")
	}
	return data
}

// crossOriginResourcePolicy 允许跨源嵌入资源
func crossOriginResourcePolicy() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cross-Origin-Resource-Policy", "cross-origin")
		c.Next()
	}
}

// adminAuth 要求 Authorization: Bearer <token>；token 为空时管理接口整体禁用
func adminAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" {
			handleError(c, http.StatusForbidden, "admin endpoints are disabled")
			return
		}
		provided, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			c.Header("WWW-Authenticate", `Bearer realm="admin"`)
			handleError(c, http.StatusUnauthorized, "unauthorized")
			return
		}
		c.Next()
	}
}

// ipRateLimiter 按客户端 IP 的固定窗口限流
type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{limit: limit, window: window, clients: make(map[string]*rateWindow)}
}

// allow 返回是否放行以及距窗口重置的剩余时间
func (l *ipRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.clients[key]
	if !ok || now.Sub(w.start) >= l.window {
		if !ok {
			l.evictExpired(now)
		}
		l.clients[key] = &rateWindow{start: now, count: 1}
		return true, 0
	}
	if w.count >= l.limit {
		return false, l.window - now.Sub(w.start)
	}
	w.count++
	return true, 0
}

// evictExpired 在表过大时清理已过期窗口，避免被大量来源地址撑爆内存
func (l *ipRateLimiter) evictExpired(now time.Time) {
	if len(l.clients) < 10000 {
		return
	}
	for k, w := range l.clients {
		if now.Sub(w.start) >= l.window {
			delete(l.clients, k)
		}
	}
}

// rateLimit 对每个客户端 IP 限制 window 内最多 limit 次请求；limit<=0 表示不限流
func rateLimit(limit int, window time.Duration, clientIP func(*gin.Context) string) gin.HandlerFunc {
	if limit <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	limiter := newIPRateLimiter(limit, window)
	return func(c *gin.Context) {
		ok, retryAfter := limiter.allow(clientIP(c), time.Now())
		if !ok {
			c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			handleError(c, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		c.Next()
	}
}
