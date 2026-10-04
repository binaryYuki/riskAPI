package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// 可信代理 & 客户端 IP 解析
// ---------------------------------------------------------------------------

// 默认可信代理：回环 + 私网（平台内部负载均衡通常位于这些网段）
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "fc00::/7",
}

// 仅在直连对端可信时才读取的单值请求头（由 CDN/代理覆写，不可追加）
var clientIPHeaders = []string{
	"EO-Client-IP",       // EdgeOne
	"CF-Connecting-IP",   // Cloudflare
	"True-Client-IP",     // Akamai / Cloudflare
	"Fastly-Client-IP",   // Fastly
	"ali-real-client-ip", // Alibaba Cloud ESA
	"X-Azure-ClientIP",   // Azure Front Door
	"X-Real-IP",          // Nginx
}

var trustedProxies = parsePrefixes(trustedProxiesFromEnv())

// trustedProxiesFromEnv 读取 TRUSTED_PROXIES（逗号分隔 CIDR/IP），未设置时使用默认值
func trustedProxiesFromEnv() []string {
	env := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if env == "" {
		return defaultTrustedProxies
	}
	return strings.Split(env, ",")
}

func parsePrefixes(items []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(item); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		log.Printf("[security] ignore invalid trusted proxy entry: %q", item)
	}
	return prefixes
}

// isTrustedProxy 判断对端是否为可信代理：配置的可信网段，或已知 CDN 回源网段
func isTrustedProxy(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	isCDN, _ := isCDNIP(addr.String())
	return isCDN
}

// clientIPFromForwardedFor 从右向左跳过可信代理，返回第一个不可信地址
// 左侧条目可被客户端任意伪造，只有最右侧的不可信跳才是真实来源
func clientIPFromForwardedFor(value string) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if !isValidIP(ip) {
			return ""
		}
		if !isTrustedProxy(ip) {
			return ip
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// 管理接口鉴权
// ---------------------------------------------------------------------------

// AdminAuthMiddleware 要求 Authorization: Bearer <ADMIN_TOKEN>
// 未配置 ADMIN_TOKEN 时管理接口整体禁用
func AdminAuthMiddleware(token string) gin.HandlerFunc {
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

// ---------------------------------------------------------------------------
// 按客户端 IP 的固定窗口限流
// ---------------------------------------------------------------------------

type rateWindow struct {
	start time.Time
	count int
}

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]*rateWindow
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

// RateLimitMiddleware 对每个客户端 IP 限制 window 内最多 limit 次请求；limit<=0 表示不限流
func RateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	if limit <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	limiter := newIPRateLimiter(limit, window)
	return func(c *gin.Context) {
		ok, retryAfter := limiter.allow(getClientIPFromCDNHeaders(c), time.Now())
		if !ok {
			c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			handleError(c, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		c.Next()
	}
}
