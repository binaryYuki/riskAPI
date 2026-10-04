package httpapi

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/ipset"
)

// 仅在直连对端可信时才读取的单值请求头（由 CDN/代理覆写，不可追加）。
// 顺序即优先级：生产链路为 EdgeOne → Cloudflare(Koyeb 边缘) → Koyeb，
// CF-Connecting-IP 是 EdgeOne 节点 IP，必须排在 EO-Client-IP 之后。
var clientIPHeaders = []string{
	"EO-Client-IP",       // EdgeOne
	"CF-Connecting-IP",   // Cloudflare
	"True-Client-IP",     // Akamai / Cloudflare
	"Fastly-Client-IP",   // Fastly
	"ali-real-client-ip", // 阿里云 ESA
	"X-Azure-ClientIP",   // Azure Front Door
	"X-Real-IP",          // Nginx
}

func parsePrefixes(items []string, log *slog.Logger) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, ok := ipset.ParseEntry(item); ok {
			prefixes = append(prefixes, p)
			continue
		}
		log.Warn("ignore invalid trusted proxy entry", "entry", item)
	}
	return prefixes
}

// isTrustedProxy 判断对端是否为可信代理：配置的可信网段，或已知 CDN 回源网段
func (s *Server) isTrustedProxy(ip string) bool {
	addr, ok := ipset.ParseAddr(ip)
	if !ok {
		return false
	}
	for _, p := range s.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	_, isCDN := s.lists.CDN(addr.String())
	return isCDN
}

// clientIP 解析真实客户端 IP。
// 只有直连对端是可信代理时才读取转发头，否则直接使用对端地址，防止客户端伪造请求头冒充任意 IP。
func (s *Server) clientIP(c *gin.Context) string {
	peer := c.RemoteIP()
	if !s.isTrustedProxy(peer) {
		return peer
	}
	for _, header := range clientIPHeaders {
		if ip := strings.TrimSpace(c.GetHeader(header)); isValidIP(ip) {
			return ip
		}
	}
	if ip := s.clientIPFromForwardedFor(c.GetHeader("X-Forwarded-For")); ip != "" {
		return ip
	}
	return peer
}

// clientIPFromForwardedFor 从右向左跳过可信代理，返回第一个不可信地址。
// 左侧条目可被客户端任意伪造，只有最右侧的不可信跳才是真实来源。
func (s *Server) clientIPFromForwardedFor(value string) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if !isValidIP(ip) {
			return ""
		}
		if !s.isTrustedProxy(ip) {
			return ip
		}
	}
	return ""
}

// isValidIP 检查 IP 地址格式（IPv4 / IPv6，不接受 zone）
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
