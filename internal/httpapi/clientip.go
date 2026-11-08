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
// 生产链路：CDN（EdgeOne / ESA / CloudFront）→ Envoy Gateway → Pod，对端是 Envoy Pod（私网，默认可信）。
// 顺序即优先级：CDN 专属头在前，通用头（X-Real-IP 等）在后；CDN 叠加时下一层写的头是前置 CDN 的节点 IP，
// 所以前置 CDN 的头必须排在前面。值本身落在已知 CDN 网段的头会被跳过（见 clientIP）。
// CDN 没带专属头时（如 CloudFront 未开 CloudFront-Viewer-Address）回退到 X-Forwarded-For：
// Envoy 会把它看到的对端（CDN 节点）追加到末尾，从右往左跳过可信代理和 CDN 网段即得用户 IP。
var clientIPHeaders = []string{
	"EO-Client-IP",              // EdgeOne
	"CloudFront-Viewer-Address", // Amazon CloudFront，值为 "IP:端口"，见 headerIP
	"True-Client-IP",            // Akamai / Cloudflare
	"Fastly-Client-IP",          // Fastly
	"ali-real-client-ip",        // 阿里云 ESA
	"X-Azure-ClientIP",          // Azure Front Door
	"CF-Connecting-IP",          // Cloudflare
	"X-Real-IP",                 // Nginx
}

// headerIP 读取单值头中的客户端 IP。
// CloudFront-Viewer-Address 形如 "198.51.100.10:46532" 或 "2001:db8::1:46532"（IPv6 不带方括号），
// 需去掉最后一个冒号后的端口；其余头为纯 IP。
func headerIP(header, value string) string {
	value = strings.TrimSpace(value)
	if header == "CloudFront-Viewer-Address" {
		if i := strings.LastIndexByte(value, ':'); i > 0 {
			value = strings.TrimSuffix(strings.TrimPrefix(value[:i], "["), "]")
		}
	}
	if isValidIP(value) {
		return value
	}
	return ""
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
	return s.isCDN(addr.String())
}

// isCDN 判断 IP 是否落在已知 CDN 网段
func (s *Server) isCDN(ip string) bool {
	_, ok := s.lists.CDN(ip)
	return ok
}

// clientIP 解析真实客户端 IP。
// 只有直连对端是可信代理时才读取转发头，否则直接使用对端地址，防止客户端伪造请求头冒充任意 IP。
// 头里的值若是已知 CDN 节点，说明它记录的是前置 CDN 这一跳而不是用户，跳过继续往下找。
func (s *Server) clientIP(c *gin.Context) string {
	ip, _ := s.resolveClientIP(c)
	return ip
}

// 客户端 IP 的来源（除请求头名外），供 /api/debug/clientip 展示
const (
	clientIPSourcePeer         = "peer"            // 对端不可信，直接用对端地址
	clientIPSourceForwardedFor = "X-Forwarded-For" // 单值头都不可用，回退到 XFF
	clientIPSourcePeerFallback = "peer-fallback"   // 对端可信但所有头都不可用
)

// resolveClientIP 返回客户端 IP 及其来源：命中的请求头名，或上面的来源常量
func (s *Server) resolveClientIP(c *gin.Context) (ip, source string) {
	peer := c.RemoteIP()
	if !s.isTrustedProxy(peer) {
		return peer, clientIPSourcePeer
	}
	for _, header := range clientIPHeaders {
		if ip := headerIP(header, c.GetHeader(header)); ip != "" && !s.isCDN(ip) {
			return ip, header
		}
	}
	if ip := s.clientIPFromForwardedFor(c.GetHeader("X-Forwarded-For")); ip != "" {
		return ip, clientIPSourceForwardedFor
	}
	return peer, clientIPSourcePeerFallback
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
