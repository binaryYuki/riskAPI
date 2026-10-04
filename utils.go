package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"net/netip"
	"strings"
)

// getClientIPFromCDNHeaders 解析真实客户端 IP
// 只有直连对端是可信代理（TRUSTED_PROXIES 或已知 CDN 网段）时才读取转发头，
// 否则直接使用对端地址，防止客户端通过伪造请求头冒充任意 IP。
func getClientIPFromCDNHeaders(c *gin.Context) string {
	peer := c.RemoteIP()
	if !isTrustedProxy(peer) {
		return peer
	}

	for _, header := range clientIPHeaders {
		if ip := strings.TrimSpace(c.GetHeader(header)); isValidIP(ip) {
			return ip
		}
	}
	if ip := clientIPFromForwardedFor(c.GetHeader("X-Forwarded-For")); ip != "" {
		return ip
	}
	return peer
}

// isValidIP 检查IP地址格式是否有效 Checks if the IP address format is valid
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// handleError sends error response
func handleError(c *gin.Context, statusCode int, message string) {
	c.IndentedJSON(statusCode, Response{
		Status:  "error",
		Message: message,
	})
	c.Abort()
}

// parseCIDRs parses a list of CIDR strings and returns a slice of net.IPNet
func parseCIDRs(cidrStrs []string) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, cidrStr := range cidrStrs {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		} else {
			fmt.Printf("Parse CIDR error: %s %v\n", cidrStr, err)
		}
	}
	return cidrs
}

// mustParsePrefixes 解析包级常量网段，格式错误直接 panic（属于编码错误）
func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefixes[i] = netip.MustParsePrefix(c)
	}
	return prefixes
}

// 特殊/保留用途网段（仅用于统计分类，不视为 bogon）
var specialPrefixes = mustParsePrefixes(
	"64:ff9b::/96", // IPv4/IPv6 translation
	"100::/64",     // Discard prefix
	"2001:10::/28", // ORCHID (deprecated)
	"2001:20::/28", // ORCHIDv2
	"2001::/32",    // Teredo
	"2002::/16",    // 6to4
	"::/96",        // IPv4-compatible (deprecated)
)

// 私有 / 保留 / bogon 网段，启动时一次性解析
var bogonPrefixes = mustParsePrefixes(
	// IPv4 私有 / 内部 / 回环 / 链路本地 / CGNAT
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
	"127.0.0.0/8",    // Loopback
	"169.254.0.0/16", // Link-local
	"100.64.0.0/10",  // CGNAT (视为非公网，按需保留)
	// IPv4 公共但特殊/测试/文档/多播等
	"0.0.0.0/8",          // 无效源 / Unspecified
	"192.0.0.0/24",       // IETF PROTOCOL ASSIGNMENTS
	"192.0.2.0/24",       // TEST-NET-1 / 测试网络
	"198.18.0.0/15",      // Benchmarking (RFC 2544) / 基准测试
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"224.0.0.0/4",        // 多播 / Multicast
	"240.0.0.0/4",        // 未来保留 / Reserved for future use
	"255.255.255.255/32", // Broadcast / 广播地址
	// IPv6（特殊过渡/废弃网段如 Teredo / 6to4 / ORCHID / 64:ff9b::/96 不标记为 bogon，保持透明）
	"::1/128",       // Loopback
	"fe80::/10",     // Link-local
	"fc00::/7",      // Unique local
	"::/128",        // Unspecified
	"2001:db8::/32", // Documentation
	"ff00::/8",      // Multicast
)

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// classifySpecialRanges 返回是否属于特殊/保留用途网段（未来可扩展分类用途）
func classifySpecialRanges(addr netip.Addr) bool {
	return containsAddr(specialPrefixes, addr)
}

// isBogonOrPrivateIP 判断是否为私网/保留地址；IPv4-mapped IPv6 按 IPv4 处理
func isBogonOrPrivateIP(ip string) bool {
	addr, ok := parseAddr(ip)
	if !ok {
		return false
	}
	return containsAddr(bogonPrefixes, addr)
}
