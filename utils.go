package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"strings"
)

// getClientIPFromCDNHeaders 优先从各大CDN的header中获取客户端IP
func getClientIPFromCDNHeaders(c *gin.Context) string {
	// CDN headers priority order (从高到低优先级)
	cdnHeaders := []string{
		"CF-Connecting-IP",         // Cloudflare
		"X-Forwarded-For",          // Standard proxy header
		"X-Real-IP",                // Nginx proxy
		"X-Client-IP",              // Apache mod_remoteip
		"X-Forwarded",              // RFC 7239
		"X-Cluster-Client-IP",      // Cluster
		"Forwarded-For",            // RFC 7239
		"Forwarded",                // RFC 7239
		"True-Client-IP",           // Akamai and CloudFlare
		"X-Original-Forwarded-For", // AWS ALB
		"X-Azure-ClientIP",         // Azure
		"X-Azure-SocketIP",         // Azure
		"Fastly-Client-IP",         // Fastly
		"X-Varnish-Client-IP",      // Varnish
		"WL-Proxy-Client-IP",       // WebLogic
		"Proxy-Client-IP",          // Proxy
		"HTTP_CLIENT_IP",           // Client IP
		"HTTP_X_FORWARDED_FOR",     // X-Forwarded-For variant
	}

	for _, header := range cdnHeaders {
		headerValue := c.GetHeader(header)
		if headerValue != "" {
			// Handle comma-separated IPs (like X-Forwarded-For)
			ips := strings.Split(headerValue, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				// 修改: 不再在此处过滤私网/保留 IP，避免所有来源都被视为 bogon 的情况；
				// 统一由后续逻辑 (checkRequestIPHandler 中 isBogonOrPrivateIP) 再判定。
				if ip != "" && isValidIP(ip) {
					return ip
				}
			}
		}
	}

	// 如果CDN headers中没有找到有效IP，则使用gin的ClientIP()作为fallback
	return c.ClientIP()
}

// isValidIP 检查IP地址格式是否有效
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

// classifySpecialRanges 预留: 返回是否属于特殊/保留用途网段（未来可扩展分类用途）
func classifySpecialRanges(ip net.IP) bool {
	specialCIDRs := []string{
		"64:ff9b::/96", // IPv4/IPv6 translation
		"100::/64",     // Discard prefix
		"2001:10::/28", // ORCHID (deprecated)
		"2001:20::/28", // ORCHIDv2
		"2001::/32",    // Teredo
		"2002::/16",    // 6to4
		"::/96",        // IPv4-compatible (deprecated)
	}
	for _, cidr := range specialCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func isBogonOrPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	// 如果是 IPv4（包括 IPv4-mapped IPv6）则统一转为 v4 处理
	if v4 := ipAddr.To4(); v4 != nil {
		// 私有 / 内部 / 回环 / 链路本地 / CGNAT
		v4Private := []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
			"127.0.0.0/8",    // Loopback
			"169.254.0.0/16", // Link-local
			"100.64.0.0/10",  // CGNAT (视为非公网，按需保留)
		}
		for _, cidr := range v4Private {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n.Contains(v4) {
				return true
			}
		}
		// 公共但特殊/测试/文档/多播等
		v4Bogon := []string{
			"0.0.0.0/8",          // 无效源
			"192.0.0.0/24",       // IETF PROTOCOL ASSIGNMENTS
			"192.0.2.0/24",       // TEST-NET-1 (文档)
			"198.18.0.0/15",      // 性能基准测试网络
			"198.51.100.0/24",    // TEST-NET-2
			"203.0.113.0/24",     // TEST-NET-3
			"224.0.0.0/4",        // 多播
			"240.0.0.0/4",        // 未来保留
			"255.255.255.255/32", // 广播
		}
		for _, cidr := range v4Bogon {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n.Contains(v4) {
				return true
			}
		}
		return false // 其余 IPv4 视为公网
	}

	// IPv6 处理（纯 IPv6，不含 IPv4-mapped 已在上面 To4 分支处理）
	v6Private := []string{
		"::1/128",   // Loopback
		"fe80::/10", // Link-local
		"fc00::/7",  // Unique local
	}
	for _, cidr := range v6Private {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ipAddr) {
			return true
		}
	}
	v6Bogon := []string{
		"::/128",        // Unspecified
		"2001:db8::/32", // Documentation
		"ff00::/8",      // Multicast
		// 下列特殊过渡/废弃网段不自动标记为 bogon，保持透明：Teredo / 6to4 / ORCHID / 64:ff9b::/96
	}
	for _, cidr := range v6Bogon {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ipAddr) {
			return true
		}
	}
	return false
}
