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
				if ip != "" && isValidIP(ip) && !isBogonOrPrivateIP(ip) {
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

// isBogonOrPrivateIP checks if an IP is bogon or private
func isBogonOrPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	privateIPBlocks := []string{
		// IPv4 RFC1918 & loopback & link-local
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
		// IPv6 private / loopback / link-local / unique local
		"::1/128",       // Loopback
		"fe80::/10",     // Link-local unicast
		"fc00::/7",      // Unique local
		"::ffff:0:0/96", // IPv4-mapped (treat as private/bogon contextually)
	}

	for _, cidr := range privateIPBlocks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ipAddr) {
			return true
		}
	}

	bogonIPBlocks := []string{
		// IPv4 bogons
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		// IPv6 bogon / special ranges
		"::/128",        // Unspecified
		"2001:db8::/32", // Documentation
		"ff00::/8",      // Multicast
	}

	for _, cidr := range bogonIPBlocks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}
