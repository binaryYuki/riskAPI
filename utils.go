package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
)

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
		return false // Invalid IP format cannot be bogon/private in this context
	}

	privateIPBlocks := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	for _, cidr := range privateIPBlocks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ipAddr) {
			return true
		}
	}

	bogonIPBlocks := []string{
		"0.0.0.0/8",          // Current network (only valid as source address)
		"100.64.0.0/10",      // Shared Address Space
		"192.0.0.0/24",       // IANA IPv4 Special Purpose Address Registry
		"192.0.2.0/24",       // TEST-NET-1, documentation and examples
		"198.18.0.0/15",      // Network Interconnect Device Benchmark Testing
		"198.51.100.0/24",    // TEST-NET-2, documentation and examples
		"203.0.113.0/24",     // TEST-NET-3, documentation and examples
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for Future Use
		"255.255.255.255/32", // Broadcast
	}

	for _, cidr := range bogonIPBlocks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}
