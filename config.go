package main

import (
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	ipCacheKey      = "risky_ip_list_entries" // Cache key for raw IP/CIDR strings
	ipCacheExpiry   = 6 * time.Hour
	updateFrequency = 1 * time.Hour
)

// Local proxy networks
var localProxies = []string{
	"10.42.0.0/8", "10.0.0.0/16", "172.16.0.0/12", "fc00::/7",
}

// IP list APIs for fetching risky IPs
var ipListAPIs = []string{
	"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
	"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
	"https://check.torproject.org/exit-addresses",
	"https://www.dan.me.uk/torlist/",
	"https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt",
	"https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1",
	"https://check.torproject.org/torbulkexitlist",
	"https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
	"https://www.spamhaus.org/drop/drop.txt",
	"https://cinsscore.com/list/ci-badguys.txt",
	"https://lists.blocklist.de/lists/all.txt",
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset",
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset",
	"https://blocklist.greensnow.co/greensnow.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/8.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/7.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/3.txt",
	"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/2.txt",
}

// Sensitive path regex for security
var sensitivePathRegex = regexp.MustCompile(`(?i)^/(\.env|\.git|\.svn|\.hg|\.DS_Store|config\.json|config\.yml|config\.yaml|wp-config\.php|composer\.json|composer\.lock|package\.json|yarn\.lock|docker-compose\.yml|id_rsa|id_rsa\.pub|\.bash_history|\.htaccess|\.htpasswd|\.ssh|\.aws|\.npmrc|\.dockerignore|\.gitignore|\.idea|vendor/.*|node_modules/.*|backup|db\.sqlite|db\.sql|dump\.sql|phpinfo\.php|test\.php|debug\.php|admin|admin\.php|webshell\.php|shell\.php|cmd\.php)$`)

// getAllowedDomains returns allowed CORS domains from environment
func getAllowedDomains() []string {
	env := os.Getenv("ALLOWED_CORS")
	if env == "" {
		return []string{"catyuki.com", "tzpro.xyz"} // Default allowed domains
	}
	parts := strings.Split(env, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// getDefaultConfig returns default application configuration
func getDefaultConfig() Config {
	return Config{
		Timeout:     10000, // milliseconds
		Retries:     3,
		RetryDelay:  2000, // milliseconds
		Concurrency: 10,   // Max concurrent goroutines for proxy filtering
	}
}
