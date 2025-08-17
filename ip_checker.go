package main

import (
	"net"
	"strings"
)

// isRiskyIP checks if an IP address is in the risky IP list
func isRiskyIP(ip string) (bool, string) {
	riskyDataMutex.RLock()
	defer riskyDataMutex.RUnlock()

	// Check single IPs first (faster lookup)
	if reason, exists := reasonMap[ip]; exists {
		return true, reason
	}

	// Check CIDR ranges
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, ""
	}

	for _, cidrInfo := range riskyCIDRInfo {
		if cidrInfo.Net.Contains(ipAddr) {
			if reason, exists := reasonMap[cidrInfo.OriginalCIDR]; exists {
				return true, reason
			}
			return true, "Unknown reason"
		}
	}

	return false, ""
}

// isCDNIP checks if an IP belongs to any CDN
func isCDNIP(ip string) (bool, string) {
	cdnIdcMutex.RLock()
	defer cdnIdcMutex.RUnlock()

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, ""
	}

	// Check single IPs first
	for provider, singleIPs := range cdnSingleIPs {
		if singleIPs[ip] {
			return true, provider
		}
	}

	// Check CIDR ranges
	for provider, cidrs := range cdnIPCache {
		for _, cidrInfo := range cidrs {
			if cidrInfo.Net.Contains(ipAddr) {
				return true, provider
			}
		}
	}

	return false, ""
}

// isIDCIP checks if an IP belongs to any IDC
func isIDCIP(ip string) (bool, string) {
	cdnIdcMutex.RLock()
	defer cdnIdcMutex.RUnlock()

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, ""
	}

	// Check single IPs first
	for provider, singleIPs := range idcSingleIPs {
		if singleIPs[ip] {
			return true, provider
		}
	}

	// Check CIDR ranges
	for provider, cidrs := range idcIPCache {
		for _, cidrInfo := range cidrs {
			if cidrInfo.Net.Contains(ipAddr) {
				return true, provider
			}
		}
	}

	return false, ""
}

// getSourceIdentifier returns source identifier from API URL
func getSourceIdentifier(apiURL string) string {
	if strings.Contains(apiURL, "X4BNet") && strings.Contains(apiURL, "datacenter") {
		return "X4BNet-datacenter"
	} else if strings.Contains(apiURL, "X4BNet") && strings.Contains(apiURL, "vpn") {
		return "X4BNet-vpn"
	} else if strings.Contains(apiURL, "torproject.org/exit-addresses") {
		return "torproject-exit"
	} else if strings.Contains(apiURL, "dan.me.uk/torlist") {
		return "dan.me.uk-tor"
	} else if strings.Contains(apiURL, "jhassine") {
		return "data-center-list"
	} else if strings.Contains(apiURL, "projecthoneypot.org") {
		return "projecthoneypot"
	} else if strings.Contains(apiURL, "torbulkexitlist") {
		return "tor-bulk-exit"
	} else if strings.Contains(apiURL, "danger.rulez.sk") {
		return "danger.rulez.sk"
	} else if strings.Contains(apiURL, "spamhaus.org") {
		return "spamhaus"
	} else if strings.Contains(apiURL, "cinsscore.com") {
		return "cinsscore"
	} else if strings.Contains(apiURL, "blocklist.de") {
		return "blocklist.de"
	} else if strings.Contains(apiURL, "firehol") && strings.Contains(apiURL, "cybercrime") {
		return "firehol-cybercrime"
	} else if strings.Contains(apiURL, "firehol") && strings.Contains(apiURL, "level1") {
		return "firehol-level1"
	} else if strings.Contains(apiURL, "firehol") && strings.Contains(apiURL, "level2") {
		return "firehol-level2"
	} else if strings.Contains(apiURL, "firehol") && strings.Contains(apiURL, "level3") {
		return "firehol-level3"
	} else if strings.Contains(apiURL, "firehol") && strings.Contains(apiURL, "level4") {
		return "firehol-level4"
	} else if strings.Contains(apiURL, "greensnow") {
		return "greensnow"
	} else if strings.Contains(apiURL, "stamparm/ipsum") {
		if strings.Contains(apiURL, "levels/8") {
			return "ipsum-level8"
		} else if strings.Contains(apiURL, "levels/7") {
			return "ipsum-level7"
		} else if strings.Contains(apiURL, "levels/6") {
			return "ipsum-level6"
		} else if strings.Contains(apiURL, "levels/5") {
			return "ipsum-level5"
		} else if strings.Contains(apiURL, "levels/4") {
			return "ipsum-level4"
		} else if strings.Contains(apiURL, "levels/3") {
			return "ipsum-level3"
		} else if strings.Contains(apiURL, "levels/2") {
			return "ipsum-level2"
		}
		return "ipsum-unknown"
	}
	return "unknown"
}
