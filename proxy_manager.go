package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// initCDNIDCCache initializes CDN and IDC caches
func initCDNIDCCache() {
	cacheInitOnce.Do(func() {
		cdnIPCache = make(map[string][]CIDRInfo)
		idcIPCache = make(map[string][]CIDRInfo)
		cdnSingleIPs = make(map[string]map[string]bool)
		idcSingleIPs = make(map[string]map[string]bool)

		// Initialize CDN providers
		cdnProviders := []string{"edgeone", "cloudflare", "fastly"}
		for _, provider := range cdnProviders {
			cdnSingleIPs[provider] = make(map[string]bool)
			loadCDNIPList(provider)
		}

		// Initialize IDC providers
		idcProviders := []string{"aws", "azure", "gcp", "akamai", "apple", "digitalocean", "linode", "oracle", "zscaler"}
		for _, provider := range idcProviders {
			idcSingleIPs[provider] = make(map[string]bool)
			loadIDCIPList(provider)
		}
	})
}

// loadCDNIPList loads CDN IP list from file
func loadCDNIPList(provider string) {
	filePath := fmt.Sprintf("data/cdn/%s.txt", provider)
	loadIPListFromFile(filePath, provider, true)
}

// loadIDCIPList loads IDC IP list from file
func loadIDCIPList(provider string) {
	filePath := fmt.Sprintf("data/idc/%s.txt", provider)
	loadIPListFromFile(filePath, provider, false)
}

// loadIPListFromFile loads IP list from file and updates cache
func loadIPListFromFile(filePath, provider string, isCDN bool) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Warning: Could not open %s: %v\n", filePath, err)
		return
	}
	defer func(file *os.File) { _ = file.Close() }(file)

	var cidrs []CIDRInfo
	singleIPs := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, CIDRInfo{Net: ipNet, OriginalCIDR: line})
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			singleIPs[line] = true
		}
	}

	cdnIdcMutex.Lock()
	if isCDN {
		cdnIPCache[provider] = cidrs
		cdnSingleIPs[provider] = singleIPs
	} else {
		idcIPCache[provider] = cidrs
		idcSingleIPs[provider] = singleIPs
	}
	cdnIdcMutex.Unlock()

	fmt.Printf("Loaded %s: %d CIDRs, %d single IPs\n", provider, len(cidrs), len(singleIPs))
}

// startCDNListSync starts CDN list synchronization
func startCDNListSync() {
	go func() {
		for {
			syncCDNLists()
			time.Sleep(24 * time.Hour) // Sync once daily
		}
	}()
}

// syncCDNLists synchronizes CDN lists from data files to cache
func syncCDNLists() {
	cdnProviders := []string{"edgeone", "cloudflare", "fastly"}
	for _, provider := range cdnProviders {
		loadCDNIPList(provider)
	}
	fmt.Println("CDN lists synchronized")
}

// syncIDCLists synchronizes IDC lists from data files to cache
func syncIDCLists() {
	idcProviders := []string{"aws", "azure", "gcp", "akamai", "apple", "digitalocean", "linode", "oracle", "zscaler"}
	for _, provider := range idcProviders {
		loadIDCIPList(provider)
	}
	fmt.Println("IDC lists synchronized")
}

// processProxies filters out risky proxies from the list
func processProxies(proxies []Proxy, concurrency int) []Proxy {
	var nonRiskyProxies []Proxy
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, concurrency)

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p Proxy) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			// Extract IP from proxy server string
			ip := extractIPFromProxy(p.Server)
			if ip == "" {
				return // Skip if no valid IP found
			}

			// Check if IP is risky
			if risky, _ := isRiskyIP(ip); !risky {
				mu.Lock()
				nonRiskyProxies = append(nonRiskyProxies, p)
				mu.Unlock()
			}
		}(proxy)
	}

	wg.Wait()
	return nonRiskyProxies
}

// extractIPFromProxy extracts IP address from proxy server string
func extractIPFromProxy(server string) string {
	if strings.Contains(server, "://") {
		parts := strings.Split(server, "://")
		if len(parts) > 1 {
			server = parts[1]
		}
	}
	// IPv6 with port like [2001:db8::1]:8080
	if strings.HasPrefix(server, "[") {
		if idx := strings.Index(server, "]"); idx != -1 {
			candidate := server[1:idx]
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	// Strip port (last colon for IPv4 or host:port); IPv6 without [] is ambiguous, rely on [] format.
	if i := strings.LastIndex(server, ":"); i != -1 && !strings.Contains(server, "]") {
		server = server[:i]
	}
	if net.ParseIP(server) != nil {
		return server
	}
	return ""
}
