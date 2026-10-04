package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// initCDNIDCCache initializes CDN and IDC caches
func initCDNIDCCache() {
	cacheInitOnce.Do(func() {
		syncCDNLists()
		syncIDCLists()
	})
}

// startCDNListSync starts CDN list synchronization
func startCDNListSync() {
	go func() {
		for {
			time.Sleep(24 * time.Hour) // Sync once daily（启动时已由 initCDNIDCCache 加载）
			syncCDNLists()
			syncIDCLists()
		}
	}()
}

// syncCDNLists 重新加载 CDN 列表并原子替换查找表
func syncCDNLists() {
	cdnSet.Store(loadProviderSet("data/cdn", cdnProviders))
	fmt.Println("CDN lists synchronized")
}

// syncIDCLists 重新加载 IDC 列表并原子替换查找表
func syncIDCLists() {
	idcSet.Store(loadProviderSet("data/idc", idcProviders))
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
