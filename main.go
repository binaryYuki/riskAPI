package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var fastlyCIDRs []*net.IPNet
var fastlyCIDRsMutex sync.RWMutex

var (
	ipRegex   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	cidrRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
)

type FastlyIPList struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

// Data structures for storing risky IPs
var (
	riskySingleIPs map[string]bool   // Stores single IPs for quick lookup
	riskyCIDRInfo  []CIDRInfo        // Stores parsed CIDR info
	reasonMap      map[string]string // Stores reasons for IPs/CIDRs
	riskyDataMutex sync.RWMutex      // Protects riskySingleIPs, riskyCIDRInfo, and reasonMap

	appCache *cache.Cache

	ipCacheKey      = "risky_ip_list_entries" // Cache key for raw IP/CIDR strings
	ipCacheExpiry   = 6 * time.Hour
	updateFrequency = 1 * time.Hour
)

// CIDRInfo stores a parsed CIDR network and its original string representation
type CIDRInfo struct {
	Net          *net.IPNet
	OriginalCIDR string
}

// IPAssociation is used to pass IP/CIDR entries and their reasons from fetchers
type IPAssociation struct {
	Entry  string // IP or CIDR string
	Reason string
}

// Config stores application configuration
type Config struct {
	Timeout     int `json:"timeout"`
	Retries     int `json:"retries"`
	RetryDelay  int `json:"retry_delay"`
	Concurrency int `json:"concurrency"` // Note: This Concurrency is not currently used to limit fetcher goroutines
}

// Proxy represents a proxy configuration
type Proxy struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

var localProxies = []string{
	"10.42.0.0/8", "10.0.0.0/16", "172.16.0.0/12", "fc00::/7",
}

func isIPInFastlyCIDR(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}
	fastlyCIDRsMutex.RLock()
	defer fastlyCIDRsMutex.RUnlock()
	for _, ipNet := range fastlyCIDRs {
		if ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func updateFastlyIPs(router *gin.Engine) {
	for {
		var ipList FastlyIPList
		resp, err := http.Get("https://api.fastly.com/public-ip-list")
		if err == nil && resp != nil {
			func() {
				defer func() {
					if cerr := resp.Body.Close(); cerr != nil {
						fmt.Println("resp.Body.Close error:", cerr)
					}
				}()
				if err := json.NewDecoder(resp.Body).Decode(&ipList); err == nil {
					fmt.Println("Fetched Fastly IPs from API")
				} else {
					fmt.Println("Decode Fastly IPs error:", err)
				}
			}()
		} else {
			// failback to hardcoded IPs
			ipList = FastlyIPList{
				Addresses: []string{
					"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
					"103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
					"140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
					"151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
					"167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
					"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
					"199.232.0.0/16",
				},
				IPv6Addresses: []string{
					"2a04:4e40::/32", "2a04:4e42::/32",
				},
			}
			fmt.Println("Using hardcoded Fastly IPs")
		}

		// combine local and Fastly IPs
		allProxies := append([]string{}, localProxies...)
		allProxies = append(allProxies, ipList.Addresses...)
		allProxies = append(allProxies, ipList.IPv6Addresses...)
		if err := router.SetTrustedProxies(allProxies); err != nil {
			fmt.Println("SetTrustedProxies error:", err)
		} else {
			fmt.Printf("SetTrustedProxies: %d IPv4, %d IPv6\n", len(ipList.Addresses), len(ipList.IPv6Addresses))
		}

		// Parse CIDR strings into net.IPNet
		cidrs := parseCIDRs(ipList.Addresses)
		cidrs = append(cidrs, parseCIDRs(ipList.IPv6Addresses)...)

		fastlyCIDRsMutex.Lock()
		fastlyCIDRs = cidrs
		fastlyCIDRsMutex.Unlock()
		fmt.Printf("Updated fastlyCIDRs: %d entries\n", len(cidrs))

		time.Sleep(1 * time.Hour)
	}
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

// IPCacheData represents the cached IP data structure (list of IP/CIDR strings)
type IPCacheData struct {
	Timestamp int64    `json:"timestamp"`
	Entries   []string `json:"entries"` // Raw IP/CIDR strings
}

// RSSFeed is a struct for parsing Project Honeypot RSS data
type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

type Response struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
}

type ResponseWithIP struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
	IP      string      `json:"ip,omitempty"`
}

type StatusCountMsg struct {
	Timestamp int64 `json:"timestamp"`
	Count     int   `json:"total_ip_count"`
}

var (
	ipListAPIs = []string{
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
		"https://checktor.483300.xyz/exit-addresses",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/8.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/7.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/3.txt",
		"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/2.txt",
	}
)

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

func handleError(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, Response{
		Status:  "error",
		Message: message,
	})
	c.Abort()
}

func CorrelationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}
		c.Set("correlation_id", correlationID)
		c.Header("X-Correlation-ID", correlationID)
		c.Next()
	}
}

func main() {
	appCache = cache.New(ipCacheExpiry, 10*time.Minute)
	riskySingleIPs = make(map[string]bool)
	riskyCIDRInfo = make([]CIDRInfo, 0)
	reasonMap = make(map[string]string)

	allowedDomains := getAllowedDomains()

	config := Config{
		Timeout:     10000, // milliseconds
		Retries:     3,
		RetryDelay:  2000, // milliseconds
		Concurrency: 10,   // Max concurrent goroutines for proxy filtering, not IP list fetching
	}

	router := gin.Default()

	// It's important to set trusted proxies if running behind a reverse proxy
	//err := router.SetTrustedProxies([]string{"10.42.0.0/16", "10.0.0.0/16", "172.16.0.0/12", "fc00::/7"})
	//if err != nil {
	//	log.Fatalf("Failed to set trusted proxies: %v", err)
	//}

	go updateFastlyIPs(router)

	router.NoRoute(func(c *gin.Context) {
		handleError(c, http.StatusNotFound, "Not Found")
	})

	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			// For security, ensure origin is well-formed, e.g., starts with https://
			if !strings.HasPrefix(origin, "https://") {
				// Allow localhost for development if desired
				// is strings.HasPrefix(origin, "http://localhost") { return true }
				// return false
			}
			for _, domain := range allowedDomains {
				// Allow exact match or subdomains
				if origin == "https://"+domain || strings.HasSuffix(origin, "."+domain) {
					return true
				}
			}
			return false
		},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"}, // OPTIONS is needed for preflight requests
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(corsConfig))

	go updateIPListsPeriodically(config)

	router.POST("/filter-proxies", func(c *gin.Context) {
		var proxies []Proxy
		if err := c.ShouldBindJSON(&proxies); err != nil {
			c.JSON(http.StatusBadRequest, Response{"error", "Request body is invalid."})
			return
		}
		nonRiskyProxies := processProxies(proxies, config.Concurrency) // Pass concurrency limit
		filteredData := gin.H{
			"filtered_count": len(proxies) - len(nonRiskyProxies),
			"proxies":        nonRiskyProxies,
		}
		c.JSON(http.StatusOK, Response{
			Status:  "ok",
			Message: filteredData,
		})
	})

	ipCheckGroup := router.Group("/api/v1/ip")
	{
		ipCheckGroup.GET("/:ip", checkIPHandler)
		ipCheckGroup.POST("/:ip", checkIPHandler)
	}
	router.GET("/api/v1/ip", checkRequestIPHandler) // Checks the request's source IP
	router.GET("/api/status", func(c *gin.Context) {
		riskyDataMutex.RLock()
		count := len(riskySingleIPs) + len(riskyCIDRInfo)
		riskyDataMutex.RUnlock()

		c.JSON(http.StatusOK, Response{
			Status: "ok",
			Message: StatusCountMsg{
				Timestamp: time.Now().Unix(),
				Count:     count,
			},
		})
	})

	fmt.Println("Starting Risky IP Filter server on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	router.Use(CorrelationMiddleware())
	// 4. 自定义日志中间件
	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()

		correlationID, _ := c.Get("correlation_id")
		log.Printf("[GIN] %s | %3d | %13v | %-15s | %-20s | correlation_id=%v",
			time.Now().Format("2006/01/02 - 15:04:05"),
			status,
			latency,
			c.ClientIP(),
			c.Request.URL.Path,
			correlationID,
		)
	})

	// 5. Gin 自带的恢复中间件（可选）
	router.Use(gin.Recovery())
}

func checkIPHandler(c *gin.Context) {
	ip := c.Param("ip")
	if !isIPAddress(ip) {
		c.JSON(http.StatusBadRequest, Response{Status: "error", Message: "Invalid IP address format"})
		return
	}
	if isBogonOrPrivateIP(ip) {
		c.JSON(http.StatusUnprocessableEntity, Response{Status: "error", Message: "This is a private or bogon IP address."})
		return
	}

	risky, reason := getRiskStatusAndReason(ip)
	if risky {
		c.JSON(http.StatusOK, Response{Status: "banned", Message: reason})
		return
	}
	c.JSON(http.StatusOK, Response{Status: "ok", Message: "IP is not listed as risky."})
}

func checkRequestIPHandler(c *gin.Context) {
	ip := extractIPFromRequest(c)

	if ip == "::1" || ip == "127.0.0.1" { // Common localhost IPs
		c.JSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "Request from localhost.",
			IP:      ip,
		})
		return
	}
	if !isIPAddress(ip) { // Also catches empty IP string
		c.JSON(http.StatusBadRequest, ResponseWithIP{Status: "error", Message: "Invalid or unidentifiable IP address.", IP: ip})
		return
	}
	if isBogonOrPrivateIP(ip) {
		c.JSON(http.StatusOK, ResponseWithIP{ // Not an error, but info that it's private
			Status:  "ok",
			Message: "Request from a private or bogon IP address.",
			IP:      ip,
		})
		return
	}

	risky, reason := getRiskStatusAndReason(ip)
	if risky {
		c.JSON(http.StatusOK, ResponseWithIP{Status: "banned", Message: reason, IP: ip})
		return
	}
	c.JSON(http.StatusOK, ResponseWithIP{Status: "ok", Message: "IP is not listed as risky.", IP: ip})
}

// getRiskStatusAndReason checks if an IP is risky and returns its status and reason.
func getRiskStatusAndReason(ip string) (bool, string) {
	riskyDataMutex.RLock()
	defer riskyDataMutex.RUnlock()

	// Check single IPs first
	if riskySingleIPs[ip] {
		reason := reasonMap[ip]
		if reason == "" {
			reason = "IP found in risk database (direct match)."
		}
		return true, reason
	}

	// Then check CIDR ranges
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, "" // Should not happen if isIPAddress was called before
	}

	for _, cidrEntry := range riskyCIDRInfo {
		if cidrEntry.Net.Contains(ipAddr) {
			reason := reasonMap[cidrEntry.OriginalCIDR]
			if reason == "" {
				reason = fmt.Sprintf("IP within risky CIDR %s.", cidrEntry.OriginalCIDR)
			}
			return true, reason
		}
	}
	return false, ""
}

func updateIPListsPeriodically(config Config) {
	if cachedData, found := appCache.Get(ipCacheKey); found {
		if ipCache, ok := cachedData.(IPCacheData); ok {
			fmt.Printf("Loading %d IP/CIDR entries from cache...\n", len(ipCache.Entries))
			processLoadedEntries(ipCache.Entries, make(map[string]string)) // Initially no reasons from cache
			riskyDataMutex.RLock()
			count := len(riskySingleIPs) + len(riskyCIDRInfo)
			riskyDataMutex.RUnlock()
			fmt.Printf("Loaded %d unique entries from cache into monitored lists.\n", count)
		}
	}

	updateIPLists(config) // Initial update

	ticker := time.NewTicker(updateFrequency)
	defer ticker.Stop()
	for range ticker.C {
		updateIPLists(config)
	}
}

// processLoadedEntries processes a list of IP/CIDR strings and populates the global risk data structures.
// It takes a list of entries and a map of reasons.
func processLoadedEntries(entries []string, reasonsForEntries map[string]string) {
	localSingleIPs := make(map[string]bool)
	localCIDRInfo := make([]CIDRInfo, 0)
	localReasonMap := make(map[string]string)

	for _, entry := range entries {
		if entry == "" {
			continue
		}
		if cidrRegex.MatchString(entry) {
			_, ipNet, err := net.ParseCIDR(entry)
			if err == nil {
				localCIDRInfo = append(localCIDRInfo, CIDRInfo{Net: ipNet, OriginalCIDR: entry})
				if reason, ok := reasonsForEntries[entry]; ok {
					localReasonMap[entry] = reason
				}
			} else {
				fmt.Printf("Error parsing CIDR from loaded entries '%s': %v\n", entry, err)
			}
		} else if ipRegex.MatchString(entry) {
			localSingleIPs[entry] = true
			if reason, ok := reasonsForEntries[entry]; ok {
				localReasonMap[entry] = reason
			}
		} else {
			// fmt.Printf("Skipping invalid entry from loaded data: %s\n", entry)
		}
	}

	riskyDataMutex.Lock()
	riskySingleIPs = localSingleIPs
	riskyCIDRInfo = localCIDRInfo
	// Only overwrite reasonMap if new reasons were provided, otherwise merge or keep existing
	// For now, let's assume reasonsForEntries is the definitive new set for these entries
	if len(reasonsForEntries) > 0 || len(entries) > 0 { // if there are entries, even with no reasons, clear old potentially irrelevant reasons.
		reasonMap = localReasonMap
	}
	riskyDataMutex.Unlock()
}

func updateIPLists(config Config) {
	fmt.Println("Starting IP lists update...")

	var wg sync.WaitGroup
	// Channel for IPAssociation to include reasons directly
	ipAssociationChan := make(chan IPAssociation, 2000) // Increased buffer size

	for _, apiURL := range ipListAPIs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			fetchIPList(url, config, ipAssociationChan)
		}(apiURL)
	}

	go func() {
		wg.Wait()
		close(ipAssociationChan)
	}()

	newEntries := make(map[string]bool)   // Temporary set to store unique entries
	newReasons := make(map[string]string) // Temporary map for reasons

	for assoc := range ipAssociationChan {
		if assoc.Entry != "" {
			newEntries[assoc.Entry] = true // Mark entry as present
			if assoc.Reason != "" {
				// If multiple sources list the same IP with different reasons, the last one wins.
				// Or, one could append reasons:
				// if existingReason, ok: = newReasons[assoc.Entry]; ok {
				//  newReasons[assoc.Entry] = existingReason + "; " + assoc.Reason
				// } else {
				//  newReasons[assoc.Entry] = assoc.Reason
				// }
				newReasons[assoc.Entry] = assoc.Reason
			}
		}
	}

	if len(newEntries) > 0 {
		entryList := make([]string, 0, len(newEntries))
		for entry := range newEntries {
			entryList = append(entryList, entry)
		}

		processLoadedEntries(entryList, newReasons) // Process and set global data structures

		appCache.Set(ipCacheKey, IPCacheData{
			Timestamp: time.Now().Unix(),
			Entries:   entryList,
		}, ipCacheExpiry)
		riskyDataMutex.RLock()
		count := len(riskySingleIPs) + len(riskyCIDRInfo)
		reasonCount := len(reasonMap)
		riskyDataMutex.RUnlock()
		fmt.Printf("Successfully updated risky IP lists: %d unique entries. Reason map entries: %d\n", count, reasonCount)
	} else {
		fmt.Println("Warning: No IP data obtained from any source. Lists not updated.")
	}
}

func fetchIPList(apiURL string, config Config, ipAssociationChan chan<- IPAssociation) {
	sourceID := getSourceIdentifier(apiURL)
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
	}

	for attempt := 0; attempt < config.Retries; attempt++ {
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", apiURL, err)
			time.Sleep(time.Duration(config.RetryDelay*(attempt+1)) * time.Millisecond)
			continue
		}
		req.Header.Set("User-Agent", "RiskyIPFilterBot/1.0 (compatible; Mozilla/5.0)")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error fetching IP list from %s (attempt %d/%d): %v\n", apiURL, attempt+1, config.Retries, err)
			time.Sleep(time.Duration(config.RetryDelay*(attempt+1)) * time.Millisecond)
			continue
		}

		var _ error
		switch {
		case strings.Contains(apiURL, "projecthoneypot.org"):
			processProjectHoneypotRSS(resp.Body, ipAssociationChan)
		case strings.Contains(apiURL, "spamhaus.org/drop"):
			processSpamhausList(resp.Body, ipAssociationChan)
		case strings.Contains(apiURL, "torproject.org/torbulkexitlist"):
			processTorBulkExitList(resp.Body, ipAssociationChan)
		case strings.Contains(apiURL, "bruteforceblocker"):
			processBruteforceBlocker(resp.Body, ipAssociationChan)
		case strings.Contains(apiURL, "torproject.org/exit-addresses"):
			processTorExitAddresses(resp.Body, ipAssociationChan)
		case strings.Contains(apiURL, "firehol"):
			processFireholList(resp.Body, ipAssociationChan, sourceID)
		default:
			processGeneralIPList(resp.Body, ipAssociationChan, sourceID)
		}

		// 立即关闭 resp.Body，避免资源泄漏
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Error closing response body for %s: %v\n", apiURL, closeErr)
		}

		// 成功处理后直接 return
		return
	}
	fmt.Printf("Failed to fetch IP list from %s after %d attempts\n", apiURL, config.Retries)
}

func extractIPFromRequest(c *gin.Context) string {
	// c.ClientIP() is usually sufficient when trusted proxies are configured.
	ip := c.ClientIP()
	// Fallback or additional checks if needed, though Gin's ClientIP is robust.
	if ip == "" {
		ip = c.RemoteIP()
	}
	// log ip
	fmt.Printf("Request IP: %s\n", ip)
	if isIPInFastlyCIDR(ip) {
		fastlyClientIP := c.Request.Header.Get("Fastly-Client-Ip")
		if fastlyClientIP != "" && isIPAddress(fastlyClientIP) {
			return fastlyClientIP
		}
		cfConnectingIP := c.Request.Header.Get("CF-Connecting-IP")
		if cfConnectingIP != "" && isIPAddress(cfConnectingIP) {
			return cfConnectingIP
		}
	}
	return ip
}

// Processors for different list formats
// They now send IPAssociation to the channel

func processProjectHoneypotRSS(body io.Reader, ipAssociationChan chan<- IPAssociation) {
	var feed RSSFeed
	if err := xml.NewDecoder(body).Decode(&feed); err != nil {
		fmt.Printf("Error parsing ProjectHoneypot RSS: %v\n", err)
		return
	}
	for _, item := range feed.Channel.Items {
		if strings.HasPrefix(item.Title, "IP:") {
			ipStr := strings.TrimSpace(strings.TrimPrefix(item.Title, "IP:"))
			if ipRegex.MatchString(ipStr) {
				reason := "ProjectHoneypot: " + strings.TrimSpace(item.Description)
				ipAssociationChan <- IPAssociation{Entry: ipStr, Reason: reason}
			}
		}
	}
}

func processSpamhausList(body io.Reader, ipAssociationChan chan<- IPAssociation) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, ";", 2) // Split by semicolon for entry and comment
		entry := strings.TrimSpace(parts[0])
		if ipRegex.MatchString(entry) || cidrRegex.MatchString(entry) {
			reason := "Spamhaus DROP list"
			if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
				reason += ": " + strings.TrimSpace(parts[1])
			}
			ipAssociationChan <- IPAssociation{Entry: entry, Reason: reason}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Spamhaus list: %v\n", err)
	}
}

func processTorBulkExitList(body io.Reader, ipAssociationChan chan<- IPAssociation) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ipRegex.MatchString(line) {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: "Tor Bulk Exit Node"}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Tor bulk exit list: %v\n", err)
	}
}

func processBruteforceBlocker(body io.Reader, ipAssociationChan chan<- IPAssociation) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && ipRegex.MatchString(fields[0]) {
			reason := "Bruteforce Blocker list"
			if len(fields) > 1 {
				reason += ": " + strings.Join(fields[1:], " ")
			}
			ipAssociationChan <- IPAssociation{Entry: fields[0], Reason: reason}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading bruteforce blocker list: %v\n", err)
	}
}

func processTorExitAddresses(body io.Reader, ipAssociationChan chan<- IPAssociation) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ExitAddress") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && ipRegex.MatchString(parts[1]) {
				ipAssociationChan <- IPAssociation{Entry: parts[1], Reason: "Tor Exit Address"}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Tor exit addresses: %v\n", err)
	}
}

func processFireholList(body io.Reader, ipAssociationChan chan<- IPAssociation, sourceID string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "Name:") || strings.HasPrefix(line, "Type:") ||
			strings.HasPrefix(line, "Maintainer:") || strings.HasPrefix(line, "Version:") {
			continue
		}
		if ipRegex.MatchString(line) || cidrRegex.MatchString(line) {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: "Firehol list: " + sourceID}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Firehol list (%s): %v\n", sourceID, err)
	}
}

func processGeneralIPList(body io.Reader, ipAssociationChan chan<- IPAssociation, sourceID string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some lists might have IP then other data; take the first field if it's an IP/CIDR
		fields := strings.Fields(line)
		if len(fields) > 0 {
			entry := fields[0]
			if ipRegex.MatchString(entry) || cidrRegex.MatchString(entry) {
				reason := "General blocklist: " + sourceID
				// Optionally, try to capture more context if available
				// if len(fields) > 1 { reason += " (" + strings.Join(fields[1:], " ") + ")" }
				ipAssociationChan <- IPAssociation{Entry: entry, Reason: reason}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading general IP list (%s): %v\n", sourceID, err)
	}
}

func getSourceIdentifier(rawURL string) string {
	// This can be made more sophisticated, e.g., using a map or regexes
	if strings.Contains(rawURL, "projecthoneypot.org") {
		return "Project Honeypot"
	} else if strings.Contains(rawURL, "torproject.org") {
		return "Tor Project"
	} else if strings.Contains(rawURL, "spamhaus.org") {
		return "Spamhaus"
	} else if strings.Contains(rawURL, "cinsscore.com") {
		return "CINS Score"
	} else if strings.Contains(rawURL, "blocklist.de") {
		return "Blocklist.de"
	} else if strings.Contains(rawURL, "firehol/blocklist-ipsets/master/cybercrime.ipset") {
		return "Firehol Cybercrime"
	} else if strings.Contains(rawURL, "firehol_level1.netset") {
		return "Firehol Level 1"
	} else if strings.Contains(rawURL, "firehol_level2.netset") {
		return "Firehol Level 2"
	} else if strings.Contains(rawURL, "firehol_level3.netset") {
		return "Firehol Level 3"
	} else if strings.Contains(rawURL, "firehol_level4.netset") {
		return "Firehol Level 4"
	} else if strings.Contains(rawURL, "greensnow.co") {
		return "GreenSnow"
	} else if strings.Contains(rawURL, "X4BNet") {
		return "X4BNet VPN/Datacenter"
	} else if strings.Contains(rawURL, "bruteforceblocker") {
		return "BruteforceBlocker"
	} else if strings.Contains(rawURL, "dan.me.uk/torlist") {
		return "Dan.me.uk Tor List"
	} else if strings.Contains(rawURL, "stamparm/ipsum") {
		// Extract level from URL, e.g. levels/8.txt -> Ipsum Level 8
		re := regexp.MustCompile(`levels/(\d+)\.txt`)
		matches := re.FindStringSubmatch(rawURL)
		if len(matches) == 2 {
			return "IPSum Level " + matches[1]
		}
		return "IPSum Wall of Shame"
	}
	// Fallback using domain
	parsedURL, err := url.Parse(rawURL)
	if err == nil {
		return parsedURL.Hostname()
	}
	return "Unknown Source"
}

func processProxies(proxies []Proxy, concurrencyLimit int) []Proxy {
	var (
		wg              sync.WaitGroup
		resultMutex     sync.Mutex
		nonRiskyProxies = make([]Proxy, 0, len(proxies))
		semaphore       = make(chan struct{}, concurrencyLimit) // Use concurrency from config
	)

	for _, proxy := range proxies {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore slot

		go func(p Proxy) {
			defer func() {
				<-semaphore // Release semaphore slot
				wg.Done()
			}()

			if isIPAddress(p.Server) { // Only check if server is an IP
				if isBogonOrPrivateIP(p.Server) {
					return // Skip bogon/private IPs
				}
				risky, _ := getRiskStatusAndReason(p.Server) // Use the main checker
				if risky {
					return // Skip risky IPs
				}
			}
			// If not an IP, or IP is not bogon/private/risky, add to results
			resultMutex.Lock()
			nonRiskyProxies = append(nonRiskyProxies, p)
			resultMutex.Unlock()
		}(proxy)
	}
	wg.Wait()
	return nonRiskyProxies
}

func isIPAddress(s string) bool {
	// Consider both IPv4 and IPv6 if needed, but current regexes are IPv4 specific.
	// net.ParseIP can validate both, but ipRegex is used for matching specific formats.
	// For general validation, net.ParseIP(s) != nil is better.
	// However, since current lists are IPv4, ipRegex is fine.
	return ipRegex.MatchString(s) || (net.ParseIP(s) != nil && strings.Contains(s, ":")) // Basic IPv6 check
}

// isRiskyIP is now effectively replaced by getRiskStatusAndReason for external use.
// The internal logic is within getRiskStatusAndReason and uses riskySingleIPs and riskyCIDRInfo.
