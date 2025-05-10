package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
)

var (
	ipRegex   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	cidrRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
)

var (
	appCache       *cache.Cache
	_              *rate.Limiter
	reasonMap      = make(map[string]string)
	reasonMapMutex sync.RWMutex

	ipCacheKey      = "risky_ip_list"
	ipCacheExpiry   = 6 * time.Hour
	updateFrequency = 1 * time.Hour
)

// Config stores application configuration
type Config struct {
	Timeout     int `json:"timeout"`
	Retries     int `json:"retries"`
	RetryDelay  int `json:"retry_delay"`
	Concurrency int `json:"concurrency"`
}

// Proxy represents a proxy configuration
type Proxy struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	// Add other fields as needed
}

// IPCache represents the cached IP data structure
type IPCache struct {
	Timestamp int64    `json:"timestamp"`
	IPs       []string `json:"ips"`
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
	riskyIPs      = make(map[string]bool)
	riskyIPsMutex sync.RWMutex
	ipListAPIs    = []string{
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

// isBogonOrPrivateIP Check if the given IP is a bogon or private IP
// Bogon IPs are addresses that are not routable on the public internet.
// Private IPs are reserved for use within private networks.
func isBogonOrPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	privateIPBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	for _, cidr := range privateIPBlocks {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ipAddr) {
			return true
		}
	}

	// Bogon IPs are IP addresses that are not allocated to any organization.
	bogonIPBlocks := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}

	for _, cidr := range bogonIPBlocks {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ipAddr) {
			return true
		}
	}

	return false
}

// RateLimitMiddleware implements rate limiting for the API
func RateLimitMiddleware() gin.HandlerFunc {
	// Create a new rate limiter allowing 45 requests per minute
	limiter := rate.NewLimiter(rate.Limit(45.0/60.0), 45) // 45 requests per minute
	_ = limiter

	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, Response{
				"error",
				"Rate limit exceeded. Maximum 45 requests per minute allowed.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func getAllowedDomains() []string {
	env := os.Getenv("ALLOWED_CORS")
	if env == "" {
		return []string{"catyuki.com", "tzpro.xyz"}
	}
	// allow separate by comma
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

func main() {
	// Initialize cache with default expiration of 1 hours
	appCache = cache.New(ipCacheExpiry, 10*time.Minute)
	allowedDomains := getAllowedDomains()

	// Default configuration
	config := Config{
		Timeout:     10000,
		Retries:     3,
		RetryDelay:  2000,
		Concurrency: 10,
	}

	// Initialize Gin router
	router := gin.Default()

	err := router.SetTrustedProxies([]string{"10.42.0.0/16", "10.0.0.0/16"})
	if err != nil {
		return
	}

	router.NoRoute(func(c *gin.Context) {
		handleError(c, http.StatusNotFound, "Not Found")
	})

	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			for _, domain := range allowedDomains {
				//if strings.HasSuffix(origin, "."+domain) || origin == "https://"+domain || origin == "http://"+domain {
				if strings.HasSuffix(origin, "."+domain) || origin == "https://"+domain {
					return true
				}
			}
			return false
		},
		AllowMethods: []string{"GET", "POST"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}
	router.Use(cors.New(corsConfig))

	// Apply rate limiting to API endpoints
	router.Use(RateLimitMiddleware())

	// Start background IP list updater
	go updateIPListsPeriodically(config)

	// API endpoints
	router.POST("/filter-proxies", func(c *gin.Context) {
		var proxies []Proxy
		if err := c.ShouldBindJSON(&proxies); err != nil {
			c.JSON(http.StatusBadRequest, Response{"error", "Request body is invalid."})
			return
		}

		// Process proxies
		nonRiskyProxies := processProxies(proxies)
		filteredData := gin.H{
			"filtered_count": len(proxies) - len(nonRiskyProxies),
			"proxies":        nonRiskyProxies,
		}

		c.JSON(http.StatusOK, Response{
			Status:  "ok",
			Message: filteredData,
		})
	})

	// New IP check endpoint with both GET and POST support
	ipCheckGroup := router.Group("/api/v1/ip")
	{
		ipCheckGroup.GET("/:ip", checkIPHandler)
		ipCheckGroup.POST("/:ip", checkIPHandler)
	}

	router.GET("/api/v1/ip", checkRequestIPHandler)

	router.GET("/api/status", func(c *gin.Context) {
		riskyIPsMutex.RLock()
		count := len(riskyIPs)
		riskyIPsMutex.RUnlock()

		c.JSON(http.StatusOK, Response{
			Status: "ok",
			Message: StatusCountMsg{
				Timestamp: time.Now().Unix(),
				Count:     count,
			},
		})
	})

	// Start server
	fmt.Println("Starting Risky IP Filter server on :8080")
	err = router.Run(":8080")
	if err != nil {
		return
	}
}

// checkIPHandler handles requests to check if an IP is risky
func checkIPHandler(c *gin.Context) {
	ip := c.Param("ip")

	// Validate IP format
	if !isIPAddress(ip) {
		c.JSON(http.StatusBadRequest, Response{
			Status:  "error",
			Message: "Invalid IP address format",
		})
		return
	}

	// validate private/bogon ips
	if isBogonOrPrivateIP(ip) {
		c.JSON(http.StatusUnprocessableEntity, Response{
			Status:  "error",
			Message: "This is a private IP address, please check if you are calling this api correctly.",
		})
		return
	}

	// Check if IP is risky
	if isRiskyIP(ip) {
		// 先查单个 IP
		reasonMapMutex.RLock()
		message := reasonMap[ip]
		reasonMapMutex.RUnlock()

		// 如果查不到，再遍历 CIDR
		if message == "" {
			ipAddr := net.ParseIP(ip)
			if ipAddr != nil {
				riskyIPsMutex.RLock()
				for cidr := range riskyIPs {
					if strings.Contains(cidr, "/") {
						_, ipNet, err := net.ParseCIDR(cidr)
						if err == nil && ipNet.Contains(ipAddr) {
							reasonMapMutex.RLock()
							message = reasonMap[cidr]
							reasonMapMutex.RUnlock()
							if message != "" {
								break
							}
						}
					}
				}
				riskyIPsMutex.RUnlock()
			}
		}

		if message == "" {
			message = "IP found in risk database"
		}

		c.JSON(http.StatusOK, Response{
			Status:  "banned",
			Message: message,
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status:  "ok",
		Message: "",
	})
}

// updateIPListsPeriodically updates the risky IP lists at regular intervals
func updateIPListsPeriodically(config Config) {
	// Try to load from cache first
	if cachedData, found := appCache.Get(ipCacheKey); found {
		if ipCache, ok := cachedData.(IPCache); ok {
			loadIPsFromCache(ipCache)
			fmt.Println("Loaded IPs from cache")
		}
	}

	// Initial update
	updateIPLists(config)

	// Schedule periodic updates
	ticker := time.NewTicker(updateFrequency)
	for range ticker.C {
		updateIPLists(config)
	}
}

// loadIPsFromCache loads IPs from cache into the riskyIPs map
func loadIPsFromCache(ipCache IPCache) {
	riskyIPsMutex.Lock()
	defer riskyIPsMutex.Unlock()

	riskyIPs = make(map[string]bool, len(ipCache.IPs))
	for _, ip := range ipCache.IPs {
		riskyIPs[ip] = true
	}
}

// updateIPLists fetches and updates the risky IP lists from all sources
func updateIPLists(config Config) {
	fmt.Println("Starting IP lists update...")

	var wg sync.WaitGroup
	ipChan := make(chan string, 1000)

	// Launch goroutines to fetch IPs from each API
	for _, api := range ipListAPIs {
		wg.Add(1)
		go func(apiURL string) {
			defer wg.Done()
			fetchIPList(apiURL, config, ipChan)
		}(api)
	}

	// Launch a goroutine to close the channel when all fetchers are done
	go func() {
		wg.Wait()
		close(ipChan)
	}()

	// Collect all IPs
	newRiskyIPs := make(map[string]bool)
	for ip := range ipChan {
		if ip != "" {
			newRiskyIPs[ip] = true
		}
	}

	// Only update if we have some data
	if len(newRiskyIPs) > 0 {
		riskyIPsMutex.Lock()
		riskyIPs = newRiskyIPs
		riskyIPsMutex.Unlock()

		// Update cache
		ipList := make([]string, 0, len(newRiskyIPs))
		for ip := range newRiskyIPs {
			ipList = append(ipList, ip)
		}

		appCache.Set(ipCacheKey, IPCache{
			Timestamp: time.Now().Unix(),
			IPs:       ipList,
		}, ipCacheExpiry)

		fmt.Printf("Successfully updated risky IP list: %d records\n", len(newRiskyIPs))
	} else {
		fmt.Println("Warning: No IP data obtained from any source")
	}
}

// fetchIPList retrieves IP lists from a given API URL
func fetchIPList(apiURL string, config Config, ipChan chan<- string) {
	sourceId := getSourceIdentifier(apiURL)
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
	}

	var retries int
	for retries < config.Retries {
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %s\n", apiURL, err)
			retries++
			time.Sleep(time.Duration(config.RetryDelay*retries) * time.Millisecond)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error fetching IP list from %s (try %d/%d): %s\n",
				apiURL, retries+1, config.Retries, err)
			retries++
			time.Sleep(time.Duration(config.RetryDelay*retries) * time.Millisecond)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("HTTP error from %s: %d\n", apiURL, resp.StatusCode)
			err := resp.Body.Close()
			if err != nil {
				return
			}
			retries++
			time.Sleep(time.Duration(config.RetryDelay*retries) * time.Millisecond)
			continue
		}

		// Process based on URL and content type
		if strings.Contains(apiURL, "projecthoneypot.org") {
			// Handle Project Honeypot RSS feed
			processProjectHoneypotRSS(resp.Body, ipChan)
		} else if strings.Contains(apiURL, "spamhaus.org/drop") {
			// Handle Spamhaus DROP list format
			processSpamhausList(resp.Body, ipChan)
		} else if strings.Contains(apiURL, "torproject.org/torbulkexitlist") {
			// Handle Tor bulk exit list format
			processTorBulkExitList(resp.Body, ipChan)
		} else if strings.Contains(apiURL, "bruteforceblocker") {
			// Handle bruteforce blocker format
			processBruteforceBlocker(resp.Body, ipChan)
		} else if strings.Contains(apiURL, "torproject.org/exit-addresses") {
			// Handle TOR exit addresses formats
			processTorExitAddresses(resp.Body, ipChan)
		} else if strings.Contains(apiURL, "firehol") {
			// Handle Firehol ipset format
			processFireholList(resp.Body, ipChan, sourceId)
		} else {
			// Default processing for general lists
			processGeneralIPList(resp.Body, ipChan, sourceId)
		}

		err = resp.Body.Close()
		if err != nil {
			return
		}
		return // Success, exit the retry loop
	}

	fmt.Printf("Failed to fetch IP list from %s after %d attempts\n", apiURL, config.Retries)
}

func extractIPFromRequest(c *gin.Context) string {

	ip := c.ClientIP()
	if ip == "" {
		ip = c.RemoteIP()
	}
	return ip
}

func checkRequestIPHandler(c *gin.Context) {
	ip := extractIPFromRequest(c)

	if ip == "::1" || ip == "127.0.0.1" {
		c.JSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "Seems like you are using localhost, please check if you are calling this api correctly.",
			IP:      ip,
		})
		return
	}

	if !isIPAddress(ip) {
		c.JSON(http.StatusBadRequest, "Invalid IP address format")
		return
	}

	if isBogonOrPrivateIP(ip) {
		c.JSON(http.StatusUnprocessableEntity, ResponseWithIP{
			"ok",
			"This is a private IP address, please check if you are calling this api correctly.",
			ip,
		})
		return
	}

	if isRiskyIP(ip) {
		reasonMapMutex.RLock()
		message := reasonMap[ip]
		reasonMapMutex.RUnlock()
		c.JSON(http.StatusOK, ResponseWithIP{
			"banned",
			message,
			ip,
		})
		return
	}

	c.JSON(http.StatusOK, ResponseWithIP{
		"ok",
		"",
		ip,
	})
}

// processProjectHoneypotRSS processes the Project Honeypot RSS feed
func processProjectHoneypotRSS(body io.Reader, ipChan chan<- string) {
	var feed RSSFeed
	if err := xml.NewDecoder(body).Decode(&feed); err != nil {
		fmt.Printf("Error parsing ProjectHoneypot RSS: %s\n", err)
		return
	}

	for _, item := range feed.Channel.Items {
		// Extract IP from title (format: "IP: xxx.xxx.xxx.xxx")
		if strings.HasPrefix(item.Title, "IP:") {
			ipStr := strings.TrimSpace(strings.TrimPrefix(item.Title, "IP:"))
			if ipRegex.MatchString(ipStr) {
				ipChan <- ipStr
				reasonMapMutex.Lock()
				reasonMap[ipStr] = "ProjectHoneypot: " + item.Description
				reasonMapMutex.Unlock()
			}
		}
	}
}

// processSpamhausList processes the Spamhaus DROP list format
func processSpamhausList(body io.Reader, ipChan chan<- string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Format: "192.168.0.0/24 ;
		parts := strings.SplitN(line, " ", 2)
		if len(parts) > 0 && (ipRegex.MatchString(parts[0]) || cidrRegex.MatchString(parts[0])) {
			ipChan <- parts[0]

			// Store reason if available
			if len(parts) > 1 {
				reasonMapMutex.Lock()
				reasonMap[parts[0]] = "Spammers: " + strings.TrimSpace(parts[1])
				reasonMapMutex.Unlock()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Spamhaus list: %s\n", err)
	}
}

// processTorBulkExitList processes the Tor bulk exit list
func processTorBulkExitList(body io.Reader, ipChan chan<- string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if ipRegex.MatchString(line) {
			ipChan <- line

			// Store reason
			reasonMapMutex.Lock()
			reasonMap[line] = "Tor Exit Node"
			reasonMapMutex.Unlock()
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Tor bulk exit list: %s\n", err)
	}
}

// processBruteforceBlocker processes the bruteforce blocker format
func processBruteforceBlocker(body io.Reader, ipChan chan<- string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format usually includes IP and additional info
		fields := strings.Fields(line)
		if len(fields) > 0 && ipRegex.MatchString(fields[0]) {
			ipChan <- fields[0]

			// Store reason if available
			if len(fields) > 1 {
				reasonMapMutex.Lock()
				reasonMap[fields[0]] = "Bruteforce Blocker: " + strings.Join(fields[1:], " ")
				reasonMapMutex.Unlock()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading bruteforce blocker list: %s\n", err)
	}
}

// processTorExitAddresses processes the Tor exit addresses format
func processTorExitAddresses(body io.Reader, ipChan chan<- string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Format: "ExitAddress 1.2.3.4 2023-01-01 00:00:00"
		if strings.HasPrefix(line, "ExitAddress") {
			parts := strings.Split(line, " ")
			if len(parts) > 1 && ipRegex.MatchString(parts[1]) {
				ipChan <- parts[1]

				// Store reason
				reasonMapMutex.Lock()
				reasonMap[parts[1]] = "Tor Exit Node"
				reasonMapMutex.Unlock()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Tor exit addresses: %s\n", err)
	}
}

// processFireholList processes Firehol ipset format
func processFireholList(body io.Reader, ipChan chan<- string, sourceId string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines and metadata
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Name:") ||
			strings.HasPrefix(line, "Type:") || strings.HasPrefix(line, "Maintainer:") {
			continue
		}

		if ipRegex.MatchString(line) || cidrRegex.MatchString(line) {
			ipChan <- line

			// Store source as reason
			reasonMapMutex.Lock()
			reasonMap[line] = "Firehol: " + sourceId
			reasonMapMutex.Unlock()
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading Firehol list: %s\n", err)
	}
}

// processGeneralIPList processes general IP list formats
func processGeneralIPList(body io.Reader, ipChan chan<- string, sourceId string) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle lines with additional data
		fields := strings.Fields(line)
		if len(fields) > 0 {
			if ipRegex.MatchString(fields[0]) || cidrRegex.MatchString(fields[0]) {
				ipChan <- fields[0]

				// Store source as reason
				reasonMapMutex.Lock()
				reasonMap[fields[0]] = "Blocked IP source: " + sourceId
				reasonMapMutex.Unlock()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading general IP list: %s\n", err)
	}
}

// getSourceIdentifier extracts a readable source identifier from a URL
func getSourceIdentifier(url string) string {
	// Extract domain and path
	if strings.Contains(url, "projecthoneypot.org") {
		return "Project Honeypot"
	} else if strings.Contains(url, "torproject.org") {
		return "Tor Project"
	} else if strings.Contains(url, "spamhaus.org") {
		return "Spamhaus"
	} else if strings.Contains(url, "cinsscore.com") {
		return "CINS Score"
	} else if strings.Contains(url, "blocklist.de") {
		return "Blocklist.de"
	} else if strings.Contains(url, "firehol") && strings.Contains(url, "level1") {
		return "Firehol Level 1"
	} else if strings.Contains(url, "firehol") && strings.Contains(url, "level2") {
		return "Firehol Level 2"
	} else if strings.Contains(url, "firehol") && strings.Contains(url, "level3") {
		return "Firehol Level 3"
	} else if strings.Contains(url, "firehol") && strings.Contains(url, "level4") {
		return "Firehol Level 4"
	} else if strings.Contains(url, "firehol") && strings.Contains(url, "cybercrime") {
		return "Firehol Cybercrime"
	} else if strings.Contains(url, "greensnow") {
		return "GreenSnow"
	} else if strings.Contains(url, "malwaredomainlist") {
		return "Malware Domain List"
	} else if strings.Contains(url, "X4BNet") {
		return "X4B VPN/Datacenter List"
	} else if strings.Contains(url, "bruteforceblocker") {
		return "Bruteforce Blocker"
	} else if strings.Contains(url, "dan.me.uk") {
		return "Dan.me.uk Tor List"
	} else if strings.Contains(url, "stamparm") {
		return "IPSum Wall of Shame"
	}

	// Generic fallback
	return "Security List"
}

// processProxies filters the proxies list to remove those with risky IPs
func processProxies(proxies []Proxy) []Proxy {
	var (
		wg              sync.WaitGroup
		resultMutex     sync.Mutex
		nonRiskyProxies []Proxy
		semaphore       = make(chan struct{}, 50) // limit concurrency
	)

	for _, proxy := range proxies {
		wg.Add(1)
		semaphore <- struct{}{} // acquire

		go func(p Proxy) {
			defer wg.Done()
			defer func() { <-semaphore }() // release

			// Check if server is an IP address
			if isIPAddress(p.Server) {
				if isRiskyIP(p.Server) || isBogonOrPrivateIP(p.Server) {
					return
				}
			}
			// If not risky or bogon, add to results
			resultMutex.Lock()
			nonRiskyProxies = append(nonRiskyProxies, p)
			resultMutex.Unlock()
		}(proxy)
	}

	wg.Wait()
	return nonRiskyProxies
}

// isIPAddress checks if a string is a valid IPv4 address
func isIPAddress(s string) bool {
	return ipRegex.MatchString(s)
}

// isRiskyIP checks if an IP is in the risky list
func isRiskyIP(ip string) bool {
	// First check direct match
	riskyIPsMutex.RLock()
	if riskyIPs[ip] {
		riskyIPsMutex.RUnlock()
		return true
	}

	// Then check CIDR ranges
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		riskyIPsMutex.RUnlock()
		return false
	}

	for cidr := range riskyIPs {
		if strings.Contains(cidr, "/") {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(ipAddr) {
				riskyIPsMutex.RUnlock()
				return true
			}
		}
	}

	riskyIPsMutex.RUnlock()
	return false
}
