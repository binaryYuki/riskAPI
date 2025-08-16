package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// updateFastlyIPs updates Fastly IP addresses and sets trusted proxies
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
			// fallback to hardcoded IPs
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
		_ = cidrs
		fastlyCIDRsMutex.Unlock()
		fmt.Printf("Updated fastlyCIDRs: %d entries\n", len(cidrs))

		time.Sleep(1 * time.Hour)
	}
}

// updateIPListsPeriodically periodically updates risky IP lists
func updateIPListsPeriodically(config Config) {
	for {
		updateIPLists(config)
		time.Sleep(updateFrequency)
	}
}

// updateIPLists fetches and updates IP lists from various sources
func updateIPLists(config Config) {
	fmt.Println("Starting IP list update...")

	ipAssociationChan := make(chan IPAssociation, 1000)
	var wg sync.WaitGroup

	// Start fetchers for each API URL
	for _, apiURL := range ipListAPIs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			fetchIPList(url, config, ipAssociationChan)
		}(apiURL)
	}

	// Close channel when all fetchers are done
	go func() {
		wg.Wait()
		close(ipAssociationChan)
	}()

	// Collect IP associations
	var ipAssociations []IPAssociation
	for association := range ipAssociationChan {
		ipAssociations = append(ipAssociations, association)
	}

	if len(ipAssociations) > 0 {
		fmt.Printf("Collected %d IP/CIDR entries from all sources\n", len(ipAssociations))
		processIPAssociations(ipAssociations)
	} else {
		fmt.Println("Warning: No IP data obtained from any source. Lists not updated.")
	}
}

// fetchIPList fetches IP list from a single API URL
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

		if resp.StatusCode != http.StatusOK {
			err := resp.Body.Close()
			if err != nil {
				return
			}
			fmt.Printf("Non-200 status code %d from %s (attempt %d/%d)\n", resp.StatusCode, apiURL, attempt+1, config.Retries)
			time.Sleep(time.Duration(config.RetryDelay*(attempt+1)) * time.Millisecond)
			continue
		}

		// Parse the response based on content type or URL
		parseResponse(resp, apiURL, sourceID, ipAssociationChan)
		err = resp.Body.Close()
		if err != nil {
			return
		}
		return // Success, exit retry loop
	}
	fmt.Printf("Failed to fetch from %s after %d attempts\n", apiURL, config.Retries)
}

// parseResponse parses HTTP response and extracts IP addresses
func parseResponse(resp *http.Response, apiURL, sourceID string, ipAssociationChan chan<- IPAssociation) {
	if strings.Contains(apiURL, "projecthoneypot.org") && strings.Contains(apiURL, "rss=1") {
		parseRSSResponse(resp, sourceID, ipAssociationChan)
	} else {
		parseTextResponse(resp, sourceID, ipAssociationChan)
	}
}

// parseRSSResponse parses RSS format response
func parseRSSResponse(resp *http.Response, sourceID string, ipAssociationChan chan<- IPAssociation) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading RSS response body: %v\n", err)
		return
	}

	var feed RSSFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		fmt.Printf("Error parsing RSS XML: %v\n", err)
		return
	}

	for _, item := range feed.Channel.Items {
		lines := strings.Split(item.Description, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(line); err == nil {
				ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
				continue
			}
			if net.ParseIP(line) != nil {
				ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
			}
		}
	}
}

// parseTextResponse parses plain text response
func parseTextResponse(resp *http.Response, sourceID string, ipAssociationChan chan<- IPAssociation) {
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Extract IP from tor exit-addresses format
		if strings.HasPrefix(line, "ExitAddress ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				line = fields[1]
			}
		}

		// Try CIDR parse (IPv4 / IPv6)
		if _, _, err := net.ParseCIDR(line); err == nil {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
			continue
		}
		// Try single IP parse
		if net.ParseIP(line) != nil {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
		}
	}
}

// processIPAssociations processes collected IP associations and updates data structures
func processIPAssociations(ipAssociations []IPAssociation) {
	newSingleIPs := make(map[string]bool)
	var newCIDRInfo []CIDRInfo
	newReasonMap := make(map[string]string)

	for _, association := range ipAssociations {
		entry := association.Entry
		reason := association.Reason

		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			newCIDRInfo = append(newCIDRInfo, CIDRInfo{Net: ipNet, OriginalCIDR: entry})
			newReasonMap[entry] = reason
			continue
		}
		if net.ParseIP(entry) != nil { // single IP (v4 or v6)
			newSingleIPs[entry] = true
			newReasonMap[entry] = reason
		}
	}

	// Update global data structures
	riskyDataMutex.Lock()
	riskySingleIPs = newSingleIPs
	riskyCIDRInfo = newCIDRInfo
	reasonMap = newReasonMap
	riskyDataMutex.Unlock()

	// Update cache
	cacheData := IPCacheData{
		Timestamp: time.Now().Unix(),
		Entries:   make([]string, 0, len(ipAssociations)),
	}
	for _, association := range ipAssociations {
		cacheData.Entries = append(cacheData.Entries, association.Entry)
	}
	appCache.Set(ipCacheKey, cacheData, ipCacheExpiry)

	fmt.Printf("Updated IP lists: %d single IPs, %d CIDR ranges\n", len(newSingleIPs), len(newCIDRInfo))
}
