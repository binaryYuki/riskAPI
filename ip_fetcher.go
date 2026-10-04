package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

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
	metricsReset()

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
		metricsAddFetchAttempt()
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

		// 成功路径
		parseResponse(resp, apiURL, sourceID, ipAssociationChan)
		err = resp.Body.Close()
		if err != nil {
			return
		}
		metricsAddFetchSuccess()
		return // Success, exit retry loop
	}
	metricsAddFetchFailure() // 所有重试失败才计一次失败
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
			metricsAddLine()
			if _, _, err := net.ParseCIDR(line); err == nil {
				ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
				classifyAndCount(line)
				continue
			}
			if net.ParseIP(line) != nil {
				ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
				classifyAndCount(line)
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
		metricsAddLine()

		// Extract IP from tor exit-addresses format
		if strings.HasPrefix(line, "ExitAddress ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				line = fields[1]
			}
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
			classifyAndCount(line)
			continue
		}
		if net.ParseIP(line) != nil {
			ipAssociationChan <- IPAssociation{Entry: line, Reason: sourceID}
			classifyAndCount(line)
		}
	}
}

// processIPAssociations 由抓取结果构建新的风险查找表并整体替换
// 同一条目出现在多个来源时，后到的来源覆盖先到的
func processIPAssociations(ipAssociations []IPAssociation) {
	newSet := newPrefixSet()
	singleIPs, cidrs := 0, 0
	for _, association := range ipAssociations {
		if !newSet.insert(association.Entry, association.Reason) {
			continue
		}
		if strings.Contains(association.Entry, "/") {
			cidrs++
		} else {
			singleIPs++
		}
	}
	storeRiskySet(newSet)

	fmt.Printf("Updated IP lists: %d single IPs, %d CIDR ranges (%d unique prefixes)\n", singleIPs, cidrs, newSet.size())
}
