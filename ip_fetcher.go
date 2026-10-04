package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sourceResult 单个数据源一次抓取的结果
type sourceResult struct {
	url     string
	entries []IPAssociation
	err     error
}

var (
	// lastGoodEntries 记录每个数据源最近一次成功抓取的条目（url → entries）。
	// 某个源本轮失败时沿用上次结果，避免其条目在全量替换中整体消失。仅由更新协程访问。
	lastGoodEntries = make(map[string][]IPAssociation)

	// riskDataReady 首轮更新完成且至少一个数据源可用后置为 true，供 /api/ready 使用
	riskDataReady atomic.Bool
)

var errEmptySource = errors.New("source returned no valid entries")

// updateIPListsPeriodically 立即执行一次更新，之后按 updateFrequency 周期更新，ctx 取消时退出
func updateIPListsPeriodically(ctx context.Context, config Config) {
	ticker := time.NewTicker(updateFrequency)
	defer ticker.Stop()
	for {
		updateIPLists(ctx, config)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// updateIPLists 并发抓取全部数据源，失败的源沿用上次成功的数据，再整体替换风险表
func updateIPLists(ctx context.Context, config Config) {
	fmt.Println("Starting IP list update...")
	metricsReset()

	results := make([]sourceResult, len(ipListAPIs))
	var wg sync.WaitGroup
	for i, apiURL := range ipListAPIs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries, err := fetchIPList(ctx, apiURL, config)
			results[i] = sourceResult{url: apiURL, entries: entries, err: err}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		fmt.Println("IP list update cancelled")
		return
	}

	// 按配置顺序合并，保证同一前缀出现在多个源时标签确定（后面的源覆盖前面的）
	var merged []IPAssociation
	fresh, stale, missing := 0, 0, 0
	for _, r := range results {
		switch {
		case r.err == nil:
			lastGoodEntries[r.url] = r.entries
			fresh++
		case lastGoodEntries[r.url] != nil:
			fmt.Printf("Warning: %s failed (%v), keeping %d entries from last successful fetch\n", getSourceIdentifier(r.url), r.err, len(lastGoodEntries[r.url]))
			stale++
		default:
			fmt.Printf("Warning: %s failed (%v) and has no previous data\n", getSourceIdentifier(r.url), r.err)
			missing++
			continue
		}
		merged = append(merged, lastGoodEntries[r.url]...)
	}
	fmt.Printf("IP list sources: %d fresh, %d stale (reused), %d unavailable\n", fresh, stale, missing)

	if fresh+stale == 0 {
		fmt.Println("Warning: No IP data obtained from any source. Lists not updated.")
		return
	}
	fmt.Printf("Collected %d IP/CIDR entries from all sources\n", len(merged))
	processIPAssociations(merged)
	riskDataReady.Store(true)
}

// fetchIPList 抓取并解析单个数据源（带重试）；全部重试失败或解析出 0 条时返回错误
func fetchIPList(ctx context.Context, apiURL string, config Config) ([]IPAssociation, error) {
	sourceID := getSourceIdentifier(apiURL)
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
	}

	var lastErr error
	for attempt := 0; attempt < config.Retries; attempt++ {
		if attempt > 0 {
			// 线性退避，可被 ctx 取消
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(config.RetryDelay*attempt) * time.Millisecond):
			}
		}
		metricsAddFetchAttempt()
		entries, err := fetchOnce(ctx, client, apiURL, sourceID)
		if err == nil {
			metricsAddFetchSuccess()
			return entries, nil
		}
		lastErr = err
		fmt.Printf("Error fetching IP list from %s (attempt %d/%d): %v\n", apiURL, attempt+1, config.Retries, err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	metricsAddFetchFailure() // 所有重试失败才计一次失败
	return nil, fmt.Errorf("after %d attempts: %w", config.Retries, lastErr)
}

func fetchOnce(ctx context.Context, client *http.Client, apiURL, sourceID string) ([]IPAssociation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RiskyIPFilterBot/1.0 (compatible; Mozilla/5.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code %d", resp.StatusCode)
	}

	var entries []IPAssociation
	if strings.Contains(apiURL, "projecthoneypot.org") && strings.Contains(apiURL, "rss=1") {
		entries, err = parseRSSResponse(resp.Body, sourceID)
	} else {
		entries, err = parseTextResponse(resp.Body, sourceID)
	}
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errEmptySource
	}
	return entries, nil
}

// parseLine 校验单行是否为 IP 或 CIDR，合法则返回条目并计入统计
func parseLine(line, sourceID string) (IPAssociation, bool) {
	metricsAddLine()
	if _, _, err := net.ParseCIDR(line); err != nil && net.ParseIP(line) == nil {
		return IPAssociation{}, false
	}
	classifyAndCount(line)
	return IPAssociation{Entry: line, Reason: sourceID}, true
}

// parseRSSResponse parses RSS format response
func parseRSSResponse(body io.Reader, sourceID string) ([]IPAssociation, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read RSS body: %w", err)
	}
	var feed RSSFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse RSS XML: %w", err)
	}

	// Project Honey Pot 的 IP 位于 <title>，格式为 "1.2.3.4 | SD"；<description> 只有事件描述
	var entries []IPAssociation
	for _, item := range feed.Channel.Items {
		ip, _, _ := strings.Cut(item.Title, "|")
		if ip = strings.TrimSpace(ip); ip == "" {
			continue
		}
		if e, ok := parseLine(ip, sourceID); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// parseTextResponse parses plain text response
func parseTextResponse(body io.Reader, sourceID string) ([]IPAssociation, error) {
	var entries []IPAssociation
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		// 去掉行内注释后取第一个字段，兼容以下格式：
		//   Spamhaus DROP: "1.10.16.0/20 ; SBL256894"
		//   BruteForceBlocker: "77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073"
		//   Tor exit-addresses: "ExitAddress 1.2.3.4 2026-01-01 00:00:00"
		line := scanner.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		line = fields[0]
		if line == "ExitAddress" && len(fields) >= 2 {
			line = fields[1]
		}
		if e, ok := parseLine(line, sourceID); ok {
			entries = append(entries, e)
		}
	}
	// 读取中断（连接断开、超时）视为失败，避免用截断的数据替换上次的完整数据
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return entries, nil
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
