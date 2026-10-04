package feeds

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
	"time"
)

const userAgent = "RiskyIPFilterBot/1.0 (compatible; Mozilla/5.0)"

var errEmptySource = errors.New("source returned no valid entries")

// rssFeed Project Honey Pot RSS 结构
type rssFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

// fetchFeed 抓取并解析单个数据源（带重试）；全部重试失败或解析出 0 条时返回错误
func (s *Store) fetchFeed(ctx context.Context, feed Feed) ([]Entry, error) {
	client := &http.Client{Timeout: s.fetch.Timeout}
	retries := max(s.fetch.Retries, 1)

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			// 线性退避，可被 ctx 取消
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * s.fetch.RetryDelay):
			}
		}
		s.stats.fetchAttempts.Add(1)
		entries, err := s.fetchOnce(ctx, client, feed)
		if err == nil {
			s.stats.fetchSuccess.Add(1)
			return entries, nil
		}
		lastErr = err
		s.log.Debug("source fetch attempt failed", "source", feed.ID, "attempt", attempt+1, "of", retries, "err", err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	s.stats.fetchFailures.Add(1) // 所有重试失败才计一次失败
	return nil, fmt.Errorf("after %d attempts: %w", retries, lastErr)
}

func (s *Store) fetchOnce(ctx context.Context, client *http.Client, feed Feed) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code %d", resp.StatusCode)
	}

	var entries []Entry
	if feed.Format == FormatRSS {
		entries, err = s.parseRSS(resp.Body, feed.ID)
	} else {
		entries, err = s.parseText(resp.Body, feed.ID)
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
func (s *Store) parseLine(line, source string) (Entry, bool) {
	s.stats.totalLines.Add(1)
	if _, _, err := net.ParseCIDR(line); err != nil && net.ParseIP(line) == nil {
		return Entry{}, false
	}
	s.stats.classify(line)
	return Entry{Value: line, Source: source}, true
}

// parseRSS Project Honey Pot 的 IP 位于 <title>，格式为 "1.2.3.4 | SD"；<description> 只有事件描述
func (s *Store) parseRSS(body io.Reader, source string) ([]Entry, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read RSS body: %w", err)
	}
	var feed rssFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse RSS XML: %w", err)
	}

	var entries []Entry
	for _, item := range feed.Channel.Items {
		ip, _, _ := strings.Cut(item.Title, "|")
		if ip = strings.TrimSpace(ip); ip == "" {
			continue
		}
		if e, ok := s.parseLine(ip, source); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// parseText 解析纯文本列表：去掉行内注释后取第一个字段，兼容以下格式：
//
//	Spamhaus DROP: "1.10.16.0/20 ; SBL256894"
//	BruteForceBlocker: "77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073"
//	Tor exit-addresses: "ExitAddress 1.2.3.4 2026-01-01 00:00:00"
func (s *Store) parseText(body io.Reader, source string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
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
		if e, ok := s.parseLine(line, source); ok {
			entries = append(entries, e)
		}
	}
	// 读取中断（连接断开、超时）视为失败，避免用截断的数据替换上次的完整数据
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return entries, nil
}
