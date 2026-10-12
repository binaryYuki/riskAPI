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
	"net/netip"
	"strings"
	"time"

	"risky_ip_filter/internal/ipset"
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

// validator 条件请求用的校验值，取自上次成功响应的 ETag / Last-Modified
type validator struct {
	etag         string
	lastModified string
}

// feedData 单个数据源一次成功抓取的全部结果。发布后只读，更新时整体替换，
// 因此前缀、计数与校验值始终来自同一次响应。
type feedData struct {
	prefixes  []netip.Prefix
	cidrs     int       // prefixes 中源里写成 CIDR 形式的条数，其余为单 IP
	validator validator // 该次响应的校验值，下次抓取时用于条件请求
}

func (d *feedData) add(p netip.Prefix, cidr bool) {
	d.prefixes = append(d.prefixes, p)
	if cidr {
		d.cidrs++
	}
}

// fetched 单个数据源一次成功抓取的结果
type fetched struct {
	data        *feedData
	notModified bool // 源返回 304：内容未变，data 为 nil，调用方沿用上次数据
}

// fetchFeed 抓取并解析单个数据源（带重试）；全部重试失败或解析出 0 条时返回错误。
// cond 非空时发起条件请求，源未变化则返回 notModified。
func (s *Store) fetchFeed(ctx context.Context, feed Feed, cond validator) (fetched, error) {
	client := &http.Client{Timeout: s.fetch.Timeout}
	retries := max(s.fetch.Retries, 1)

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			// 线性退避，可被 ctx 取消
			select {
			case <-ctx.Done():
				return fetched{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * s.fetch.RetryDelay):
			}
		}
		s.stats.fetchAttempts.Add(1)
		res, err := s.fetchOnce(ctx, client, feed, cond)
		if err == nil {
			s.stats.fetchSuccess.Add(1)
			return res, nil
		}
		lastErr = err
		s.log.Debug("source fetch attempt failed", "source", feed.ID, "attempt", attempt+1, "of", retries, "err", err)
		if ctx.Err() != nil {
			return fetched{}, ctx.Err()
		}
	}
	s.stats.fetchFailures.Add(1) // 所有重试失败才计一次失败
	return fetched{}, fmt.Errorf("after %d attempts: %w", retries, lastErr)
}

func (s *Store) fetchOnce(ctx context.Context, client *http.Client, feed Feed, cond validator) (fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return fetched{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	if cond.etag != "" {
		req.Header.Set("If-None-Match", cond.etag)
	}
	if cond.lastModified != "" {
		req.Header.Set("If-Modified-Since", cond.lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fetched{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 只有发出了条件请求，304 才有意义；否则按异常状态处理
	if resp.StatusCode == http.StatusNotModified && cond != (validator{}) {
		return fetched{notModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return fetched{}, fmt.Errorf("non-200 status code %d", resp.StatusCode)
	}

	var data *feedData
	if feed.Format == FormatRSS {
		data, err = s.parseRSS(resp.Body)
	} else {
		data, err = s.parseText(resp.Body, feed.Format == FormatHostPort)
	}
	if err != nil {
		return fetched{}, err
	}
	if len(data.prefixes) == 0 {
		return fetched{}, errEmptySource
	}
	data.validator = validator{etag: resp.Header.Get("ETag"), lastModified: resp.Header.Get("Last-Modified")}
	return fetched{data: data}, nil
}

// parseLine 将单行解析为规范化前缀，合法则追加到 d 并计入统计。
// 全链路只在此处解析一次：解析成功即为合法，统计与后续建表都直接使用解析结果。
func (s *Store) parseLine(line string, d *feedData) {
	s.stats.totalLines.Add(1)
	// 带 zone 的地址（fe80::1%eth0）不是可路由的公网地址，不接受
	if strings.Contains(line, "%") {
		return
	}
	p, ok := ipset.ParseEntry(line)
	if !ok {
		return
	}
	// 解析后 "1.2.3.4" 与 "1.2.3.4/32" 是同一个前缀，写法只能在这里区分
	cidr := strings.Contains(line, "/")
	s.stats.classify(p, cidr)
	d.add(p, cidr)
}

// parseRSS Project Honey Pot 的 IP 位于 <title>，格式为 "1.2.3.4 | SD"；<description> 只有事件描述
func (s *Store) parseRSS(body io.Reader) (*feedData, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read RSS body: %w", err)
	}
	var feed rssFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse RSS XML: %w", err)
	}

	d := &feedData{}
	for _, item := range feed.Channel.Items {
		ip, _, _ := strings.Cut(item.Title, "|")
		if ip = strings.TrimSpace(ip); ip == "" {
			continue
		}
		s.parseLine(ip, d)
	}
	return d, nil
}

// parseText 解析纯文本列表：去掉行内注释后取第一个字段，兼容以下格式：
//
//	Spamhaus DROP: "1.10.16.0/20 ; SBL256894"
//	BruteForceBlocker: "77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073"
//	Tor exit-addresses: "ExitAddress 1.2.3.4 2026-01-01 00:00:00"
//
// hostPort 为 true 时（FormatHostPort）第一个字段视为代理地址，去掉协议与端口后取 IP。
func (s *Store) parseText(body io.Reader, hostPort bool) (*feedData, error) {
	d := &feedData{}
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
		if hostPort {
			line = hostFromProxy(line)
		}
		s.parseLine(line, d)
	}
	// 读取中断（连接断开、超时）视为失败，避免用截断的数据替换上次的完整数据
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return d, nil
}

// hostFromProxy 从 "scheme://ip:port"、"[v6]:port"、"ip:port" 中取出主机部分；无端口时原样返回
func hostFromProxy(addr string) string {
	if _, rest, ok := strings.Cut(addr, "://"); ok {
		addr = rest
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
