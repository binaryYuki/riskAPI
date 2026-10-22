package ipsb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// GeoResponse models the ip.sb geoip API response.
type GeoResponse struct {
	IP            string   `json:"ip"`
	CountryCode   string   `json:"country_code"`
	Country       string   `json:"country"`
	RegionCode    string   `json:"region_code"`
	Region        string   `json:"region"`
	City          string   `json:"city"`
	Latitude      float64  `json:"latitude"`
	Longitude     float64  `json:"longitude"`
	ASN           int      `json:"asn"`
	Organization  string   `json:"organization"`
	ISP           string   `json:"isp"`
	Timezone      string   `json:"timezone"`
	UTCOffset     string   `json:"utc_offset"`
	PostalCode    string   `json:"postal_code"`
	ContinentCode string   `json:"continent_code"`
	ContinentName string   `json:"continent_name"`
	Languages     []string `json:"languages"`
}

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// baseURL 测试时替换为 httptest 地址
var baseURL = "https://api.ip.sb/geoip"

// Limiter 限速器：Wait 阻塞到获得配额，所需等待超过 ctx 截止时间时返回错误。*rate.Limiter 即满足该接口
type Limiter interface {
	Wait(ctx context.Context) error
}

// Client ip.sb 查询客户端，可并发使用：经 http.DefaultTransport 复用长连接，并按 limiter 限速（ip.sb 限制 5 次/秒）
type Client struct {
	http    *http.Client
	limiter Limiter // 为 nil 时不限速
}

// NewClient 按 perSecond 在本实例内均匀限速；perSecond <= 0 表示不限速
func NewClient(perSecond float64) *Client {
	if perSecond <= 0 {
		return NewClientWithLimiter(nil)
	}
	// burst=1：请求间隔至少 1/perSecond，任意 1 秒窗口内都不会超过上限
	return NewClientWithLimiter(rate.NewLimiter(rate.Limit(perSecond), 1))
}

// NewClientWithLimiter 使用指定限速器（如多实例共享的限速器）；limiter 为 nil 表示不限速
func NewClientWithLimiter(limiter Limiter) *Client {
	return &Client{
		// Transport 留空即使用 http.DefaultTransport：main 已调大其连接池，开启 tracing 时还会被 otelhttp 包装，
		// 不能断言为 *http.Transport
		http:    &http.Client{Timeout: 5 * time.Second},
		limiter: limiter,
	}
}

// Query fetches geo information for an IP using ip.sb public API.
// Returned map is normalized (snake_case keys) and omits the raw IP field.
// 等待限速配额超过 ctx 截止时间时立即返回错误。
func (c *Client) Query(ctx context.Context, ip string) (map[string]interface{}, error) {
	if net.ParseIP(ip) == nil {
		return nil, errors.New("invalid ip")
	}
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("ip.sb rate limit: %w", err)
		}
	}

	url := fmt.Sprintf("%s/%s", baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip.sb http %d", resp.StatusCode)
	}
	var gr GeoResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, err
	}
	if gr.CountryCode == "" && gr.ContinentCode == "" {
		return nil, errors.New("ip.sb empty response")
	}

	out := map[string]interface{}{
		"country_code":   gr.CountryCode,
		"country":        gr.Country,
		"region_code":    gr.RegionCode,
		"region":         gr.Region,
		"city":           gr.City,
		"latitude":       gr.Latitude,
		"longitude":      gr.Longitude,
		"asn":            gr.ASN,
		"organization":   gr.Organization,
		"isp":            gr.ISP,
		"timezone":       gr.Timezone,
		"utc_offset":     gr.UTCOffset,
		"postal_code":    gr.PostalCode,
		"continent_code": gr.ContinentCode,
		"continent_name": gr.ContinentName,
	}
	if len(gr.Languages) > 0 {
		out["languages"] = gr.Languages
	}
	return out, nil
}
