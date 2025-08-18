package ipsb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
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

const (
	baseURL = "https://api.ip.sb/geoip"
	ua      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Query fetches geo information for an IP using ip.sb public API.
// Returned map is normalized (snake_case keys) and omits the raw IP field.
func Query(ctx context.Context, ip string, client *http.Client) (map[string]interface{}, error) {
	if net.ParseIP(ip) == nil {
		return nil, errors.New("invalid ip")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	url := fmt.Sprintf("%s/%s", baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")

	resp, err := client.Do(req)
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
