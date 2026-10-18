package meituan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Raw response structures mapping Meituan API JSON
type ipResp struct {
	Data struct {
		Lng       float64 `json:"lng"`
		FromWhere string  `json:"fromwhere"`
		IP        string  `json:"ip"`
		RGeo      struct {
			Country  string `json:"country"`
			Province string `json:"province"`
			AdCode   string `json:"adcode"`
			City     string `json:"city"`
			District string `json:"district"`
		} `json:"rgeo"`
		Lat float64 `json:"lat"`
	} `json:"data"`
	// 定位不到时返回 HTTP 200 + {"error":{"code":404,"type":"Data Not found","message":"Can Not Loc"}}
	Error *struct {
		Code    int    `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type locationResp struct {
	Data struct {
		Area         int     `json:"area"`
		Country      string  `json:"country"`
		Lng          float64 `json:"lng"`
		CityPinyin   string  `json:"cityPinyin"`
		City         string  `json:"city"`
		IsForeign    bool    `json:"isForeign"`
		OriginCityID int     `json:"originCityID"`
		DPCityID     int     `json:"dpCityId"`
		OpenCityName string  `json:"openCityName"`
		IsOpen       bool    `json:"isOpen"`
		Province     string  `json:"province"`
		AreaName     string  `json:"areaName"`
		ParentArea   int     `json:"parentArea"`
		District     string  `json:"district"`
		ID           int     `json:"id"`
		Detail       string  `json:"detail"`
		Lat          float64 `json:"lat"`
	} `json:"data"`
}

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// 测试时替换为 httptest 地址
var (
	ipAPI       = "https://apimobile.meituan.com/locate/v2/ip/loc"
	locationAPI = "https://apimobile.meituan.com/group/v1/city/latlng"
)

// ErrNotFound 美团明确表示没有该 IP 的定位数据（重试也不会变化）
var ErrNotFound = errors.New("meituan: no location data for ip")

// defaultClient 未传 client 时共用，复用长连接
var defaultClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 8
	return &http.Client{Timeout: 5 * time.Second, Transport: t}
}()

// QueryOptions controls optional behaviour.
// Enhanced triggers the second detail lookup (lat/lng to rich city record).
type QueryOptions struct {
	Enhanced bool
	Timeout  time.Duration // optional per-request timeout override
}

// Query performs Meituan IP lookup. Returns a map ready to be merged into provider results.
// Keys are normalized to snake_case for consistency with existing project output style.
func Query(ctx context.Context, ip string, client *http.Client, opt QueryOptions) (map[string]interface{}, error) {
	if net.ParseIP(ip) == nil {
		return nil, errors.New("invalid ip")
	}
	if client == nil {
		client = defaultClient
	}
	if opt.Timeout > 0 {
		// create a derived client with its own timeout
		client = &http.Client{Timeout: opt.Timeout, Transport: client.Transport}
	}

	ipData, err := queryIP(ctx, client, ip)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"country":   ipData.Data.RGeo.Country,
		"province":  ipData.Data.RGeo.Province,
		"city":      ipData.Data.RGeo.City,
		"district":  ipData.Data.RGeo.District,
		"latitude":  ipData.Data.Lat,
		"longitude": ipData.Data.Lng,
		"fromwhere": ipData.Data.FromWhere,
		"adcode":    ipData.Data.RGeo.AdCode,
		"accuracy":  "medium", // default, may upgrade to high if enhanced succeeds
	}

	if opt.Enhanced {
		if loc, err := queryLocation(ctx, client, ipData.Data.Lat, ipData.Data.Lng, "0"); err == nil && loc != nil {
			result["area_name"] = loc.Data.AreaName
			result["detail"] = loc.Data.Detail
			result["city_pinyin"] = loc.Data.CityPinyin
			result["open_city_name"] = loc.Data.OpenCityName
			result["is_foreign"] = loc.Data.IsForeign
			result["dp_city_id"] = loc.Data.DPCityID
			result["area"] = loc.Data.Area
			result["parent_area"] = loc.Data.ParentArea
			result["accuracy"] = "high"
		}
	}
	return result, nil
}

func queryIP(ctx context.Context, client *http.Client, ip string) (*ipResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipAPI, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("rgeo", "true")
	q.Set("ip", ip)
	req.URL.RawQuery = q.Encode()
	setHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("meituan ip api http %d", resp.StatusCode)
	}
	var out ipResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil && out.Error.Code == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if out.Data.RGeo.Country == "" {
		return nil, errors.New("meituan ip api malformed data")
	}
	return &out, nil
}

// ReverseGeocode 用美团把经纬度解析为行政区划（tag=1 返回附近地点的精确坐标）。
// 美团无该坐标数据时返回 nil, nil。
func ReverseGeocode(ctx context.Context, client *http.Client, lat, lng float64) (map[string]interface{}, error) {
	if client == nil {
		client = defaultClient
	}
	loc, err := queryLocation(ctx, client, lat, lng, "1")
	if err != nil {
		return nil, err
	}
	d := loc.Data
	if d.Country == "" && d.City == "" {
		return nil, nil
	}
	return map[string]interface{}{
		"country":        d.Country,
		"province":       d.Province,
		"city":           d.City,
		"district":       d.District,
		"area_name":      d.AreaName,
		"detail":         d.Detail,
		"city_pinyin":    d.CityPinyin,
		"open_city_name": d.OpenCityName,
		"is_foreign":     d.IsForeign,
		"dp_city_id":     d.DPCityID,
		"latitude":       d.Lat,
		"longitude":      d.Lng,
	}, nil
}

func queryLocation(ctx context.Context, client *http.Client, lat, lng float64, tag string) (*locationResp, error) {
	url := fmt.Sprintf("%s/%f,%f", locationAPI, lat, lng)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("tag", tag)
	req.URL.RawQuery = q.Encode()
	setHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("meituan location api http %d", resp.StatusCode)
	}
	var out locationResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// Data may be empty; no error if so
	return &out, nil
}

func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Referer", "https://www.meituan.com/")
}

// Suitable reports whether the IP is acceptable for Meituan lookup.
// Meituan IP locate endpoint effectively supports only public IPv4; IPv6 requests are unreliable.
func Suitable(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil { // parse failed
		return false
	}
	// Only IPv4 supported
	if parsed.To4() == nil {
		return false
	}
	// Exclude loopback / unspecified / link-local
	if parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return false
	}
	// Exclude RFC1918 private ranges
	privateBlocks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range privateBlocks {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsed) {
			return false
		}
	}
	return true
}
