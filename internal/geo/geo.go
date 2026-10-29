// Package geo 聚合多个 IP 地理位置数据源：本地 MMDB（ipinfo / iplocate / maxmind）、
// 纯真库，以及外部 API：ip.sb 总是查询；中国 IP 另查美团 IP 定位，并用美团把 ip.sb 经纬度逆地理编码。
package geo

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"risky_ip_filter/internal/geo/ipsb"
	"risky_ip_filter/internal/geo/meituan"
	"risky_ip_filter/internal/geo/qqwry"
)

// mmdbProviders 各 provider 的 MMDB 文件（相对 providers 目录；按顺序深度合并，后者覆盖同名字段）。
// maxmind 的 City 库包含 Country 库的全部字段并增加 city / subdivisions / location / postal；
// 保留 Country 库，City 库缺失时仍能给出国家
var mmdbProviders = []struct {
	name string
	dbs  []string
}{
	{"ipinfo", []string{"ipinfo/ipinfo-country.mmdb", "ipinfo/ipinfo-asn.mmdb"}},
	{"iplocate", []string{"iplocate/iplocate-country.mmdb", "iplocate/iplocate-asn.mmdb"}},
	{"maxmind", []string{"maxmind/GeoLite2-Country.mmdb", "maxmind/GeoLite2-City.mmdb", "maxmind/GeoLite2-ASN.mmdb"}},
}

// maxReverseGeoRadiusKm maxmind 误差半径超过该值时坐标只是国家/大区默认点（如中国为郑州附近、半径 1000km），
// ip.sb 返回同一坐标时不做美团逆地理编码，避免把默认点解析成看似精确的街区
const maxReverseGeoRadiusKm = 100

// Service 地理位置查询服务，可并发使用
type Service struct {
	providersDir  string
	qq            *qqwry.DB
	ipsb          *ipsb.Client
	lookupTimeout time.Duration
	log           *slog.Logger
	readers       sync.Map // MMDB 路径 → *maxminddb.Reader
}

// New 创建查询服务；qq 可为 nil（纯真库加载失败时跳过）。
// ipsbLimiter 为 ip.sb 请求限速（免费接口按出口 IP 限制 5 次/秒，多副本共用出口时应使用共享限速器），为 nil 时不限速
func New(providersDir string, qq *qqwry.DB, ipsbLimiter ipsb.Limiter, lookupTimeout time.Duration, log *slog.Logger) *Service {
	return &Service{
		providersDir:  providersDir,
		qq:            qq,
		ipsb:          ipsb.NewClientWithLimiter(ipsbLimiter),
		lookupTimeout: lookupTimeout,
		log:           log,
	}
}

// QQWryStats 返回纯真库加载统计
func (s *Service) QQWryStats() map[string]any {
	return s.qq.Stats()
}

// Lookup 查询 IP 的各数据源结果。complete=false 表示外部 API 失败（含超时），结果不完整。
// log 用于携带请求级字段（如 correlation_id）。
func (s *Service) Lookup(ctx context.Context, ipStr string, log *slog.Logger) (results map[string]any, complete bool) {
	ip := net.ParseIP(ipStr)
	results = make(map[string]any)

	// 本地 MMDB 查询（reader 常驻内存，单次仅需微秒级，无需并发或超时控制）
	for _, p := range mmdbProviders {
		// 将同一 provider 的多个 MMDB 结果合并为一个 map
		providerData := make(map[string]any)
		for _, db := range p.dbs {
			dbPath := filepath.Join(s.providersDir, db)
			data, err := s.lookupMMDB(dbPath, ip)
			if err == nil {
				mergeGeneric(providerData, data)
			} else if !errors.Is(err, errMMDBUnavailable) {
				log.ErrorContext(ctx, "mmdb lookup failed", "provider", p.name, "db", dbPath, "err", err)
			}
		}
		if len(providerData) > 0 {
			removeIPKey(providerData)
			results[p.name] = providerData
		}
	}

	// 纯真库（本地查询，仅 IPv4）
	if country, area, err := s.qq.Query(ipStr); err == nil {
		results["qqwry"] = map[string]any{
			"data": qqwry.ParseCountry(country),
			"area": area,
		}
	} else {
		log.ErrorContext(ctx, "qqwry lookup failed", "err", err)
	}

	ctx, cancel := context.WithTimeout(ctx, s.lookupTimeout)
	defer cancel()

	// ip.sb 总是查询；其它 provider 判定为中国(CN) 时才使用美团（IP 定位与逆地理编码），海外 IP 不查美团
	china := isChina(results)
	var (
		wg                    sync.WaitGroup
		ipsbData, meituanData map[string]any
		ipsbDone, meituanDone = true, true
	)
	coarse := coarsePoints(results)
	wg.Go(func() { ipsbData, ipsbDone = s.queryIPSB(ctx, ipStr, china, coarse, log) })
	if china {
		wg.Go(func() { meituanData, meituanDone = queryMeituan(ctx, ipStr, log) })
	}
	wg.Wait()
	if len(ipsbData) > 0 {
		results["ipsb"] = ipsbData
	}
	if len(meituanData) > 0 {
		results["meituan"] = meituanData
	}
	return results, ipsbDone && meituanDone
}

// queryIPSB 查询 ip.sb；reverseGeo 为 true 且结果带经纬度（不在 coarse 中）时用美团逆地理编码，放入 "meituan_geo" 字段。
// done=false 表示请求失败（含超时、限速等待超时），结果不完整
func (s *Service) queryIPSB(ctx context.Context, ip string, reverseGeo bool, coarse map[latLng]bool, log *slog.Logger) (data map[string]any, done bool) {
	data, err := s.ipsb.Query(ctx, ip)
	if err != nil {
		log.ErrorContext(ctx, "ipsb lookup failed", "err", err)
		return nil, false
	}
	lat, _ := data["latitude"].(float64)
	lng, _ := data["longitude"].(float64)
	if !reverseGeo || (lat == 0 && lng == 0) || coarse[latLng{lat, lng}] {
		return data, true
	}
	g, err := meituan.ReverseGeocode(ctx, nil, lat, lng)
	if err != nil {
		log.ErrorContext(ctx, "meituan reverse geocode failed", "err", err)
		return data, false
	}
	if g != nil {
		data["meituan_geo"] = g
	}
	return data, true
}

// queryMeituan 查询美团 IP 定位。美团明确无数据视为查询完成（重试不会变化），不影响缓存时长
func queryMeituan(ctx context.Context, ip string, log *slog.Logger) (data map[string]any, done bool) {
	if !meituan.Suitable(ip) {
		log.InfoContext(ctx, "meituan skipped", "reason", "unsuitable_ipv4")
		return nil, true
	}
	data, err := meituan.Query(ctx, ip, nil, meituan.QueryOptions{Enhanced: true})
	switch {
	case errors.Is(err, meituan.ErrNotFound):
		log.InfoContext(ctx, "meituan has no data for ip")
		return nil, true
	case err != nil:
		log.ErrorContext(ctx, "meituan lookup failed", "err", err)
		return nil, false
	}
	return data, true
}

type latLng struct{ lat, lng float64 }

// coarsePoints 返回本地库中误差半径超过 maxReverseGeoRadiusKm 的坐标
func coarsePoints(results map[string]any) map[latLng]bool {
	mm, _ := results["maxmind"].(map[string]any)
	loc, _ := mm["location"].(map[string]any)
	lat, ok1 := loc["latitude"].(float64)
	lng, ok2 := loc["longitude"].(float64)
	radius, ok3 := loc["accuracy_radius"].(uint64)
	if !ok1 || !ok2 || !ok3 || radius <= maxReverseGeoRadiusKm {
		return nil
	}
	return map[latLng]bool{{lat, lng}: true}
}

// isChina 判断结果中是否有任何 provider 显示为中国
func isChina(results map[string]any) bool {
	// ipinfo: country == "CN"
	if v, ok := results["ipinfo"].(map[string]any); ok {
		if c, ok2 := v["country"].(string); ok2 && c == "CN" {
			return true
		}
	}
	// maxmind: country.iso_code == "CN"
	if v, ok := results["maxmind"].(map[string]any); ok {
		if country, ok2 := v["country"].(map[string]any); ok2 {
			if iso, ok3 := country["iso_code"].(string); ok3 && iso == "CN" {
				return true
			}
		}
	}
	// iplocate: country_code == "CN"
	if v, ok := results["iplocate"].(map[string]any); ok {
		if c, ok2 := v["country_code"].(string); ok2 && c == "CN" {
			return true
		}
	}
	return false
}

// removeIPKey 递归移除 map 中名为 "ip" 的字段
func removeIPKey(data any) {
	switch d := data.(type) {
	case map[string]any:
		for k, v := range d {
			if k == "ip" {
				delete(d, k)
				continue
			}
			removeIPKey(v)
		}
	case []any:
		for _, item := range d {
			removeIPKey(item)
		}
	}
}

// mergeGeneric 递归合并 src 到 dst（双方都是 map 时深度合并，否则后者覆盖）
func mergeGeneric(dst map[string]any, src any) {
	switch s := src.(type) {
	case map[string]any:
		for k, v := range s {
			if existing, ok := dst[k]; ok {
				em, eok := existing.(map[string]any)
				vm, vok := v.(map[string]any)
				if eok && vok {
					mergeGeneric(em, vm)
					continue
				}
			}
			dst[k] = v
		}
	case []any:
		// 顶层是数组时放入统一键 "_list"，已存在则追加
		if _, exists := dst["_list"]; !exists {
			dst["_list"] = s
		} else if existSlice, ok := dst["_list"].([]any); ok {
			dst["_list"] = append(existSlice, s...)
		}
	default:
		// 基本类型：放入 _value 列表，避免覆盖
		if _, exists := dst["_value"]; !exists {
			dst["_value"] = []any{s}
		} else if arr, ok := dst["_value"].([]any); ok {
			dst["_value"] = append(arr, s)
		}
	}
}
