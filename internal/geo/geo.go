// Package geo 聚合多个 IP 地理位置数据源：本地 MMDB（ipinfo / iplocate / maxmind）、
// 纯真库，以及按地区选择的外部 API（中国 IP 用美团，其余用 ip.sb）。
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

// mmdbProviders 各 provider 的 MMDB 文件（相对 providers 目录；country 在前、asn 在后，合并时后者覆盖同名字段）
var mmdbProviders = []struct {
	name string
	dbs  []string
}{
	{"ipinfo", []string{"ipinfo/ipinfo-country.mmdb", "ipinfo/ipinfo-asn.mmdb"}},
	{"iplocate", []string{"iplocate/iplocate-country.mmdb", "iplocate/iplocate-asn.mmdb"}},
	{"maxmind", []string{"maxmind/GeoLite2-Country.mmdb", "maxmind/GeoLite2-ASN.mmdb"}},
}

// Service 地理位置查询服务，可并发使用
type Service struct {
	providersDir  string
	qq            *qqwry.DB
	lookupTimeout time.Duration
	log           *slog.Logger
	readers       sync.Map // MMDB 路径 → *maxminddb.Reader
}

// New 创建查询服务；qq 可为 nil（纯真库加载失败时跳过）
func New(providersDir string, qq *qqwry.DB, lookupTimeout time.Duration, log *slog.Logger) *Service {
	return &Service{providersDir: providersDir, qq: qq, lookupTimeout: lookupTimeout, log: log}
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
	complete = true

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
				log.Error("mmdb lookup failed", "provider", p.name, "db", dbPath, "err", err)
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
		log.Error("qqwry lookup failed", "err", err)
	}

	ctx, cancel := context.WithTimeout(ctx, s.lookupTimeout)
	defer cancel()

	// 仅当其它 provider 判定为中国(CN) 且 IP 适合时再调用美团 API；否则(非中国)调用 ip.sb
	if isChina(results) {
		if !meituan.Suitable(ipStr) {
			log.Info("meituan skipped", "reason", "unsuitable_ipv4")
		} else if data, err := meituan.Query(ctx, ipStr, nil, meituan.QueryOptions{Enhanced: true}); err != nil {
			complete = false
			log.Error("meituan lookup failed", "err", err)
		} else if len(data) > 0 {
			results["meituan"] = data
		}
	} else {
		if data, err := ipsb.Query(ctx, ipStr, nil); err != nil {
			complete = false
			log.Error("ipsb lookup failed", "err", err)
		} else if len(data) > 0 {
			results["ipsb"] = data
		}
	}
	return results, complete
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
