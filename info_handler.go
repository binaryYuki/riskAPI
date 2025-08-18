package main

import (
	"context"
	"net"
	"net/http"
	"os"

	"risky_ip_filter/providers/meituan"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
)

// ipInfoHandler 提供汇总的多 provider MMDB 查询结果
func ipInfoHandler(c *gin.Context) {
	ipStr := c.Param("ip")
	if ipStr == "" {
		ipStr = getClientIPFromCDNHeaders(c)
	}
	if net.ParseIP(ipStr) == nil {
		handleError(c, http.StatusBadRequest, "Invalid IP address format")
		return
	}

	// 复用 risk 逻辑: 对 bogon / 私网 IP 直接过滤, 不做 MMDB 查询
	if isBogonOrPrivateIP(ipStr) {
		resp := InfoResponse{Status: "ok", IP: ipStr, Results: map[string]interface{}{
			"private_bogon": true,
			"message":       "IP is private/bogon, lookup skipped",
		}}
		appCache.Set("info:"+ipStr, resp, infoCacheExpiry)
		c.IndentedJSON(http.StatusOK, resp)
		return
	}

	cacheKey := "info:" + ipStr
	if v, found := appCache.Get(cacheKey); found {
		if resp, ok := v.(InfoResponse); ok {
			c.IndentedJSON(http.StatusOK, resp)
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), infoLookupTimeout)
	defer cancel()

	type providerDef struct {
		name       string
		countryDBs []string
		asnDBs     []string
	}
	providers := []providerDef{
		{"ipinfo", []string{"providers/ipinfo/ipinfo-country.mmdb"}, []string{"providers/ipinfo/ipinfo-asn.mmdb"}},
		{"iplocate", []string{"providers/iplocate/iplocate-country.mmdb"}, []string{"providers/iplocate/iplocate-asn.mmdb"}},
		{"maxmind", []string{"providers/maxmind/GeoLite2-Country.mmdb"}, []string{"providers/maxmind/GeoLite2-ASN.mmdb"}},
	}

	ip := net.ParseIP(ipStr)
	results := make(map[string]interface{})

	for _, p := range providers {
		select {
		case <-ctx.Done():
			// 超时则停止后续 provider
			goto RESPONSE
		default:
		}
		// 将同一 provider 的多个 MMDB 结果合并为一个 map
		providerData := make(map[string]interface{})
		for _, dbPath := range append(append([]string{}, p.countryDBs...), p.asnDBs...) {
			if !statOk(dbPath) {
				continue
			}
			select { // 每个 DB 单独检查超时
			case <-ctx.Done():
				goto RESPONSE
			default:
			}
			if data, err := lookupGeneric(dbPath, ip); err == nil {
				mergeGeneric(providerData, data)
			}
		}
		if len(providerData) > 0 {
			removeIPKey(providerData)
			results[p.name] = providerData
		}
	}

	// 新增: Meituan 在线 API 查询 (非 MMDB)
	if meituan.Suitable(ipStr) { // 仅在 IP 合适时尝试
		if mtData, err := meituan.Query(ctx, ipStr, nil, meituan.QueryOptions{Enhanced: true}); err == nil && len(mtData) > 0 {
			results["meituan"] = mtData
		}
	}

RESPONSE:
	resp := InfoResponse{Status: "ok", IP: ipStr, Results: results}
	appCache.Set(cacheKey, resp, infoCacheExpiry)
	c.IndentedJSON(http.StatusOK, resp)
}

// lookupGeneric 以通用结构解析 MMDB (不定义固定 struct) 返回 map / slice / 基本类型构成的结构
func lookupGeneric(dbPath string, ip net.IP) (interface{}, error) {
	reader, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	var v interface{}
	if err := reader.Lookup(ip, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// removeIPKey 递归移除 map 中名为 "ip" 的字段
func removeIPKey(data interface{}) {
	switch d := data.(type) {
	case map[string]interface{}:
		for k, v := range d {
			if k == "ip" {
				delete(d, k)
				continue
			}
			removeIPKey(v)
		}
	case []interface{}:
		for _, item := range d {
			removeIPKey(item)
		}
	}
}

// mergeGeneric 递归合并 data 到 dst 中(仅当 key 不存在或目标值为 map 且源值为 map 时深度合并)
func mergeGeneric(dst map[string]interface{}, src interface{}) {
	switch s := src.(type) {
	case map[string]interface{}:
		for k, v := range s {
			if existing, ok := dst[k]; ok {
				// 若双方都是 map 递归合并，否则后者覆盖
				em, eok := existing.(map[string]interface{})
				vm, vok := v.(map[string]interface{})
				if eok && vok {
					mergeGeneric(em, vm)
					continue
				}
			}
			dst[k] = v
		}
	case []interface{}:
		// 若顶层是数组，直接放入一个统一键（仅当未占用）。
		// 避免命名冲突，用 "_list" 作为键。
		if _, exists := dst["_list"]; !exists {
			dst["_list"] = s
		} else {
			// 如果已存在且也是 slice，简单追加
			if existSlice, ok := dst["_list"].([]interface{}); ok {
				dst["_list"] = append(existSlice, s...)
			}
		}
	default:
		// 基本类型：放入 _value 列表，避免覆盖
		if _, exists := dst["_value"]; !exists {
			dst["_value"] = []interface{}{s}
		} else if arr, ok := dst["_value"].([]interface{}); ok {
			dst["_value"] = append(arr, s)
		}
	}
}

// statOk 检查文件是否存在且大小>0
func statOk(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return false
	}
	return true
}
