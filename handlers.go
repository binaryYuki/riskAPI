package main

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var version = "dev"

// checkIPHandler handles IP checking requests
func checkIPHandler(c *gin.Context) {
	ip := c.Param("ip")

	// Validate IP format (IPv4 / IPv6)
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid IP address format")
		return
	}

	// Check if IP is bogon or private
	if isBogonOrPrivateIP(ip) {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "IP is not risky (private/bogon)",
			IP:      ip,
		})
		return
	}

	// Check if IP is risky
	isRisky, reason := isRiskyIP(ip)
	if isRisky {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "risky",
			Message: "IP is in risky list: " + reason,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to CDN
	isCDN, cdnProvider := isCDNIP(ip)
	if isCDN {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "cdn",
			Message: "IP belongs to CDN: " + cdnProvider,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to IDC
	isIDC, idcProvider := isIDCIP(ip)
	if isIDC {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "idc",
			Message: "IP belongs to IDC: " + idcProvider,
			IP:      ip,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, ResponseWithIP{
		Status:  "ok",
		Message: "IP is not risky",
		IP:      ip,
	})
}

// checkRequestIPHandler checks the request's source IP
func checkRequestIPHandler(c *gin.Context) {
	ip := getClientIPFromCDNHeaders(c)

	// Validate IP format
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}

	// Check if IP is bogon or private
	if isBogonOrPrivateIP(ip) {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "Client IP is not risky (private/bogon)",
			IP:      ip,
		})
		return
	}

	// Check if IP is risky
	isRisky, reason := isRiskyIP(ip)
	if isRisky {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "banned",
			Message: reason,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to CDN
	isCDN, cdnProvider := isCDNIP(ip)
	if isCDN {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "cdn",
			Message: "Client IP belongs to CDN: " + cdnProvider,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to IDC
	isIDC, idcProvider := isIDCIP(ip)
	if isIDC {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "idc",
			Message: "Client IP belongs to IDC: " + idcProvider,
			IP:      ip,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, ResponseWithIP{
		Status:  "ok",
		Message: "IP is not listed as risky.",
		IP:      ip,
	})
}

// homeHandler handles root path requests
func homeHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusMisdirectedRequest,
		WelcomeJson{Msg: "Welcome to Catyuki's Risky IP Filter API. Use /api/v1/ip to check IPs."})
}

// filterProxiesHandler handles proxy filtering requests
func filterProxiesHandler(c *gin.Context) {
	var proxies []Proxy
	if err := c.ShouldBindJSON(&proxies); err != nil {
		c.JSON(http.StatusBadRequest, Response{"error", "Request body is invalid."})
		return
	}

	config := getDefaultConfig()
	nonRiskyProxies := processProxies(proxies, config.Concurrency)
	filteredData := gin.H{
		"filtered_count": len(proxies) - len(nonRiskyProxies),
		"proxies":        nonRiskyProxies,
	}
	c.JSON(http.StatusOK, Response{
		Status:  "ok",
		Message: filteredData,
	})
}

// statusHandler handles status requests
func statusHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
	})
}

// cdnHandler handles CDN list requests
func cdnHandler(c *gin.Context) {
	name := c.Param("name")
	allowed := map[string]bool{"edgeone": true, "cloudflare": true, "fastly": true}
	if !allowed[name] {
		handleError(c, http.StatusNotFound, "Not Found")
		return
	}

	filePath := "data/" + name + ".txt"
	file, err := os.Open(filePath)
	if err != nil {
		handleError(c, http.StatusInternalServerError, "File open error")
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		handleError(c, http.StatusInternalServerError, "File read error")
		return
	}
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}

// cdnAllHandler handles combined CDN list requests
func cdnAllHandler(c *gin.Context) {
	var result []string
	providers := []struct{ name, label string }{
		{"edgeone", "====== edgeone ======"},
		{"cloudflare", "====== cloudflare ======"},
		{"fastly", "====== fastly ======"},
	}

	for _, p := range providers {
		result = append(result, p.label)
		filePath := "data/" + p.name + ".txt"
		data, err := os.ReadFile(filePath)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					result = append(result, l)
				}
			}
		} else {
			result = append(result, "# Error reading "+p.name+": "+err.Error())
		}
		result = append(result, "") // 空行分割
	}

	c.String(http.StatusOK, strings.Join(result, "\n"))
}

// versionHandler handles version requests
func versionHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"version": version,
		},
	})
}

// notFoundHandler handles 404 requests
func notFoundHandler(c *gin.Context) {
	handleError(c, http.StatusNotFound, "Not Found")
}

// metricsHandler 返回当前解析/抓取统计快照
func metricsHandler(c *gin.Context) {
	snapshot := getMetricsSnapshot()
	// 追加蜜罐指标
	hits, fake, blocks, penalty, offenders := HoneytrapMetricsSnapshot()
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"parser": snapshot,
			"honeytrap": gin.H{
				"hits_total":           hits,
				"fake_ok_total":        fake,
				"blocks_total":         blocks,
				"penalty_ms_total":     penalty,
				"unique_offenders_cnt": offenders,
			},
		},
	})
}

// flushCacheHandler 按路径参数清空或部分清理缓存
// 路径格式: /api/cache/flush/:method/:range
// :method 可为 all | info | risk
// all: 忽略 :range, 清空所有缓存 (info 缓存 + 风险列表 + CDN/IDC 缓存)
// info: :range=all 清空所有 info: 缓存; 否则认为是具体 IP, 删除对应 info:<ip>
// risk: :range=all 清空风险 IP/CIDR 列表; 否则按 IP 或 CIDR 删除单条
func flushCacheHandler(c *gin.Context) {
	method := c.Param("method")
	rng := c.Param("range")
	if rng != "" && strings.HasPrefix(rng, "/") { // 通配符路径去掉前导斜杠
		rng = rng[1:]
	}
	result := gin.H{"method": method, "range": rng} // 移到前导斜杠处理之后

	switch method {
	case "all":
		// 清空 info 缓存
		if appCache != nil {
			appCache.Flush()
		}
		// 清空风险数据
		riskyDataMutex.Lock()
		riskyCIDRInfo = nil
		reasonMap = make(map[string]string)
		riskyDataMutex.Unlock()
		// 清空 CDN/IDC 缓存
		cdnIdcMutex.Lock()
		cdnIPCache = make(map[string][]CIDRInfo)
		idcIPCache = make(map[string][]CIDRInfo)
		cdnSingleIPs = make(map[string]map[string]bool)
		idcSingleIPs = make(map[string]map[string]bool)
		cdnIdcMutex.Unlock()

		// 立即重新加载 CDN & IDC 列表，避免等待下一次定时同步
		syncCDNLists()
		syncIDCLists()

		result["flushed_info_cache"] = true
		result["flushed_risk"] = true
		result["flushed_cdn_idc"] = true

	case "info":
		if appCache == nil {
			break
		}
		if rng == "all" {
			// 仅清除 info: 前缀键
			for k := range appCache.Items() {
				if strings.HasPrefix(k, "info:") {
					appCache.Delete(k)
				}
			}
			result["flushed_info_all"] = true
		} else {
			if decoded, err := url.PathUnescape(rng); err == nil {
				rng = decoded
			}
			key := "info:" + rng
			appCache.Delete(key)
			result["flushed_info_key"] = rng
		}

	case "risk":
		if rng == "all" {
			riskyDataMutex.Lock()
			riskyCIDRInfo = nil
			reasonMap = make(map[string]string)
			riskyDataMutex.Unlock()
			result["flushed_risk_all"] = true
		} else {
			if decoded, err := url.PathUnescape(rng); err == nil {
				rng = decoded
			}
			removed := removeRiskEntry(rng)
			result["removed_entry"] = rng
			result["removed"] = removed
		}
	default:
		handleError(c, http.StatusBadRequest, "unsupported method")
		return
	}

	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: result})
}

// flushCacheIndexHandler 返回可用缓存刷新端点说明(隐藏 method=all)
func flushCacheIndexHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: gin.H{
		"description": "使用 POST /api/cache/flush/:method/:range 刷新缓存, :method 仅支持 info | risk",
		"endpoints": []string{
			"POST /api/cache/flush/info/<ip> # Delete the cache for a specific IP for info lookups (e.g. /api/cache/flush/info/1.1.1.1)",
			"POST /api/cache/flush/risk/<ip_or_cidr> # Delete a specific risky IP or CIDR (e.g. /api/cache/flush/risk/1.1.1.1)",
		},
	}})
}

// removeRiskEntry 删除单个风险 IP 或 CIDR, 返回是否删除成功
func removeRiskEntry(entry string) bool {
	removed := false
	riskyDataMutex.Lock()
	defer riskyDataMutex.Unlock()

	if _, ok := reasonMap[entry]; ok {
		delete(reasonMap, entry)
		removed = true
	}

	if strings.Contains(entry, "/") {
		var newList []CIDRInfo
		for _, ci := range riskyCIDRInfo {
			if ci.OriginalCIDR == entry {
				removed = true
				continue
			}
			newList = append(newList, ci)
		}
		riskyCIDRInfo = newList
	}
	return removed
}

// qqwryStatsHandler 处理纯真数据库状态查询请求
func qqwryStatsHandler(c *gin.Context) {
	stats := GetQQWryStats()
	c.IndentedJSON(http.StatusOK, Response{
		Status:  "ok",
		Message: stats,
	})
}

// exportCIDRsHandler 导出所有风险 CIDR 为文本，并注释来源
func exportCIDRsHandler(c *gin.Context) {
	// 收集并格式化所有 CIDR
	var lines []string
	// 加锁读取
	riskyDataMutex.RLock()
	for _, ci := range riskyCIDRInfo {
		src := reasonMap[ci.OriginalCIDR]
		if strings.TrimSpace(src) == "" {
			src = "unknown"
		}
		lines = append(lines, ci.OriginalCIDR+" # "+src)
	}
	riskyDataMutex.RUnlock()

	// 排序稳定输出
	if len(lines) == 0 {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.String(http.StatusOK, "# empty\n")
		return
	}
	// 简单字典序
	sort.Strings(lines)

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=1800, immutable") // 30分钟
	c.Header("X-Last-Updated", time.Now().UTC().Format(time.RFC3339))
	c.Header("X-Total-Count", strconv.Itoa(len(lines)))
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}
