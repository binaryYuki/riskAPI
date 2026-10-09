package httpapi

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// flush POST /api/cache/flush/:method/*range 清空或部分清理缓存
//
//	all:  忽略 range，清空 info 缓存与风险列表，并立即重新加载 CDN/IDC 列表
//	info: range=all 清空全部 info 缓存；否则视为 IP，删除对应条目
//	risk: range=all 清空风险列表；否则按 IP 或 CIDR 删除单条
func (s *Server) flush(c *gin.Context) {
	method := c.Param("method")
	rng := strings.TrimPrefix(c.Param("range"), "/") // 通配符参数带前导斜杠
	result := gin.H{"method": method, "range": rng}

	switch method {
	case "all":
		s.infoCache.Flush()
		s.risk.Clear()
		s.lists.Reload()
		result["flushed_info_cache"] = true
		result["flushed_risk"] = true
		result["flushed_cdn_idc"] = true

	case "info":
		if rng == "all" {
			s.infoCache.DeletePrefix(infoCachePrefix)
			result["flushed_info_all"] = true
		} else {
			if decoded, err := url.PathUnescape(rng); err == nil {
				rng = decoded
			}
			s.infoCache.Delete(infoCachePrefix + rng)
			result["flushed_info_key"] = rng
		}

	case "risk":
		if rng == "all" {
			s.risk.Clear()
			result["flushed_risk_all"] = true
		} else {
			if decoded, err := url.PathUnescape(rng); err == nil {
				rng = decoded
			}
			result["removed_entry"] = rng
			result["removed"] = s.risk.Remove(rng)
		}

	default:
		handleError(c, http.StatusBadRequest, "unsupported method")
		return
	}
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: result})
}

// flushIndex GET /api/cache/flush 返回可用的缓存刷新端点说明（不列出 method=all）
func (s *Server) flushIndex(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: gin.H{
		"description": "使用 POST /api/cache/flush/:method/:range 刷新缓存, :method 仅支持 info | risk",
		"endpoints": []string{
			"POST /api/cache/flush/info/<ip> # Delete the cache for a specific IP for info lookups (e.g. /api/cache/flush/info/1.1.1.1)",
			"POST /api/cache/flush/risk/<ip_or_cidr> # Delete a specific risky IP or CIDR (e.g. /api/cache/flush/risk/1.1.1.1)",
		},
	}})
}

// exportCIDRs GET /api/export 导出全部风险 CIDR 并注释来源；单个 IP（/32、/128）不导出。
// 被蜜罐标记的来源以混淆后的标识附在末尾，写成注释行，不影响按 CIDR 解析的使用方
func (s *Server) exportCIDRs(c *gin.Context) {
	var lines []string
	for pfx, src := range s.risk.Snapshot().All() {
		if pfx.IsSingleIP() {
			continue
		}
		if strings.TrimSpace(src) == "" {
			src = "unknown"
		}
		lines = append(lines, pfx.String()+" # "+src)
	}

	sort.Strings(lines) // 字典序，保持与旧版输出一致
	cidrs := len(lines)
	flagged := s.trap.FlaggedSources()
	for _, f := range flagged {
		lines = append(lines, "# honeytrap "+f.ID+" until "+f.Until.UTC().Format(time.RFC3339))
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	if len(lines) == 0 {
		c.String(http.StatusOK, "# empty\n")
		return
	}
	c.Header("Cache-Control", "public, max-age=1800, immutable")
	c.Header("X-Last-Updated", time.Now().UTC().Format(time.RFC3339))
	c.Header("X-Total-Count", strconv.Itoa(cidrs))
	c.Header("X-Honeytrap-Count", strconv.Itoa(len(flagged)))
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}

// revealSource GET /api/honeytrap/source/:id 把蜜罐日志或标记文件中混淆后的来源还原为地址
func (s *Server) revealSource(c *gin.Context) {
	source, ok := s.trap.Reveal(c.Param("id"))
	if !ok {
		handleError(c, http.StatusNotFound, "unknown source id, or it was not created with the current HONEYTRAP_SECRET")
		return
	}
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: gin.H{"source": source, "flagged": s.trap.Flagged(strings.TrimSuffix(source, "/64"))}})
}
