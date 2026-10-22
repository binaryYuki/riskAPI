package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// flushRequest 一次清理操作；CLUSTER_MODE=1 时广播给其它实例在本地执行
type flushRequest struct {
	Method string `json:"method"`
	Range  string `json:"range"` // 已 URL 解码
}

// clusterMessage 实例间广播的消息
type clusterMessage struct {
	Type  string        `json:"type"`
	Flush *flushRequest `json:"flush,omitempty"`
}

const clusterMsgFlush = "flush"

// flush POST /api/cache/flush/:method/*range 清空或部分清理缓存
//
//	all:  忽略 range，清空 info 缓存与风险列表，并立即重新加载 CDN/IDC 列表
//	info: range=all 清空全部 info 缓存；否则视为 IP，删除对应条目
//	risk: range=all 清空风险列表；否则按 IP 或 CIDR 删除单条
//
// CLUSTER_MODE=1 时同时清理共享 info 缓存，并通过 Redis pub/sub 广播给其它实例在本地执行同样的清理
// （只送达当时在线的实例；结果中的计数只反映处理该请求的实例）
func (s *Server) flush(c *gin.Context) {
	rng := strings.TrimPrefix(c.Param("range"), "/") // 通配符参数带前导斜杠
	req := flushRequest{Method: c.Param("method"), Range: rng}
	if decoded, err := url.PathUnescape(rng); err == nil {
		req.Range = decoded
	}
	switch req.Method {
	case "all", "info", "risk":
	default:
		handleError(c, http.StatusBadRequest, "unsupported method")
		return
	}

	result := gin.H{"method": req.Method, "range": rng}
	s.applyFlush(req, result)
	s.flushSharedInfo(c, req, result)
	s.broadcastFlush(c, req, result)
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: result})
}

// applyFlush 在本实例执行清理，结果写入 result
func (s *Server) applyFlush(req flushRequest, result gin.H) {
	switch req.Method {
	case "all":
		s.infoCache.Flush()
		s.risk.Clear()
		s.lists.Reload()
		result["flushed_info_cache"] = true
		result["flushed_risk"] = true
		result["flushed_cdn_idc"] = true

	case "info":
		if req.Range == "all" {
			s.infoCache.DeletePrefix(infoCachePrefix)
			result["flushed_info_all"] = true
		} else {
			s.infoCache.Delete(infoCachePrefix + req.Range)
			result["flushed_info_key"] = req.Range
		}

	case "risk":
		if req.Range == "all" {
			s.risk.Clear()
			result["flushed_risk_all"] = true
		} else {
			result["removed_entry"] = req.Range
			result["removed"] = s.risk.Remove(req.Range)
		}
	}
}

// flushSharedInfo 清理共享 info 缓存（只需处理请求的实例执行一次），结果写入 result
func (s *Server) flushSharedInfo(c *gin.Context, req flushRequest, result gin.H) {
	if s.shared == nil || req.Method == "risk" {
		return
	}
	ctx := c.Request.Context()
	var err error
	if req.Method == "all" || req.Range == "all" {
		var n int
		n, err = s.shared.Flush(ctx)
		result["flushed_shared_info"] = n
	} else {
		err = s.shared.Delete(ctx, req.Range)
	}
	if err != nil {
		result["shared_error"] = err.Error()
	}
}

// broadcastFlush 通知其它实例执行同样的清理，结果写入 result
func (s *Server) broadcastFlush(c *gin.Context, req flushRequest, result gin.H) {
	if s.broadcaster == nil {
		return
	}
	payload, err := json.Marshal(clusterMessage{Type: clusterMsgFlush, Flush: &req})
	if err == nil {
		err = s.broadcaster.Publish(c.Request.Context(), payload)
	}
	if err != nil {
		s.requestLog(c).WarnContext(c.Request.Context(), "broadcast flush failed", "err", err)
		result["broadcast_error"] = err.Error()
		return
	}
	result["broadcast"] = true
}

// HandleClusterMessage 处理其它实例广播的消息（自己发出的消息不会回调到这里）
func (s *Server) HandleClusterMessage(payload []byte) {
	var msg clusterMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		s.log.Warn("ignoring invalid cluster message", "err", err)
		return
	}
	switch msg.Type {
	case clusterMsgFlush:
		if msg.Flush == nil {
			return
		}
		result := gin.H{}
		s.applyFlush(*msg.Flush, result)
		s.log.Info("applied flush from another instance", "method", msg.Flush.Method, "range", msg.Flush.Range)
	default:
		s.log.Warn("ignoring unknown cluster message", "type", msg.Type)
	}
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

// exportCIDRs GET /api/export 导出全部风险 CIDR 并注释来源；单个 IP（/32、/128）不导出
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

	c.Header("Content-Type", "text/plain; charset=utf-8")
	if len(lines) == 0 {
		c.String(http.StatusOK, "# empty\n")
		return
	}
	sort.Strings(lines) // 字典序，保持与旧版输出一致
	c.Header("Cache-Control", "public, max-age=1800, immutable")
	c.Header("X-Last-Updated", time.Now().UTC().Format(time.RFC3339))
	c.Header("X-Total-Count", strconv.Itoa(len(lines)))
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}
