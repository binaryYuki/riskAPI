package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/ipset"
)

const infoCachePrefix = "info:"

// SharedCache 跨实例共享的二级缓存。Get 未命中返回 nil；出错时调用方按未命中处理（实现负责打日志）
type SharedCache interface {
	Get(ctx context.Context, key string) (value []byte, ttl time.Duration, err error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Flush(ctx context.Context) (int, error)
}

// InfoResponse /api/v1/info 响应
type InfoResponse struct {
	Status  string         `json:"status"`
	IP      string         `json:"ip"`
	Results map[string]any `json:"results"`
}

// ipInfo GET /api/v1/info[/:ip] 汇总多数据源的地理位置结果（带缓存）
func (s *Server) ipInfo(c *gin.Context) {
	ipStr := c.Param("ip")
	if ipStr == "" {
		ipStr = s.clientIP(c)
	}
	if net.ParseIP(ipStr) == nil {
		handleError(c, http.StatusBadRequest, "Invalid IP address format")
		return
	}

	// 私网/bogon 直接返回，结果固定，无需写缓存（避免 fc00::/7 等海量地址污染缓存）
	if ipset.IsBogonOrPrivate(ipStr) {
		c.Header("X-Catyuki-Cache", "MISS")
		c.IndentedJSON(http.StatusOK, InfoResponse{Status: "ok", IP: ipStr, Results: map[string]any{
			"private_bogon": true,
			"message":       "IP is private/bogon, lookup skipped",
		}})
		return
	}

	results, hit := s.lookupInfo(c.Request.Context(), ipStr, s.requestLog(c).With("ip", ipStr))
	if hit {
		c.Header("X-Catyuki-Cache", "HIT")
	} else {
		c.Header("X-Catyuki-Cache", "MISS")
	}
	c.IndentedJSON(http.StatusOK, InfoResponse{Status: "ok", IP: ipStr, Results: results})
}

// lookupInfo 查询公网 IP 的多数据源地理位置结果（带缓存），hit 表示命中缓存；调用方需先排除私网/bogon
func (s *Server) lookupInfo(ctx context.Context, ipStr string, log *slog.Logger) (results map[string]any, hit bool) {
	cacheKey := infoCachePrefix + ipStr
	if v, found := s.infoCache.Get(cacheKey); found {
		if resp, ok := v.(InfoResponse); ok {
			return resp.Results, true
		}
	}
	// 其它实例查过的结果：写回本实例缓存，剩余有效期与共享缓存一致
	if results, ttl, ok := s.sharedInfoGet(ctx, ipStr); ok {
		s.infoCache.SetWithTTL(cacheKey, InfoResponse{Status: "ok", IP: ipStr, Results: results}, ttl)
		return results, true
	}
	results, complete := s.geo.Lookup(ctx, ipStr, log)
	// 外部 API 失败（含超时）时结果不完整，只做短时缓存以便尽快重试
	ttl := s.cfg.InfoCacheTTL
	if !complete {
		ttl = s.cfg.InfoPartialCacheTTL
	}
	s.infoCache.SetWithTTL(cacheKey, InfoResponse{Status: "ok", IP: ipStr, Results: results}, ttl)
	s.sharedInfoSet(ctx, ipStr, results, ttl, log)
	return results, false
}

func (s *Server) sharedInfoGet(ctx context.Context, ipStr string) (map[string]any, time.Duration, bool) {
	if s.shared == nil {
		return nil, 0, false
	}
	raw, ttl, err := s.shared.Get(ctx, ipStr)
	if err != nil || raw == nil {
		return nil, 0, false
	}
	// UseNumber 保留整数原样（如 asn、geoname_id），输出与本实例查询结果一致
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var results map[string]any
	if err := dec.Decode(&results); err != nil {
		return nil, 0, false
	}
	return results, ttl, true
}

func (s *Server) sharedInfoSet(ctx context.Context, ipStr string, results map[string]any, ttl time.Duration, log *slog.Logger) {
	if s.shared == nil {
		return
	}
	raw, err := json.Marshal(results)
	if err != nil {
		log.WarnContext(ctx, "encode info for shared cache failed", "err", err)
		return
	}
	_ = s.shared.Set(ctx, ipStr, raw, ttl)
}
