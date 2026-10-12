package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/ipset"
)

const infoCachePrefix = "info:"

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
	results, complete := s.geo.Lookup(ctx, ipStr, log)
	// 外部 API 失败（含超时）时结果不完整，只做短时缓存以便尽快重试
	ttl := s.cfg.InfoCacheTTL
	if !complete {
		ttl = s.cfg.InfoPartialCacheTTL
	}
	s.infoCache.SetWithTTL(cacheKey, InfoResponse{Status: "ok", IP: ipStr, Results: results}, ttl)
	return results, false
}
