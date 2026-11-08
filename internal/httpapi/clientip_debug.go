package httpapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 调试输出中不回显的请求头（凭据）
var clientIPDebugRedacted = map[string]bool{
	"Authorization": true,
	"Cookie":        true,
}

type ipDebugInfo struct {
	IP           string `json:"ip"`
	TrustedProxy bool   `json:"trusted_proxy"`
	CDN          string `json:"cdn,omitempty"` // 所属 CDN 提供商，不在已知网段时为空
}

type headerCandidate struct {
	Header string `json:"header"`
	Value  string `json:"value"`
	IP     string `json:"ip,omitempty"`  // 解析出的 IP，值无效时为空
	CDN    string `json:"cdn,omitempty"` // IP 落在已知 CDN 网段时为提供商名（解析时会被跳过）
}

// clientIPDebug GET /api/debug/clientip 展示本次请求的客户端 IP 解析过程（管理接口）。
// 用于排查 CDN 链路下 client_ip 取错：看各候选头的值、哪些被当作 CDN 节点跳过、最终取自哪里。
func (s *Server) clientIPDebug(c *gin.Context) {
	ip, source := s.resolveClientIP(c)

	peer := c.RemoteIP()
	candidates := make([]headerCandidate, 0, len(clientIPHeaders))
	for _, header := range clientIPHeaders {
		value := c.GetHeader(header)
		if value == "" {
			continue
		}
		cand := headerCandidate{Header: header, Value: value, IP: headerIP(header, value)}
		if cand.IP != "" {
			cand.CDN, _ = s.lists.CDN(cand.IP)
		}
		candidates = append(candidates, cand)
	}

	xff := c.GetHeader("X-Forwarded-For")
	hops := []ipDebugInfo{}
	for _, part := range strings.Split(xff, ",") {
		if part = strings.TrimSpace(part); part != "" {
			hops = append(hops, s.ipDebug(part))
		}
	}

	headers := make(map[string]string, len(c.Request.Header))
	for name, values := range c.Request.Header {
		if clientIPDebugRedacted[name] {
			headers[name] = "[redacted]"
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	c.Header("Cache-Control", "no-store")
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: gin.H{
		"client_ip":       ip,
		"source":          source,
		"peer":            s.ipDebug(peer),
		"candidates":      candidates,
		"x_forwarded_for": gin.H{"raw": xff, "hops": hops},
		"headers":         headers,
		"header_priority": clientIPHeaders,
	}})
}

func (s *Server) ipDebug(ip string) ipDebugInfo {
	info := ipDebugInfo{IP: ip, TrustedProxy: s.isTrustedProxy(ip)}
	if isValidIP(ip) {
		info.CDN, _ = s.lists.CDN(ip)
	}
	return info
}
