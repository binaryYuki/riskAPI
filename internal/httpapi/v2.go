package httpapi

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/ipset"
	"risky_ip_filter/internal/risktoken"
)

const (
	riskKeysPath   = "/.well-known/risk-keys.json"
	nonceMinLen    = 8
	nonceMaxLen    = 128
	audienceMaxLen = 253
)

// SignedIPResponse /api/v2/ip 响应：v1 字段 + 签名令牌
type SignedIPResponse struct {
	ResponseWithIP
	Token string `json:"token,omitempty"`
}

// SignedInfoResponse /api/v2/info 响应：地理位置 + 风险判定 + 签名令牌
type SignedInfoResponse struct {
	Status  string         `json:"status"`
	IP      string         `json:"ip"`
	IsRisky bool           `json:"isRisky"`
	IsIDC   bool           `json:"isIdc"`
	IsProxy bool           `json:"isProxy"`
	Results map[string]any `json:"results"`
	Token   string         `json:"token,omitempty"`
}

// tokenRequest 解析后的签名参数；want 为 false 时不签发令牌
type tokenRequest struct {
	want  bool
	aud   string
	nonce string
}

// parseTokenRequest 校验 aud/nonce；失败时已写入错误响应，返回 ok=false
func (s *Server) parseTokenRequest(c *gin.Context) (tokenRequest, bool) {
	aud := strings.ToLower(strings.TrimSpace(c.Query("aud")))
	nonce := c.Query("nonce")
	if aud == "" && nonce == "" {
		return tokenRequest{}, true
	}
	switch {
	case aud == "" || nonce == "":
		handleError(c, http.StatusBadRequest, "aud and nonce must be provided together")
	case !isValidAudience(aud):
		handleError(c, http.StatusBadRequest, "aud must be a host name")
	case !isValidNonce(nonce):
		handleError(c, http.StatusBadRequest, "nonce must be 8-128 characters of [A-Za-z0-9._~:-]")
	case s.signer == nil:
		handleError(c, http.StatusServiceUnavailable, "token signing is not configured")
	case !s.audiences.allows(aud):
		handleError(c, http.StatusForbidden, "aud is not allowed")
	case !originMatchesAudience(c.GetHeader("Origin"), aud):
		// 浏览器跨域请求的 Origin 无法被页面脚本伪造：别的站点不能替本站申请令牌
		handleError(c, http.StatusForbidden, "aud does not match Origin")
	default:
		return tokenRequest{want: true, aud: aud, nonce: nonce}, true
	}
	return tokenRequest{}, false
}

// sign 为判定结果签发令牌；未请求令牌时返回空串
func (s *Server) sign(req tokenRequest, resp ResponseWithIP) string {
	if !req.want {
		return ""
	}
	token, _ := s.signer.Sign(risktoken.Claims{
		IP:      resp.IP,
		Status:  resp.Status,
		IsRisky: resp.IsRisky,
		IsIDC:   resp.IsIDC,
		IsProxy: resp.IsProxy,
		Aud:     req.aud,
		Nonce:   req.nonce,
	})
	return token
}

// checkRequestIPV2 GET /api/v2/ip?aud=&nonce= 检查请求方自身 IP 并签名结果
func (s *Server) checkRequestIPV2(c *gin.Context) {
	req, ok := s.parseTokenRequest(c)
	if !ok {
		return
	}
	ip := s.clientIP(c)
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}
	resp := s.requestIPResponse(ip)
	c.IndentedJSON(http.StatusOK, SignedIPResponse{ResponseWithIP: resp, Token: s.sign(req, resp)})
}

// ipInfoV2 GET /api/v2/info?aud=&nonce= 返回请求方自身 IP 的地理位置与风险判定，并签名判定结果。
// 令牌绑定访客 IP，因此不提供 /:ip 形式；查询任意 IP 请使用 v1
func (s *Server) ipInfoV2(c *gin.Context) {
	req, ok := s.parseTokenRequest(c)
	if !ok {
		return
	}
	ip := s.clientIP(c)
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}
	verdict := s.requestIPResponse(ip)

	var results map[string]any
	if ipset.IsBogonOrPrivate(ip) {
		c.Header("X-Catyuki-Cache", "MISS")
		results = map[string]any{"private_bogon": true, "message": "IP is private/bogon, lookup skipped"}
	} else {
		var hit bool
		results, hit = s.lookupInfo(c.Request.Context(), ip, s.requestLog(c).With("ip", ip))
		if hit {
			c.Header("X-Catyuki-Cache", "HIT")
		} else {
			c.Header("X-Catyuki-Cache", "MISS")
		}
	}
	c.IndentedJSON(http.StatusOK, SignedInfoResponse{
		Status:  "ok",
		IP:      ip,
		IsRisky: verdict.IsRisky,
		IsIDC:   verdict.IsIDC,
		IsProxy: verdict.IsProxy,
		Results: results,
		Token:   s.sign(req, verdict),
	})
}

// riskKeys GET /.well-known/risk-keys.json 公布验签公钥；未配置签名时 404
func (s *Server) riskKeys(c *gin.Context) {
	if s.signer == nil {
		handleError(c, http.StatusNotFound, "Not Found")
		return
	}
	// 覆盖全局 no-store：公钥可短时缓存，轮换时旧公钥会继续公布一段时间
	c.Header("Cache-Control", "public, max-age=300")
	c.IndentedJSON(http.StatusOK, s.signer.KeySet())
}

// audiencePolicy RISK_TOKEN_AUDIENCES：精确域名，或 "*.example.com" 匹配其任意层级子域名（不含 example.com 本身）
type audiencePolicy struct {
	exact    map[string]bool
	suffixes []string // ".example.com"
}

func newAudiencePolicy(items []string) audiencePolicy {
	p := audiencePolicy{exact: map[string]bool{}}
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if domain, ok := strings.CutPrefix(item, "*."); ok && domain != "" {
			p.suffixes = append(p.suffixes, "."+domain)
		} else if item != "" {
			p.exact[item] = true
		}
	}
	return p
}

// allows 未配置任何条目时不限制
func (p audiencePolicy) allows(aud string) bool {
	if len(p.exact) == 0 && len(p.suffixes) == 0 {
		return true
	}
	if p.exact[aud] {
		return true
	}
	for _, suffix := range p.suffixes {
		if strings.HasSuffix(aud, suffix) {
			return true
		}
	}
	return false
}

// isValidAudience aud 只接受小写主机名（不含端口与协议）
func isValidAudience(aud string) bool {
	if len(aud) > audienceMaxLen || strings.HasPrefix(aud, ".") || strings.HasSuffix(aud, ".") || strings.Contains(aud, "..") {
		return false
	}
	for _, r := range aud {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// isValidNonce nonce 限定为 URL 安全字符，避免日志/JSON 注入与超长输入
func isValidNonce(nonce string) bool {
	if len(nonce) < nonceMinLen || len(nonce) > nonceMaxLen {
		return false
	}
	for _, r := range nonce {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~:-", r)) {
			return false
		}
	}
	return true
}

// originMatchesAudience 有 Origin 时其主机名必须等于 aud；无 Origin（服务端直接调用）不限制
func originMatchesAudience(origin, aud string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), aud)
}
