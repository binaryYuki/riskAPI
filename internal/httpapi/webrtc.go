package httpapi

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

const (
	// webrtcMaxBody 请求体上限：正常页面的 ICE 候选不超过几十条
	webrtcMaxBody = 16 << 10
	// webrtcMaxCandidates 单次请求处理的候选（含 ips）上限，超出部分忽略
	webrtcMaxCandidates = 32
	// webrtcInfoConcurrency 地理位置查询并发上限（未命中缓存时会调用外部 API）
	webrtcInfoConcurrency = 8
)

// WebRTCRequest POST /api/v1/webrtc 请求体。
// candidates 为浏览器 onicecandidate 事件中 RTCIceCandidate.candidate 的原始字符串；
// ips 供已自行解析出地址的客户端直接上报。两者可同时提供，按 IP 去重。
type WebRTCRequest struct {
	Candidates []string `json:"candidates"`
	IPs        []string `json:"ips"`
}

// WebRTCCandidate 单个 WebRTC 地址的判定结果
type WebRTCCandidate struct {
	IP            string `json:"ip"`
	Type          string `json:"type,omitempty"` // host / srflx / prflx / relay；来自 ips 时为空
	Status        string `json:"status"`         // ok / private / risky / cdn / idc
	Message       string `json:"message,omitempty"`
	IsRisky       bool   `json:"isRisky"`
	SameAsRequest bool   `json:"sameAsRequest"`
	// Info 与 /api/v1/info 的 results 相同；私网/bogon 地址不查询，省略该字段
	Info map[string]any `json:"info,omitempty"`
}

// WebRTCResponse POST /api/v1/webrtc 响应
type WebRTCResponse struct {
	Status        string         `json:"status"` // ok / leak
	RequestIP     string         `json:"requestIp"`
	RequestStatus string         `json:"requestStatus"`
	RequestInfo   map[string]any `json:"requestInfo,omitempty"`
	// Leak 存在与请求 IP 同地址族、但不相同的公网 WebRTC 地址，即 HTTP 走了代理/VPN 而 UDP 暴露了真实出口
	Leak bool `json:"leak"`
	// IsRisky 请求 IP 或任一 WebRTC 地址命中风险列表
	IsRisky    bool              `json:"isRisky"`
	Candidates []WebRTCCandidate `json:"candidates"`
}

// webrtcCheck POST /api/v1/webrtc 对比浏览器 WebRTC 暴露的地址与 HTTP 请求来源，检测代理/VPN 泄露
func (s *Server) webrtcCheck(c *gin.Context) {
	reqIP, err := netip.ParseAddr(s.clientIP(c))
	if err != nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}
	reqIP = reqIP.Unmap()

	var body WebRTCRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, webrtcMaxBody)
	if err := c.ShouldBindJSON(&body); err != nil {
		handleError(c, http.StatusBadRequest, "Request body is invalid.")
		return
	}

	reqVerdict := s.classify(reqIP.String())
	resp := WebRTCResponse{
		Status:        "ok",
		RequestIP:     reqIP.String(),
		RequestStatus: verdictStatus(reqVerdict.kind),
		IsRisky:       reqVerdict.kind == verdictRisky,
		Candidates:    []WebRTCCandidate{},
	}

	for _, cand := range collectWebRTCAddrs(body) {
		v := s.classify(cand.addr.String())
		item := WebRTCCandidate{
			IP:            cand.addr.String(),
			Type:          cand.typ,
			Status:        verdictStatus(v.kind),
			Message:       v.detail,
			IsRisky:       v.kind == verdictRisky,
			SameAsRequest: cand.addr == reqIP,
		}
		resp.IsRisky = resp.IsRisky || item.IsRisky
		// 私网地址（host 候选）与跨地址族（双栈下 v4/v6 本就不同）不算泄露
		if v.kind != verdictPrivate && !item.SameAsRequest && cand.addr.Is4() == reqIP.Is4() {
			resp.Leak = true
		}
		resp.Candidates = append(resp.Candidates, item)
	}
	s.fillWebRTCInfo(c, &resp)
	if resp.Leak {
		resp.Status = "leak"
	}
	c.IndentedJSON(http.StatusOK, resp)
}

// fillWebRTCInfo 并发查询请求 IP 与各公网候选地址的地理位置
func (s *Server) fillWebRTCInfo(c *gin.Context, resp *WebRTCResponse) {
	ctx, log := c.Request.Context(), s.requestLog(c)
	sem := make(chan struct{}, webrtcInfoConcurrency)
	var wg sync.WaitGroup
	lookup := func(ip, status string, dst *map[string]any) {
		if status == "private" {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			*dst, _ = s.lookupInfo(ctx, ip, log.With("ip", ip))
		}()
	}
	lookup(resp.RequestIP, resp.RequestStatus, &resp.RequestInfo)
	for i := range resp.Candidates {
		cand := &resp.Candidates[i]
		if cand.SameAsRequest {
			continue // 与请求 IP 相同，复用 requestInfo 结果
		}
		lookup(cand.IP, cand.Status, &cand.Info)
	}
	wg.Wait()
	for i := range resp.Candidates {
		if resp.Candidates[i].SameAsRequest {
			resp.Candidates[i].Info = resp.RequestInfo
		}
	}
}

// verdictStatus 判定类别对应的 status 字段值
func verdictStatus(k verdictKind) string {
	switch k {
	case verdictPrivate:
		return "private"
	case verdictRisky:
		return "risky"
	case verdictCDN:
		return "cdn"
	case verdictIDC:
		return "idc"
	default:
		return "ok"
	}
}

type webrtcAddr struct {
	addr netip.Addr
	typ  string
}

// collectWebRTCAddrs 解析候选与 ips，按 IP 去重（保留首次出现的类型），最多 webrtcMaxCandidates 条
func collectWebRTCAddrs(body WebRTCRequest) []webrtcAddr {
	var out []webrtcAddr
	seen := make(map[netip.Addr]bool)
	add := func(raw, typ string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || addr.Zone() != "" {
			return // mDNS 主机名（xxx.local）等非 IP 地址直接跳过
		}
		addr = addr.Unmap()
		if seen[addr] || len(out) >= webrtcMaxCandidates {
			return
		}
		seen[addr] = true
		out = append(out, webrtcAddr{addr: addr, typ: typ})
	}
	for _, cand := range body.Candidates {
		if ip, typ, ok := parseICECandidate(cand); ok {
			add(ip, typ)
		}
	}
	for _, ip := range body.IPs {
		add(ip, "")
	}
	return out
}

// parseICECandidate 解析 RFC 8839 candidate-attribute：
// "candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type> ..."
// 兼容带 "a=" 前缀的 SDP 行
func parseICECandidate(s string) (ip, typ string, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "a=")
	if !strings.HasPrefix(s, "candidate:") {
		return "", "", false
	}
	fields := strings.Fields(s)
	if len(fields) < 8 || fields[6] != "typ" {
		return "", "", false
	}
	return fields[4], fields[7], true
}
