package httpapi

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/ipset"
	"risky_ip_filter/internal/netlists"
)

// Response 标准响应
type Response struct {
	Status  string `json:"status"`
	Message any    `json:"message,omitempty"`
}

// ResponseWithIP 带 IP 字段的响应
type ResponseWithIP struct {
	Status  string `json:"status"`
	Message any    `json:"message,omitempty"`
	IP      string `json:"ip,omitempty"`
	IsRisky bool   `json:"isRisky"` // 仅命中风险列表时为 true；CDN/IDC 不算
}

// handleError 返回错误响应并中止后续处理
func handleError(c *gin.Context, statusCode int, message string) {
	c.IndentedJSON(statusCode, Response{Status: "error", Message: message})
	c.Abort()
}

// verdictKind IP 判定结果类别，优先级依次为 private > risky > cdn > idc > clean
type verdictKind int

const (
	verdictPrivate verdictKind = iota
	verdictRisky
	verdictCDN
	verdictIDC
	verdictClean
)

type verdict struct {
	kind   verdictKind
	detail string // 风险来源或提供商
}

// classify 按优先级判定 IP 类别；调用方需先校验 IP 格式
func (s *Server) classify(ip string) verdict {
	if ipset.IsBogonOrPrivate(ip) {
		return verdict{kind: verdictPrivate}
	}
	if source, ok := s.risk.Lookup(ip); ok {
		return verdict{kind: verdictRisky, detail: source}
	}
	if provider, ok := s.lists.CDN(ip); ok {
		return verdict{kind: verdictCDN, detail: provider}
	}
	if provider, ok := s.lists.IDC(ip); ok {
		return verdict{kind: verdictIDC, detail: provider}
	}
	return verdict{kind: verdictClean}
}

// checkIP GET/POST /api/v1/ip/:ip 检查指定 IP
func (s *Server) checkIP(c *gin.Context) {
	ip := c.Param("ip")
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid IP address format")
		return
	}
	v := s.classify(ip)
	resp := ResponseWithIP{IP: ip, IsRisky: v.kind == verdictRisky}
	switch v.kind {
	case verdictPrivate:
		resp.Status, resp.Message = "ok", "IP is not risky (private/bogon)"
	case verdictRisky:
		resp.Status, resp.Message = "risky", "IP is in risky list: "+v.detail
	case verdictCDN:
		resp.Status, resp.Message = "cdn", "IP belongs to CDN: "+v.detail
	case verdictIDC:
		resp.Status, resp.Message = "idc", "IP belongs to IDC: "+v.detail
	default:
		resp.Status, resp.Message = "ok", "IP is not risky"
	}
	c.IndentedJSON(http.StatusOK, resp)
}

// checkRequestIP GET /api/v1/ip 检查请求方自身 IP
func (s *Server) checkRequestIP(c *gin.Context) {
	ip := s.clientIP(c)
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}
	v := s.classify(ip)
	resp := ResponseWithIP{IP: ip, IsRisky: v.kind == verdictRisky}
	switch v.kind {
	case verdictPrivate:
		resp.Status, resp.Message = "ok", "Client IP is not risky (private/bogon)"
	case verdictRisky:
		resp.Status, resp.Message = "banned", v.detail
	case verdictCDN:
		resp.Status, resp.Message = "cdn", "Client IP belongs to CDN: "+v.detail
	case verdictIDC:
		resp.Status, resp.Message = "idc", "Client IP belongs to IDC: "+v.detail
	default:
		resp.Status, resp.Message = "ok", "IP is not listed as risky."
	}
	c.IndentedJSON(http.StatusOK, resp)
}

// Proxy 待过滤的代理
type Proxy struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

// filterProxies POST /filter-proxies 过滤掉服务器 IP 在风险列表中的代理（保持输入顺序）
func (s *Server) filterProxies(c *gin.Context) {
	var proxies []Proxy
	if err := c.ShouldBindJSON(&proxies); err != nil {
		c.JSON(http.StatusBadRequest, Response{"error", "Request body is invalid."})
		return
	}
	var kept []Proxy // 全部被过滤时序列化为 null，与原接口一致
	for _, p := range proxies {
		ip := extractIPFromProxy(p.Server)
		if ip == "" {
			continue // 无法解析出 IP 的代理直接丢弃
		}
		if _, risky := s.risk.Lookup(ip); !risky {
			kept = append(kept, p)
		}
	}
	c.JSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"filtered_count": len(proxies) - len(kept),
			"proxies":        kept,
		},
	})
}

// extractIPFromProxy 从 "scheme://host:port"、"[v6]:port"、"ip:port" 或纯 IP 中提取 IP
func extractIPFromProxy(server string) string {
	if _, rest, ok := strings.Cut(server, "://"); ok {
		server = rest
	}
	// 带端口的 IPv6，如 [2001:db8::1]:8080
	if strings.HasPrefix(server, "[") {
		if idx := strings.Index(server, "]"); idx != -1 {
			if candidate := server[1:idx]; net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	// 去掉端口（IPv4 或 host:port）；不带 [] 的 IPv6 有歧义，要求使用 [] 格式
	if i := strings.LastIndex(server, ":"); i != -1 && !strings.Contains(server, "]") {
		server = server[:i]
	}
	if net.ParseIP(server) != nil {
		return server
	}
	return ""
}

// home 根路径
func (s *Server) home(c *gin.Context) {
	c.IndentedJSON(http.StatusMisdirectedRequest, gin.H{
		"message": "Welcome to Catyuki's Risky IP Filter API. Use /api/v1/ip to check IPs.",
	})
}

func (s *Server) notFound(c *gin.Context) {
	handleError(c, http.StatusNotFound, "Not Found")
}

// status 存活检查
func (s *Server) status(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{Status: "ok"})
}

// ready 就绪检查：风险 IP 列表首轮加载完成前返回 503，
// 供平台健康检查使用，避免新实例在数据为空时接流量（期间所有 IP 都会被判为 ok）
func (s *Server) ready(c *gin.Context) {
	if !s.risk.Ready() {
		c.IndentedJSON(http.StatusServiceUnavailable, Response{
			Status:  "loading",
			Message: "risk IP lists are not loaded yet",
		})
		return
	}
	cdn, idc := s.lists.Sizes()
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"risk_prefixes": s.risk.Snapshot().Len(),
			"cdn_prefixes":  cdn,
			"idc_prefixes":  idc,
		},
	})
}

func (s *Server) versionInfo(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{
		Status:  "ok",
		Message: gin.H{"version": s.version},
	})
}

func (s *Server) qqwryStats(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{Status: "ok", Message: s.geo.QQWryStats()})
}

// cdnList GET /cdn/:name 返回某 CDN 的网段文件
func (s *Server) cdnList(c *gin.Context) {
	path, ok := s.lists.CDNFile(c.Param("name"))
	if !ok {
		handleError(c, http.StatusNotFound, "Not Found")
		return
	}
	file, err := os.Open(path)
	if err != nil {
		handleError(c, http.StatusInternalServerError, "File open error")
		return
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		handleError(c, http.StatusInternalServerError, "File read error")
		return
	}
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}

// cdnAll GET /cdn/all 返回全部 CDN 网段，按提供商分段
func (s *Server) cdnAll(c *gin.Context) {
	var result []string
	for _, name := range netlists.CDNProviders {
		result = append(result, "====== "+name+" ======")
		path, _ := s.lists.CDNFile(name)
		data, err := os.ReadFile(path)
		if err != nil {
			result = append(result, "# Error reading "+name+": "+err.Error())
		} else {
			for _, l := range strings.Split(string(data), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					result = append(result, l)
				}
			}
		}
		result = append(result, "") // 空行分隔
	}
	c.String(http.StatusOK, strings.Join(result, "\n"))
}
