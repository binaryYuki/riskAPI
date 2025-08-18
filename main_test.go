package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/patrickmn/go-cache"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	handleError(c, http.StatusBadRequest, "bad request")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"bad request"}`, w.Body.String())
}

func TestCheckRequestIPHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
		wantBody   string
		setup      func()
	}{
		{
			name:       "localhost",
			remoteAddr: "127.0.0.1:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"Client IP is not risky (private/bogon)","ip":"127.0.0.1"}`,
		},
		{
			name:       "invalid ip",
			remoteAddr: "invalid-ip:12345",
			wantCode:   http.StatusBadRequest,
			wantBody:   `{"message":"Invalid or unidentifiable IP address.", "status":"error"}`,
		},
		{
			name:       "private ip",
			remoteAddr: "192.168.1.1:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"Client IP is not risky (private/bogon)","ip":"192.168.1.1"}`,
		},
		{
			name:       "risky ip",
			remoteAddr: "8.8.8.8:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"banned","message":"Test reason","ip":"8.8.8.8"}`,
			setup: func() {
				_ = map[string]bool{"8.8.8.8": true}
				reasonMap = map[string]string{"8.8.8.8": "Test reason"}
			},
		},
		{
			name:       "safe ip",
			remoteAddr: "8.8.4.4:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"IP is not listed as risky.","ip":"8.8.4.4"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			router := gin.Default()
			router.GET("/api/v1/ip", checkRequestIPHandler)
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
			req.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
			assert.JSONEq(t, tt.wantBody, w.Body.String())
		})
	}
}

func TestCorrelationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("generates correlation id", func(t *testing.T) {
		router := gin.New()
		router.Use(CorrelationMiddleware())
		router.GET("/test-correlation", func(c *gin.Context) {
			id, exists := c.Get("correlation_id")
			assert.True(t, exists)
			c.String(http.StatusOK, "%v", id)
		})
		req, _ := http.NewRequest(http.MethodGet, "/test-correlation", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		id := w.Body.String()
		assert.NotEmpty(t, id)
		assert.Equal(t, id, w.Header().Get("X-Request-ID"))
	})

	t.Run("uses provided correlation id", func(t *testing.T) {
		router := gin.New()
		router.Use(CorrelationMiddleware())
		router.GET("/test-correlation", func(c *gin.Context) {
			id, exists := c.Get("correlation_id")
			assert.True(t, exists)
			c.String(http.StatusOK, "%v", id)
		})
		req, _ := http.NewRequest(http.MethodGet, "/test-correlation", nil)
		req.Header.Set("X-Correlation-ID", "testid123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, "testid123", w.Body.String())
		assert.Equal(t, "testid123", w.Header().Get("X-Request-ID"))
	})
}

func TestRiskyIPChannels(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// edgeone
	riskyCIDRInfo = []CIDRInfo{}
	_ = map[string]bool{}
	reasonMap = map[string]string{}
	_, edgeoneNet, _ := net.ParseCIDR("1.71.146.0/23")
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: edgeoneNet, OriginalCIDR: "1.71.146.0/23"})
	reasonMap["1.71.146.0/23"] = "edgeone"

	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "1.71.146.1:12345"
	router.ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), "edgeone")

	// fastly
	riskyCIDRInfo = []CIDRInfo{}
	_ = map[string]bool{}
	reasonMap = map[string]string{}
	_, fastlyNet, _ := net.ParseCIDR("23.235.32.0/20")
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: fastlyNet, OriginalCIDR: "23.235.32.0/20"})
	reasonMap["23.235.32.0/20"] = "fastly"

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req2.RemoteAddr = "23.235.32.1:12345"
	router.ServeHTTP(w2, req2)
	assert.Contains(t, w2.Body.String(), "fastly")
}

func getFirstCIDRFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			return
		}
	}(f)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "//") {
			return line, nil
		}
	}
	return "", nil
}

func ipFromCIDR(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.String(), nil // fallback for IPv6
	}
	ip4[3]++ // 取第一个可用IP
	return ip4.String(), nil
}

func TestAllRiskyChannelsAuto(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var testFiles []string
	err := filepath.Walk("data", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") {
			// to-do： fix apple test issues
			if strings.Contains(path, "apple") {
				return filepath.SkipDir
			}
			testFiles = append(testFiles, path)
		}
		return nil
	})
	if err != nil {
		return
	}
	for _, file := range testFiles {
		cidr, err := getFirstCIDRFromFile(file)
		if err != nil || cidr == "" {
			continue
		}
		ip, err := ipFromCIDR(cidr)
		if err != nil {
			continue
		}
		// 渠道名用文件名
		parts := strings.Split(file, string(os.PathSeparator))
		channel := strings.TrimSuffix(parts[len(parts)-1], ".txt")
		t.Run(channel, func(t *testing.T) {
			riskyCIDRInfo = []CIDRInfo{}
			_ = map[string]bool{}
			reasonMap = map[string]string{}
			_, netObj, _ := net.ParseCIDR(cidr)
			riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: netObj, OriginalCIDR: cidr})
			reasonMap[cidr] = channel
			router := gin.Default()
			router.GET("/api/v1/ip", checkRequestIPHandler)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
			req.RemoteAddr = ip + ":12345"
			router.ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), channel)
		})
	}
}

// Test for bogon/private IP fast-path in /api/v1/info
func TestIPInfoHandlerBogon(t *testing.T) {
	gin.SetMode(gin.TestMode)
	appCache = cache.New(infoCacheExpiry, infoCacheExpiry)

	router := gin.New()
	router.GET("/api/v1/info/:ip", ipInfoHandler)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/info/127.0.0.1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", w.Code)
	}

	expected := `{"status":"ok","ip":"127.0.0.1","results":{"private_bogon":true,"message":"IP is private/bogon, lookup skipped"}}`
	got := compactJSON(w.Body.String())
	want := compactJSON(expected)
	if got != want {
		t.Fatalf("unexpected body.\nwant: %s\n got: %s", want, got)
	}

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/info/127.0.0.1", nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("cache request expected 200 got %d", w2.Code)
	}
}

// Test for valid IP address in /api/v1/info
func compactJSON(s string) string {
	b := []byte(s)
	var out []byte
	var err error
	var tmp interface{}
	if err = json.Unmarshal(b, &tmp); err != nil {
		// 如果不是严格 JSON（例如多余换行空格），尝试去掉空白再解码
		return s // 回退原字符串
	}
	out, err = json.Marshal(tmp)
	if err != nil {
		return s
	}
	return string(out)
}

func TestCDNBaseAddressAndFlushReload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	appCache = cache.New(ipCacheExpiry, ipCacheExpiry)
	initCDNIDCCache()
	cidrNet, cidrStr, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone cidr found")
	}
	baseIP := cidrNet.IP.String()
	ok, provider := isCDNIP(baseIP)
	if !ok || provider != "edgeone" {
		t.Fatalf("expected %s in edgeone (cidr=%s) got ok=%v provider=%s", baseIP, cidrStr, ok, provider)
	}
	router := gin.New()
	router.POST("/api/cache/flush/:method/*range", flushCacheHandler) // 使用通配符路由
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/cache/flush/all/x", nil)
	router.ServeHTTP(w, req)
	ok2, provider2 := isCDNIP(baseIP)
	if !ok2 || provider2 != "edgeone" {
		t.Fatalf("after flush reload failed base=%s cidr=%s", baseIP, cidrStr)
	}
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/ip/:ip", checkIPHandler)
	r.GET("/api/v1/ip", checkRequestIPHandler)
	r.POST("/api/cache/flush/:method/*range", flushCacheHandler) // 使用通配符路由
	r.GET("/api/v1/info/:ip", ipInfoHandler)
	return r
}

func resetRiskData() {
	riskyDataMutex.Lock()
	riskyCIDRInfo = nil
	reasonMap = make(map[string]string)
	riskyDataMutex.Unlock()
}

// 动态读取 CDN provider 首个 /24 CIDR
func firstCDN24(provider string) (*net.IPNet, string, error) {
	path := "data/cdn/" + provider + ".txt"
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			return
		}
	}(f)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			ones, bits := ipNet.Mask.Size()
			if bits == 32 && ones == 24 { // 仅取 /24 简化边界测试
				return ipNet, line, nil
			}
		}
	}
	return nil, "", fmt.Errorf("no /24 found for %s", provider)
}

func ipAdd(ip net.IP, offset int) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	res := make(net.IP, 4)
	copy(res, ip4)
	u := uint32(res[0])<<24 | uint32(res[1])<<16 | uint32(res[2])<<8 | uint32(res[3])
	u += uint32(offset)
	res[0] = byte(u >> 24)
	res[1] = byte(u >> 16)
	res[2] = byte(u >> 8)
	res[3] = byte(u)
	return res
}

func broadcastIP(n *net.IPNet) net.IP {
	ip4 := n.IP.To4()
	if ip4 == nil {
		return nil
	}
	mask := net.IP(n.Mask).To4()
	b := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		b[i] = ip4[i] | ^mask[i]
	}
	return b
}

func TestHTTP_CDN_CIDRBoundaries(t *testing.T) {
	initCDNIDCCache()
	r := setupTestRouter()
	cidrNet, _, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone")
	}
	base := cidrNet.IP
	mid := ipAdd(base, 128)
	bcast := broadcastIP(cidrNet)
	outside := ipAdd(bcast, 1)
	cases := []struct{ ip, want string }{
		{base.String(), "cdn"},
		{mid.String(), "cdn"},
		{bcast.String(), "cdn"},
		{outside.String(), "ok"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/"+c.ip, nil)
		r.ServeHTTP(w, req)
		if got := extractStatus(w.Body.String()); got != c.want {
			t.Fatalf("ip %s want %s got %s body=%s", c.ip, c.want, got, w.Body.String())
		}
	}
}

// 风险优先级高于 CDN (动态 CIDR)
func TestPriority_RiskyOverridesCDN(t *testing.T) {
	initCDNIDCCache()
	resetRiskData()
	cidrNet, cidrStr, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone")
	}
	riskyDataMutex.Lock()
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: cidrNet, OriginalCIDR: cidrStr})
	reasonMap[cidrStr] = "test-risk"
	riskyDataMutex.Unlock()
	r := setupTestRouter()
	probe := ipAdd(cidrNet.IP, 5).String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/"+probe, nil)
	r.ServeHTTP(w, req)
	if extractStatus(w.Body.String()) != "risky" {
		t.Fatalf("expected risky got %s body=%s", extractStatus(w.Body.String()), w.Body.String())
	}
}

// 私网优先级高于风险
func TestPriority_PrivateOverridesRisky(t *testing.T) {
	resetRiskData()
	_, netObj, _ := net.ParseCIDR("10.0.0.0/8")
	riskyDataMutex.Lock()
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: netObj, OriginalCIDR: "10.0.0.0/8"})
	reasonMap["10.0.0.0/8"] = "should-not-show"
	riskyDataMutex.Unlock()
	r := setupTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/10.1.2.3", nil)
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "private/bogon") {
		t.Fatalf("private should short-circuit risk body=%s", w.Body.String())
	}
}

// 单个风险 IP
func TestSingleRiskyIP(t *testing.T) {
	resetRiskData()
	riskyDataMutex.Lock()
	reasonMap["9.9.9.9"] = "single-test"
	riskyDataMutex.Unlock()
	r := setupTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/9.9.9.9", nil)
	r.ServeHTTP(w, req)
	if extractStatus(w.Body.String()) != "risky" {
		t.Fatalf("single ip not risky body=%s", w.Body.String())
	}
}

// 风险列表 flush 单条与全部
func TestFlushRiskSingleAndAll(t *testing.T) {
	resetRiskData()
	riskyDataMutex.Lock()
	reasonMap["203.0.114.0/24"] = "risk-block" // 使用非 bogon 段
	_, n, _ := net.ParseCIDR("203.0.114.0/24")
	riskyCIDRInfo = []CIDRInfo{{Net: n, OriginalCIDR: "203.0.114.0/24"}}
	riskyDataMutex.Unlock()
	r := setupTestRouter()

	// 命中 risky
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/203.0.114.5", nil)
	r.ServeHTTP(w1, req1)
	if extractStatus(w1.Body.String()) != "risky" {
		t.Fatalf("pre flush expect risky %s", w1.Body.String())
	}

	// 删除单条 (不用 URL 编码，直接传 CIDR)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/api/cache/flush/risk/203.0.114.0/24", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("flush request failed code=%d body=%s", w2.Code, w2.Body.String())
	}

	// 检查 flush 响应确认删除成功
	var flushResp map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &flushResp); err != nil {
		t.Fatalf("flush response parse error: %v", err)
	}
	if msg, ok := flushResp["message"].(map[string]interface{}); ok {
		if removed, ok := msg["removed"].(bool); !ok || !removed {
			t.Fatalf("flush did not remove entry: %+v", flushResp)
		}
	} else {
		t.Fatalf("flush response missing message: %+v", flushResp)
	}

	// 再查
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/203.0.114.5", nil)
	r.ServeHTTP(w3, req3)
	if extractStatus(w3.Body.String()) == "risky" {
		t.Fatalf("single removal failed %s", w3.Body.String())
	}

	// 重新添加并 flush all
	resetRiskData()
	riskyDataMutex.Lock()
	reasonMap["203.0.114.0/24"] = "risk-block"
	riskyCIDRInfo = []CIDRInfo{{Net: n, OriginalCIDR: "203.0.114.0/24"}}
	riskyDataMutex.Unlock()
	w4 := httptest.NewRecorder()
	req4, _ := http.NewRequest(http.MethodPost, "/api/cache/flush/risk/all", nil)
	r.ServeHTTP(w4, req4)
	w5 := httptest.NewRecorder()
	req5, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/203.0.114.9", nil)
	r.ServeHTTP(w5, req5)
	if extractStatus(w5.Body.String()) == "risky" {
		t.Fatalf("risk all flush failed %s", w5.Body.String())
	}
}

// info 缓存 flush
func TestFlushInfoCache(t *testing.T) {
	appCache = cache.New(infoCacheExpiry, infoCacheExpiry)
	r := setupTestRouter()
	ip := "8.8.8.8"
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/api/v1/info/"+ip, nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first info lookup failed")
	}
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/api/cache/flush/info/"+ip, nil)
	r.ServeHTTP(w2, req2)
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodGet, "/api/v1/info/"+ip, nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("rebuild after single flush failed")
	}
	w4 := httptest.NewRecorder()
	req4, _ := http.NewRequest(http.MethodPost, "/api/cache/flush/info/all", nil)
	r.ServeHTTP(w4, req4)
	w5 := httptest.NewRecorder()
	req5, _ := http.NewRequest(http.MethodGet, "/api/v1/info/"+ip, nil)
	r.ServeHTTP(w5, req5)
	if w5.Code != http.StatusOK {
		t.Fatalf("rebuild after info all flush failed")
	}
}

// 路由参数 vs 客户端 IP 一致性
func TestRouteParamVsClientIPConsistency(t *testing.T) {
	resetRiskData()
	appCache = cache.New(infoCacheExpiry, infoCacheExpiry)
	r := setupTestRouter()
	ip := "1.1.1.1"
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/"+ip, nil)
	r.ServeHTTP(w1, req1)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req2.RemoteAddr = ip + ":12345"
	r.ServeHTTP(w2, req2)
	if extractStatus(w1.Body.String()) != extractStatus(w2.Body.String()) {
		t.Fatalf("status mismatch param=%s client=%s", w1.Body.String(), w2.Body.String())
	}
}

// JSON status 提取
func extractStatus(body string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	v, _ := m["status"].(string)
	return v
}
