package httpapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httpRecorder()
	c, _ := gin.CreateTestContext(w)
	handleError(c, http.StatusBadRequest, "bad request")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"bad request"}`, w.Body.String())
}

func TestCheckRequestIP(t *testing.T) {
	env := newTestEnv(t)
	tests := []struct {
		name       string
		remoteAddr string
		risky      map[string]string
		wantCode   int
		wantBody   string
	}{
		{"localhost", "127.0.0.1:12345", nil, http.StatusOK,
			`{"status":"ok","message":"Client IP is not risky (private/bogon)","ip":"127.0.0.1"}`},
		{"invalid ip", "invalid-ip:12345", nil, http.StatusBadRequest,
			`{"message":"Invalid or unidentifiable IP address.", "status":"error"}`},
		{"private ip", "192.168.1.1:12345", nil, http.StatusOK,
			`{"status":"ok","message":"Client IP is not risky (private/bogon)","ip":"192.168.1.1"}`},
		{"risky ip", "8.8.8.8:12345", map[string]string{"8.8.8.8": "Test reason"}, http.StatusOK,
			`{"status":"banned","message":"Test reason","ip":"8.8.8.8"}`},
		{"safe ip", "8.8.4.4:12345", nil, http.StatusOK,
			`{"status":"ok","message":"IP is not listed as risky.","ip":"8.8.4.4"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env.setRisky(tt.risky)
			w := env.do(http.MethodGet, "/api/v1/ip", withRemote(tt.remoteAddr))
			assert.Equal(t, tt.wantCode, w.Code)
			assert.JSONEq(t, tt.wantBody, w.Body.String())
		})
	}
}

func TestCheckIPCases(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"8.8.8.8": "Test reason"})
	cases := []struct {
		ip     string
		status int
		want   string
	}{
		{"127.0.0.1", http.StatusOK, "private/bogon"},
		{"10.0.0.1", http.StatusOK, "private/bogon"},
		{"8.8.8.8", http.StatusOK, "risky"},
		{"invalid-ip", http.StatusBadRequest, "Invalid IP address format"},
		{"203.0.113.1", http.StatusOK, "ok"},
	}
	for _, c := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			w := env.do(method, "/api/v1/ip/"+c.ip)
			assert.Equal(t, c.status, w.Code, "%s %s", method, c.ip)
			assert.Contains(t, w.Body.String(), c.want, "%s %s", method, c.ip)
		}
	}
}

func TestCheckIP_ExactMessages(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"9.9.9.9": "single-test"})
	cases := map[string]string{
		"9.9.9.9":    `{"status":"risky","message":"IP is in risky list: single-test","ip":"9.9.9.9"}`,
		"104.16.0.1": `{"status":"cdn","message":"IP belongs to CDN: cloudflare","ip":"104.16.0.1"}`,
		"3.5.140.1":  `{"status":"idc","message":"IP belongs to IDC: aws","ip":"3.5.140.1"}`,
		"1.0.0.0":    `{"status":"ok","message":"IP is not risky","ip":"1.0.0.0"}`,
	}
	for ip, want := range cases {
		assert.JSONEq(t, want, env.do(http.MethodGet, "/api/v1/ip/"+ip).Body.String(), ip)
	}
	// 客户端版本的文案不同
	assert.JSONEq(t, `{"status":"cdn","message":"Client IP belongs to CDN: cloudflare","ip":"104.16.0.1"}`,
		env.do(http.MethodGet, "/api/v1/ip", withRemote("104.16.0.1:1")).Body.String())
	assert.JSONEq(t, `{"status":"idc","message":"Client IP belongs to IDC: aws","ip":"3.5.140.1"}`,
		env.do(http.MethodGet, "/api/v1/ip", withRemote("3.5.140.1:1")).Body.String())
}

func TestCorrelationMiddleware(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/status")
	id := w.Header().Get("X-Request-ID")
	assert.Len(t, id, 32, "generated UUIDv7 without dashes")
	assert.NotContains(t, id, "-")

	w = env.do(http.MethodGet, "/api/status", withHeader("X-Correlation-ID", "test-id-123"))
	assert.Equal(t, "testid123", w.Header().Get("X-Request-ID"))
	assert.Equal(t, "private, no-cache, no-store, max-age=0, must-revalidate", w.Header().Get("Cache-Control"))
}

func TestRiskyIPChannels(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"1.71.146.0/23": "edgeone"})
	assert.Contains(t, env.do(http.MethodGet, "/api/v1/ip", withRemote("1.71.146.1:12345")).Body.String(), "edgeone")

	env.setRisky(map[string]string{"23.235.32.0/20": "fastly"})
	assert.Contains(t, env.do(http.MethodGet, "/api/v1/ip", withRemote("23.235.32.1:12345")).Body.String(), "fastly")
}

func firstCIDRFromFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); line != "" && !strings.HasPrefix(line, "//") {
			return line
		}
	}
	return ""
}

func TestAllRiskyChannelsAuto(t *testing.T) {
	env := newTestEnv(t)
	var files []string
	_ = filepath.Walk(testDataDir, func(path string, info os.FileInfo, err error) error {
		// apple.txt 是 /32 单 IP 列表，首行 +1 后不在列表内，跳过
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") && !strings.Contains(path, "apple") {
			files = append(files, path)
		}
		return nil
	})
	assert.NotEmpty(t, files)
	for _, file := range files {
		cidr := firstCIDRFromFile(file)
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip4[3]++ // 取第一个可用 IP
			ip = ip4
		}
		channel := strings.TrimSuffix(filepath.Base(file), ".txt")
		t.Run(channel, func(t *testing.T) {
			env.setRisky(map[string]string{cidr: channel})
			w := env.do(http.MethodGet, "/api/v1/ip", withRemote(net.JoinHostPort(ip.String(), "12345")))
			assert.Contains(t, w.Body.String(), channel)
		})
	}
}

func TestIPInfoBogon(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/v1/info/127.0.0.1")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","ip":"127.0.0.1","results":{"private_bogon":true,"message":"IP is private/bogon, lookup skipped"}}`, w.Body.String())
	assert.Equal(t, 0, env.cache.Len(), "bogon results are not cached")

	assert.Equal(t, http.StatusBadRequest, env.do(http.MethodGet, "/api/v1/info/not-an-ip").Code)
}

func TestInfoCacheHitMiss(t *testing.T) {
	if _, err := os.Stat(filepath.Join(testProvidersDir, "maxmind", "GeoLite2-Country.mmdb")); err != nil {
		t.Skip("geo databases not present; run ./scripts/fetch-geo-data.sh")
	}
	env := newTestEnv(t)
	w1 := env.do(http.MethodGet, "/api/v1/info/8.8.8.8")
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Catyuki-Cache"))
	w2 := env.do(http.MethodGet, "/api/v1/info/8.8.8.8")
	assert.Equal(t, "HIT", w2.Header().Get("X-Catyuki-Cache"))
	assert.Equal(t, w1.Body.String(), w2.Body.String())
	assert.Contains(t, w1.Body.String(), `"maxmind"`)
}

// firstCDN24 读取某 CDN 提供商的第一个 IPv4 /24 网段
func firstCDN24(provider string) (*net.IPNet, string, error) {
	f, err := os.Open(filepath.Join(testDataDir, "cdn", provider+".txt"))
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			if ones, bits := ipNet.Mask.Size(); bits == 32 && ones == 24 {
				return ipNet, line, nil
			}
		}
	}
	return nil, "", fmt.Errorf("no /24 found for %s", provider)
}

func ipAdd(ip net.IP, offset int) net.IP {
	ip4 := ip.To4()
	u := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	u += uint32(offset)
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}

func TestCDN_CIDRBoundaries(t *testing.T) {
	env := newTestEnv(t)
	cidrNet, _, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone")
	}
	base := cidrNet.IP
	cases := []struct{ ip, want string }{
		{base.String(), "cdn"},
		{ipAdd(base, 128).String(), "cdn"},
		{ipAdd(base, 255).String(), "cdn"},
		{ipAdd(base, 256).String(), "ok"},
	}
	for _, c := range cases {
		w := env.do(http.MethodGet, "/api/v1/ip/"+c.ip)
		assert.Equal(t, c.want, statusOf(w.Body.String()), "ip %s body=%s", c.ip, w.Body.String())
	}
}

func TestCDNFlushAllReloads(t *testing.T) {
	env := newTestEnv(t)
	cidrNet, _, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone")
	}
	base := cidrNet.IP.String()
	assert.Equal(t, "cdn", statusOf(env.do(http.MethodGet, "/api/v1/ip/"+base).Body.String()))

	env.setRisky(map[string]string{"9.9.9.9": "x"})
	w := env.do(http.MethodPost, "/api/cache/flush/all/x", asAdmin())
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"flushed_cdn_idc": true`)
	assert.Equal(t, "cdn", statusOf(env.do(http.MethodGet, "/api/v1/ip/"+base).Body.String()), "CDN lists are reloaded after flush")
	assert.Equal(t, "ok", statusOf(env.do(http.MethodGet, "/api/v1/ip/9.9.9.9").Body.String()), "risk list is cleared")
}

func TestPriority(t *testing.T) {
	env := newTestEnv(t)
	cidrNet, cidrStr, err := firstCDN24("edgeone")
	if err != nil {
		t.Skip("no /24 edgeone")
	}
	// 风险优先级高于 CDN
	env.setRisky(map[string]string{cidrStr: "test-risk"})
	assert.Equal(t, "risky", statusOf(env.do(http.MethodGet, "/api/v1/ip/"+ipAdd(cidrNet.IP, 5).String()).Body.String()))

	// 私网优先级高于风险
	env.setRisky(map[string]string{"10.0.0.0/8": "should-not-show"})
	body := env.do(http.MethodGet, "/api/v1/ip/10.1.2.3").Body.String()
	assert.Contains(t, body, "private/bogon")
	assert.NotContains(t, body, "should-not-show")
}

func TestFlushRiskSingleAndAll(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"203.0.114.0/24": "risk-block"})
	assert.Equal(t, "risky", statusOf(env.do(http.MethodGet, "/api/v1/ip/203.0.114.5").Body.String()))

	// 删除单条（不做 URL 编码，直接传 CIDR）
	w := env.do(http.MethodPost, "/api/cache/flush/risk/203.0.114.0/24", asAdmin())
	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Message map[string]any `json:"message"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp.Message["removed"])
	assert.Equal(t, "203.0.114.0/24", resp.Message["removed_entry"])
	assert.NotEqual(t, "risky", statusOf(env.do(http.MethodGet, "/api/v1/ip/203.0.114.5").Body.String()))

	// 重新添加后全部清空
	env.setRisky(map[string]string{"203.0.114.0/24": "risk-block"})
	w = env.do(http.MethodPost, "/api/cache/flush/risk/all", asAdmin())
	assert.Contains(t, w.Body.String(), `"flushed_risk_all": true`)
	assert.NotEqual(t, "risky", statusOf(env.do(http.MethodGet, "/api/v1/ip/203.0.114.9").Body.String()))
}

func TestFlushInfoCache(t *testing.T) {
	env := newTestEnv(t)
	env.cache.Set("info:1.1.1.1", "test1")
	env.cache.Set("info:2.2.2.2", "test2")

	w := env.do(http.MethodPost, "/api/cache/flush/info/1.1.1.1", asAdmin())
	assert.Equal(t, http.StatusOK, w.Code)
	_, found := env.cache.Get("info:1.1.1.1")
	assert.False(t, found)
	_, found = env.cache.Get("info:2.2.2.2")
	assert.True(t, found)

	env.do(http.MethodPost, "/api/cache/flush/info/all", asAdmin())
	_, found = env.cache.Get("info:2.2.2.2")
	assert.False(t, found)

	assert.Equal(t, http.StatusBadRequest, env.do(http.MethodPost, "/api/cache/flush/unknown/xxx", asAdmin()).Code)
}

func TestFlushIndex(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/cache/flush", asAdmin())
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "POST /api/cache/flush/info/")
	assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodGet, "/api/cache/flush").Code)
}

func TestRouteParamVsClientIPConsistency(t *testing.T) {
	env := newTestEnv(t)
	w1 := env.do(http.MethodGet, "/api/v1/ip/1.1.1.1")
	w2 := env.do(http.MethodGet, "/api/v1/ip", withRemote("1.1.1.1:12345"))
	assert.Equal(t, statusOf(w1.Body.String()), statusOf(w2.Body.String()))
}

func TestMetricsVersionFilterProxies(t *testing.T) {
	env := newTestEnv(t)

	w := env.do(http.MethodGet, "/api/metrics")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"parser"`)
	assert.Contains(t, w.Body.String(), `"unique_offenders_cnt"`)

	w = env.do(http.MethodGet, "/version")
	assert.JSONEq(t, `{"status":"ok","message":{"version":"test"}}`, w.Body.String())

	env.setRisky(map[string]string{"8.8.8.8": "x"})
	body := `[{"name":"p1","server":"1.1.1.1"},{"name":"p2","server":"8.8.8.8:443"},{"name":"p3","server":"socks5://[2001:db8::1]:1080"},{"name":"p4","server":"bad"}]`
	w = env.do(http.MethodPost, "/filter-proxies", withBody(body, "application/json"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","message":{"filtered_count":2,"proxies":[{"name":"p1","server":"1.1.1.1"},{"name":"p3","server":"socks5://[2001:db8::1]:1080"}]}}`, w.Body.String())

	w = env.do(http.MethodPost, "/filter-proxies", withBody("not json", "application/json"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMetricsPrometheus(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"1.2.3.0/24": "x"})
	w := env.do(http.MethodGet, "/metrics")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain; version=0.0.4")
	body := w.Body.String()
	assert.Contains(t, body, "# TYPE riskapi_risk_prefixes gauge\nriskapi_risk_prefixes 1\n")
	assert.Contains(t, body, `riskapi_build_info{version="test"} 1`)
	assert.Contains(t, body, "riskapi_ready 0\n")
	assert.Contains(t, body, "# TYPE riskapi_honeytrap_hits_total counter")
}

func TestExportCIDRs(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/export")
	assert.Equal(t, "# empty\n", w.Body.String())

	env.setRisky(map[string]string{
		"1.2.3.0/24": "src-a",
		"5.6.7.8":    "src-single", // 单 IP 不导出
		"9.9.0.0/16": "",
	})
	w = env.do(http.MethodGet, "/api/export")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.2.3.0/24 # src-a\n9.9.0.0/16 # unknown", w.Body.String())
	assert.Equal(t, "2", w.Header().Get("X-Total-Count"))
	assert.Equal(t, "public, max-age=1800, immutable", w.Header().Get("Cache-Control"))
}

func TestReady(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/ready")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "loading", statusOf(w.Body.String()))
	assert.Equal(t, http.StatusOK, env.do(http.MethodGet, "/api/status").Code)
}

func TestCDNEndpoints(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/cdn/edgeone")
	assert.Equal(t, http.StatusOK, w.Code)
	want, err := os.ReadFile(filepath.Join(testDataDir, "cdn", "edgeone.txt"))
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimRight(string(want), "\n"), w.Body.String())

	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/cdn/akamai").Code)

	w = env.do(http.MethodGet, "/cdn/all")
	assert.Equal(t, http.StatusOK, w.Code)
	for _, p := range []string{"edgeone", "cloudflare", "fastly"} {
		assert.Contains(t, w.Body.String(), "====== "+p+" ======")
	}
}

func TestHomeAndNotFound(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/")
	assert.Equal(t, http.StatusMisdirectedRequest, w.Code)
	assert.JSONEq(t, `{"message":"Welcome to Catyuki's Risky IP Filter API. Use /api/v1/ip to check IPs."}`, w.Body.String())

	w = env.do(http.MethodGet, "/no/such/route")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"Not Found"}`, w.Body.String())

	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/.well-known/security.txt").Code)
}

func TestQQWryStats(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/qqwry/stats")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"loaded"`)
}
