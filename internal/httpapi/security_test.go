package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/honeytrap"
)

func httpRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func clientIPOf(env *testEnv, remote string, headers map[string]string) string {
	opts := []reqOpt{withRemote(remote)}
	for k, v := range headers {
		opts = append(opts, withHeader(k, v))
	}
	var resp ResponseWithIP
	_ = json.Unmarshal(env.do(http.MethodGet, "/api/v1/ip", opts...).Body.Bytes(), &resp)
	return resp.IP
}

func TestClientIP_IgnoresSpoofedHeadersFromUntrustedPeer(t *testing.T) {
	env := newTestEnv(t)
	for _, h := range append(append([]string{}, clientIPHeaders...), "X-Forwarded-For") {
		assert.Equal(t, "8.8.8.8", clientIPOf(env, "8.8.8.8:1234", map[string]string{h: "1.2.3.4"}),
			"header %s must be ignored from untrusted peer", h)
	}
}

func TestClientIP_HonorsHeadersFromTrustedPeer(t *testing.T) {
	env := newTestEnv(t)
	assert.Equal(t, "1.2.3.4", clientIPOf(env, "10.1.2.3:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"}))
	// EO-Client-IP 优先于 CF-Connecting-IP（生产链路 EdgeOne → Cloudflare）
	assert.Equal(t, "1.2.3.4", clientIPOf(env, "10.1.2.3:1234", map[string]string{
		"EO-Client-IP":     "1.2.3.4",
		"CF-Connecting-IP": "5.6.7.8",
	}))
	// 已知 CDN 网段的对端同样可信
	assert.Equal(t, "1.2.3.4", clientIPOf(env, "104.16.0.1:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"}))
}

func TestClientIP_ForwardedForUsesRightmostUntrusted(t *testing.T) {
	env := newTestEnv(t)
	// 最左侧是客户端伪造的值，真实来源是代理追加的最右侧不可信地址
	assert.Equal(t, "1.2.3.4", clientIPOf(env, "10.1.2.3:1234", map[string]string{
		"X-Forwarded-For": "6.6.6.6, 1.2.3.4, 10.0.0.9",
	}))
}

func TestClientIP_CustomTrustedProxies(t *testing.T) {
	env := newTestEnv(t, func(c *config.Config) { c.TrustedProxies = []string{"203.0.113.1"} })
	assert.Equal(t, "10.1.2.3", clientIPOf(env, "10.1.2.3:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"}),
		"private peers are no longer trusted when TRUSTED_PROXIES excludes them")
}

func TestAdminAuth(t *testing.T) {
	cases := []struct {
		name, token, header string
		want                int
	}{
		{"disabled when token unset", "", "Bearer anything", http.StatusForbidden},
		{"missing header", "s3cret", "", http.StatusUnauthorized},
		{"wrong token", "s3cret", "Bearer nope", http.StatusUnauthorized},
		{"wrong scheme", "s3cret", "s3cret", http.StatusUnauthorized},
		{"valid token", "s3cret", "Bearer s3cret", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, func(c *config.Config) { c.AdminToken = tc.token })
			var opts []reqOpt
			if tc.header != "" {
				opts = append(opts, withHeader("Authorization", tc.header))
			}
			assert.Equal(t, tc.want, env.do(http.MethodPost, "/api/cache/flush/info/1.1.1.1", opts...).Code)
		})
	}
}

func TestRateLimitOnParse(t *testing.T) {
	env := newTestEnv(t, func(c *config.Config) { c.ParseRateLimitPerMin = 2 })
	do := func(remote string) *httptest.ResponseRecorder {
		return env.do(http.MethodGet, "/api/v1/parse?url=https://example.com", withRemote(remote))
	}
	assert.Equal(t, http.StatusServiceUnavailable, do("8.8.8.8:1").Code) // 未配置密钥
	assert.Equal(t, http.StatusServiceUnavailable, do("8.8.8.8:2").Code)
	w := do("8.8.8.8:3")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	// 不同来源互不影响
	assert.Equal(t, http.StatusServiceUnavailable, do("9.9.9.9:1").Code)
}

func TestIPRateLimiter_WindowReset(t *testing.T) {
	l := newIPRateLimiter(1, time.Minute)
	now := time.Now()
	ok, _ := l.allow("a", now)
	assert.True(t, ok)
	ok, _ = l.allow("a", now.Add(time.Second))
	assert.False(t, ok)
	ok, _ = l.allow("a", now.Add(time.Minute))
	assert.True(t, ok)
}

func TestSensitivePath_Returns403(t *testing.T) {
	env := newTestEnv(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, path := range []string{"/.env", "/.git", "/wp-config.php", "/admin", "/vendor/autoload.php", "/.ENV"} {
			assert.Equal(t, http.StatusForbidden, env.do(method, path).Code, "%s %s", method, path)
		}
	}
	w := env.do(http.MethodGet, "/.env")
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, w.Body.String(), "403")
	assert.JSONEq(t, `{"error":"forbidden"}`, env.do(http.MethodPost, "/.env").Body.String())
}

func TestHoneytrapWiredWithClientIP(t *testing.T) {
	env := newTestEnv(t, func(c *config.Config) {
		c.Honeytrap = honeytrap.Config{Enabled: true, BaseDelayMinMS: 1, BaseDelayMaxMS: 1, MaxPenaltyMS: 1, BlockThreshold: 2}
	})
	// 伪造的转发头不能让同一来源绕过封禁
	env.do(http.MethodGet, "/wp-login.php", withRemote("8.8.8.8:1"), withHeader("CF-Connecting-IP", "1.1.1.1"))
	w := env.do(http.MethodGet, "/wp-login.php", withRemote("8.8.8.8:1"), withHeader("CF-Connecting-IP", "2.2.2.2"))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func trapConfig(mutate ...func(*honeytrap.Config)) func(*config.Config) {
	return func(c *config.Config) {
		c.Honeytrap = honeytrap.Config{Enabled: true, BaseDelayMinMS: 1, BaseDelayMaxMS: 1, MaxPenaltyMS: 1, FakeOKProb: 1}
		for _, m := range mutate {
			m(&c.Honeytrap)
		}
	}
}

func TestHoneytrap_ServesBaitInsteadOf403(t *testing.T) {
	env := newTestEnv(t, trapConfig())
	w := env.do(http.MethodGet, "/.env", withRemote("8.8.8.8:1"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "DB_PASSWORD=")
	assert.Empty(t, w.Header().Get("X-Request-ID"))

	// 伪造概率为 0 时仍由敏感路径拦截返回 403
	env = newTestEnv(t, trapConfig(func(c *honeytrap.Config) { c.FakeOKProb = 0 }))
	assert.Equal(t, http.StatusForbidden, env.do(http.MethodGet, "/.env", withRemote("8.8.8.8:1")).Code)
	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/wp-login.php", withRemote("9.9.9.9:1")).Code)
}

func TestHoneytrap_FlaggedSourceIsRisky(t *testing.T) {
	env := newTestEnv(t, trapConfig())
	lookup := func(ip string) ResponseWithIP {
		var resp ResponseWithIP
		// 查询方用另一个来源，与被查询的 IP 无关
		assert.NoError(t, json.Unmarshal(env.do(http.MethodGet, "/api/v1/ip/"+ip, withRemote("9.9.9.9:1")).Body.Bytes(), &resp))
		return resp
	}
	assert.False(t, lookup("45.33.32.156").IsRisky)

	env.do(http.MethodGet, "/.git/config", withRemote("45.33.32.156:1"))
	resp := lookup("45.33.32.156")
	assert.True(t, resp.IsRisky)
	assert.Equal(t, "risky", resp.Status)
	assert.Contains(t, resp.Message, honeytrap.Source)

	// 请求方自查同样生效
	var self ResponseWithIP
	assert.NoError(t, json.Unmarshal(env.do(http.MethodGet, "/api/v1/ip", withRemote("45.33.32.156:2")).Body.Bytes(), &self))
	assert.Equal(t, "banned", self.Status)
	assert.Equal(t, honeytrap.Source, self.Message)

	// /filter-proxies 也会过滤被标记的来源
	w := env.do(http.MethodPost, "/filter-proxies", withBody(`[{"name":"a","server":"45.33.32.156:8080"},{"name":"b","server":"45.33.32.157:8080"}]`, "application/json"))
	assert.Contains(t, w.Body.String(), `"filtered_count":1`)

	// CDN 回源网段即使被记到也不判为风险
	env.do(http.MethodGet, "/.git/config", withRemote("104.16.0.1:1"))
	assert.Equal(t, "cdn", lookup("104.16.0.1").Status)
}

func TestHoneytrap_ExportIncludesObfuscatedFlaggedSources(t *testing.T) {
	env := newTestEnv(t, trapConfig(func(c *honeytrap.Config) { c.Secret = "test-secret" }))
	assert.Equal(t, "# empty\n", env.do(http.MethodGet, "/api/export").Body.String())

	env.do(http.MethodGet, "/.git/config", withRemote("45.33.32.156:1"))
	id := honeytrapSourceID(t, "test-secret", "45.33.32.156")

	// 风险表为空时，蜜罐来源也会导出
	w := env.do(http.MethodGet, "/api/export")
	assert.Regexp(t, `^# honeytrap `+id+` until \d{4}-\d\d-\d\dT[\d:]+Z$`, w.Body.String())
	assert.Equal(t, "0", w.Header().Get("X-Total-Count"))
	assert.Equal(t, "1", w.Header().Get("X-Honeytrap-Count"))

	// 与风险 CIDR 一起导出时排在末尾，且不出现真实地址
	env.setRisky(map[string]string{"203.0.113.0/24": "feed-a"})
	w = env.do(http.MethodGet, "/api/export")
	assert.Equal(t, "203.0.113.0/24 # feed-a\n# honeytrap "+id, strings.SplitN(w.Body.String(), " until ", 2)[0])
	assert.NotContains(t, w.Body.String(), "45.33.32.156")
	assert.Equal(t, "1", w.Header().Get("X-Total-Count"))
}

func TestHoneytrap_AccessLogIsSealedOnRuleHits(t *testing.T) {
	var buf bytes.Buffer
	env := newTestEnvWithLog(t, slog.New(slog.NewJSONHandler(&buf, nil)), trapConfig(func(c *honeytrap.Config) { c.Secret = "test-secret" }))
	accessLines := func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "request" {
				out = append(out, rec)
			}
		}
		return out
	}

	// 普通请求：访问日志保持明文
	env.do(http.MethodGet, "/api/status", withRemote("45.33.32.156:1"))
	lines := accessLines()
	require.Len(t, lines, 1)
	assert.Equal(t, "45.33.32.156", lines[0]["client_ip"])
	assert.Equal(t, "/api/status", lines[0]["path"])
	assert.NotContains(t, lines[0], "sealed")

	// 命中蜜罐规则：整行只剩一个封存的字符串，日志里不再出现这次请求的地址和路径
	buf.Reset()
	env.do(http.MethodGet, "/wp-login.php", withRemote("45.33.32.200:1"))
	lines = accessLines()
	require.Len(t, lines, 1)
	sealed, _ := lines[0]["sealed"].(string)
	require.NotEmpty(t, sealed)
	assert.ElementsMatch(t, []string{"time", "level", "msg", "sealed"}, slices.Collect(maps.Keys(lines[0])))
	assert.NotContains(t, buf.String(), "45.33.32.200")
	assert.NotContains(t, sealed, "wp-login")

	// 管理接口可以还原；内容与明文访问日志的字段一致
	assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodPost, "/api/honeytrap/unseal", withBody(sealed, "text/plain")).Code)
	w := env.do(http.MethodPost, "/api/honeytrap/unseal", asAdmin(), withBody(sealed+"\nnot-sealed\n", "text/plain"))
	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Message []map[string]any `json:"message"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Message, 2)
	assert.Equal(t, "45.33.32.200", resp.Message[0]["client_ip"])
	assert.Equal(t, "/wp-login.php", resp.Message[0]["path"])
	assert.EqualValues(t, http.StatusOK, resp.Message[0]["status"])
	assert.NotEmpty(t, resp.Message[0]["correlation_id"])
	assert.Nil(t, resp.Message[1])

	// 没有命中规则的 404 不封存
	buf.Reset()
	env.do(http.MethodGet, "/no/such/route", withRemote("45.33.32.201:1"))
	assert.Equal(t, "45.33.32.201", accessLines()[0]["client_ip"])
}

func TestHoneytrap_RevealSourceRequiresAdmin(t *testing.T) {
	env := newTestEnv(t, trapConfig(func(c *honeytrap.Config) { c.Secret = "test-secret" }))
	env.do(http.MethodGet, "/.git/config", withRemote("45.33.32.156:1"))

	// 同一密钥下标识是确定的，可以由另一个蜜罐实例算出
	id := honeytrapSourceID(t, "test-secret", "45.33.32.156")
	assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodGet, "/api/honeytrap/source/"+id).Code)

	w := env.do(http.MethodGet, "/api/honeytrap/source/"+id, asAdmin())
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"source": "45.33.32.156"`)
	assert.Contains(t, w.Body.String(), `"flagged": true`)

	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/api/honeytrap/source/not-a-source-id", asAdmin()).Code)
	other := honeytrapSourceID(t, "another-secret", "45.33.32.156")
	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/api/honeytrap/source/"+other, asAdmin()).Code)
}

// honeytrapSourceID 用给定密钥算出某个 IP 的混淆标识：让一个临时蜜罐标记它，再从标记文件里读出来
func honeytrapSourceID(t *testing.T, secret, ip string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "flagged.jsonl")
	env := newTestEnv(t, trapConfig(func(c *honeytrap.Config) { c.Secret, c.FlagFile = secret, file }))
	env.do(http.MethodGet, "/.env", withRemote(ip+":1"))
	data, err := os.ReadFile(file)
	assert.NoError(t, err)
	var rec struct {
		Source string `json:"source"`
	}
	assert.NoError(t, json.Unmarshal(data, &rec))
	return rec.Source
}

func TestHoneytrap_NotFoundProbingIsScored(t *testing.T) {
	env := newTestEnv(t, trapConfig(func(c *honeytrap.Config) { c.BlockThreshold = 3 }))
	for _, path := range []string{"/a", "/b"} {
		assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, path, withRemote("8.8.8.8:1")).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, env.do(http.MethodGet, "/c", withRemote("8.8.8.8:1")).Code)
	// 真实路由与其他来源不受影响
	assert.Equal(t, http.StatusOK, env.do(http.MethodGet, "/api/status", withRemote("8.8.8.8:1")).Code)
	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/c", withRemote("9.9.9.9:1")).Code)
}

func TestParse_MissingAndInvalidURL(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/v1/parse")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing required query parameter: url")

	w = env.do(http.MethodGet, "/api/v1/parse?url=ftp://example.com")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "only http/https")
}

func TestParse_ForwardAndVV(t *testing.T) {
	secret := "unit-test-secret"
	targetURL := "https://www.xiaohongshu.com/explore/abc123"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/parse", r.URL.Path)
		assert.True(t, verifyVVForURL(secret, r.URL.Query().Get("_vv"), targetURL), "invalid vv")

		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, targetURL, body["url"])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	env := newTestEnv(t, func(c *config.Config) {
		c.ParseSecret = secret
		c.ParseWorkerBase = upstream.URL + "/"
	})
	w := env.do(http.MethodGet, "/api/v1/parse?url="+targetURL)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"ok":true}`, w.Body.String())
}

func TestParse_NonJSONUpstreamPassThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream oops"))
	}))
	defer upstream.Close()
	env := newTestEnv(t, func(c *config.Config) {
		c.ParseSecret = "s"
		c.ParseWorkerBase = upstream.URL
	})
	w := env.do(http.MethodGet, "/api/v1/parse?url=https://example.com")
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, "upstream oops", w.Body.String())
}

func verifyVVForURL(secret, vv, targetURL string) bool {
	parts := strings.Split(vv, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return false
	}
	bodyHash := sha256.Sum256([]byte(`{"url":"` + targetURL + `"}`))
	plain := strings.Join([]string{parts[0], parts[1], parts[2], "POST", "/api/parse", hex.EncodeToString(bodyHash[:]), targetURL}, "\n")
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(plain))
	return parts[3] == strings.TrimRight(base64.URLEncoding.EncodeToString(m.Sum(nil)), "=")
}

// 命中蜜罐规则的请求不生成追踪 span：否则路径和客户端地址会以明文上报，访问日志的封存就失去意义
func TestHoneytrap_RuleHitsAreNotTraced(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	traced := func(mutate func(*config.Config)) *testEnv {
		env := newTestEnv(t, mutate)
		env.server.tracerProvider = tp
		env.h = env.server.Handler()
		return env
	}

	env := traced(trapConfig())
	env.do(http.MethodGet, "/wp-login.php", withRemote("45.33.32.200:1"))
	env.do(http.MethodGet, "/.env", withRemote("45.33.32.200:1"))
	assert.Empty(t, rec.Ended(), "honeypot rule hits must not produce spans")

	// 其他请求照常追踪，包括未命中规则的 404
	env.do(http.MethodGet, "/api/v1/ip/1.1.1.1", withRemote("45.33.32.201:1"))
	env.do(http.MethodGet, "/no/such/route", withRemote("45.33.32.201:1"))
	assert.Len(t, rec.Ended(), 2)

	// 蜜罐关闭时这些路径只是普通的 403/404，照常追踪
	rec.Reset()
	env = traced(func(c *config.Config) {})
	env.do(http.MethodGet, "/.env", withRemote("45.33.32.200:1"))
	assert.Len(t, rec.Ended(), 1)
}
