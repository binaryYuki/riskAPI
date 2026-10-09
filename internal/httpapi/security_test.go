package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
