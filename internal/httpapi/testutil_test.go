package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/cache"
	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/geo"
	"risky_ip_filter/internal/geo/qqwry"
	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/netlists"
)

const (
	testDataDir      = "../../data"
	testProvidersDir = "../../providers"
	testAdminToken   = "test-admin-token"
)

var (
	sharedOnce  sync.Once
	sharedLists *netlists.Lists
	sharedQQ    *qqwry.DB
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sharedDeps CDN/IDC 列表与纯真库加载较慢，在测试间共享（只读）
func sharedDeps() (*netlists.Lists, *qqwry.DB) {
	sharedOnce.Do(func() {
		sharedLists = netlists.New(testDataDir, discardLog())
		sharedLists.Reload()
		sharedQQ, _ = qqwry.Open(testProvidersDir + "/qqwry/qqwry.dat")
	})
	return sharedLists, sharedQQ
}

type testEnv struct {
	t      *testing.T
	server *Server
	h      *gin.Engine
	risk   *feeds.Store
	cache  *cache.Cache
}

// newTestEnv 构建带完整中间件链的测试服务；蜜罐默认关闭，管理令牌为 testAdminToken
func newTestEnv(t *testing.T, mutate ...func(*config.Config)) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.Load()
	cfg.DataDir = testDataDir
	cfg.ProvidersDir = testProvidersDir
	cfg.AdminToken = testAdminToken
	cfg.TrustedProxies = config.DefaultTrustedProxies
	cfg.ParseSecret = ""
	cfg.ParseRateLimitPerMin = 0
	cfg.Honeytrap = honeytrap.Config{Enabled: false}
	for _, m := range mutate {
		m(&cfg)
	}

	lists, qq := sharedDeps()
	log := discardLog()
	env := &testEnv{
		t:     t,
		risk:  feeds.NewStore(nil, feeds.FetchConfig{}, log),
		cache: cache.New(cfg.InfoCacheMaxEntries, cfg.InfoCacheTTL),
	}
	env.server = New(Deps{
		Config:    cfg,
		Version:   "test",
		Log:       log,
		Risk:      env.risk,
		Lists:     lists,
		Geo:       geo.New(cfg.ProvidersDir, qq, 1500*time.Millisecond, log),
		InfoCache: env.cache,
		Trap:      honeytrap.New(cfg.Honeytrap, log),
	})
	env.h = env.server.Handler()
	return env
}

// setRisky 用给定的 条目→来源 替换风险表
func (e *testEnv) setRisky(entries map[string]string) {
	var list []feeds.Entry
	for v, src := range entries {
		list = append(list, feeds.Entry{Value: v, Source: src})
	}
	e.risk.Replace(list)
}

type reqOpt func(*http.Request)

func withRemote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func withBody(body, contentType string) reqOpt {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
	}
}

func asAdmin() reqOpt { return withHeader("Authorization", "Bearer "+testAdminToken) }

func (e *testEnv) do(method, path string, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "192.0.2.10:1234" // 默认对端：TEST-NET-1（不可信、非 CDN）
	for _, o := range opts {
		o(req)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// statusOf 提取 JSON 响应的 status 字段
func statusOf(body string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	v, _ := m["status"].(string)
	return v
}
