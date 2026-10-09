package honeytrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// fastCfg 延迟压到 1ms 的启用配置；默认总是返回伪造内容
func fastCfg(mutate ...func(*Config)) Config {
	cfg := Config{Enabled: true, BaseDelayMinMS: 1, BaseDelayMaxMS: 1, MaxPenaltyMS: 1, FakeOKProb: 1}
	for _, m := range mutate {
		m(&cfg)
	}
	return cfg
}

// logCapture 收集蜜罐输出的 JSON 日志，供测试按事件类型取用
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// of 返回某类事件的日志记录
func (l *logCapture) of(kind eventKind) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "honeytrap "+string(kind) {
			out = append(out, rec)
		}
	}
	return out
}

// newTestTrap 构建与线上相同的接线：中间件 + NoRoute 链首的 NotFound
func newTestTrap(cfg Config) (*Trap, *gin.Engine) {
	return buildTrap(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// newLoggedTrap 与 newTestTrap 相同，并记录全部事件日志
func newLoggedTrap(cfg Config) (*Trap, *gin.Engine, *logCapture) {
	logs := &logCapture{}
	cfg.EnableLog = true
	trap, r := buildTrap(cfg, slog.New(slog.NewJSONHandler(logs, nil)))
	return trap, r, logs
}

// hidden 返回某个 IP 在该蜜罐日志中的混淆标识
func hidden(trap *Trap, ip string) string {
	key, _ := sourceKey(ip)
	return trap.obf.hide(key)
}

func buildTrap(cfg Config, log *slog.Logger) (*Trap, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	trap := New(cfg, log)
	clientIP := func(c *gin.Context) string { return c.RemoteIP() }
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Header("X-Request-ID", "real-service") })
	r.Use(trap.Middleware(clientIP))
	r.GET("/api/v1/ip", func(c *gin.Context) { c.String(http.StatusOK, "real") })
	r.NoRoute(trap.NotFound(clientIP), func(c *gin.Context) { c.String(http.StatusNotFound, "real 404") })
	return trap, r
}

func do(r *gin.Engine, method, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	req.Host = "example.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func get(r *gin.Engine, path, remote string) *httptest.ResponseRecorder {
	return do(r, http.MethodGet, path, remote)
}

func TestMiddleware_ServesBaitAndHidesRealService(t *testing.T) {
	trap, r := newTestTrap(fastCfg())

	w := get(r, "/.env", "8.8.8.8:1")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "DB_PASSWORD=")
	assert.Contains(t, w.Body.String(), "APP_URL=https://example.com")
	assert.Equal(t, "nginx", w.Header().Get("Server"))
	assert.Empty(t, w.Header().Get("X-Request-ID"), "headers of the real service must not leak into bait")

	// 假凭据按来源确定：同一来源每次相同，不同来源不同
	assert.Equal(t, w.Body.String(), get(r, "/.env", "8.8.8.8:2").Body.String())
	assert.NotEqual(t, w.Body.String(), get(r, "/.env", "9.9.9.9:1").Body.String())

	stats := trap.Stats()
	assert.Equal(t, uint64(3), stats.Hits)
	assert.Equal(t, uint64(3), stats.FakeOK)
	assert.Equal(t, 2, stats.Offenders)
}

func TestMiddleware_FormerDecoyPathsAreScoredBait(t *testing.T) {
	trap, r := newTestTrap(fastCfg())
	for path, want := range map[string]string{
		"/wp-login.php":               "Powered by WordPress",
		"/wp-admin":                   "Powered by WordPress",
		"/phpmyadmin":                 "phpMyAdmin",
		"/login":                      "Sign in",
		"/admin":                      "Sign in",
		"/unified-payments-interface": "Sign in",
		"/npci-upi":                   "Sign in",
	} {
		w := do(r, http.MethodPost, path, "8.8.8.8:1")
		// 每个路径换一个来源，避免累计到封禁阈值
		trap.scores = newScorer(trap.scores.cfg)
		assert.Equal(t, http.StatusOK, w.Code, path)
		assert.Contains(t, w.Body.String(), want, path)
	}
}

func TestMiddleware_PassThrough(t *testing.T) {
	// 关闭：不计分、不伪造
	trap, r := newTestTrap(Config{Enabled: false})
	assert.Equal(t, "real 404", get(r, "/.env", "8.8.8.8:1").Body.String())
	assert.Equal(t, Stats{}, trap.Stats())
	assert.False(t, trap.Flagged("8.8.8.8"))

	// 未命中规则的真实路由不受影响
	trap, r = newTestTrap(fastCfg())
	w := get(r, "/api/v1/ip", "8.8.8.8:1")
	assert.Equal(t, "real", w.Body.String())
	assert.Equal(t, "real-service", w.Header().Get("X-Request-ID"))
	assert.Equal(t, 0, trap.Stats().Offenders)

	// 伪造概率为 0：仍然计分和延迟，但交给后续处理函数，且 404 不重复计分
	trap, r = newTestTrap(fastCfg(func(c *Config) { c.FakeOKProb = 0 }))
	assert.Equal(t, "real 404", get(r, "/wp-login.php", "8.8.8.8:1").Body.String())
	assert.Equal(t, uint64(1), trap.Stats().Hits)
	assert.Equal(t, uint64(0), trap.Stats().FakeOK)
	key, _ := sourceKey("8.8.8.8")
	assert.Equal(t, WeightMedium, trap.scores.sources[key].score)
}

func TestShouldBait_DeterministicPerSourceAndPath(t *testing.T) {
	trap, _ := newTestTrap(fastCfg(func(c *Config) { c.FakeOKProb = 0.5 }))
	baited := 0
	for i := range 200 {
		ip, path := fmt.Sprintf("10.0.%d.1", i), "/.env"
		first := trap.shouldBait(ip, path)
		assert.Equal(t, first, trap.shouldBait(ip, path))
		if first {
			baited++
		}
	}
	assert.InDelta(t, 100, baited, 40)
}

func TestTrap_FlagsSource(t *testing.T) {
	trap, r := newTestTrap(fastCfg())

	// 一次中权重命中不足以标记，两个不同的中权重路径可以
	get(r, "/wp-login.php", "1.1.1.1:1")
	assert.False(t, trap.Flagged("1.1.1.1"))
	get(r, "/phpmyadmin/", "1.1.1.1:1")
	assert.True(t, trap.Flagged("1.1.1.1"))

	// 高权重诱饵一次即标记；IPv6 按 /64 归并
	get(r, "/.git/config", "[2001:db8:1:2::1]:1")
	assert.True(t, trap.Flagged("2001:db8:1:2:ffff::9"))
	assert.False(t, trap.Flagged("2001:db8:1:3::1"))

	assert.False(t, trap.Flagged("9.9.9.9"))
	assert.False(t, trap.Flagged("not-an-ip"))
	stats := trap.Stats()
	assert.Equal(t, uint64(2), stats.Flags)
	assert.Equal(t, 2, stats.Flagged)
}

func TestTrap_ConcurrentHitsBlockPerIP(t *testing.T) {
	trap, r := newTestTrap(fastCfg(func(c *Config) {
		c.BlockThreshold = 20
		c.BlockWindow = time.Hour
		c.BlockDuration = time.Hour
	}))

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			get(r, fmt.Sprintf("/scan-%d.php", i), "8.8.8.8:1")
		}()
	}
	wg.Wait()

	// 封禁按来源生效，覆盖规则路径与未知路径，但不影响真实路由和其他来源
	assert.Equal(t, http.StatusTooManyRequests, get(r, "/.env", "8.8.8.8:2").Code)
	assert.Equal(t, http.StatusTooManyRequests, get(r, "/no/such/route", "8.8.8.8:3").Code)
	assert.Equal(t, http.StatusOK, get(r, "/api/v1/ip", "8.8.8.8:4").Code)
	assert.Equal(t, http.StatusOK, get(r, "/.env", "9.9.9.9:1").Code)
	assert.True(t, trap.Flagged("8.8.8.8"), "a blocked source is always flagged")
	assert.NotZero(t, trap.Stats().Blocks)
}

func TestNotFound_ScoresProbing(t *testing.T) {
	trap, r := newTestTrap(fastCfg())

	// 同一个 404 反复请求只按重复计分，不会被标记
	for range 20 {
		assert.Equal(t, http.StatusNotFound, get(r, "/favicon.ico", "1.1.1.1:1").Code)
	}
	assert.False(t, trap.Flagged("1.1.1.1"))

	// 短时间内探测多个不同的不存在路径会被标记，继续探测则被封禁
	for i := range 8 {
		assert.Equal(t, "real 404", get(r, fmt.Sprintf("/probe/%d", i), "2.2.2.2:1").Body.String())
	}
	assert.True(t, trap.Flagged("2.2.2.2"))
	for i := 8; i < 16; i++ {
		get(r, fmt.Sprintf("/probe/%d", i), "2.2.2.2:1")
	}
	assert.Equal(t, http.StatusTooManyRequests, get(r, "/probe/x", "2.2.2.2:1").Code)
	assert.Zero(t, trap.Stats().Hits, "plain 404s are scored but not tarpitted")
}

func TestDelay_CapsConcurrentSleepers(t *testing.T) {
	trap, _ := newTestTrap(fastCfg())
	assert.True(t, trap.delay(t.Context(), 1))

	trap.delaying.Store(maxDelaying)
	start := time.Now()
	assert.False(t, trap.delay(t.Context(), 5000), "over the cap the request is not delayed")
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, int64(maxDelaying), trap.delaying.Load())
}

func TestBackoffPenalty(t *testing.T) {
	assert.Equal(t, 0, backoffPenalty(0, 1000))
	assert.Equal(t, 0, backoffPenalty(1.5, 1000))
	assert.Equal(t, 50, backoffPenalty(2, 1000))
	assert.Equal(t, 100, backoffPenalty(4, 1000))
	assert.Equal(t, 400, backoffPenalty(8, 1000))
	assert.Equal(t, 1000, backoffPenalty(12, 1000))
	assert.Equal(t, 1000, backoffPenalty(1e6, 1000), "no shift overflow for large scores")
}

func TestWithDefaults(t *testing.T) {
	cfg := Config{FakeOKProb: 3, BlockThreshold: 2}.withDefaults()
	assert.Equal(t, 1.0, cfg.FakeOKProb)
	assert.Equal(t, 2, cfg.FlagThreshold, "flag threshold never exceeds block threshold")

	cfg = Config{}.withDefaults()
	assert.Equal(t, 8, cfg.FlagThreshold)
	assert.Equal(t, 16, cfg.BlockThreshold)
	assert.Equal(t, time.Hour, cfg.FlagDuration)
}
