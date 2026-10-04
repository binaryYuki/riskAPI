package honeytrap

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func newTestTrap(cfg Config) (*Trap, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	trap := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := gin.New()
	r.Use(trap.Middleware(func(c *gin.Context) string { return c.RemoteIP() }))
	r.GET("/*path", func(c *gin.Context) { c.Status(http.StatusNotFound) })
	return trap, r
}

func hit(r *gin.Engine, remote, ua string) int {
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req.RemoteAddr = remote
	req.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestTrap_ConcurrentHitsBlockAndPrune(t *testing.T) {
	trap, r := newTestTrap(Config{
		Enabled:        true,
		BaseDelayMinMS: 1,
		BaseDelayMaxMS: 1,
		MaxPenaltyMS:   1,
		BlockThreshold: 5,
		BlockWindow:    time.Hour,
		BlockDuration:  time.Hour,
		MaxOffenders:   2,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hit(r, "8.8.8.8:1", "ua")
		}()
	}
	wg.Wait()
	assert.Equal(t, http.StatusTooManyRequests, hit(r, "8.8.8.8:1", "other-ua"), "blocking is per IP regardless of UA")

	// 跟踪上限：第三个来源不再被记录
	hit(r, "1.1.1.1:1", "ua")
	hit(r, "2.2.2.2:1", "ua")
	assert.Equal(t, 2, trap.Stats().Offenders)

	// 封禁期内不清理，封禁结束且窗口过期后清理
	trap.prune(time.Now())
	assert.Equal(t, 2, trap.Stats().Offenders)
	trap.prune(time.Now().Add(3 * time.Hour))
	assert.Equal(t, 0, trap.Stats().Offenders)
}

func TestTrap_DisabledAndNonSuspiciousPassThrough(t *testing.T) {
	trap, r := newTestTrap(Config{Enabled: false})
	assert.Equal(t, http.StatusNotFound, hit(r, "8.8.8.8:1", "ua"))
	assert.Equal(t, uint64(0), trap.Stats().Hits)

	_, r = newTestTrap(Config{Enabled: true, BaseDelayMinMS: 1, BaseDelayMaxMS: 1})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestBackoffPenalty(t *testing.T) {
	assert.Equal(t, 0, backoffPenalty(1, 1000))
	assert.Equal(t, 50, backoffPenalty(2, 1000))
	assert.Equal(t, 100, backoffPenalty(3, 1000))
	assert.Equal(t, 1000, backoffPenalty(10, 1000))
	assert.Equal(t, 1000, backoffPenalty(100, 1000), "no shift overflow for large counts")
}

func TestRegisterDecoys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	r := gin.New()
	New(Config{Decoys: true}, log).RegisterDecoys(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/wp-login.php", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())

	r = gin.New()
	New(Config{Decoys: false}, log).RegisterDecoys(r)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/wp-login.php", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
