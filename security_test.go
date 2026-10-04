package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func clientIPRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, getClientIPFromCDNHeaders(c)) })
	return r
}

func requestClientIP(r *gin.Engine, remoteAddr string, headers map[string]string) string {
	req, _ := http.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Body.String()
}

func TestClientIP_IgnoresSpoofedHeadersFromUntrustedPeer(t *testing.T) {
	r := clientIPRouter()
	for _, h := range append(append([]string{}, clientIPHeaders...), "X-Forwarded-For") {
		got := requestClientIP(r, "8.8.8.8:1234", map[string]string{h: "1.2.3.4"})
		assert.Equal(t, "8.8.8.8", got, "header %s must be ignored from untrusted peer", h)
	}
}

func TestClientIP_HonorsHeadersFromTrustedPeer(t *testing.T) {
	r := clientIPRouter()
	got := requestClientIP(r, "10.1.2.3:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"})
	assert.Equal(t, "1.2.3.4", got)

	// 无可用头时回退到对端地址
	got = requestClientIP(r, "10.1.2.3:1234", nil)
	assert.Equal(t, "10.1.2.3", got)
}

func TestClientIP_ForwardedForUsesRightmostUntrusted(t *testing.T) {
	r := clientIPRouter()
	// 最左侧是客户端伪造的值，真实来源是代理追加的最右侧不可信地址
	got := requestClientIP(r, "10.1.2.3:1234", map[string]string{
		"X-Forwarded-For": "6.6.6.6, 1.2.3.4, 10.0.0.9",
	})
	assert.Equal(t, "1.2.3.4", got)
}

func TestAdminAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
			r := gin.New()
			r.POST("/admin", AdminAuthMiddleware(tc.token), func(c *gin.Context) { c.Status(http.StatusOK) })
			req, _ := http.NewRequest(http.MethodPost, "/admin", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/limited", RateLimitMiddleware(2, time.Minute), func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(remote string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	assert.Equal(t, http.StatusOK, do("8.8.8.8:1").Code)
	assert.Equal(t, http.StatusOK, do("8.8.8.8:2").Code)
	w := do("8.8.8.8:3")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	// 不同来源互不影响
	assert.Equal(t, http.StatusOK, do("9.9.9.9:1").Code)
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

func TestParseProxyHandler_NotConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	old := parseVVSecret
	t.Cleanup(func() { parseVVSecret = old })
	parseVVSecret = ""

	r := gin.New()
	r.GET("/api/v1/parse", parseProxyHandler)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/parse?url=https://example.com/a", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestBoundedRadixCache_EvictsOldestOverCapacity(t *testing.T) {
	c := NewBoundedRadixCache(3, time.Hour)
	for i := 0; i < 5; i++ {
		c.Set(fmt.Sprintf("info:%d", i), i)
	}
	assert.Len(t, c.Items(), 3)
	_, ok := c.Get("info:0")
	assert.False(t, ok)
	_, ok = c.Get("info:1")
	assert.False(t, ok)
	v, ok := c.Get("info:4")
	assert.True(t, ok)
	assert.Equal(t, 4, v)
}

func TestBoundedRadixCache_Expires(t *testing.T) {
	c := NewBoundedRadixCache(0, 20*time.Millisecond)
	c.Set("info:a", "x")
	_, ok := c.Get("info:a")
	assert.True(t, ok)
	time.Sleep(40 * time.Millisecond)
	_, ok = c.Get("info:a")
	assert.False(t, ok)
	assert.Empty(t, c.Items())
}

func TestBoundedRadixCache_OverwriteKeepsLatest(t *testing.T) {
	c := NewBoundedRadixCache(2, time.Hour)
	c.Set("a", 1)
	c.Set("a", 2)
	c.Set("b", 3)
	v, ok := c.Get("a")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	assert.Len(t, c.Items(), 2)
}

func TestHoneytrap_ConcurrentHitsAndPrune(t *testing.T) {
	gin.SetMode(gin.TestMode)
	offenders = sync.Map{}
	trackedOffenders = 0

	cfg := HoneytrapConfig{
		Enabled:        true,
		BaseDelayMinMS: 1,
		BaseDelayMaxMS: 1,
		MaxPenaltyMS:   1,
		BlockThreshold: 5,
		BlockWindow:    time.Hour,
		BlockDuration:  time.Hour,
		MaxOffenders:   2,
	}
	r := gin.New()
	r.Use(Honeytrap(cfg))
	r.GET("/*path", func(c *gin.Context) { c.Status(http.StatusNotFound) })

	hit := func(remote string) int {
		req, _ := http.NewRequest(http.MethodGet, "/.env", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hit("8.8.8.8:1")
		}()
	}
	wg.Wait()
	assert.Equal(t, http.StatusTooManyRequests, hit("8.8.8.8:1"))

	// 跟踪上限：第三个来源不再被记录
	hit("1.1.1.1:1")
	hit("2.2.2.2:1")
	assert.EqualValues(t, 2, trackedOffenders)

	// 封禁期内不清理，封禁结束且窗口过期后清理
	pruneOffenders(time.Now(), time.Hour)
	assert.EqualValues(t, 2, trackedOffenders)
	pruneOffenders(time.Now().Add(3*time.Hour), time.Hour)
	assert.EqualValues(t, 0, trackedOffenders)
}

func TestSensitivePathMiddleware_Returns403(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SensitivePathMiddleware())
	r.Any("/*path", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, path := range []string{"/.env", "/.git", "/wp-config.php"} {
			req, _ := http.NewRequest(method, path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code, "%s %s", method, path)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "/.env", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.NotEmpty(t, w.Body.String())
}
