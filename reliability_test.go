package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var fastFetchConfig = Config{Timeout: 2000, Retries: 2, RetryDelay: 1, Concurrency: 1}

// withFeeds 临时替换数据源列表并重置跨轮次状态
func withFeeds(t *testing.T, urls ...string) {
	t.Helper()
	oldAPIs, oldLastGood := ipListAPIs, lastGoodEntries
	oldReady := riskDataReady.Load()
	ipListAPIs = urls
	lastGoodEntries = make(map[string][]IPAssociation)
	riskDataReady.Store(false)
	t.Cleanup(func() {
		ipListAPIs, lastGoodEntries = oldAPIs, oldLastGood
		riskDataReady.Store(oldReady)
	})
}

func TestUpdateIPLists_FailedSourceKeepsLastGoodData(t *testing.T) {
	var failing atomic.Bool
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "# comment\n5.5.5.0/24\n6.6.6.6\n")
	}))
	defer flaky.Close()
	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "7.7.7.7\n")
	}))
	defer stable.Close()
	withFeeds(t, flaky.URL, stable.URL)

	updateIPLists(context.Background(), fastFetchConfig)
	for _, ip := range []string{"5.5.5.9", "6.6.6.6", "7.7.7.7"} {
		ok, _ := isRiskyIP(ip)
		assert.True(t, ok, ip)
	}

	// 第二轮 flaky 源失败：其条目应沿用上一轮结果，而不是消失
	failing.Store(true)
	updateIPLists(context.Background(), fastFetchConfig)
	for _, ip := range []string{"5.5.5.9", "6.6.6.6", "7.7.7.7"} {
		ok, _ := isRiskyIP(ip)
		assert.True(t, ok, "entries from failed source must be retained: %s", ip)
	}
}

func TestUpdateIPLists_EmptyResponseTreatedAsFailure(t *testing.T) {
	var empty atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if empty.Load() {
			// 例如被限流后返回的 HTML 页面：200 但没有任何合法条目
			_, _ = io.WriteString(w, "<html>rate limited</html>\n")
			return
		}
		_, _ = io.WriteString(w, "8.8.8.0/24\n")
	}))
	defer srv.Close()
	withFeeds(t, srv.URL)

	updateIPLists(context.Background(), fastFetchConfig)
	empty.Store(true)
	updateIPLists(context.Background(), fastFetchConfig)
	ok, _ := isRiskyIP("8.8.8.8")
	assert.True(t, ok, "an empty response must not wipe previous data")
}

func TestUpdateIPLists_ReadinessAndAllSourcesDown(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	withFeeds(t, down.URL)
	setRiskyEntries(map[string]string{"9.9.9.9": "previous"})

	updateIPLists(context.Background(), fastFetchConfig)
	assert.False(t, riskDataReady.Load(), "not ready while no source has ever succeeded")
	ok, _ := isRiskyIP("9.9.9.9")
	assert.True(t, ok, "existing data must not be replaced when every source fails")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/ready", readyHandler)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ready", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	riskDataReady.Store(true)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ready", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "risk_prefixes")
}

func TestParseTextResponse_TruncatedBodyIsError(t *testing.T) {
	body := io.MultiReader(strings.NewReader("1.1.1.1\n2.2.2.2\n"), iotest.ErrReader(errors.New("connection reset")))
	_, err := parseTextResponse(body, "test")
	assert.Error(t, err)
}

func TestParseTextResponse_Formats(t *testing.T) {
	body := strings.NewReader("# c\n; c\n\nExitAddress 1.2.3.4 2026-01-01 00:00:00\n10.0.0.0/8\nnot-an-ip\n2001:db8::1\n")
	entries, err := parseTextResponse(body, "src")
	assert.NoError(t, err)
	var got []string
	for _, e := range entries {
		got = append(got, e.Entry)
		assert.Equal(t, "src", e.Reason)
	}
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1"}, got)
}

func TestParseTextResponse_InlineComments(t *testing.T) {
	body := strings.NewReader(
		"; Spamhaus DROP List\n" +
			"1.10.16.0/20 ; SBL256894\n" +
			"77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073\n" +
			"ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n")
	entries, err := parseTextResponse(body, "src")
	assert.NoError(t, err)
	var got []string
	for _, e := range entries {
		got = append(got, e.Entry)
	}
	assert.Equal(t, []string{"1.10.16.0/20", "77.91.122.9"}, got)
}

func TestParseRSSResponse_IPFromTitle(t *testing.T) {
	body := strings.NewReader(`<rss version="2.0"><channel>
<item><title>34.178.149.189 | SD</title><description>Event: Bad Event | Total: 26</description></item>
<item><title>2001:db8::5 | H</title><description>x</description></item>
<item><title>garbage | SD</title><description>y</description></item>
</channel></rss>`)
	entries, err := parseRSSResponse(body, "honeypot")
	assert.NoError(t, err)
	var got []string
	for _, e := range entries {
		got = append(got, e.Entry)
	}
	assert.Equal(t, []string{"34.178.149.189", "2001:db8::5"}, got)
}

func TestUpdateIPListsPeriodically_StopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "1.2.3.4\n")
	}))
	defer srv.Close()
	withFeeds(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		updateIPListsPeriodically(ctx, fastFetchConfig)
		close(done)
	}()
	assert.Eventually(t, riskDataReady.Load, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updater did not stop after context cancellation")
	}
}

func TestFetchIPList_CancelDuringRetryBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := fetchIPList(ctx, srv.URL, Config{Timeout: 2000, Retries: 3, RetryDelay: 10000})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 2*time.Second, "retry backoff must be interruptible")
}

func TestCDNHandler_ServesCanonicalFiles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/cdn/:name", cdnHandler)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/cdn/edgeone", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	want, err := os.ReadFile("data/cdn/edgeone.txt")
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimRight(string(want), "\n"), w.Body.String())
}
