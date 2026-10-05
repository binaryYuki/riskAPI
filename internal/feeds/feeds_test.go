package feeds

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
)

var fastFetch = FetchConfig{Timeout: 2 * time.Second, Retries: 2, RetryDelay: time.Millisecond}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestStore(urls ...string) *Store {
	var fs []Feed
	for i, u := range urls {
		fs = append(fs, Feed{ID: "feed-" + string(rune('a'+i)), URL: u})
	}
	return NewStore(fs, fastFetch, discardLog())
}

func textServer(body func() (int, string)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, text := body()
		w.WriteHeader(code)
		_, _ = io.WriteString(w, text)
	}))
}

func isRisky(s *Store, ip string) bool {
	_, ok := s.Lookup(ip)
	return ok
}

func TestUpdate_FailedSourceKeepsLastGoodData(t *testing.T) {
	var failing atomic.Bool
	flaky := textServer(func() (int, string) {
		if failing.Load() {
			return http.StatusInternalServerError, "boom"
		}
		return http.StatusOK, "# comment\n5.5.5.0/24\n6.6.6.6\n"
	})
	defer flaky.Close()
	stable := textServer(func() (int, string) { return http.StatusOK, "7.7.7.7\n" })
	defer stable.Close()
	s := newTestStore(flaky.URL, stable.URL)

	s.Update(context.Background())
	for _, ip := range []string{"5.5.5.9", "6.6.6.6", "7.7.7.7"} {
		assert.True(t, isRisky(s, ip), ip)
	}
	source, _ := s.Lookup("5.5.5.9")
	assert.Equal(t, "feed-a", source)

	// 第二轮 flaky 源失败：其条目应沿用上一轮结果，而不是消失
	failing.Store(true)
	s.Update(context.Background())
	for _, ip := range []string{"5.5.5.9", "6.6.6.6", "7.7.7.7"} {
		assert.True(t, isRisky(s, ip), "entries from failed source must be retained: %s", ip)
	}
}

func TestUpdate_EmptyResponseTreatedAsFailure(t *testing.T) {
	var empty atomic.Bool
	srv := textServer(func() (int, string) {
		if empty.Load() {
			// 例如被限流后返回的 HTML 页面：200 但没有任何合法条目
			return http.StatusOK, "<html>rate limited</html>\n"
		}
		return http.StatusOK, "8.8.8.0/24\n"
	})
	defer srv.Close()
	s := newTestStore(srv.URL)

	s.Update(context.Background())
	empty.Store(true)
	s.Update(context.Background())
	assert.True(t, isRisky(s, "8.8.8.8"), "an empty response must not wipe previous data")
}

func TestUpdate_ReadinessAndAllSourcesDown(t *testing.T) {
	down := textServer(func() (int, string) { return http.StatusServiceUnavailable, "down" })
	defer down.Close()
	s := newTestStore(down.URL)
	s.Replace([]Entry{{Value: "9.9.9.9", Source: "previous"}})

	s.Update(context.Background())
	assert.False(t, s.Ready(), "not ready while no source has ever succeeded")
	assert.True(t, isRisky(s, "9.9.9.9"), "existing data must not be replaced when every source fails")
	assert.Equal(t, 1, s.Stats().FetchFailures)
	assert.Equal(t, 2, s.Stats().FetchAttempts)
}

func TestUpdate_ConditionalRequests(t *testing.T) {
	var etag atomic.Value
	etag.Store(`"v1"`)
	var body atomic.Value
	body.Store("5.5.5.0/24\n")
	var full, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := etag.Load().(string)
		if r.Header.Get("If-None-Match") == current {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", current)
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	s := newTestStore(srv.URL)

	// 首轮没有校验值：全量抓取
	s.Update(context.Background())
	assert.Equal(t, int32(1), full.Load())
	assert.True(t, isRisky(s, "5.5.5.9"))

	// 源未变化：304，沿用上次数据，且不计为失败
	s.Update(context.Background())
	assert.Equal(t, int32(1), full.Load())
	assert.Equal(t, int32(1), notModified.Load())
	assert.True(t, isRisky(s, "5.5.5.9"))
	assert.Equal(t, 0, s.Stats().FetchFailures)
	assert.Equal(t, 1, s.Stats().FetchAttempts)

	// 清空后即使源返回 304 也要把表重建回来
	s.Clear()
	s.Update(context.Background())
	assert.Equal(t, int32(2), notModified.Load())
	assert.True(t, isRisky(s, "5.5.5.9"), "table must be rebuilt after Clear even when the source is unchanged")

	// 源变化：重新全量抓取并替换旧数据
	etag.Store(`"v2"`)
	body.Store("6.6.6.0/24\n")
	s.Update(context.Background())
	assert.Equal(t, int32(2), full.Load())
	assert.True(t, isRisky(s, "6.6.6.9"))
	assert.False(t, isRisky(s, "5.5.5.9"))
}

func TestFetchFeed_UnsolicitedNotModifiedIsError(t *testing.T) {
	srv := textServer(func() (int, string) { return http.StatusNotModified, "" })
	defer srv.Close()
	s := newTestStore()
	_, err := s.fetchFeed(context.Background(), Feed{ID: "x", URL: srv.URL}, validator{})
	assert.Error(t, err, "304 without a conditional request leaves no data to reuse")
}

func TestUpdate_LaterSourceWinsForDuplicatePrefix(t *testing.T) {
	a := textServer(func() (int, string) { return http.StatusOK, "1.2.3.0/24\n" })
	defer a.Close()
	b := textServer(func() (int, string) { return http.StatusOK, "1.2.3.0/24\n" })
	defer b.Close()
	s := newTestStore(a.URL, b.URL)
	for range 3 {
		s.Update(context.Background())
		source, _ := s.Lookup("1.2.3.4")
		assert.Equal(t, "feed-b", source, "label must be deterministic regardless of fetch completion order")
	}
}

func TestParseText_TruncatedBodyIsError(t *testing.T) {
	s := newTestStore()
	body := io.MultiReader(strings.NewReader("1.1.1.1\n2.2.2.2\n"), iotest.ErrReader(errors.New("connection reset")))
	_, err := s.parseText(body, "test")
	assert.Error(t, err)
}

func entryValues(entries []Entry) []string {
	var got []string
	for _, e := range entries {
		got = append(got, e.Value)
	}
	return got
}

func TestParseText_Formats(t *testing.T) {
	s := newTestStore()
	body := strings.NewReader("# c\n; c\n\nExitAddress 1.2.3.4 2026-01-01 00:00:00\n10.0.0.0/8\nnot-an-ip\n2001:db8::1\n")
	entries, err := s.parseText(body, "src")
	assert.NoError(t, err)
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1"}, entryValues(entries))
	for _, e := range entries {
		assert.Equal(t, "src", e.Source)
	}
}

func TestParseText_InlineComments(t *testing.T) {
	s := newTestStore()
	body := strings.NewReader(
		"; Spamhaus DROP List\n" +
			"1.10.16.0/20 ; SBL256894\n" +
			"77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073\n" +
			"ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n")
	entries, err := s.parseText(body, "src")
	assert.NoError(t, err)
	assert.Equal(t, []string{"1.10.16.0/20", "77.91.122.9"}, entryValues(entries))
}

func TestParseRSS_IPFromTitle(t *testing.T) {
	s := newTestStore()
	body := strings.NewReader(`<rss version="2.0"><channel>
<item><title>34.178.149.189 | SD</title><description>Event: Bad Event | Total: 26</description></item>
<item><title>2001:db8::5 | H</title><description>x</description></item>
<item><title>garbage | SD</title><description>y</description></item>
</channel></rss>`)
	entries, err := s.parseRSS(body, "honeypot")
	assert.NoError(t, err)
	assert.Equal(t, []string{"34.178.149.189", "2001:db8::5"}, entryValues(entries))
}

func TestStats_Classify(t *testing.T) {
	var st Stats
	st.classify("1.2.3.4")
	st.classify("1.2.3.0/24")
	st.classify("2002::/16")
	st.classify("garbage")
	snap := st.Snapshot()
	assert.Equal(t, 1, snap.ParsedIPs)
	assert.Equal(t, 2, snap.ParsedCIDRs)
	assert.Equal(t, 1, snap.SpecialRanges)
}

func TestRun_StopsOnCancel(t *testing.T) {
	srv := textServer(func() (int, string) { return http.StatusOK, "1.2.3.4\n" })
	defer srv.Close()
	s := newTestStore(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx, time.Hour)
		close(done)
	}()
	assert.Eventually(t, s.Ready, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updater did not stop after context cancellation")
	}
}

func TestFetchFeed_CancelDuringRetryBackoff(t *testing.T) {
	srv := textServer(func() (int, string) { return http.StatusInternalServerError, "down" })
	defer srv.Close()
	s := NewStore(nil, FetchConfig{Timeout: 2 * time.Second, Retries: 3, RetryDelay: 10 * time.Second}, discardLog())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := s.fetchFeed(ctx, Feed{ID: "x", URL: srv.URL}, validator{})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 2*time.Second, "retry backoff must be interruptible")
}

func TestStore_RemoveAndClear(t *testing.T) {
	s := newTestStore()
	s.Replace([]Entry{{Value: "1.2.3.0/24", Source: "a"}, {Value: "4.5.6.7", Source: "b"}})
	assert.True(t, s.Remove("1.2.3.0/24"))
	assert.False(t, s.Remove("1.2.3.0/24"))
	assert.False(t, isRisky(s, "1.2.3.4"))
	assert.True(t, isRisky(s, "4.5.6.7"))
	s.Clear()
	assert.Equal(t, 0, s.Snapshot().Len())
}

func TestStore_ConcurrentReadsDuringWrites(t *testing.T) {
	s := newTestStore()
	s.Replace([]Entry{{Value: "1.2.3.0/24", Source: "a"}})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Lookup("1.2.3.4")
				}
			}
		}()
	}
	for range 50 {
		s.Replace([]Entry{{Value: "1.2.3.0/24", Source: "b"}})
		s.Remove("1.2.3.0/24")
	}
	close(stop)
	wg.Wait()
}

func TestDefaultFeeds_UniqueIDsAndURLs(t *testing.T) {
	ids, urls := map[string]bool{}, map[string]bool{}
	for _, f := range DefaultFeeds {
		assert.False(t, ids[f.ID], "duplicate id %s", f.ID)
		assert.False(t, urls[f.URL], "duplicate url %s", f.URL)
		ids[f.ID], urls[f.URL] = true, true
	}
	assert.Len(t, DefaultFeeds, 24)
}
