package feeds

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"risky_ip_filter/internal/ipset"
)

// 本文件针对"只解析一次、按源打包 feedData"的重构，确认没有引入准确性与安全性问题。
// legacy* 基线实现见 bench_test.go。

// ---- 准确性 ----

// 同一地址的不同写法必须落到同一个前缀上，且不会比源里写的范围更宽
func TestUpdate_EquivalentNotationsResolveToSamePrefix(t *testing.T) {
	srv := textServer(func() (int, string) {
		return http.StatusOK, strings.Join([]string{
			"1.2.3.4", "1.2.3.4/32", "::ffff:1.2.3.4", // 同一个单 IP 的三种写法
			"45.20.30.40/24",                          // 主机位未清零
			"::ffff:9.8.7.0/120",                      // IPv4-mapped CIDR，等价于 9.8.7.0/24
			"2001:DB8:AB::/48",                        // 大写 IPv6
			"2001:0db8:00cd:0000:0000:0000:0000:0001", // 未压缩 IPv6
		}, "\n") + "\n"
	})
	defer srv.Close()
	s := newTestStore(srv.URL)
	s.Update(context.Background())

	assert.Equal(t, 5, s.Snapshot().Len(), "equivalent notations must collapse into one prefix")
	for ip, want := range map[string]bool{
		"1.2.3.4": true, "::ffff:1.2.3.4": true, "1.2.3.5": false,
		"45.20.30.1": true, "45.20.30.255": true, "45.20.31.1": false, "45.20.29.255": false,
		"9.8.7.200": true, "::ffff:9.8.7.200": true, "9.8.8.1": false, "9.8.6.255": false,
		"2001:db8:ab:1::5": true, "2001:db8:ac::1": false,
		"2001:db8:cd::1": true, "2001:db8:cd::2": false,
	} {
		assert.Equal(t, want, isRisky(s, ip), ip)
	}
}

// 解析统计必须与重构前逐项相同（行数、单 IP、CIDR、特殊网段）
func TestStats_MatchLegacyOnCorpus(t *testing.T) {
	special := []byte("2002::1\n2001::/32\n64:ff9b::1.2.3.4\n1.2.3.4/32\n2001:db8::1/128\nfe80::1%eth0\n")
	var legacy Stats
	s := newTestStore()
	for _, body := range append(benchCorpus(), special) {
		_, err := legacyParseText(&legacy, bytes.NewReader(body), "src")
		assert.NoError(t, err)
		_, err = s.parseText(bytes.NewReader(body), false)
		assert.NoError(t, err)
	}
	want := legacy.Snapshot()
	assert.NotZero(t, want.ParsedIPs)
	assert.NotZero(t, want.ParsedCIDRs)
	assert.NotZero(t, want.SpecialRanges)
	assert.Equal(t, want, s.stats.Snapshot())
}

// 校验值必须始终来自当前数据对应的那次响应：
// 失败的轮次不能丢掉它，而数据被一次不带 ETag 的响应替换后，旧的 ETag 不能再被发送
// （否则源恰好回到旧版本时会收到 304，把新数据误当成旧版本继续使用）
func TestUpdate_ValidatorAlwaysBelongsToCurrentData(t *testing.T) {
	var phase atomic.Int32
	var mu sync.Mutex
	var seen []string // 每个请求携带的 If-None-Match
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm := r.Header.Get("If-None-Match")
		mu.Lock()
		seen = append(seen, inm)
		mu.Unlock()
		switch phase.Load() {
		case 0:
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, "5.5.5.0/24\n")
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			if inm == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, "5.5.5.0/24\n")
		default: // 新数据，不带任何校验头
			_, _ = io.WriteString(w, "6.6.6.0/24\n")
		}
	}))
	defer srv.Close()
	s := newTestStore(srv.URL)
	round := func(p int32) []string {
		phase.Store(p)
		mu.Lock()
		seen = nil
		mu.Unlock()
		s.Update(context.Background())
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}

	assert.Equal(t, []string{""}, round(0), "first fetch has no validator")

	assert.Equal(t, []string{`"v1"`, `"v1"`}, round(1), "every retry must stay conditional")
	assert.True(t, isRisky(s, "5.5.5.9"))

	assert.Equal(t, []string{`"v1"`}, round(2), "a failed round must not drop the validator")
	assert.True(t, isRisky(s, "5.5.5.9"))

	assert.Equal(t, []string{`"v1"`}, round(3))
	assert.True(t, isRisky(s, "6.6.6.9"))
	assert.False(t, isRisky(s, "5.5.5.9"))

	assert.Equal(t, []string{""}, round(4), "validator of replaced data must not be reused")
	assert.True(t, isRisky(s, "6.6.6.9"))
}

// ---- 安全性 ----

// 响应读到一半出错时，已经解析出的那部分不能进表，也不能覆盖上一次的完整数据
func TestUpdate_PartialBodyIsNeverPublished(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"connection cut mid-body": func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "4096") // 声明的长度大于实际写出的内容
			_, _ = io.WriteString(w, "6.6.6.6\n7.7.7.0/24\n")
		},
		"oversized line": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, "6.6.6.6\n7.7.7.0/24\n"+strings.Repeat("1", 200_000)+"\n8.8.8.8\n")
		},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			var broken atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if broken.Load() {
					bad(w)
					return
				}
				_, _ = io.WriteString(w, "5.5.5.0/24\n")
			}))
			defer srv.Close()
			s := newTestStore(srv.URL)

			s.Update(context.Background())
			broken.Store(true)
			s.Update(context.Background())

			assert.Equal(t, 1, s.Stats().FetchFailures)
			assert.True(t, isRisky(s, "5.5.5.9"), "previous complete data must be kept")
			for _, ip := range []string{"6.6.6.6", "7.7.7.7", "8.8.8.8"} {
				assert.False(t, isRisky(s, ip), "partially parsed entry leaked into the table: %s", ip)
			}
			assert.Equal(t, 1, s.Snapshot().Len())
		})
	}
}

// 畸形或恶意构造的行必须被拒绝，不能 panic，也不能被解析成别的地址
func TestParseLine_HostileInputsRejected(t *testing.T) {
	s := newTestStore()
	// 首尾空白不在此列：parseText 取 Fields、parseRSS 做 TrimSpace，parseLine 收不到带首尾空白的行
	for _, line := range []string{
		"1.2.3.4/-1", "1.2.3.4/999999999999999999999", "1.2.3.4/3 2", "1.2.3.4//24", "1.2.3.4/24/8",
		"::ffff:1.2.3.4/200", "::ffff:1.2.3.0/64", // IPv4-mapped 掩码短于 96 位无法对应到 IPv4 前缀
		"%", "/%", "1.2.3.4%", "fe80::1%" + strings.Repeat("a", 10_000), "fe80::1%eth0/64",
		"1.2.3.4\x00", "\x001.2.3.4", "1.2.3.4\rx", "1.2.3.4,5.6.7.8", "1.2.3.4 5.6.7.8",
		"１.２.３.４", "1。2。3。4", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "1.2.3", "1.2.3.4.",
		strings.Repeat("1", 1<<20), strings.Repeat("1.", 100_000), strings.Repeat(":", 100_000),
	} {
		d := &feedData{}
		assert.NotPanics(t, func() { s.parseLine(line, d) })
		assert.Empty(t, d.prefixes, "must be rejected: %.40q", line)
		assert.Zero(t, d.cidrs)
	}
}

// 规范化不能把前缀变宽：解析出的掩码长度必须与源里写的一致
func TestParseLine_NeverWidensPrefix(t *testing.T) {
	s := newTestStore()
	for line, want := range map[string]string{
		"1.2.3.4":                "1.2.3.4/32",
		"1.2.3.4/32":             "1.2.3.4/32",
		"1.2.3.4/31":             "1.2.3.4/31",
		"1.2.3.255/24":           "1.2.3.0/24",
		"::ffff:1.2.3.4":         "1.2.3.4/32",
		"::ffff:1.2.3.4/128":     "1.2.3.4/32",
		"::ffff:1.2.3.255/120":   "1.2.3.0/24",
		"::ffff:1.2.3.4/96":      "0.0.0.0/0",
		"2001:db8::1":            "2001:db8::1/128",
		"2001:db8::ffff:ffff/64": "2001:db8::/64",
	} {
		d := &feedData{}
		s.parseLine(line, d)
		if assert.Len(t, d.prefixes, 1, line) {
			assert.Equal(t, netip.MustParsePrefix(want), d.prefixes[0], line)
		}
	}
}

// Update、查询与单条删除并发进行时不能有数据竞争（配合 -race 运行）
func TestStore_ConcurrentUpdateLookupRemove(t *testing.T) {
	srv := textServer(func() (int, string) { return http.StatusOK, "5.5.5.0/24\n6.6.6.6\n" })
	defer srv.Close()
	s := NewStore([]Feed{
		{ID: "a", URL: srv.URL, Tags: TagProxy},
		{ID: "b", URL: srv.URL + "/b", Tags: TagIDC, TagOnly: true},
	}, fastFetch, discardLog())

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
					s.Lookup("5.5.5.9")
					s.Tags("6.6.6.6")
					s.Snapshot().Len()
					s.Stats()
				}
			}
		}()
	}
	for range 20 {
		s.Update(context.Background())
		s.Remove("6.6.6.6")
	}
	close(stop)
	wg.Wait()
	assert.True(t, isRisky(s, "5.5.5.9"))
}

// ---- 整段文本的对照模糊测试 ----

var parseTextSeeds = []string{
	"",
	"# only a comment\n",
	"1.2.3.4\n5.6.7.0/24 ; SBL1\n",
	"ExitAddress 1.2.3.4 2026-01-01 00:00:00\nExitNode ABC\n",
	"77.91.122.9\t\t# 2026-09-29 12:02:10\t\t26\t2855073\n",
	"::ffff:1.2.3.4\n::ffff:1.2.3.0/120\n::ffff:1.2.3.0/64\nfe80::1%eth0\n",
	"1.2.3.4/32\r\n5.6.7.8\r\n",
	"1.2.3.4#x\n#1.2.3.4\n;1.2.3.4\n 1.2.3.4 \n\t5.6.7.8\t\n",
	"<html>rate limited</html>\n",
	"1.2.3.4\x005.6.7.8\n\xff\xfe\n1.2.3.4 5.6.7.8\n",
}

// 整段响应体经新旧两套解析后，得到的前缀序列、CIDR 计数与统计必须完全一致。
//
//	go test -fuzz=FuzzParseText_MatchesLegacy ./internal/feeds
func FuzzParseText_MatchesLegacy(f *testing.F) {
	for _, seed := range parseTextSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var legacyStats Stats
		legacy, legacyErr := legacyParseText(&legacyStats, bytes.NewReader(body), "src")
		s := newTestStore()
		d, err := s.parseText(bytes.NewReader(body), false)
		if !assert.Equal(t, legacyErr == nil, err == nil, "error mismatch: legacy=%v current=%v", legacyErr, err) || err != nil {
			return
		}

		// 重构前能通过校验的条目，只有写入时解析成功的才真正进表
		var want []netip.Prefix
		wantCIDRs := 0
		for _, e := range legacy {
			if p, ok := ipset.ParseEntry(e.Value); ok {
				want = append(want, p)
				if strings.Contains(e.Value, "/") {
					wantCIDRs++
				}
			}
		}
		if assert.Len(t, d.prefixes, len(want)) {
			for i := range want {
				assert.Equal(t, want[i], d.prefixes[i])
			}
		}
		assert.Equal(t, wantCIDRs, d.cidrs)
		assert.Equal(t, legacyStats.Snapshot(), s.stats.Snapshot())
	})
}
