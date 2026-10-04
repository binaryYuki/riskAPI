package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestPrefixSet_LongestPrefixMatch(t *testing.T) {
	s := newPrefixSet()
	s.insert("10.0.0.0/8", "wide")
	s.insert("10.1.0.0/16", "narrow")
	s.insert("10.1.2.3", "single")

	cases := map[string]string{
		"10.9.9.9": "wide",
		"10.1.9.9": "narrow",
		"10.1.2.3": "single",
	}
	for ip, want := range cases {
		got, ok := s.lookup(ip)
		assert.True(t, ok, ip)
		assert.Equal(t, want, got, ip)
	}
	_, ok := s.lookup("11.0.0.1")
	assert.False(t, ok)
}

func TestPrefixSet_IPv4MappedAndIPv6(t *testing.T) {
	s := newPrefixSet()
	s.insert("1.2.3.0/24", "v4")
	s.insert("2001:db8:1::/48", "v6")

	got, ok := s.lookup("::ffff:1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, "v4", got)

	got, ok = s.lookup("2001:db8:1:2::1")
	assert.True(t, ok)
	assert.Equal(t, "v6", got)

	// 非规范 CIDR（主机位不为 0）按网络地址处理
	s.insert("5.6.7.8/24", "noncanonical")
	got, ok = s.lookup("5.6.7.200")
	assert.True(t, ok)
	assert.Equal(t, "noncanonical", got)
}

func TestPrefixSet_InvalidInput(t *testing.T) {
	s := newPrefixSet()
	assert.False(t, s.insert("not-an-ip", "x"))
	assert.False(t, s.insert("1.2.3.0/33", "x"))
	_, ok := s.lookup("not-an-ip")
	assert.False(t, ok)

	var nilSet *prefixSet
	_, ok = nilSet.lookup("1.2.3.4")
	assert.False(t, ok, "nil set must be safe before initialization")
}

func TestPrefixSet_InsertIfAbsentKeepsFirst(t *testing.T) {
	s := newPrefixSet()
	s.insertIfAbsent("1.2.3.0/24", "first")
	s.insertIfAbsent("1.2.3.0/24", "second")
	got, _ := s.lookup("1.2.3.4")
	assert.Equal(t, "first", got)
}

func TestPrefixSet_WithoutIsCopyOnWrite(t *testing.T) {
	s := newPrefixSet()
	s.insert("1.2.3.0/24", "a")
	s.insert("4.5.6.7", "b")

	next, removed := s.without("1.2.3.0/24")
	assert.True(t, removed)
	_, ok := next.lookup("1.2.3.4")
	assert.False(t, ok)
	_, ok = s.lookup("1.2.3.4")
	assert.True(t, ok, "original set must stay unchanged for concurrent readers")

	_, removed = next.without("9.9.9.0/24")
	assert.False(t, removed)
}

func TestRiskySet_ConcurrentReadsDuringReplace(t *testing.T) {
	setRiskyEntries(map[string]string{"1.2.3.0/24": "a"})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					isRiskyIP("1.2.3.4")
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		processIPAssociations([]IPAssociation{{Entry: "1.2.3.0/24", Reason: "b"}})
		removeRiskEntry("1.2.3.0/24")
	}
	close(stop)
	wg.Wait()
}

func TestIsBogonOrPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":               true,
		"192.168.0.1":            true,
		"127.0.0.1":              true,
		"100.64.1.1":             true,
		"203.0.113.9":            true,
		"255.255.255.255":        true,
		"::ffff:192.168.1.1":     true, // IPv4-mapped 按 IPv4 处理
		"::1":                    true,
		"fe80::1":                true,
		"fd00::1":                true,
		"2001:db8::1":            true,
		"8.8.8.8":                false,
		"2001:4860:4860::8888":   false,
		"2002::1":                false, // 6to4 保持透明
		"not-an-ip":              false,
		"::ffff:8.8.8.8":         false,
		"172.32.0.1":             false,
		"2001:0:4136:e378::1234": false, // Teredo 保持透明
	}
	for ip, want := range cases {
		assert.Equal(t, want, isBogonOrPrivateIP(ip), ip)
	}
}

func TestClassifyAndCount(t *testing.T) {
	metricsReset()
	classifyAndCount("1.2.3.4")
	classifyAndCount("1.2.3.0/24")
	classifyAndCount("2002::/16")
	classifyAndCount("garbage")
	snap := getMetricsSnapshot()
	assert.Equal(t, 1, snap.ParsedIPs)
	assert.Equal(t, 2, snap.ParsedCIDRs)
	assert.Equal(t, 1, snap.SpecialRanges)
}

func TestRadixCache_SetWithTTL(t *testing.T) {
	c := NewBoundedRadixCache(10, time.Hour)
	c.SetWithTTL("short", 1, 20*time.Millisecond)
	c.Set("long", 2)
	time.Sleep(40 * time.Millisecond)
	_, ok := c.Get("short")
	assert.False(t, ok)
	_, ok = c.Get("long")
	assert.True(t, ok)
}

func TestMMDBReaderIsReused(t *testing.T) {
	const db = "providers/maxmind/GeoLite2-Country.mmdb"
	if !statOk(db) {
		t.Skip("mmdb not present")
	}
	r1, err := mmdbReader(db)
	assert.NoError(t, err)
	r2, err := mmdbReader(db)
	assert.NoError(t, err)
	assert.Same(t, r1, r2)

	_, err = lookupGeneric(db, net.ParseIP("8.8.8.8"))
	assert.NoError(t, err)

	_, err = mmdbReader("providers/does-not-exist.mmdb")
	assert.ErrorIs(t, err, errMMDBUnavailable)
}

func TestExportCIDRsHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setRiskyEntries(map[string]string{
		"1.2.3.0/24": "src-a",
		"5.6.7.8":    "src-single", // 单 IP 不导出
		"9.9.0.0/16": "",
	})
	r := gin.New()
	r.GET("/api/export", exportCIDRsHandler)
	req, _ := http.NewRequest(http.MethodGet, "/api/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	lines := strings.Split(w.Body.String(), "\n")
	assert.Equal(t, []string{"1.2.3.0/24 # src-a", "9.9.0.0/16 # unknown"}, lines)
	assert.Equal(t, "2", w.Header().Get("X-Total-Count"))
}
