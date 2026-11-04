package feeds

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 可信源只进入可信表，不影响风险表与标记表；风险表照常保留同一网段（判定时由 httpapi 让可信优先）
func TestUpdate_TrustedFeedOnlyEntersTrustedTable(t *testing.T) {
	dc := textServer(func() (int, string) { return http.StatusOK, "66.249.0.0/16\n" })
	defer dc.Close()
	bot := textServer(func() (int, string) { return http.StatusOK, "66.249.66.0/27\n2001:4860:4801:10::/64\n" })
	defer bot.Close()
	s := NewStore([]Feed{
		{ID: "dc", URL: dc.URL, Tags: TagIDC},
		{ID: "googlebot", URL: bot.URL, Trusted: true, Tags: TagProxy}, // Tags 对可信源不生效
	}, fastFetch, discardLog())
	require.True(t, s.Update(context.Background()))

	for _, ip := range []string{"66.249.66.1", "2001:4860:4801:10::1"} {
		source, ok := s.Trusted(ip)
		assert.True(t, ok, ip)
		assert.Equal(t, "googlebot", source, ip)
	}
	_, ok := s.Trusted("66.249.67.1")
	assert.False(t, ok)
	assert.Equal(t, 2, s.TrustedLen())

	source, ok := s.Lookup("66.249.66.1")
	assert.True(t, ok)
	assert.Equal(t, "dc", source)
	assert.Equal(t, TagIDC, s.Tags("66.249.66.1"))
	_, ok = s.Lookup("2001:4860:4801:10::1")
	assert.False(t, ok, "trusted feed must not enter the risk table")

	// 管理端按条删除只针对风险表，不会误删可信网段
	s.Remove("66.249.66.0/27")
	_, ok = s.Trusted("66.249.66.1")
	assert.True(t, ok)
}

// 过宽前缀或条目过多视为源被篡改：整源拒收，沿用上次数据
func TestUpdate_TrustedFeedRejectsSuspiciousData(t *testing.T) {
	var body atomic.Value
	body.Store("66.249.66.0/27\n")
	srv := textServer(func() (int, string) { return http.StatusOK, body.Load().(string) })
	defer srv.Close()
	s := NewStore([]Feed{{ID: "googlebot", URL: srv.URL, Trusted: true}}, fastFetch, discardLog())
	require.True(t, s.Update(context.Background()))

	var many strings.Builder
	for i := range trustedMaxEntries + 1 {
		fmt.Fprintf(&many, "10.%d.%d.1\n", i/256, i%256)
	}
	for name, bad := range map[string]string{
		"broad v4": "66.249.66.0/27\n0.0.0.0/1\n",
		"broad v6": "2001:4860::/32\n",
		"too many": many.String(),
		"empty":    "# nothing\n",
	} {
		body.Store(bad)
		s.Update(context.Background())
		_, ok := s.Trusted("66.249.66.1")
		assert.True(t, ok, "%s: last good data must be kept", name)
		_, ok = s.Trusted("1.2.3.4")
		assert.False(t, ok, "%s: rejected data must not be applied", name)
		assert.Equal(t, 1, s.TrustedLen(), name)
	}

	// 边界：/20 与 /48 恰好允许
	body.Store("1.2.0.0/20\n2001:db8:1::/48\n")
	s.Update(context.Background())
	_, ok := s.Trusted("1.2.3.4")
	assert.True(t, ok)
}

// 集群快照携带可信源，加载方同样得到可信表
func TestSnapshot_CarriesTrustedFeeds(t *testing.T) {
	url, _ := countingServer(t, "66.249.66.0/27\n")
	feeds := []Feed{{ID: "googlebot", URL: url, Trusted: true}}
	src := NewStore(feeds, fastFetch, discardLog())
	require.True(t, src.Update(context.Background()))
	data, err := src.encodeSnapshot()
	require.NoError(t, err)
	snap, err := decodeSnapshot(data)
	require.NoError(t, err)

	dst := NewStore(feeds, fastFetch, discardLog())
	require.True(t, dst.applySnapshot(snap))
	source, ok := dst.Trusted("66.249.66.1")
	assert.True(t, ok)
	assert.Equal(t, "googlebot", source)
	_, ok = dst.Lookup("66.249.66.1")
	assert.False(t, ok)
}

func TestDefaultFeeds_TrustedFeedsAreTextOnly(t *testing.T) {
	n := 0
	for _, f := range DefaultFeeds {
		if !f.Trusted {
			continue
		}
		n++
		assert.Equal(t, FormatText, f.Format, f.ID)
		assert.Zero(t, f.Tags, f.ID)
		assert.True(t, strings.HasPrefix(f.URL, trustedListBase), f.ID)
	}
	assert.Equal(t, 16, n)
}
