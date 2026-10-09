package honeytrap

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testScorer(mutate ...func(*scoreConfig)) *scorer {
	cfg := scoreConfig{
		flagThreshold:  8,
		blockThreshold: 16,
		leakPerSec:     16.0 / 60, // 60 秒漏空一个封禁阈值
		flagDuration:   time.Hour,
		blockDuration:  3 * time.Minute,
		idle:           time.Minute,
		maxSources:     100,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return newScorer(cfg)
}

func TestSourceKey(t *testing.T) {
	key := func(ip string) string {
		k, ok := sourceKey(ip)
		assert.True(t, ok, ip)
		return k.String()
	}
	assert.Equal(t, "8.8.8.8", key("8.8.8.8"))
	assert.Equal(t, "8.8.8.8", key("::ffff:8.8.8.8"), "IPv4-mapped addresses are scored as IPv4")
	assert.Equal(t, "2001:db8:1:2::", key("2001:db8:1:2:3:4:5:6"))
	assert.Equal(t, key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::1"))
	assert.NotEqual(t, key("2001:db8:1:2::1"), key("2001:db8:1:3::1"))
	_, ok := sourceKey("nope")
	assert.False(t, ok)
}

func TestScorer_DedupesRepeatedPaths(t *testing.T) {
	s := testScorer()
	src := netip.MustParseAddr("8.8.8.8")
	now := time.Now()

	out := s.observe(src, 1, WeightMedium, now)
	assert.Equal(t, 0.0, out.prior)
	assert.Equal(t, 4.0, out.score)

	// 同一路径重复 10 次只加很小的分
	for range 10 {
		out = s.observe(src, 1, WeightMedium, now)
	}
	assert.Equal(t, 6.5, out.score)
	assert.False(t, out.newlyFlagged || out.newlyBlocked)

	// 低权重路径重复时不会反而加得更多
	s.observe(src, 2, 0.1, now)
	assert.InDelta(t, 6.7, s.observe(src, 2, 0.1, now).score, 1e-9)
}

func TestScorer_LeaksOverTime(t *testing.T) {
	s := testScorer()
	src := netip.MustParseAddr("8.8.8.8")
	now := time.Now()

	s.observe(src, 1, WeightMedium, now)
	// 15 秒漏掉 4 分：桶已空，同一路径重新按全额计分
	out := s.observe(src, 1, WeightMedium, now.Add(15*time.Second))
	assert.InDelta(t, 0, out.prior, 1e-9)
	assert.InDelta(t, 4, out.score, 1e-9)

	// 桶未空时路径仍被记住
	out = s.observe(src, 1, WeightMedium, now.Add(20*time.Second))
	assert.InDelta(t, 4-5*16.0/60+repeatWeight, out.score, 1e-9)
}

func TestScorer_FlagThenBlock(t *testing.T) {
	s := testScorer()
	src := netip.MustParseAddr("8.8.8.8")
	now := time.Now()

	out := s.observe(src, 1, WeightHigh, now)
	assert.True(t, out.newlyFlagged)
	assert.False(t, out.newlyBlocked)
	assert.True(t, s.flagged(src, now))

	out = s.observe(src, 2, WeightHigh, now)
	assert.False(t, out.newlyFlagged, "already flagged")
	assert.True(t, out.newlyBlocked)
	assert.Equal(t, now.Add(3*time.Minute), out.blockUntil)

	// 封禁期内不再计分
	out = s.observe(src, 3, WeightHigh, now.Add(time.Minute))
	assert.True(t, out.blocked)
	assert.Equal(t, 16.0, out.score)

	// 封禁结束后分数已漏空，重新开始；标记比封禁保留得更久
	after := now.Add(4 * time.Minute)
	out = s.observe(src, 3, WeightMedium, after)
	assert.False(t, out.blocked)
	assert.Equal(t, 4.0, out.score)
	assert.True(t, s.flagged(src, after))
	assert.False(t, s.flagged(src, now.Add(2*time.Hour)))
	assert.False(t, s.flagged(netip.MustParseAddr("9.9.9.9"), now))
}

func TestScorer_EvictsLeastRecentlyActive(t *testing.T) {
	s := testScorer(func(c *scoreConfig) { c.maxSources = 3 })
	now := time.Now()
	a, b, c, d := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3"), netip.MustParseAddr("4.4.4.4")

	s.observe(a, 1, WeightHigh, now) // 最久未活动，但已被标记
	s.observe(b, 1, WeightLow, now.Add(time.Second))
	s.observe(c, 1, WeightLow, now.Add(2*time.Second))
	s.observe(b, 2, WeightLow, now.Add(3*time.Second)) // b 重新活动，c 成为最久未活动的未标记来源

	s.observe(d, 1, WeightLow, now.Add(4*time.Second))
	tracked, flagged := s.counts(now.Add(4 * time.Second))
	assert.Equal(t, 3, tracked)
	assert.Equal(t, 1, flagged)
	assert.Contains(t, s.sources, a, "flagged sources are kept while an unflagged one can be evicted")
	assert.Contains(t, s.sources, b)
	assert.NotContains(t, s.sources, c)
	assert.Contains(t, s.sources, d)

	// 全部被标记时仍然淘汰最久未活动的记录，保证表不超过上限
	s = testScorer(func(c *scoreConfig) { c.maxSources = 2 })
	s.observe(a, 1, WeightHigh, now)
	s.observe(b, 1, WeightHigh, now.Add(time.Second))
	s.observe(c, 1, WeightHigh, now.Add(2*time.Second))
	assert.Len(t, s.sources, 2)
	assert.NotContains(t, s.sources, a)
}

func TestScorer_Prune(t *testing.T) {
	s := testScorer(func(c *scoreConfig) { c.flagDuration = 10 * time.Minute })
	now := time.Now()
	flagged, idle, active := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3")

	s.observe(flagged, 1, WeightHigh, now)
	s.observe(idle, 1, WeightMedium, now)
	s.observe(active, 1, WeightMedium, now.Add(90*time.Second))

	s.prune(now.Add(2 * time.Minute))
	assert.Contains(t, s.sources, flagged, "kept while flagged")
	assert.NotContains(t, s.sources, idle)
	assert.Contains(t, s.sources, active, "still within the idle window")
	assert.Equal(t, 2, s.lru.Len())

	s.prune(now.Add(time.Hour))
	assert.Empty(t, s.sources)
	assert.Zero(t, s.lru.Len())
}
