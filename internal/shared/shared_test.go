package shared

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func newTestClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := Open(context.Background(), "redis://"+mr.Addr(), "test:", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func TestOpen_InvalidURL(t *testing.T) {
	_, err := Open(context.Background(), "http://example.com", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Error(t, err)
}

func TestOpen_UnreachableDoesNotFail(t *testing.T) {
	c, err := Open(context.Background(), "redis://127.0.0.1:1", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	_ = c.Close()
}

func TestCache_GetSetDeleteFlush(t *testing.T) {
	c, mr := newTestClient(t)
	ctx := context.Background()
	k := c.Cache("info")

	v, ttl, err := k.Get(ctx, "1.1.1.1")
	require.NoError(t, err)
	assert.Nil(t, v)
	assert.Zero(t, ttl)

	require.NoError(t, k.Set(ctx, "1.1.1.1", []byte(`{"a":1}`), time.Hour))
	require.NoError(t, k.Set(ctx, "2.2.2.2", []byte(`{"b":2}`), time.Hour))
	assert.True(t, mr.Exists("test:cache:info:1.1.1.1"))

	v, ttl, err = k.Get(ctx, "1.1.1.1")
	require.NoError(t, err)
	assert.Equal(t, `{"a":1}`, string(v))
	assert.InDelta(t, time.Hour, ttl, float64(time.Second))

	require.NoError(t, k.Delete(ctx, "1.1.1.1"))
	v, _, _ = k.Get(ctx, "1.1.1.1")
	assert.Nil(t, v)

	// Flush 只删除本命名空间
	require.NoError(t, mr.Set("test:other", "keep"))
	n, err := k.Flush(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.True(t, mr.Exists("test:other"))
}

func TestCache_SetRequiresTTL(t *testing.T) {
	c, _ := newTestClient(t)
	assert.Error(t, c.Cache("info").Set(context.Background(), "k", []byte("v"), 0))
}

func TestCache_ExpiredIsMiss(t *testing.T) {
	c, mr := newTestClient(t)
	ctx := context.Background()
	k := c.Cache("info")
	require.NoError(t, k.Set(ctx, "k", []byte("v"), time.Minute))
	mr.FastForward(2 * time.Minute)
	v, _, err := k.Get(ctx, "k")
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestCache_RedisDownReturnsError(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	_, _, err := c.Cache("info").Get(context.Background(), "k")
	assert.Error(t, err)
}

func TestCache_CoolsDownAfterFailure(t *testing.T) {
	c, mr := newTestClient(t)
	k := c.Cache("info")
	mr.Close()
	_, _, err := k.Get(context.Background(), "k")
	require.Error(t, err)

	// 冷却期内不再访问 Redis，立即返回
	start := time.Now()
	_, _, err = k.Get(context.Background(), "k")
	assert.ErrorIs(t, err, errUnavailable)
	assert.ErrorIs(t, k.Set(context.Background(), "k", []byte("v"), time.Minute), errUnavailable)
	assert.Less(t, time.Since(start), 10*time.Millisecond)

	// 冷却期结束后重新探测，Redis 恢复即可用
	require.NoError(t, mr.Restart())
	k.health.retryAt.Store(time.Now().UnixNano())
	require.NoError(t, k.Set(context.Background(), "k", []byte("v"), time.Minute))
	assert.False(t, k.health.degraded.Load())
}

func TestRateLimiter_SharedAcrossClients(t *testing.T) {
	mr := miniredis.RunT(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	// 两个实例共享 10 次/秒（间隔 100ms）
	var limiters []*RateLimiter
	for range 2 {
		c, err := Open(ctx, "redis://"+mr.Addr(), "test:", log)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		limiters = append(limiters, c.RateLimiter("ipsb", 10, rate.NewLimiter(rate.Inf, 1)))
	}

	start := time.Now()
	for i := range 4 {
		require.NoError(t, limiters[i%2].Wait(ctx))
	}
	// 4 次请求合计至少间隔 3 × 100ms；各自限速时只需约 100ms
	assert.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond)
}

func TestRateLimiter_DeadlineExceeded(t *testing.T) {
	c, _ := newTestClient(t)
	l := c.RateLimiter("ipsb", 1, rate.NewLimiter(rate.Inf, 1))
	require.NoError(t, l.Wait(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	assert.Error(t, l.Wait(ctx))
	assert.Less(t, time.Since(start), 50*time.Millisecond, "should fail fast instead of waiting")
}

func TestRateLimiter_FallbackWhenRedisDown(t *testing.T) {
	c, mr := newTestClient(t)
	fallback := rate.NewLimiter(rate.Inf, 1)
	l := c.RateLimiter("ipsb", 1, fallback)
	mr.Close()
	// Redis 不可用时使用本地限速器（此处不限速），不会报错
	for range 3 {
		assert.NoError(t, l.Wait(context.Background()))
	}
}

func TestSnapshots_PublishLoadClaim(t *testing.T) {
	c, mr := newTestClient(t)
	ctx := context.Background()
	s := c.Snapshots("feeds")

	ts, err := s.SnapshotTime(ctx)
	require.NoError(t, err)
	assert.True(t, ts.IsZero())
	data, _, err := s.LoadSnapshot(ctx)
	require.NoError(t, err)
	assert.Nil(t, data)

	published := time.UnixMilli(time.Now().UnixMilli())
	require.NoError(t, s.PublishSnapshot(ctx, []byte("payload\x00binary"), published))
	ts, err = s.SnapshotTime(ctx)
	require.NoError(t, err)
	assert.True(t, published.Equal(ts))
	data, ts, err = s.LoadSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, "payload\x00binary", string(data))
	assert.True(t, published.Equal(ts))

	won, err := s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.True(t, won)
	won, err = s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.False(t, won, "claim is held until ttl expires")
	mr.FastForward(2 * time.Minute)
	won, err = s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.True(t, won)
}
