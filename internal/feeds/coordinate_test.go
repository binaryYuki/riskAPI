package feeds

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memCoordinator 内存实现，模拟多个实例共用的 Redis
type memCoordinator struct {
	mu        sync.Mutex
	data      []byte
	published time.Time
	claimed   time.Time // 抓取权到期时间
	err       error     // 非 nil 时所有操作返回该错误
	claims    int
}

func (m *memCoordinator) SnapshotTime(context.Context) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.published, m.err
}

func (m *memCoordinator) LoadSnapshot(context.Context) ([]byte, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data, m.published, m.err
}

func (m *memCoordinator) PublishSnapshot(_ context.Context, data []byte, published time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.data, m.published = data, published
	return nil
}

func (m *memCoordinator) Claim(_ context.Context, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	m.claims++
	if time.Now().Before(m.claimed) {
		return false, nil
	}
	m.claimed = time.Now().Add(ttl)
	return true, nil
}

// countingServer 返回固定内容并统计请求次数
func countingServer(t *testing.T, body string) (url string, hits *atomic.Int64) {
	hits = new(atomic.Int64)
	srv := textServer(func() (int, string) {
		hits.Add(1)
		return http.StatusOK, body
	})
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

func sharedStore(coord Coordinator, url string) *Store {
	s := NewStore([]Feed{{ID: "proxy", URL: url, Tags: TagProxy}}, fastFetch, discardLog())
	s.SetCoordinator(coord)
	return s
}

func TestShared_OnlyOneInstanceFetches(t *testing.T) {
	url, hits := countingServer(t, "1.2.3.4\n10.20.0.0/16\n")
	coord := &memCoordinator{}
	ctx := context.Background()

	leader, follower := sharedStore(coord, url), sharedStore(coord, url)
	var lst, fst syncState
	leader.syncShared(ctx, time.Hour, &lst)
	follower.syncShared(ctx, time.Hour, &fst)

	assert.Equal(t, int64(1), hits.Load(), "follower must not fetch upstream")
	assert.True(t, follower.Ready())
	assert.True(t, isRisky(follower, "1.2.3.4"))
	assert.True(t, isRisky(follower, "10.20.1.1"))
	assert.Equal(t, TagProxy, follower.Tags("1.2.3.4"), "tags follow the local feed config")
	assert.Equal(t, 2, follower.Stats().TotalLines, "stats come from the fetching instance")

	// 快照未过期：后续同步不再抓取，也不争抢
	claims := coord.claims
	leader.syncShared(ctx, time.Hour, &lst)
	follower.syncShared(ctx, time.Hour, &fst)
	assert.Equal(t, int64(1), hits.Load())
	assert.Equal(t, claims, coord.claims)
}

func TestShared_StaleSnapshotIsLoadedThenRefreshed(t *testing.T) {
	url, hits := countingServer(t, "5.6.7.8\n")
	coord := &memCoordinator{}
	ctx := context.Background()

	old := sharedStore(coord, url)
	var ost syncState
	old.syncShared(ctx, time.Hour, &ost)
	coord.published = coord.published.Add(-2 * time.Hour)
	coord.claimed = time.Time{}

	// 新实例：先用旧快照立即就绪，再因快照过期抢到抓取权并刷新
	fresh := sharedStore(coord, url)
	var st syncState
	fresh.syncShared(ctx, time.Hour, &st)
	assert.True(t, fresh.Ready())
	assert.Equal(t, int64(2), hits.Load())
	assert.WithinDuration(t, time.Now(), coord.published, time.Minute)
}

func TestShared_ClaimHeldWaitsForSnapshot(t *testing.T) {
	url, hits := countingServer(t, "5.6.7.8\n")
	coord := &memCoordinator{claimed: time.Now().Add(time.Minute)} // 另一个实例正在抓取
	s := sharedStore(coord, url)
	var st syncState
	s.syncShared(context.Background(), time.Hour, &st)
	assert.Zero(t, hits.Load())
	assert.False(t, s.Ready())
}

func TestShared_InvalidSnapshotTriggersFetch(t *testing.T) {
	url, hits := countingServer(t, "5.6.7.8\n")
	coord := &memCoordinator{data: []byte("not gzip"), published: time.Now()}
	s := sharedStore(coord, url)
	var st syncState
	s.syncShared(context.Background(), time.Hour, &st)
	assert.Equal(t, int64(1), hits.Load())
	assert.True(t, s.Ready())

	snap, err := decodeSnapshot(coord.data)
	require.NoError(t, err, "a valid snapshot replaces the invalid one")
	assert.Equal(t, []string{"5.6.7.8"}, snap.Feeds["proxy"])
}

func TestShared_RedisDownFetchesLocallyOncePerInterval(t *testing.T) {
	url, hits := countingServer(t, "5.6.7.8\n")
	coord := &memCoordinator{err: errors.New("connection refused")}
	s := sharedStore(coord, url)
	var st syncState
	ctx := context.Background()

	s.syncShared(ctx, time.Hour, &st)
	assert.True(t, s.Ready())
	s.syncShared(ctx, time.Hour, &st)
	assert.Equal(t, int64(1), hits.Load(), "local fallback respects the update interval")

	// Redis 恢复后：没有快照，争抢并发布
	coord.err = nil
	s.syncShared(ctx, time.Hour, &st)
	assert.Equal(t, int64(2), hits.Load())
	assert.NotNil(t, coord.data)
}

func TestShared_FailedFetchDoesNotPublish(t *testing.T) {
	down := textServer(func() (int, string) { return http.StatusServiceUnavailable, "down" })
	defer down.Close()
	coord := &memCoordinator{}
	s := sharedStore(coord, down.URL)
	var st syncState
	s.syncShared(context.Background(), time.Hour, &st)
	assert.Nil(t, coord.data)
	assert.False(t, s.Ready())
}

func TestSnapshot_RoundTripIgnoresUnknownFeeds(t *testing.T) {
	url, _ := countingServer(t, "1.1.1.0/24\n")
	src := NewStore([]Feed{{ID: "a", URL: url}, {ID: "b", URL: url}}, fastFetch, discardLog())
	require.True(t, src.Update(context.Background()))
	data, err := src.encodeSnapshot()
	require.NoError(t, err)

	snap, err := decodeSnapshot(data)
	require.NoError(t, err)
	dst := NewStore([]Feed{{ID: "b"}}, fastFetch, discardLog())
	require.True(t, dst.applySnapshot(snap))
	source, ok := dst.Lookup("1.1.1.1")
	assert.True(t, ok)
	assert.Equal(t, "b", source)

	none := NewStore([]Feed{{ID: "c"}}, fastFetch, discardLog())
	assert.False(t, none.applySnapshot(snap))
}

func TestShared_RunStopsOnCancel(t *testing.T) {
	url, _ := countingServer(t, "1.2.3.4\n")
	s := sharedStore(&memCoordinator{}, url)
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
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}
