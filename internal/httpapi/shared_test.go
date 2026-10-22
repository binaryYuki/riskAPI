package httpapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memSharedCache 内存实现，模拟多个实例共用的 Redis
type memSharedCache struct {
	mu   sync.Mutex
	data map[string][]byte
	ttl  map[string]time.Duration
}

func newMemSharedCache() *memSharedCache {
	return &memSharedCache{data: map[string][]byte{}, ttl: map[string]time.Duration{}}
}

func (m *memSharedCache) Get(_ context.Context, key string) ([]byte, time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data[key], m.ttl[key], nil
}

func (m *memSharedCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key], m.ttl[key] = value, ttl
	return nil
}

func (m *memSharedCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memSharedCache) Flush(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.data)
	m.data = map[string][]byte{}
	return n, nil
}

func TestSharedInfoCache_HitFromOtherInstance(t *testing.T) {
	sc := newMemSharedCache()
	// 其它实例写入的结果，含超出 float64 精度的整数
	require.NoError(t, sc.Set(context.Background(), "1.0.0.1", []byte(`{"ipsb":{"asn":13335,"id":9007199254740993}}`), 10*time.Minute))

	env := newTestEnv(t)
	env.server.shared = sc
	w := env.do(http.MethodGet, "/api/v1/info/1.0.0.1")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "HIT", w.Header().Get("X-Catyuki-Cache"))
	assert.Contains(t, w.Body.String(), `"asn": 13335`)
	assert.Contains(t, w.Body.String(), `"id": 9007199254740993`)

	_, found := env.cache.Get(infoCachePrefix + "1.0.0.1")
	assert.True(t, found, "shared hit is stored in the local cache")
}

func TestSharedInfoCache_MissIsShared(t *testing.T) {
	if _, err := os.Stat(filepath.Join(testProvidersDir, "maxmind", "GeoLite2-Country.mmdb")); err != nil {
		t.Skip("geo databases not present; run ./scripts/fetch-geo-data.sh")
	}
	sc := newMemSharedCache()
	a, b := newTestEnv(t), newTestEnv(t)
	a.server.shared, b.server.shared = sc, sc

	w1 := a.do(http.MethodGet, "/api/v1/info/8.8.8.8")
	assert.Equal(t, "MISS", w1.Header().Get("X-Catyuki-Cache"))
	raw, ttl, _ := sc.Get(context.Background(), "8.8.8.8")
	require.NotNil(t, raw)
	assert.Positive(t, ttl)

	w2 := b.do(http.MethodGet, "/api/v1/info/8.8.8.8")
	assert.Equal(t, "HIT", w2.Header().Get("X-Catyuki-Cache"))
	assert.Equal(t, strings.TrimSpace(w1.Body.String()), strings.TrimSpace(w2.Body.String()))
}

func TestSharedInfoCache_Flush(t *testing.T) {
	sc := newMemSharedCache()
	ctx := context.Background()
	_ = sc.Set(ctx, "1.1.1.1", []byte(`{}`), time.Hour)
	_ = sc.Set(ctx, "2.2.2.2", []byte(`{}`), time.Hour)
	env := newTestEnv(t)
	env.server.shared = sc

	env.do(http.MethodPost, "/api/cache/flush/info/1.1.1.1", asAdmin())
	raw, _, _ := sc.Get(ctx, "1.1.1.1")
	assert.Nil(t, raw)
	raw, _, _ = sc.Get(ctx, "2.2.2.2")
	assert.NotNil(t, raw)

	w := env.do(http.MethodPost, "/api/cache/flush/info/all", asAdmin())
	assert.Contains(t, w.Body.String(), `"flushed_shared_info": 1`)
	raw, _, _ = sc.Get(ctx, "2.2.2.2")
	assert.Nil(t, raw)
}
