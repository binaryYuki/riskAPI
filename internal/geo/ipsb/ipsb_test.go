package ipsb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func fakeServer(t *testing.T, hits *atomic.Int32) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ip":"1.1.1.1","country_code":"AU","city":"Sydney","latitude":-33.8688,"longitude":151.209}`))
	}))
	t.Cleanup(srv.Close)
	old := baseURL
	baseURL = srv.URL
	t.Cleanup(func() { baseURL = old })
}

func TestQuery(t *testing.T) {
	var hits atomic.Int32
	fakeServer(t, &hits)
	data, err := NewClient(0).Query(context.Background(), "1.1.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "Sydney", data["city"])
	assert.Equal(t, -33.8688, data["latitude"])

	_, err = NewClient(0).Query(context.Background(), "not-an-ip")
	assert.Error(t, err)
}

func TestQueryRateLimited(t *testing.T) {
	var hits atomic.Int32
	fakeServer(t, &hits)
	c := NewClient(5)

	start := time.Now()
	for range 3 {
		_, err := c.Query(context.Background(), "1.1.1.1")
		assert.NoError(t, err)
	}
	// burst=1：第 2、3 次各需等待 200ms
	assert.GreaterOrEqual(t, time.Since(start), 350*time.Millisecond)

	// 截止时间早于下一个配额时立即失败，不发出请求
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Query(ctx, "1.1.1.1")
	assert.Error(t, err)
	assert.Equal(t, int32(3), hits.Load())
}

type wrappedTransport struct{ http.RoundTripper }

// 开启 tracing 时 http.DefaultTransport 被 otelhttp 包装，不再是 *http.Transport
func TestNewClientWithWrappedDefaultTransport(t *testing.T) {
	var hits atomic.Int32
	fakeServer(t, &hits)
	old := http.DefaultTransport
	http.DefaultTransport = wrappedTransport{old}
	t.Cleanup(func() { http.DefaultTransport = old })

	_, err := NewClient(0).Query(context.Background(), "1.1.1.1")
	assert.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load())
}
