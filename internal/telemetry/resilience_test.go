package telemetry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"risky_ip_filter/internal/config"
)

// 上报链路故障不能影响服务本身：以下测试覆盖后端不可达、handler panic、错误刷屏

// unreachableEndpoint 返回一个已关闭端口的地址，连接会立即被拒绝
func unreachableEndpoint(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return "http://" + addr
}

func TestResilience_UnreachableBackend(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", unreachableEndpoint(t))
	var buf bytes.Buffer
	tel := setup(t.Context(), config.Config{LogFormat: "json", LogLevel: "info", OpenTelemetry: true}, "test", &buf)
	require.True(t, tel.Enabled())

	// 远超队列容量的日志与 span：记录必须立即返回（排队或丢弃），不能等网络
	start := time.Now()
	tracer := tel.TracerProvider.Tracer("test")
	for i := range 20000 {
		ctx, span := tracer.Start(context.Background(), "op")
		tel.Log.InfoContext(ctx, "request", "i", i)
		span.End()
	}
	assert.Less(t, time.Since(start), 3*time.Second, "logging must not block on an unreachable backend")

	// stdout 那一路完整保留
	assert.Equal(t, 20000, strings.Count(buf.String(), `"msg":"request"`))

	// 停机有上限，不拖住进程退出
	start = time.Now()
	_ = tel.Shutdown()
	assert.Less(t, time.Since(start), shutdownTimeout+time.Second)
}

type panicHandler struct{ slog.Handler }

func (panicHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (panicHandler) Handle(context.Context, slog.Record) error { panic("exporter bug") }

func TestResilience_HandlerPanicIsContained(t *testing.T) {
	var buf bytes.Buffer
	local := slog.NewJSONHandler(&buf, nil)
	log := slog.New(slog.NewMultiHandler(local, newOTelHandler(panicHandler{}, slog.LevelInfo)))

	assert.NotPanics(t, func() { log.Info("still works") })
	assert.Contains(t, buf.String(), "still works")
}

func TestResilience_ErrorLogThrottled(t *testing.T) {
	var buf bytes.Buffer
	l := newThrottledErrorLogger(slog.New(slog.NewJSONHandler(&buf, nil)), time.Minute)
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	for range 100 {
		l.Handle(errors.New("401 Unauthorized"))
	}
	assert.Equal(t, 1, strings.Count(buf.String(), "opentelemetry export error"))

	now = now.Add(time.Minute)
	l.Handle(errors.New("401 Unauthorized"))
	assert.Equal(t, 2, strings.Count(buf.String(), "opentelemetry export error"))
	assert.Contains(t, buf.String(), `"suppressed":99`)
}

func TestResilience_InvalidEndpointDoesNotStopService(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "://not a url")
	var buf bytes.Buffer
	tel := setup(t.Context(), config.Config{LogFormat: "json", LogLevel: "info", OpenTelemetry: true}, "test", &buf)
	tel.Log.Info("service keeps running")
	assert.Contains(t, buf.String(), "service keeps running")
	assert.NotPanics(t, func() { _ = tel.Shutdown() })
}
