package httpapi

import (
	"net/http"
	"reflect"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func newTracedEnv(t *testing.T) (*testEnv, *tracetest.SpanRecorder) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	env := newTestEnv(t)
	env.server.tracerProvider = tp
	env.h = env.server.Handler()
	return env, rec
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := make(map[attribute.Key]attribute.Value)
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

func nameOfHandler(h gin.HandlerFunc) string {
	return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
}

func TestTracing_DisabledWithoutProvider(t *testing.T) {
	env := newTestEnv(t)
	assert.Nil(t, env.server.tracerProvider)
	for _, h := range env.h.Handlers {
		assert.NotContains(t, nameOfHandler(h), "otelgin")
	}
}

func TestTracing_ServerSpan(t *testing.T) {
	env, rec := newTracedEnv(t)
	// 可信代理（私网）转发：client.address 应取转发头中的真实 IP，而非 gin 看到的对端
	w := env.do(http.MethodGet, "/api/v1/ip/1.1.1.1",
		withRemote("10.0.0.1:443"), withHeader("X-Forwarded-For", "203.0.113.9"))
	require.Equal(t, http.StatusOK, w.Code)

	spans := rec.Ended()
	require.Len(t, spans, 1)
	s := spans[0]
	assert.Equal(t, "GET /api/v1/ip/:ip", s.Name())
	assert.Equal(t, oteltrace.SpanKindServer, s.SpanKind())

	attrs := spanAttrs(s)
	assert.Equal(t, "203.0.113.9", attrs["client.address"].AsString())
	assert.Equal(t, w.Header().Get("X-Request-ID"), attrs["correlation_id"].AsString())
	assert.Equal(t, "/api/v1/ip/:ip", attrs["http.route"].AsString())
	assert.EqualValues(t, 200, attrs["http.response.status_code"].AsInt64())
}

func TestTracing_IgnoresInboundTraceparent(t *testing.T) {
	env, rec := newTracedEnv(t)
	env.do(http.MethodGet, "/version",
		withHeader("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"))

	spans := rec.Ended()
	require.Len(t, spans, 1)
	assert.False(t, spans[0].Parent().IsValid(), "untrusted inbound trace context must not be adopted")
	assert.NotEqual(t, "0af7651916cd43dd8448eb211c80319c", spans[0].SpanContext().TraceID().String())
}

func TestTracing_SkipsHealthAndMetrics(t *testing.T) {
	env, rec := newTracedEnv(t)
	env.do(http.MethodGet, "/api/ready")
	env.do(http.MethodGet, "/metrics")
	assert.Empty(t, rec.Ended())
}
