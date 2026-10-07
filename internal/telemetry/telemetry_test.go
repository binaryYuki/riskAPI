package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"risky_ip_filter/internal/config"
)

// otlpReceiver 记录收到的 OTLP/HTTP 请求（protobuf 编码）
type otlpReceiver struct {
	mu     sync.Mutex
	logs   []*logspb.ResourceLogs
	spans  int
	auth   []string
	server *httptest.Server
}

func newOTLPReceiver(t *testing.T) *otlpReceiver {
	r := &otlpReceiver{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := io.Reader(req.Body)
		if req.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(req.Body)
			require.NoError(t, err)
			body = gz
		}
		raw, err := io.ReadAll(body)
		require.NoError(t, err)

		r.mu.Lock()
		defer r.mu.Unlock()
		r.auth = append(r.auth, req.Header.Get("Authorization"))
		switch req.URL.Path {
		case "/v1/logs":
			var m collogs.ExportLogsServiceRequest
			require.NoError(t, proto.Unmarshal(raw, &m))
			r.logs = append(r.logs, m.ResourceLogs...)
		case "/v1/traces":
			var m coltrace.ExportTraceServiceRequest
			require.NoError(t, proto.Unmarshal(raw, &m))
			for _, rs := range m.ResourceSpans {
				for _, ss := range rs.ScopeSpans {
					r.spans += len(ss.Spans)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func attrMap(kvs []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	m := make(map[string]*commonpb.AnyValue, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	return m
}

func TestSetup_DisabledCreatesNothing(t *testing.T) {
	var buf bytes.Buffer
	tel := setup(t.Context(), config.Config{LogFormat: "json", LogLevel: "info",
		OTel: config.OTelConfig{BetterStackToken: "tok"}}, "test", &buf)

	assert.False(t, tel.Enabled())
	assert.Nil(t, tel.TracerProvider)
	_, isMulti := tel.Log.Handler().(*slog.MultiHandler)
	assert.False(t, isMulti)
	assert.NoError(t, tel.Shutdown())
	assert.Empty(t, buf.String())
}

func TestSetup_ExportsLogsAndTraces(t *testing.T) {
	recv := newOTLPReceiver(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", recv.server.URL)
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

	var buf bytes.Buffer
	tel := setup(t.Context(), config.Config{LogFormat: "json", LogLevel: "debug", OpenTelemetry: true,
		OTel: config.OTelConfig{LogLevel: "info"}}, "v-test", &buf)
	require.True(t, tel.Enabled())
	assert.Contains(t, buf.String(), `"msg":"opentelemetry enabled"`)
	assert.Contains(t, buf.String(), `"destination":"otlp"`)

	ctx, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
	tel.Log.InfoContext(ctx, "request",
		"status", 200,
		"latency", 1500*time.Microsecond,
		"until", time.Date(2026, 10, 7, 9, 0, 0, 0, time.FixedZone("CST", 8*3600)),
		"err", errors.New("boom"),
		slog.Group("geo", "country", "JP", "rtt", 2*time.Millisecond),
	)
	tel.Log.Debug("below remote level") // stdout 有，远程没有
	span.End()
	require.NoError(t, tel.Shutdown())

	recv.mu.Lock()
	defer recv.mu.Unlock()
	assert.Equal(t, 1, recv.spans)

	var records []*logspb.LogRecord
	for _, rl := range recv.logs {
		res := attrMap(rl.Resource.Attributes)
		assert.Equal(t, "riskapi", res["service.name"].GetStringValue())
		assert.Equal(t, "v-test", res["service.version"].GetStringValue())
		assert.NotEmpty(t, res["service.instance.id"].GetStringValue())
		for _, sl := range rl.ScopeLogs {
			assert.Equal(t, ScopeName, sl.Scope.Name)
			records = append(records, sl.LogRecords...)
		}
	}
	var req *logspb.LogRecord
	for _, r := range records {
		assert.NotEqual(t, "below remote level", r.Body.GetStringValue())
		if r.Body.GetStringValue() == "request" {
			req = r
		}
	}
	require.NotNil(t, req, "request log not exported")

	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, req.SeverityNumber)
	assert.Equal(t, "INFO", req.SeverityText)
	assert.Equal(t, span.SpanContext().TraceID().String(), hex.EncodeToString(req.TraceId))
	assert.Equal(t, span.SpanContext().SpanID().String(), hex.EncodeToString(req.SpanId))

	a := attrMap(req.Attributes)
	assert.EqualValues(t, 200, a["status"].GetIntValue())
	assert.InDelta(t, 1.5, a["latency_ms"].GetDoubleValue(), 1e-9)
	assert.NotContains(t, a, "latency")
	assert.Equal(t, "2026-10-07T01:00:00Z", a["until"].GetStringValue())
	assert.Equal(t, "boom", a["exception.message"].GetStringValue())
	geo := attrMap(a["geo"].GetKvlistValue().GetValues())
	assert.Equal(t, "JP", geo["country"].GetStringValue())
	assert.InDelta(t, 2.0, geo["rtt_ms"].GetDoubleValue(), 1e-9)
}

func TestDestination_BetterStack(t *testing.T) {
	d := newDestination(config.OTelConfig{BetterStackToken: "tok", BetterStackHost: "https://h.example.com/"})
	assert.Equal(t, "betterstack", d.name)
	assert.Equal(t, "https://h.example.com", d.baseURL)
	assert.Equal(t, "Bearer tok", d.headers["Authorization"])
	assert.NotContains(t, d.endpoint, "tok")
	assert.Len(t, d.logOptions(), 3)
	assert.Len(t, d.traceOptions(), 3)

	std := newDestination(config.OTelConfig{})
	assert.Equal(t, "otlp", std.name)
	assert.Nil(t, std.logOptions())
	assert.Nil(t, std.traceOptions())
}
