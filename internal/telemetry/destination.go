package telemetry

import (
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	"risky_ip_filter/internal/config"
)

// destination OTLP 导出目标。
//
// 设置了 BETTERSTACK_SOURCE_TOKEN 时直接发往 Better Stack（显式选项优先于 OTEL_EXPORTER_OTLP_* 环境变量）；
// 否则不传任何选项，由 SDK 按标准环境变量配置（默认 http://localhost:4318，适合旁路 collector）。
type destination struct {
	name     string // 仅用于启动日志
	endpoint string // 仅用于启动日志，不含认证信息
	baseURL  string // 为空表示交给标准环境变量
	headers  map[string]string
}

func newDestination(c config.OTelConfig) destination {
	if c.BetterStackToken == "" {
		return destination{name: "otlp", endpoint: envEndpoint()}
	}
	base := "https://" + bareHost(c.BetterStackHost)
	return destination{
		name:     "betterstack",
		endpoint: base,
		baseURL:  base,
		headers:  map[string]string{"Authorization": "Bearer " + c.BetterStackToken},
	}
}

func (d destination) logOptions() []otlploghttp.Option {
	if d.baseURL == "" {
		return nil
	}
	return []otlploghttp.Option{
		otlploghttp.WithEndpointURL(d.baseURL + "/v1/logs"),
		otlploghttp.WithHeaders(d.headers),
		otlploghttp.WithCompression(otlploghttp.GzipCompression),
	}
}

func (d destination) traceOptions() []otlptracehttp.Option {
	if d.baseURL == "" {
		return nil
	}
	return []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(d.baseURL + "/v1/traces"),
		otlptracehttp.WithHeaders(d.headers),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	}
}

// bareHost 接受裸主机名，也容忍误填的 scheme 与末尾斜杠
func bareHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	return strings.TrimRight(host, "/")
}

func envEndpoint() string {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "http://localhost:4318 (default)"
}
