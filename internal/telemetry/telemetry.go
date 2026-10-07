// Package telemetry 创建进程级 logger，并在 OPENTELEMETRY=1 时通过 OTLP/HTTP
// 上报日志与链路追踪。未开启时不创建任何 OpenTelemetry 组件。
package telemetry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"risky_ip_filter/internal/config"
)

// ScopeName 本服务产生的日志与 span 的 instrumentation scope
const ScopeName = "risky_ip_filter"

// shutdownTimeout 停机时等待剩余日志与 span 发出的上限。
// 15s 优雅停机 + 3s 须小于 compose 的 stop_grace_period（20s）
const shutdownTimeout = 3 * time.Second

// Telemetry 进程级可观测性组件
type Telemetry struct {
	// Log 始终输出到 stdout；开启上报时同时发往 OTLP
	Log *slog.Logger
	// TracerProvider 未开启上报时为 nil，调用方据此跳过埋点
	TracerProvider trace.TracerProvider

	shutdown func(context.Context) error
}

// Setup 按配置创建 Telemetry。上报链路的任何故障都不影响服务本身：
//   - 启动：导出器创建失败时降级为只写 stdout，服务照常启动（不会因 OTel 返回错误）
//   - 运行：日志与 span 先进有界队列，由后台 goroutine 批量发送；队列满时丢弃，绝不阻塞请求
//   - 后端故障：导出失败只按间隔限流记一条 stdout 警告；handler 内部 panic 被拦截（见 otelHandler）
//   - 停机：最多等待 shutdownTimeout，超时直接放弃剩余数据
func Setup(ctx context.Context, cfg config.Config, version string) *Telemetry {
	return setup(ctx, cfg, version, os.Stdout)
}

func setup(ctx context.Context, cfg config.Config, version string, stdout io.Writer) *Telemetry {
	local := newStdoutHandler(stdout, cfg.LogFormat, parseLevel(cfg.LogLevel, slog.LevelInfo))
	t := &Telemetry{Log: slog.New(local), shutdown: func(context.Context) error { return nil }}
	if !cfg.OpenTelemetry {
		return t
	}

	localLog := t.Log
	otel.SetErrorHandler(newThrottledErrorLogger(localLog, errorLogInterval))

	res, err := newResource(ctx, version)
	if err != nil {
		// 部分 detector 失败时 res 仍可用，记录后继续
		localLog.Warn("opentelemetry resource detection incomplete", "err", err)
	}
	if res == nil {
		res = resource.Default()
	}

	dest := newDestination(cfg.OTel)
	logExp, err := otlploghttp.New(ctx, dest.logOptions()...)
	if err != nil {
		localLog.Error("opentelemetry disabled: cannot create log exporter", "err", err)
		return t
	}
	traceExp, err := otlptracehttp.New(ctx, dest.traceOptions()...)
	if err != nil {
		_ = logExp.Shutdown(ctx)
		localLog.Error("opentelemetry disabled: cannot create trace exporter", "err", err)
		return t
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
	)
	// 采样器未显式指定：SDK 读取 OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG，默认全采样
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExp),
	)

	remoteLevel := parseLevel(cfg.OTel.LogLevel, parseLevel(cfg.LogLevel, slog.LevelInfo))
	remote := newOTelHandler(otelslog.NewHandler(ScopeName,
		otelslog.WithLoggerProvider(lp),
		otelslog.WithVersion(version),
	), remoteLevel)

	t.Log = slog.New(slog.NewMultiHandler(local, remote))
	t.TracerProvider = tp
	t.shutdown = func(ctx context.Context) error {
		// 先停 trace 再停 log：停机过程中产生的日志仍能发出
		return errors.Join(tp.Shutdown(ctx), lp.Shutdown(ctx))
	}

	t.Log.Info("opentelemetry enabled",
		"destination", dest.name,
		"endpoint", dest.endpoint,
		"min_level", remoteLevel.String(),
	)
	return t
}

// Enabled 是否开启了 OTLP 上报
func (t *Telemetry) Enabled() bool { return t.TracerProvider != nil }

// Shutdown 发出排队中的日志与 span；未开启时为空操作
func (t *Telemetry) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return t.shutdown(ctx)
}

// InstrumentDefaultTransport 为 http.DefaultTransport 加上客户端 span。
// 外部 API、风险源下载、parse 转发都经由它；OTLP 导出器使用自己的 transport，不受影响。
// 未开启上报时不做任何事。
func (t *Telemetry) InstrumentDefaultTransport() {
	if !t.Enabled() {
		return
	}
	http.DefaultTransport = otelhttp.NewTransport(http.DefaultTransport,
		otelhttp.WithTracerProvider(t.TracerProvider),
	)
}

func newResource(ctx context.Context, version string) (*resource.Resource, error) {
	attrs := []resource.Option{
		resource.WithAttributes(
			semconv.ServiceName("riskapi"),
			semconv.ServiceVersion(version),
		),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
	}
	if h, err := os.Hostname(); err == nil {
		// 容器内为容器 ID，用于区分多副本
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceInstanceID(h)))
	}
	// 放在最后：OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES 可覆盖上面的默认值
	attrs = append(attrs, resource.WithFromEnv())
	return resource.New(ctx, attrs...)
}

func newStdoutHandler(w io.Writer, format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(format, "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

func parseLevel(s string, def slog.Level) slog.Level {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return def
	}
	return lvl
}
