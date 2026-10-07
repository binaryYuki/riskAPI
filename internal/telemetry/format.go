package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
)

// OTLP 日志记录格式（OpenTelemetry Logs Data Model）：
//
//	Timestamp       事件时间
//	SeverityNumber  DEBUG=5 INFO=9 WARN=13 ERROR=17；SeverityText 为 "DEBUG" 等
//	Body            slog 消息，如 "request"
//	TraceId/SpanId  以 *Context 方法记录且 ctx 中有 span 时自动关联
//	Resource        service.name=riskapi、service.version、service.instance.id、host.name、telemetry.sdk.*
//	Scope           risky_ip_filter@<version>
//	Attributes      slog 属性，键名原样保留；Group 为嵌套 map
//
// 属性值转换（本 handler 在交给 otelslog 之前完成）：
//   - time.Duration → 键名追加 _ms，浮点毫秒（bridge 默认是整数纳秒，不直观）
//   - time.Time     → UTC RFC3339Nano 字符串（bridge 默认是 Unix 纳秒整数）
//   - error         → 由 SDK 写为 exception.message / exception.type
const durationSuffix = "_ms"

// otelHandler 为 otelslog handler 增加级别过滤与上述属性转换
type otelHandler struct {
	next  slog.Handler
	level slog.Level
}

func newOTelHandler(next slog.Handler, level slog.Level) slog.Handler {
	return &otelHandler{next: next, level: level}
}

func (h *otelHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.level && h.next.Enabled(ctx, l)
}

// Handle 拦截 panic：日志也会在没有 gin.Recovery 保护的后台 goroutine（风险源更新等）中记录，
// 上报链路的 bug 不能让进程崩溃。错误由 slog.Logger 忽略，stdout 那一路不受影响。
func (h *otelHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("opentelemetry log handler panic: %v", p)
			otel.Handle(err)
		}
	}()
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(convertAttr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *otelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	converted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		converted[i] = convertAttr(a)
	}
	return &otelHandler{next: h.next.WithAttrs(converted), level: h.level}
}

func (h *otelHandler) WithGroup(name string) slog.Handler {
	return &otelHandler{next: h.next.WithGroup(name), level: h.level}
}

func convertAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindDuration:
		return slog.Float64(a.Key+durationSuffix, float64(v.Duration())/float64(time.Millisecond))
	case slog.KindTime:
		return slog.String(a.Key, v.Time().UTC().Format(time.RFC3339Nano))
	case slog.KindGroup:
		group := v.Group()
		converted := make([]slog.Attr, len(group))
		for i, ga := range group {
			converted[i] = convertAttr(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(converted...)}
	default:
		return slog.Attr{Key: a.Key, Value: v}
	}
}
