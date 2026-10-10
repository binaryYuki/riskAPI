package telemetry

import "context"

type skipExportKey struct{}

// SkipExport 返回的 ctx 用 *Context 方法记录日志时只写 stdout，不经 OTLP 上报。
// 用于健康检查等高频且无排查价值的日志；未开启上报时无影响。
func SkipExport(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipExportKey{}, true)
}

// ExportSkipped 报告 ctx 是否带有 SkipExport 标记
func ExportSkipped(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	skip, _ := ctx.Value(skipExportKey{}).(bool)
	return skip
}
