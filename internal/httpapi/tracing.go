package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// 入站 span 格式：
//
//	name        "<METHOD> <路由模板>"，如 "GET /api/v1/ip/:ip"；未匹配路由为 "HTTP GET route not found"
//	kind        SERVER
//	attributes  otelgin 的 HTTP 语义约定属性（http.request.method、url.path、http.route、
//	            http.response.status_code、user_agent.original 等），另外：
//	            client.address  按可信代理规则解析的真实客户端 IP（覆盖 otelgin 取到的 CDN 地址）
//	            correlation_id  与响应头 X-Request-ID 相同，便于用户报障时反查链路
//	status      5xx 为 Error
//
// 不提取入站 traceparent：公开 API 的调用方不可信，每个请求都是新 trace 的根。
// 出站请求同样不注入 traceparent，避免把内部 trace ID 泄露给第三方 API。

// telemetrySkipPaths 健康检查与指标抓取，量大且无排查价值：不生成 span，访问日志也不经 OTLP 上报（stdout 照常）
var telemetrySkipPaths = map[string]bool{
	"/api/ready": true,
	"/metrics":   true,
}

func (s *Server) tracing() gin.HandlerFunc {
	return otelgin.Middleware("riskapi",
		otelgin.WithTracerProvider(s.tracerProvider),
		otelgin.WithFilter(func(r *http.Request) bool { return !telemetrySkipPaths[r.URL.Path] }),
	)
}

// annotateSpan 为当前请求的 span 补充本服务特有的属性；未开启追踪时为空操作
func (s *Server) annotateSpan(c *gin.Context) {
	span := trace.SpanFromContext(c.Request.Context())
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(
		semconv.ClientAddress(s.clientIP(c)),
		attribute.String("correlation_id", correlationID(c)),
	)
}
