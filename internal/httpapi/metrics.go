package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// metricsJSON GET /api/metrics 返回解析与蜜罐统计（JSON）
func (s *Server) metricsJSON(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"parser":    s.risk.Stats(),
			"honeytrap": s.trap.Stats(),
		},
	})
}

// metricsPrometheus GET /metrics 以 Prometheus 文本格式输出指标
func (s *Server) metricsPrometheus(c *gin.Context) {
	var b strings.Builder
	metric := func(name, typ, help string, value any, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		if len(labels) > 0 {
			fmt.Fprintf(&b, "%s{%s} %v\n", name, strings.Join(labels, ","), value)
		} else {
			fmt.Fprintf(&b, "%s %v\n", name, value)
		}
	}
	boolGauge := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}

	cdn, idc := s.lists.Sizes()
	feed := s.risk.Stats()
	trap := s.trap.Stats()

	metric("riskapi_build_info", "gauge", "Build information.", 1, fmt.Sprintf("version=%q", s.version))
	metric("riskapi_ready", "gauge", "Whether risk IP lists have completed their first load.", boolGauge(s.risk.Ready()))
	metric("riskapi_risk_prefixes", "gauge", "Unique prefixes in the risk IP table.", s.risk.Snapshot().Len())
	metric("riskapi_cdn_prefixes", "gauge", "Prefixes in the CDN table.", cdn)
	metric("riskapi_idc_prefixes", "gauge", "Prefixes in the IDC table.", idc)
	metric("riskapi_info_cache_entries", "gauge", "Entries in the /api/v1/info cache.", s.infoCache.Len())

	metric("riskapi_feed_last_update_timestamp_seconds", "gauge", "Start time of the last feed update.", feed.LastUpdateTs)
	metric("riskapi_feed_fetch_attempts", "gauge", "Fetch attempts in the last feed update.", feed.FetchAttempts)
	metric("riskapi_feed_fetch_success", "gauge", "Sources fetched successfully in the last feed update.", feed.FetchSuccess)
	metric("riskapi_feed_fetch_failures", "gauge", "Sources that failed all retries in the last feed update.", feed.FetchFailures)
	metric("riskapi_feed_parsed_lines", "gauge", "Lines parsed in the last feed update.", feed.TotalLines)

	metric("riskapi_honeytrap_hits_total", "counter", "Requests delayed by the honeytrap.", trap.Hits)
	metric("riskapi_honeytrap_fake_ok_total", "counter", "Fake 200 responses served by the honeytrap.", trap.FakeOK)
	metric("riskapi_honeytrap_blocks_total", "counter", "Requests rejected with 429 by the honeytrap.", trap.Blocks)
	metric("riskapi_honeytrap_penalty_ms_total", "counter", "Total delay injected by the honeytrap in milliseconds.", trap.PenaltyMS)
	metric("riskapi_honeytrap_tracked_offenders", "gauge", "Sources currently tracked by the honeytrap.", trap.Offenders)

	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}
