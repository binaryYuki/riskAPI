package main

import (
	"strings"
	"sync/atomic"
	"time"
)

// metrics holds basic parsing statistics (not persistent)
// 抓取时每解析一行都会计数，使用原子计数器避免 20+ 个抓取协程争抢同一把锁
var metrics struct {
	TotalLines    atomic.Int64
	ParsedIPs     atomic.Int64
	ParsedCIDRs   atomic.Int64
	FetchAttempts atomic.Int64
	FetchSuccess  atomic.Int64
	FetchFailures atomic.Int64
	SpecialRanges atomic.Int64
	LastUpdateTs  atomic.Int64
}

func metricsReset() {
	metrics.TotalLines.Store(0)
	metrics.ParsedIPs.Store(0)
	metrics.ParsedCIDRs.Store(0)
	metrics.FetchAttempts.Store(0)
	metrics.FetchSuccess.Store(0)
	metrics.FetchFailures.Store(0)
	metrics.SpecialRanges.Store(0)
	metrics.LastUpdateTs.Store(time.Now().Unix())
}

func metricsAddLine()         { metrics.TotalLines.Add(1) }
func metricsAddIP()           { metrics.ParsedIPs.Add(1) }
func metricsAddCIDR()         { metrics.ParsedCIDRs.Add(1) }
func metricsAddFetchAttempt() { metrics.FetchAttempts.Add(1) }
func metricsAddFetchSuccess() { metrics.FetchSuccess.Add(1) }
func metricsAddFetchFailure() { metrics.FetchFailures.Add(1) }
func metricsAddSpecialRange() { metrics.SpecialRanges.Add(1) }

// MetricsSnapshot 用于对外展示的不可变快照
type MetricsSnapshot struct {
	TotalLines    int   `json:"total_lines"`
	ParsedIPs     int   `json:"parsed_ips"`
	ParsedCIDRs   int   `json:"parsed_cidrs"`
	FetchAttempts int   `json:"fetch_attempts"`
	FetchSuccess  int   `json:"fetch_success"`
	FetchFailures int   `json:"fetch_failures"`
	SpecialRanges int   `json:"special_ranges"`
	LastUpdateTs  int64 `json:"last_update_ts"`
}

func getMetricsSnapshot() MetricsSnapshot {
	return MetricsSnapshot{
		TotalLines:    int(metrics.TotalLines.Load()),
		ParsedIPs:     int(metrics.ParsedIPs.Load()),
		ParsedCIDRs:   int(metrics.ParsedCIDRs.Load()),
		FetchAttempts: int(metrics.FetchAttempts.Load()),
		FetchSuccess:  int(metrics.FetchSuccess.Load()),
		FetchFailures: int(metrics.FetchFailures.Load()),
		SpecialRanges: int(metrics.SpecialRanges.Load()),
		LastUpdateTs:  metrics.LastUpdateTs.Load(),
	}
}

// classifyAndCount 用于后续扩展分类统计，目前只做占位
func classifyAndCount(ipOrCIDR string) {
	p, ok := parseEntry(ipOrCIDR)
	if !ok {
		return
	}
	if p.IsSingleIP() && !strings.Contains(ipOrCIDR, "/") {
		metricsAddIP()
	} else {
		metricsAddCIDR()
	}
	// 取网络地址第一个 IP 判断特殊网段
	if classifySpecialRanges(p.Addr()) {
		metricsAddSpecialRange()
	}
}
