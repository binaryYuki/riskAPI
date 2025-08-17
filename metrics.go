package main

import (
	"net"
	"sync"
	"time"
)

// metrics holds basic parsing statistics (not persistent)
var metrics = struct {
	sync.RWMutex
	TotalLines    int
	ParsedIPs     int
	ParsedCIDRs   int
	FetchAttempts int
	FetchSuccess  int
	FetchFailures int
	SpecialRanges int
	LastUpdateTs  int64
}{}

func metricsReset() {
	metrics.Lock()
	metrics.TotalLines = 0
	metrics.ParsedIPs = 0
	metrics.ParsedCIDRs = 0
	metrics.FetchAttempts = 0
	metrics.FetchSuccess = 0
	metrics.FetchFailures = 0
	metrics.SpecialRanges = 0
	metrics.LastUpdateTs = time.Now().Unix()
	metrics.Unlock()
}

func metricsAddLine() {
	metrics.Lock()
	metrics.TotalLines++
	metrics.Unlock()
}

func metricsAddIP() {
	metrics.Lock()
	metrics.ParsedIPs++
	metrics.Unlock()
}

func metricsAddCIDR() {
	metrics.Lock()
	metrics.ParsedCIDRs++
	metrics.Unlock()
}

func metricsAddFetchAttempt() {
	metrics.Lock()
	metrics.FetchAttempts++
	metrics.Unlock()
}

func metricsAddFetchSuccess() {
	metrics.Lock()
	metrics.FetchSuccess++
	metrics.Unlock()
}

func metricsAddFetchFailure() {
	metrics.Lock()
	metrics.FetchFailures++
	metrics.Unlock()
}

func metricsAddSpecialRange() {
	metrics.Lock()
	metrics.SpecialRanges++
	metrics.Unlock()
}

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
	metrics.RLock()
	defer metrics.RUnlock()
	return MetricsSnapshot{
		TotalLines:    metrics.TotalLines,
		ParsedIPs:     metrics.ParsedIPs,
		ParsedCIDRs:   metrics.ParsedCIDRs,
		FetchAttempts: metrics.FetchAttempts,
		FetchSuccess:  metrics.FetchSuccess,
		FetchFailures: metrics.FetchFailures,
		SpecialRanges: metrics.SpecialRanges,
		LastUpdateTs:  metrics.LastUpdateTs,
	}
}

// classifyAndCount 用于后续扩展分类统计，目前只做占位
func classifyAndCount(ipOrCIDR string) {
	if _, ipNet, err := net.ParseCIDR(ipOrCIDR); err == nil {
		metricsAddCIDR()
		// 取网络地址第一IP判断特殊网段
		if classifySpecialRanges(ipNet.IP) {
			metricsAddSpecialRange()
		}
		return
	}
	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		metricsAddIP()
		if classifySpecialRanges(ip) {
			metricsAddSpecialRange()
		}
	}
}
