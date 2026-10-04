package feeds

import (
	"strings"
	"sync/atomic"
	"time"

	"risky_ip_filter/internal/ipset"
)

// Stats 最近一轮抓取的解析统计（每轮开始时清零）。
// 抓取时每解析一行都会计数，使用原子计数器避免多个抓取协程争抢同一把锁。
type Stats struct {
	totalLines    atomic.Int64
	parsedIPs     atomic.Int64
	parsedCIDRs   atomic.Int64
	fetchAttempts atomic.Int64
	fetchSuccess  atomic.Int64
	fetchFailures atomic.Int64
	specialRanges atomic.Int64
	lastUpdateTs  atomic.Int64
}

// StatsSnapshot 用于对外展示的不可变快照
type StatsSnapshot struct {
	TotalLines    int   `json:"total_lines"`
	ParsedIPs     int   `json:"parsed_ips"`
	ParsedCIDRs   int   `json:"parsed_cidrs"`
	FetchAttempts int   `json:"fetch_attempts"`
	FetchSuccess  int   `json:"fetch_success"`
	FetchFailures int   `json:"fetch_failures"`
	SpecialRanges int   `json:"special_ranges"`
	LastUpdateTs  int64 `json:"last_update_ts"`
}

func (s *Stats) reset() {
	s.totalLines.Store(0)
	s.parsedIPs.Store(0)
	s.parsedCIDRs.Store(0)
	s.fetchAttempts.Store(0)
	s.fetchSuccess.Store(0)
	s.fetchFailures.Store(0)
	s.specialRanges.Store(0)
	s.lastUpdateTs.Store(time.Now().Unix())
}

// Snapshot 返回当前统计
func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		TotalLines:    int(s.totalLines.Load()),
		ParsedIPs:     int(s.parsedIPs.Load()),
		ParsedCIDRs:   int(s.parsedCIDRs.Load()),
		FetchAttempts: int(s.fetchAttempts.Load()),
		FetchSuccess:  int(s.fetchSuccess.Load()),
		FetchFailures: int(s.fetchFailures.Load()),
		SpecialRanges: int(s.specialRanges.Load()),
		LastUpdateTs:  s.lastUpdateTs.Load(),
	}
}

// classify 统计单个合法条目：单 IP / CIDR，以及是否属于特殊网段
func (s *Stats) classify(entry string) {
	p, ok := ipset.ParseEntry(entry)
	if !ok {
		return
	}
	if p.IsSingleIP() && !strings.Contains(entry, "/") {
		s.parsedIPs.Add(1)
	} else {
		s.parsedCIDRs.Add(1)
	}
	// 取网络地址第一个 IP 判断特殊网段
	if ipset.IsSpecial(p.Addr()) {
		s.specialRanges.Add(1)
	}
}
