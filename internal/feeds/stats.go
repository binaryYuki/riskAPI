package feeds

import (
	"net/netip"
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

// restore 用共享快照中抓取方的统计覆盖本实例统计（本实例未抓取时 /metrics 仍能反映数据源状况）
func (s *Stats) restore(v StatsSnapshot) {
	s.totalLines.Store(int64(v.TotalLines))
	s.parsedIPs.Store(int64(v.ParsedIPs))
	s.parsedCIDRs.Store(int64(v.ParsedCIDRs))
	s.fetchAttempts.Store(int64(v.FetchAttempts))
	s.fetchSuccess.Store(int64(v.FetchSuccess))
	s.fetchFailures.Store(int64(v.FetchFailures))
	s.specialRanges.Store(int64(v.SpecialRanges))
	s.lastUpdateTs.Store(v.LastUpdateTs)
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

// addUnchanged 把未变化（304）的源上次解析时的统计计入本轮，使各项统计不因源未变化而变小
func (s *Stats) addUnchanged(d *feedData) {
	s.totalLines.Add(int64(d.lines))
	s.parsedIPs.Add(int64(len(d.prefixes) - d.cidrs))
	s.parsedCIDRs.Add(int64(d.cidrs))
	s.specialRanges.Add(int64(d.special))
}

// classify 统计单个合法条目：单 IP / CIDR，以及是否属于特殊网段（返回值）。
// cidr 表示源里写成带掩码的形式，"1.2.3.4/32" 也按 CIDR 计。
func (s *Stats) classify(p netip.Prefix, cidr bool) (special bool) {
	if !cidr {
		s.parsedIPs.Add(1)
	} else {
		s.parsedCIDRs.Add(1)
	}
	// 取网络地址第一个 IP 判断特殊网段
	if ipset.IsSpecial(p.Addr()) {
		s.specialRanges.Add(1)
		return true
	}
	return false
}
