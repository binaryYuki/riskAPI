package feeds

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"risky_ip_filter/internal/ipset"
)

// Entry 数据源中的一条 IP/CIDR 及其来源 ID
type Entry struct {
	Value  string
	Source string
}

// FetchConfig 抓取参数
type FetchConfig struct {
	Timeout    time.Duration // 单次请求超时
	Retries    int           // 每个源的最大尝试次数
	RetryDelay time.Duration // 线性退避基数：第 n 次重试前等待 n*RetryDelay
}

// tables 一次发布的全部查找表，整体原子替换以保证查询时三者一致
type tables struct {
	risk  *ipset.Set // 风险前缀 → 来源 ID
	proxy *ipset.Set // 代理标记前缀 → 来源 ID
	idc   *ipset.Set // IDC 标记前缀 → 来源 ID
}

func emptyTables() *tables {
	return &tables{risk: ipset.New(), proxy: ipset.New(), idc: ipset.New()}
}

// batch 同一数据源的条目及其属性
type batch struct {
	entries []Entry
	tags    Tag
	tagOnly bool
}

// Store 维护风险前缀表与代理/IDC 标记表。查询无锁（atomic.Pointer 发布只读表），
// 更新时在后台构建新表后整体替换，替换前后查询始终可用。写操作串行化。
type Store struct {
	feeds []Feed
	fetch FetchConfig
	log   *slog.Logger
	stats Stats

	set     atomic.Pointer[tables]
	writeMu sync.Mutex // 串行化整表替换 / 单条删除

	updateMu   sync.Mutex           // 串行化 Update，保护 lastGood 与 validators
	lastGood   map[string][]Entry   // 每个源最近一次成功的条目（Feed.ID → entries）
	validators map[string]validator // lastGood 对应响应的校验值，与 lastGood 同步更新
	ready      atomic.Bool          // 首轮更新完成且至少一个源可用
}

// NewStore 创建空的风险表
func NewStore(feeds []Feed, fetch FetchConfig, log *slog.Logger) *Store {
	s := &Store{
		feeds:      feeds,
		fetch:      fetch,
		log:        log,
		lastGood:   make(map[string][]Entry),
		validators: make(map[string]validator),
	}
	s.set.Store(emptyTables())
	return s
}

// Lookup 返回 IP 命中的风险来源 ID
func (s *Store) Lookup(ip string) (source string, ok bool) {
	return s.set.Load().risk.Lookup(ip)
}

// Tags 返回 IP 命中的属性标记（与是否命中风险表无关）
func (s *Store) Tags(ip string) Tag {
	t := s.set.Load()
	var tags Tag
	if _, ok := t.proxy.Lookup(ip); ok {
		tags |= TagProxy
	}
	if _, ok := t.idc.Lookup(ip); ok {
		tags |= TagIDC
	}
	return tags
}

// Snapshot 返回当前只读风险表（用于导出与统计）
func (s *Store) Snapshot() *ipset.Set {
	return s.set.Load().risk
}

// Ready 首轮数据是否已加载
func (s *Store) Ready() bool {
	return s.ready.Load()
}

// Stats 返回最近一轮抓取的统计
func (s *Store) Stats() StatsSnapshot {
	return s.stats.Snapshot()
}

// Replace 由条目构建新风险表（不带标记）并整体替换；同一前缀后出现的条目覆盖先出现的
func (s *Store) Replace(entries []Entry) {
	s.replace([]batch{{entries: entries}})
}

func (s *Store) replace(batches []batch) {
	next := emptyTables()
	singleIPs, cidrs := 0, 0
	for _, b := range batches {
		for _, e := range b.entries {
			if !b.tagOnly {
				if !next.risk.Insert(e.Value, e.Source) {
					continue
				}
				if strings.Contains(e.Value, "/") {
					cidrs++
				} else {
					singleIPs++
				}
			}
			if b.tags&TagProxy != 0 {
				next.proxy.Insert(e.Value, e.Source)
			}
			if b.tags&TagIDC != 0 {
				next.idc.Insert(e.Value, e.Source)
			}
		}
	}
	s.writeMu.Lock()
	s.set.Store(next)
	s.writeMu.Unlock()
	s.log.Info("risk list updated", "single_ips", singleIPs, "cidrs", cidrs, "unique_prefixes", next.risk.Len(),
		"proxy_prefixes", next.proxy.Len(), "idc_prefixes", next.idc.Len())
}

// Clear 清空风险表与标记表
func (s *Store) Clear() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.set.Store(emptyTables())
}

// Remove 从风险表与标记表中删除单个 IP 或 CIDR（写时复制后整体替换），返回是否有表删除成功
func (s *Store) Remove(entry string) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cur := s.set.Load()
	risk, r1 := cur.risk.Without(entry)
	proxy, r2 := cur.proxy.Without(entry)
	idc, r3 := cur.idc.Without(entry)
	removed := r1 || r2 || r3
	if removed {
		s.set.Store(&tables{risk: risk, proxy: proxy, idc: idc})
	}
	return removed
}

// Run 立即执行一次更新，之后按 interval 周期更新，ctx 取消时退出
func (s *Store) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.Update(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Update 并发抓取全部数据源，失败的源沿用上次成功的数据，再整体替换风险表。
// 抓取与构建期间查询继续使用旧表。
func (s *Store) Update(ctx context.Context) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	s.log.Info("risk list update started", "sources", len(s.feeds))
	s.stats.reset()

	type result struct {
		fetched
		err error
	}
	results := make([]result, len(s.feeds))
	var wg sync.WaitGroup
	for i, feed := range s.feeds {
		// 只有手里有上次的数据才发条件请求，否则 304 时无数据可用
		var cond validator
		if s.lastGood[feed.ID] != nil {
			cond = s.validators[feed.ID]
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.fetchFeed(ctx, feed, cond)
			results[i] = result{fetched: res, err: err}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		s.log.Info("risk list update cancelled")
		return
	}

	// 按配置顺序合并，保证同一前缀出现在多个源时标签确定
	var batches []batch
	fresh, stale, missing, total := 0, 0, 0, 0
	for i, r := range results {
		feed := s.feeds[i]
		switch {
		case r.err == nil && r.notModified:
			unchanged++
		case r.err == nil:
			s.lastGood[feed.ID] = r.entries
			s.validators[feed.ID] = r.validator
			fresh++
		case s.lastGood[feed.ID] != nil:
			s.log.Warn("source failed, reusing last successful data", "source", feed.ID, "err", r.err, "entries", len(s.lastGood[feed.ID]))
			stale++
		default:
			s.log.Warn("source failed with no previous data", "source", feed.ID, "err", r.err)
			missing++
			continue
		}
		batches = append(batches, batch{entries: s.lastGood[feed.ID], tags: feed.Tags, tagOnly: feed.TagOnly})
		total += len(s.lastGood[feed.ID])
	}
	s.log.Info("risk list sources", "fresh", fresh, "stale", stale, "unavailable", missing, "entries", total)

	if fresh+unchanged+stale == 0 {
		s.log.Warn("no data obtained from any source, risk list not updated")
		return
	}
	s.replace(batches)
	s.ready.Store(true)
}
