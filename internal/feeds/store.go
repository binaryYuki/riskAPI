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

// Store 维护风险前缀表。查询无锁（atomic.Pointer 发布只读表），写操作串行化。
type Store struct {
	feeds []Feed
	fetch FetchConfig
	log   *slog.Logger
	stats Stats

	set     atomic.Pointer[ipset.Set]
	writeMu sync.Mutex // 串行化整表替换 / 单条删除

	updateMu sync.Mutex         // 串行化 Update，保护 lastGood
	lastGood map[string][]Entry // 每个源最近一次成功的条目（Feed.ID → entries）
	ready    atomic.Bool        // 首轮更新完成且至少一个源可用
}

// NewStore 创建空的风险表
func NewStore(feeds []Feed, fetch FetchConfig, log *slog.Logger) *Store {
	s := &Store{
		feeds:    feeds,
		fetch:    fetch,
		log:      log,
		lastGood: make(map[string][]Entry),
	}
	s.set.Store(ipset.New())
	return s
}

// Lookup 返回 IP 命中的来源 ID
func (s *Store) Lookup(ip string) (source string, ok bool) {
	return s.set.Load().Lookup(ip)
}

// Snapshot 返回当前只读表（用于导出与统计）
func (s *Store) Snapshot() *ipset.Set {
	return s.set.Load()
}

// Ready 首轮数据是否已加载
func (s *Store) Ready() bool {
	return s.ready.Load()
}

// Stats 返回最近一轮抓取的统计
func (s *Store) Stats() StatsSnapshot {
	return s.stats.Snapshot()
}

// Replace 由条目构建新表并整体替换；同一前缀后出现的条目覆盖先出现的
func (s *Store) Replace(entries []Entry) {
	next := ipset.New()
	singleIPs, cidrs := 0, 0
	for _, e := range entries {
		if !next.Insert(e.Value, e.Source) {
			continue
		}
		if strings.Contains(e.Value, "/") {
			cidrs++
		} else {
			singleIPs++
		}
	}
	s.writeMu.Lock()
	s.set.Store(next)
	s.writeMu.Unlock()
	s.log.Info("risk list updated", "single_ips", singleIPs, "cidrs", cidrs, "unique_prefixes", next.Len())
}

// Clear 清空风险表
func (s *Store) Clear() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.set.Store(ipset.New())
}

// Remove 删除单个 IP 或 CIDR（写时复制后整体替换），返回是否删除成功
func (s *Store) Remove(entry string) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	next, removed := s.set.Load().Without(entry)
	if removed {
		s.set.Store(next)
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

// Update 并发抓取全部数据源，失败的源沿用上次成功的数据，再整体替换风险表
func (s *Store) Update(ctx context.Context) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	s.log.Info("risk list update started", "sources", len(s.feeds))
	s.stats.reset()

	type result struct {
		entries []Entry
		err     error
	}
	results := make([]result, len(s.feeds))
	var wg sync.WaitGroup
	for i, feed := range s.feeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries, err := s.fetchFeed(ctx, feed)
			results[i] = result{entries: entries, err: err}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		s.log.Info("risk list update cancelled")
		return
	}

	// 按配置顺序合并，保证同一前缀出现在多个源时标签确定
	var merged []Entry
	fresh, stale, missing := 0, 0, 0
	for i, r := range results {
		feed := s.feeds[i]
		switch {
		case r.err == nil:
			s.lastGood[feed.ID] = r.entries
			fresh++
		case s.lastGood[feed.ID] != nil:
			s.log.Warn("source failed, reusing last successful data", "source", feed.ID, "err", r.err, "entries", len(s.lastGood[feed.ID]))
			stale++
		default:
			s.log.Warn("source failed with no previous data", "source", feed.ID, "err", r.err)
			missing++
			continue
		}
		merged = append(merged, s.lastGood[feed.ID]...)
	}
	s.log.Info("risk list sources", "fresh", fresh, "stale", stale, "unavailable", missing, "entries", len(merged))

	if fresh+stale == 0 {
		s.log.Warn("no data obtained from any source, risk list not updated")
		return
	}
	s.Replace(merged)
	s.ready.Store(true)
}
