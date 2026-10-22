package feeds

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// snapshotSyncInterval 共享模式下检查快照的周期；只读一个时间戳，开销很小
	snapshotSyncInterval = 30 * time.Second
	// snapshotWaitInterval 尚无数据时（集群冷启动，等待抓取方发布首个快照）的检查周期
	snapshotWaitInterval = 5 * time.Second
	// claimTTL 一轮抓取权的有效期，须大于一轮抓取的最长耗时（单源 10s 超时 × 3 次 + 退避约 40s）；
	// 抓取方崩溃时其它实例最多等这么久接手
	claimTTL = 5 * time.Minute
	// snapshotVersion 快照格式版本；不兼容的旧格式快照被忽略，改由本实例抓取
	snapshotVersion = 1
)

// Coordinator 多实例共享抓取结果（可选）：每个周期只由一个实例抓取并发布快照，其它实例加载快照，
// 外部数据源的请求量与副本数无关
type Coordinator interface {
	// SnapshotTime 最近一次发布的快照时间；没有快照时返回零值
	SnapshotTime(ctx context.Context) (time.Time, error)
	// LoadSnapshot 读取最近一次发布的快照；没有快照时返回 nil
	LoadSnapshot(ctx context.Context) (data []byte, published time.Time, err error)
	// PublishSnapshot 发布快照
	PublishSnapshot(ctx context.Context, data []byte, published time.Time) error
	// Claim 争抢一轮抓取权，ttl 内其它实例无法获得
	Claim(ctx context.Context, ttl time.Duration) (bool, error)
}

// snapshot 各数据源最近一次成功的条目与抓取统计（gzip 压缩的 JSON）
type snapshot struct {
	Version int                 `json:"version"`
	Feeds   map[string][]string `json:"feeds"` // Feed.ID → IP/CIDR
	Stats   StatsSnapshot       `json:"stats"`
}

// SetCoordinator 启用多实例共享，须在 Run 之前调用
func (s *Store) SetCoordinator(c Coordinator) {
	s.coord = c
}

// syncState 共享模式下 Run 循环的状态，只在 Run 所在协程中访问
type syncState struct {
	applied    time.Time // 当前数据的发布时间（来自快照或本实例抓取）
	localFetch time.Time // Redis 不可用时本实例上次自行抓取的时间
}

// runShared 每 snapshotSyncInterval 同步一次（尚无数据时每 snapshotWaitInterval），ctx 取消时退出
func (s *Store) runShared(ctx context.Context, interval time.Duration) {
	var st syncState
	for {
		s.syncShared(ctx, interval, &st)
		wait := snapshotSyncInterval
		if !s.Ready() {
			wait = snapshotWaitInterval
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// syncShared 快照比当前数据新则加载；快照超过 interval 未更新（或不存在）时争抢抓取权，抢到的实例抓取并发布。
// Redis 不可用时退回本实例按 interval 自行抓取
func (s *Store) syncShared(ctx context.Context, interval time.Duration, st *syncState) {
	published, err := s.coord.SnapshotTime(ctx)
	if err == nil {
		valid := true
		if published.After(st.applied) {
			valid = s.loadSnapshot(ctx, st)
		}
		// 快照无法使用（如滚动升级期间格式不兼容）时视同过期，重新抓取并发布
		if valid && !published.IsZero() && time.Since(published) < interval {
			return
		}
		var won bool
		if won, err = s.coord.Claim(ctx, claimTTL); err == nil {
			if won {
				s.fetchAndPublish(ctx, st)
			}
			return
		}
	}
	if ctx.Err() != nil {
		return
	}
	if time.Since(st.localFetch) < interval {
		return
	}
	s.log.Warn("shared risk list snapshot unavailable, fetching sources locally", "err", err)
	st.localFetch = time.Now()
	if s.Update(ctx) {
		st.applied = st.localFetch
	}
}

// fetchAndPublish 抓取全部数据源并发布快照；全部失败时不发布，抓取权到期后由任一实例重试
func (s *Store) fetchAndPublish(ctx context.Context, st *syncState) {
	started := time.Now()
	if !s.Update(ctx) {
		return
	}
	st.applied = started
	data, err := s.encodeSnapshot()
	if err != nil {
		s.log.Error("encode risk list snapshot failed", "err", err)
		return
	}
	if err := s.coord.PublishSnapshot(ctx, data, started); err != nil {
		s.log.Warn("publish risk list snapshot failed", "err", err)
		return
	}
	s.log.Info("risk list snapshot published", "bytes", len(data))
}

// loadSnapshot 加载共享快照并替换风险表，失败时保留当前数据。
// 返回 false 表示快照本身不可用（缺失、损坏或格式不兼容）；读取出错视为暂时故障，返回 true 等下一轮重试
func (s *Store) loadSnapshot(ctx context.Context, st *syncState) bool {
	data, published, err := s.coord.LoadSnapshot(ctx)
	if err != nil {
		s.log.Warn("load risk list snapshot failed", "err", err)
		return true
	}
	if data == nil {
		return false
	}
	snap, err := decodeSnapshot(data)
	if err != nil {
		s.log.Warn("ignoring invalid risk list snapshot", "err", err)
		return false
	}
	if !s.applySnapshot(snap) {
		s.log.Warn("risk list snapshot contains no configured sources")
		return false
	}
	st.applied = published
	s.log.Info("risk list loaded from shared snapshot", "published", published.UTC().Format(time.RFC3339), "bytes", len(data))
	return true
}

// applySnapshot 用快照替换各源的 lastGood 并重建风险表（按本实例的数据源配置合并，快照中未配置的源被忽略）。
// 本实例之后成为抓取方时，抓取失败的源同样沿用快照中的数据
func (s *Store) applySnapshot(snap snapshot) bool {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	lastGood := make(map[string][]Entry, len(snap.Feeds))
	var batches []batch
	for _, feed := range s.feeds {
		values, ok := snap.Feeds[feed.ID]
		if !ok {
			continue
		}
		entries := make([]Entry, len(values))
		for i, v := range values {
			entries[i] = Entry{Value: v, Source: feed.ID}
		}
		lastGood[feed.ID] = entries
		batches = append(batches, batch{entries: entries, tags: feed.Tags, tagOnly: feed.TagOnly})
	}
	if len(batches) == 0 {
		return false
	}
	s.lastGood = lastGood
	s.stats.restore(snap.Stats)
	s.replace(batches)
	s.ready.Store(true)
	return true
}

// encodeSnapshot 序列化各源最近一次成功的条目
func (s *Store) encodeSnapshot() ([]byte, error) {
	s.updateMu.Lock()
	snap := snapshot{Version: snapshotVersion, Feeds: make(map[string][]string, len(s.lastGood)), Stats: s.stats.Snapshot()}
	for id, entries := range s.lastGood {
		values := make([]string, len(entries))
		for i, e := range entries {
			values[i] = e.Value
		}
		snap.Feeds[id] = values
	}
	s.updateMu.Unlock()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(snap); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSnapshot(data []byte) (snapshot, error) {
	var snap snapshot
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return snap, err
	}
	if err := json.NewDecoder(zr).Decode(&snap); err != nil {
		return snap, err
	}
	if snap.Version != snapshotVersion {
		return snap, fmt.Errorf("unsupported snapshot version %d", snap.Version)
	}
	return snap, nil
}
