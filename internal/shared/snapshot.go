package shared

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// snapshotTimeout 读写风险数据快照（数 MB）的超时
const snapshotTimeout = 30 * time.Second

// Snapshots 风险数据快照的发布与读取，实现 feeds.Coordinator
type Snapshots struct {
	c       *Client
	dataKey string
	timeKey string // 发布时间（Unix 毫秒），与数据在同一事务中写入
	lockKey string
}

// Snapshots 返回名为 name 的快照存储
func (c *Client) Snapshots(name string) *Snapshots {
	base := c.key("snapshot:" + name)
	return &Snapshots{c: c, dataKey: base + ":data", timeKey: base + ":published", lockKey: base + ":claim"}
}

// SnapshotTime 最近一次发布的时间；没有快照时返回零值
func (s *Snapshots) SnapshotTime(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	ms, err := s.c.rdb.Get(ctx, s.timeKey).Int64()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms), nil
}

// LoadSnapshot 读取最近一次发布的快照与其发布时间；没有快照时返回 nil, 零值, nil
func (s *Snapshots) LoadSnapshot(ctx context.Context) ([]byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	vals, err := s.c.rdb.MGet(ctx, s.timeKey, s.dataKey).Result()
	if err != nil {
		return nil, time.Time{}, err
	}
	ts, ok1 := vals[0].(string)
	data, ok2 := vals[1].(string)
	if !ok1 || !ok2 {
		return nil, time.Time{}, nil
	}
	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, time.Time{}, err
	}
	return []byte(data), time.UnixMilli(ms), nil
}

// PublishSnapshot 原子写入快照与发布时间。快照不设过期：即使很旧，也比新实例没有数据好，
// 部署 Redis 时应使用 volatile-* 淘汰策略，避免内存不足时快照被淘汰
func (s *Snapshots) PublishSnapshot(ctx context.Context, data []byte, published time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	_, err := s.c.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, s.dataKey, data, 0)
		p.Set(ctx, s.timeKey, published.UnixMilli(), 0)
		return nil
	})
	return err
}

// Claim 争抢一轮抓取权：ttl 内其它实例的 Claim 都返回 false。
// 不主动释放：抓取方崩溃时到期后由其它实例重试
func (s *Snapshots) Claim(ctx context.Context, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return s.c.rdb.SetNX(ctx, s.lockKey, time.Now().UnixMilli(), ttl).Result()
}
