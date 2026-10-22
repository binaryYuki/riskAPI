// Package shared 可选的 Redis/Valkey 共享状态：多副本部署时让各实例共用 info 缓存、ip.sb 限速与风险数据快照，
// 避免每个副本各自请求外部数据源（同一出口 IP 下容易被限流）。
// 未配置 REDIS_URL 时不启用，各实例独立运行；运行期 Redis 不可用时各功能自动回退到本实例状态。
package shared

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// opTimeout 单次 Redis 操作的超时；请求路径上的操作（缓存、限速）须远小于外部 API 查询超时
	opTimeout = 300 * time.Millisecond
	// retryAfter Redis 出错后在这段时间内直接使用本地状态，不再让每个请求等待超时
	retryAfter = 5 * time.Second
)

// errUnavailable Redis 近期出错，处于 retryAfter 冷却期
var errUnavailable = errors.New("redis unavailable (cooling down)")

// Client 共享状态客户端，可并发使用
type Client struct {
	rdb    *redis.Client
	prefix string
	log    *slog.Logger
}

// Open 解析 redis:// 或 rediss:// 地址（同样适用于 Valkey）。地址格式错误时返回错误；
// 连不上只记录警告、不阻止启动，Redis 恢复前各功能使用本实例状态
func Open(ctx context.Context, url, prefix string, log *slog.Logger) (*Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	// 以调用方 ctx 的截止时间作为读写超时，各操作自行控制超时
	opt.ContextTimeoutEnabled = true
	c := &Client{rdb: redis.NewClient(opt), prefix: prefix, log: log}

	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := c.rdb.Ping(pctx).Err(); err != nil {
		log.Warn("redis unreachable at startup, using local state until it recovers", "addr", opt.Addr, "err", err)
	} else {
		log.Info("redis connected, sharing cache, rate limit and risk list snapshots", "addr", opt.Addr, "prefix", prefix)
	}
	return c, nil
}

// Close 关闭连接池
func (c *Client) Close() error {
	return c.rdb.Close()
}

func (c *Client) key(name string) string {
	return c.prefix + name
}

// health 记录某项共享功能的可用状态：出错后 retryAfter 内跳过 Redis（熔断），
// 只在状态切换时打日志，避免 Redis 故障期间每个请求都刷一条
type health struct {
	what     string
	log      *slog.Logger
	degraded atomic.Bool
	retryAt  atomic.Int64 // UnixNano，degraded 时在此之前跳过 Redis
}

// available 是否应尝试 Redis；冷却期结束后放行请求探测是否恢复
func (h *health) available() bool {
	return !h.degraded.Load() || time.Now().UnixNano() >= h.retryAt.Load()
}

func (h *health) fail(err error) {
	h.retryAt.Store(time.Now().Add(retryAfter).UnixNano())
	if !h.degraded.Swap(true) {
		h.log.Warn("redis unavailable, falling back to local state", "feature", h.what, "err", err, "retry_after", retryAfter)
	}
}

func (h *health) ok() {
	if h.degraded.Swap(false) {
		h.log.Info("redis recovered", "feature", h.what)
	}
}
