package shared

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"golang.org/x/time/rate"
)

// RateLimiter 跨实例共享的限速器（GCRA，所有实例合计不超过上限）。
// Redis 不可用时退回 fallback（每个实例各自限速）
type RateLimiter struct {
	limiter  *redis_rate.Limiter
	key      string
	limit    redis_rate.Limit
	fallback *rate.Limiter
	health   *health
}

// RateLimiter 创建名为 name 的共享限速器：所有实例合计每秒最多 perSecond 次，请求间隔均匀（burst=1）。
// perSecond 须大于 0；fallback 为 Redis 不可用时本实例使用的限速器
func (c *Client) RateLimiter(name string, perSecond float64, fallback *rate.Limiter) *RateLimiter {
	return &RateLimiter{
		limiter: redis_rate.NewLimiter(c.rdb),
		key:     c.key("ratelimit:" + name),
		// redis_rate 的 Rate 为整数：用"每 1/perSecond 秒 1 次"表达小数速率
		limit:    redis_rate.Limit{Rate: 1, Burst: 1, Period: time.Duration(float64(time.Second) / perSecond)},
		fallback: fallback,
		health:   &health{what: "ratelimit:" + name, log: c.log},
	}
}

// Wait 阻塞到获得配额；所需等待超过 ctx 截止时间时立即返回错误（与 rate.Limiter.Wait 一致）
func (l *RateLimiter) Wait(ctx context.Context) error {
	for {
		if !l.health.available() {
			return l.fallback.Wait(ctx)
		}
		res, err := l.allow(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			l.health.fail(err)
			return l.fallback.Wait(ctx)
		}
		l.health.ok()
		if res.Allowed > 0 {
			return nil
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < res.RetryAfter {
			return fmt.Errorf("shared rate limit: would wait %s, exceeds context deadline", res.RetryAfter)
		}
		t := time.NewTimer(res.RetryAfter)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (l *RateLimiter) allow(ctx context.Context) (*redis_rate.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return l.limiter.Allow(ctx, l.key, l.limit)
}
