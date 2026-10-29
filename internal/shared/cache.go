package shared

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache 跨实例共享的字节缓存（/api/v1/info 的二级缓存）。
// 出错时返回错误由调用方决定是否忽略；状态切换时打日志
type Cache struct {
	c      *Client
	prefix string // 完整键前缀
	health *health
}

// Cache 返回名为 name 的缓存命名空间
func (c *Client) Cache(name string) *Cache {
	return &Cache{c: c, prefix: c.key("cache:" + name + ":"), health: &health{what: "cache:" + name, log: c.log}}
}

// Get 返回值与剩余有效期；未命中时返回 nil, 0, nil
func (k *Cache) Get(ctx context.Context, key string) ([]byte, time.Duration, error) {
	if !k.health.available() {
		return nil, 0, errUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	var get *redis.StringCmd
	var ttl *redis.DurationCmd
	_, err := k.c.rdb.Pipelined(ctx, func(p redis.Pipeliner) error {
		get = p.Get(ctx, k.prefix+key)
		ttl = p.PTTL(ctx, k.prefix+key)
		return nil
	})
	if errors.Is(err, redis.Nil) {
		k.health.ok()
		return nil, 0, nil
	}
	if err != nil {
		k.health.fail(err)
		return nil, 0, err
	}
	k.health.ok()
	// 两条命令之间键过期时 PTTL 为负数，视为未命中
	if ttl.Val() <= 0 {
		return nil, 0, nil
	}
	return []byte(get.Val()), ttl.Val(), nil
}

// Set 写入，ttl 必须大于 0（共享缓存不允许永不过期的条目，否则会占满 Redis）
func (k *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("shared cache: ttl must be positive")
	}
	if !k.health.available() {
		return errUnavailable
	}
	// 写入不应因请求结束而中断
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	if err := k.c.rdb.Set(ctx, k.prefix+key, value, ttl).Err(); err != nil {
		k.health.fail(err)
		return err
	}
	k.health.ok()
	return nil
}

// Delete 删除单个键
func (k *Cache) Delete(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return k.c.rdb.Del(ctx, k.prefix+key).Err()
}

// Flush 删除该命名空间下全部键（SCAN 分批 UNLINK，不阻塞 Redis），返回删除数量
func (k *Cache) Flush(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	deleted := 0
	iter := k.c.rdb.Scan(ctx, 0, k.prefix+"*", 1000).Iterator()
	batch := make([]string, 0, 1000)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := k.c.rdb.Unlink(ctx, batch...).Result()
		deleted += int(n)
		batch = batch[:0]
		return err
	}
	for iter.Next(ctx) {
		batch = append(batch, iter.Val())
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return deleted, err
			}
		}
	}
	if err := iter.Err(); err != nil {
		return deleted, err
	}
	return deleted, flush()
}
