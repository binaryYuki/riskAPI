// Package cache 提供带 TTL 与容量上限的并发安全缓存。
package cache

import (
	"sync"
	"time"

	"github.com/armon/go-radix"
)

// Cache 基于 radix.Tree 的键值缓存，支持 Set/Get/Delete/Flush/Items。
// 可选 TTL 与最大条目数：达到上限时按写入顺序（FIFO）淘汰最旧条目；
// 默认 TTL 下最旧写入即最早过期。ttl/maxEntries 为 0 表示不限制。
type Cache struct {
	tree       *radix.Tree
	mutex      sync.RWMutex
	ttl        time.Duration
	maxEntries int
	order      []orderItem // 写入顺序队列，用于 FIFO 淘汰
}

type entry struct {
	value     any
	expiresAt time.Time // 零值表示永不过期
}

type orderItem struct {
	key       string
	expiresAt time.Time
}

// New 创建缓存；maxEntries<=0 不限容量，ttl<=0 永不过期
func New(maxEntries int, ttl time.Duration) *Cache {
	return &Cache{
		tree:       radix.New(),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// Set 以默认 TTL 写入
func (c *Cache) Set(key string, value any) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL 以指定 TTL 写入（ttl<=0 表示永不过期）。
// TTL 不同的条目共用写入顺序队列：淘汰仍按写入顺序进行，过期条目在 Get 时惰性删除，容量上限始终有效。
func (c *Cache) SetWithTTL(key string, value any, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}
	c.tree.Insert(key, entry{value: value, expiresAt: expiresAt})
	if c.maxEntries <= 0 && ttl <= 0 {
		return
	}
	c.order = append(c.order, orderItem{key: key, expiresAt: expiresAt})
	c.evictLocked(now)
}

// evictLocked 从队首清理过期条目，并在超出上限时淘汰最旧条目
func (c *Cache) evictLocked(now time.Time) {
	for len(c.order) > 0 {
		head := c.order[0]
		v, ok := c.tree.Get(head.key)
		// 队首记录已失效（被删除或被覆盖写入）：直接丢弃
		if !ok || !v.(entry).expiresAt.Equal(head.expiresAt) {
			c.order = c.order[1:]
			continue
		}
		overCap := c.maxEntries > 0 && c.tree.Len() > c.maxEntries
		if !overCap && !v.(entry).expired(now) {
			break
		}
		c.tree.Delete(head.key)
		c.order = c.order[1:]
	}
}

// Get 读取未过期的值
func (c *Cache) Get(key string) (any, bool) {
	c.mutex.RLock()
	v, ok := c.tree.Get(key)
	c.mutex.RUnlock()
	if !ok {
		return nil, false
	}
	e := v.(entry)
	if e.expired(time.Now()) {
		c.deleteIfExpired(key)
		return nil, false
	}
	return e.value, true
}

// deleteIfExpired 加写锁后再次确认过期，避免误删并发写入的新值
func (c *Cache) deleteIfExpired(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if v, ok := c.tree.Get(key); ok && v.(entry).expired(time.Now()) {
		c.tree.Delete(key)
	}
}

// Delete 删除键
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.tree.Delete(key)
}

// DeletePrefix 删除所有以 prefix 开头的键，返回删除数量
func (c *Cache) DeletePrefix(prefix string) int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.tree.DeletePrefix(prefix)
}

// Flush 清空全部条目
func (c *Cache) Flush() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.tree = radix.New()
	c.order = nil
}

// Len 返回当前条目数（可能包含尚未惰性删除的过期条目）
func (c *Cache) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.tree.Len()
}
