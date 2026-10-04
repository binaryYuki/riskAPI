package main

import (
	"encoding/xml"
	"net"
	"sync"
	"time"

	"github.com/armon/go-radix"
)

// CIDRInfo stores a parsed CIDR network and its original string representation
type CIDRInfo struct {
	Net          *net.IPNet
	OriginalCIDR string
}

// IPAssociation is used to pass IP/CIDR entries and their reasons from fetchers
type IPAssociation struct {
	Entry  string // IP or CIDR string
	Reason string
}

// Config stores application configuration
type Config struct {
	Timeout     int `json:"timeout"`
	Retries     int `json:"retries"`
	RetryDelay  int `json:"retry_delay"`
	Concurrency int `json:"concurrency"`
}

// WelcomeJson root handler
type WelcomeJson struct {
	Msg string `json:"message"`
}

// Proxy represents a proxy configuration
type Proxy struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

// IPCacheData represents the cached IP data structure
type IPCacheData struct {
	Timestamp int64    `json:"timestamp"`
	Entries   []string `json:"entries"`
}

// RSSFeed is a struct for parsing Project Honeypot RSS data
type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

// Response represents standard API response
type Response struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
}

// ResponseWithIP represents API response with IP field
type ResponseWithIP struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
	IP      string      `json:"ip,omitempty"`
}

// InfoResponse represents the response structure for /api/v1/info
type InfoResponse struct {
	Status  string                 `json:"status"`
	IP      string                 `json:"ip"`
	Results map[string]interface{} `json:"results"`
}

// RadixCache 封装 radix.Tree，实现与 cache.Cache 兼容的接口
// 支持 Set/Get/Delete/Flush/Items 方法
// 可选 TTL 与最大条目数：达到上限时按写入顺序（FIFO）淘汰最旧条目；
// 由于所有条目 TTL 相同，最旧写入即最早过期。ttl/maxEntries 为 0 表示不限制。
type RadixCache struct {
	tree       *radix.Tree
	mutex      sync.RWMutex
	ttl        time.Duration
	maxEntries int
	order      []cacheOrderItem // 写入顺序队列，用于 FIFO 淘汰
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time // 零值表示永不过期
}

type cacheOrderItem struct {
	key       string
	expiresAt time.Time
}

func NewRadixCache() *RadixCache {
	return NewBoundedRadixCache(0, 0)
}

func NewBoundedRadixCache(maxEntries int, ttl time.Duration) *RadixCache {
	return &RadixCache{
		tree:       radix.New(),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (e cacheEntry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

func (rc *RadixCache) Set(key string, value interface{}, _ ...interface{}) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	now := time.Now()
	var expiresAt time.Time
	if rc.ttl > 0 {
		expiresAt = now.Add(rc.ttl)
	}
	rc.tree.Insert(key, cacheEntry{value: value, expiresAt: expiresAt})
	if rc.maxEntries <= 0 && rc.ttl <= 0 {
		return
	}
	rc.order = append(rc.order, cacheOrderItem{key: key, expiresAt: expiresAt})
	rc.evictLocked(now)
}

// evictLocked 从队首清理过期条目，并在超出上限时淘汰最旧条目
func (rc *RadixCache) evictLocked(now time.Time) {
	for len(rc.order) > 0 {
		head := rc.order[0]
		v, ok := rc.tree.Get(head.key)
		// 队首记录已失效（被删除或被覆盖写入）：直接丢弃
		if !ok || !v.(cacheEntry).expiresAt.Equal(head.expiresAt) {
			rc.order = rc.order[1:]
			continue
		}
		overCap := rc.maxEntries > 0 && rc.tree.Len() > rc.maxEntries
		if !overCap && !v.(cacheEntry).expired(now) {
			break
		}
		rc.tree.Delete(head.key)
		rc.order = rc.order[1:]
	}
}

func (rc *RadixCache) Get(key string) (interface{}, bool) {
	rc.mutex.RLock()
	v, ok := rc.tree.Get(key)
	rc.mutex.RUnlock()
	if !ok {
		return nil, false
	}
	entry := v.(cacheEntry)
	if entry.expired(time.Now()) {
		rc.deleteIfExpired(key)
		return nil, false
	}
	return entry.value, true
}

// deleteIfExpired 加写锁后再次确认过期，避免误删并发写入的新值
func (rc *RadixCache) deleteIfExpired(key string) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	if v, ok := rc.tree.Get(key); ok && v.(cacheEntry).expired(time.Now()) {
		rc.tree.Delete(key)
	}
}

func (rc *RadixCache) Delete(key string) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	rc.tree.Delete(key)
}

func (rc *RadixCache) Flush() {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	rc.tree = radix.New()
	rc.order = nil
}

func (rc *RadixCache) Items() map[string]interface{} {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()
	now := time.Now()
	items := make(map[string]interface{})
	rc.tree.Walk(func(s string, v interface{}) bool {
		if entry := v.(cacheEntry); !entry.expired(now) {
			items[s] = entry.value
		}
		return false
	})
	return items
}

var (
	_              map[string]bool   // Stores single IPs for quick lookup
	riskyCIDRInfo  []CIDRInfo        // Stores parsed CIDR info
	reasonMap      map[string]string // Stores reasons for IPs/CIDRs
	riskyDataMutex sync.RWMutex      // Protects riskySingleIPs, riskyCIDRInfo, and reasonMap

	appCache *RadixCache

	cdnIPCache    map[string][]CIDRInfo      // CDN IP 缓存 (edgeone, cloudflare, fastly)
	idcIPCache    map[string][]CIDRInfo      // IDC IP 缓存 (aws, azure, gcp, etc.)
	cdnSingleIPs  map[string]map[string]bool // CDN 单个 IP 缓存
	idcSingleIPs  map[string]map[string]bool // IDC 单个 IP 缓存
	cdnIdcMutex   sync.RWMutex               // 保护 CDN/IDC 缓存的读写锁
	cacheInitOnce sync.Once                  // 确保缓存只初始化一次
)
