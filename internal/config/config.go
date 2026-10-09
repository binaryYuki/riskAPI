// Package config 从环境变量加载全部运行配置。
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/honeytrap"
)

// Config 运行配置；字段默认值见 Load
type Config struct {
	Addr            string        // 监听地址
	ShutdownTimeout time.Duration // 优雅停机等待进行中请求的最长时间
	LogFormat       string        // LOG_FORMAT: text | json
	LogLevel        string        // LOG_LEVEL: debug | info | warn | error

	DataDir      string // CDN/IDC 列表、403 页面所在目录
	ProvidersDir string // MMDB 所在目录
	QQWryPath    string // QQWRY_PATH

	AllowedCORS    []string // ALLOWED_CORS：允许跨域的域名（含子域名，仅 https）
	AdminToken     string   // ADMIN_TOKEN：管理接口令牌，为空时管理接口禁用
	TrustedProxies []string // TRUSTED_PROXIES：可读取转发头的直连对端（CIDR/IP）

	ParseWorkerBase      string // PARSE_WORKER_BASE
	ParseSecret          string // PARSE_VV_SECRET，为空时 /api/v1/parse 返回 503
	ParseRateLimitPerMin int    // PARSE_RATE_LIMIT_PER_MIN，<=0 不限流

	InfoCacheMaxEntries int           // INFO_CACHE_MAX_ENTRIES
	InfoCacheTTL        time.Duration // /api/v1/info 结果缓存时间
	InfoPartialCacheTTL time.Duration // 外部 API 失败（结果不完整）时的缓存时间
	InfoLookupTimeout   time.Duration // 外部 API 查询超时

	FeedUpdateInterval time.Duration
	FeedFetch          feeds.FetchConfig
	Feeds              []feeds.Feed

	Honeytrap honeytrap.Config
}

// DefaultTrustedProxies 默认可信代理：回环 + 私网（平台内部负载均衡通常位于这些网段）
var DefaultTrustedProxies = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "fc00::/7",
}

// Load 读取环境变量并填充默认值
func Load() Config {
	return Config{
		Addr:            envString("LISTEN_ADDR", ":8080"),
		ShutdownTimeout: 15 * time.Second,
		LogFormat:       envString("LOG_FORMAT", "text"),
		LogLevel:        envString("LOG_LEVEL", "info"),

		DataDir:      "data",
		ProvidersDir: "providers",
		QQWryPath:    envString("QQWRY_PATH", "providers/qqwry/qqwry.dat"),

		AllowedCORS:    envList("ALLOWED_CORS", []string{"catyuki.com", "tzpro.xyz"}),
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
		TrustedProxies: envList("TRUSTED_PROXIES", DefaultTrustedProxies),

		ParseWorkerBase:      envString("PARSE_WORKER_BASE", "https://xhs-proxy.tzpro.workers.dev"),
		ParseSecret:          envString("PARSE_VV_SECRET", ""),
		ParseRateLimitPerMin: envInt("PARSE_RATE_LIMIT_PER_MIN", 30),

		InfoCacheMaxEntries: envInt("INFO_CACHE_MAX_ENTRIES", 20000),
		InfoCacheTTL:        time.Hour,
		InfoPartialCacheTTL: time.Minute,
		InfoLookupTimeout:   1500 * time.Millisecond,

		FeedUpdateInterval: time.Hour,
		FeedFetch: feeds.FetchConfig{
			Timeout:    10 * time.Second,
			Retries:    3,
			RetryDelay: 2 * time.Second,
		},
		Feeds: feeds.DefaultFeeds,

		Honeytrap: honeytrap.Config{
			Enabled:        envBool("HONEYTRAP_ENABLED", true),
			BaseDelayMinMS: envInt("HONEYTRAP_BASE_DELAY_MIN_MS", 40),
			BaseDelayMaxMS: envInt("HONEYTRAP_BASE_DELAY_MAX_MS", 220),
			MaxPenaltyMS:   envInt("HONEYTRAP_MAX_PENALTY_MS", 1200),
			FakeOKProb:     envFloat("HONEYTRAP_FAKEOK", 1),
			EnableLog:      envBool("HONEYTRAP_LOG", true),
			FlagThreshold:  envInt("HONEYTRAP_FLAG_THRESHOLD", 8),
			FlagDuration:   time.Duration(envInt("HONEYTRAP_FLAG_DURATION_SEC", 3600)) * time.Second,
			BlockThreshold: envInt("HONEYTRAP_BLOCK_THRESHOLD", 16),
			BlockWindow:    time.Duration(envInt("HONEYTRAP_BLOCK_WINDOW_SEC", 60)) * time.Second,
			BlockDuration:  time.Duration(envInt("HONEYTRAP_BLOCK_DURATION_SEC", 180)) * time.Second,
			MaxOffenders:   envInt("HONEYTRAP_MAX_OFFENDERS", 100000),
		},
	}
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envList(key string, def []string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func envInt(key string, def int) int {
	if i, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
		return i
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if f, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64); err == nil {
		return f
	}
	return def
}

func envBool(key string, def bool) bool {
	if b, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(key))); err == nil {
		return b
	}
	return def
}
