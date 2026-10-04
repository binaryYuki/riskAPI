package main

import (
	"log"
	"math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type offenderStat struct {
	mu         sync.Mutex
	Count      int64
	FirstSeen  time.Time
	LastSeen   time.Time
	BlockUntil time.Time
}

// HoneytrapConfig 用于配置可疑路径、延迟与软封策略
type HoneytrapConfig struct {
	Enabled        bool
	SuspiciousPath *regexp.Regexp
	BaseDelayMinMS int
	BaseDelayMaxMS int
	MaxPenaltyMS   int
	FakeOKProb     float64
	EnableLog      bool

	// 软封参数（在窗口期内命中次数超过阈值则一段时间内 429）
	BlockThreshold int           // 次数阈值
	BlockWindow    time.Duration // 统计窗口
	BlockDuration  time.Duration // 封禁时长

	MaxOffenders int // 最多跟踪的来源数，超出后新来源不再计数（仍施加基础延迟）
}

// 运行时状态
var (
	// offenders: key=客户端 IP, val=*offenderStat
	offenders        sync.Map
	trackedOffenders int64

	// 指标
	honeyHitsTotal      uint64
	honeyFakeOKTotal    uint64
	honeyBlocksTotal    uint64
	honeyPenaltyMsTotal uint64
)

func Honeytrap(cfg HoneytrapConfig) gin.HandlerFunc {
	// 默认值
	if cfg.SuspiciousPath == nil {
		cfg.SuspiciousPath = DefaultSuspiciousRegex()
	}
	if cfg.BaseDelayMinMS <= 0 {
		cfg.BaseDelayMinMS = 30
	}
	if cfg.BaseDelayMaxMS < cfg.BaseDelayMinMS {
		cfg.BaseDelayMaxMS = cfg.BaseDelayMinMS + 200
	}
	if cfg.MaxPenaltyMS <= 0 {
		cfg.MaxPenaltyMS = 1500
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 12
	}
	if cfg.BlockWindow <= 0 {
		cfg.BlockWindow = 60 * time.Second
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 2 * time.Minute
	}
	if cfg.MaxOffenders <= 0 {
		cfg.MaxOffenders = 100000
	}
	if cfg.Enabled {
		go offenderJanitor(cfg)
	}

	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if !cfg.SuspiciousPath.MatchString(path) {
			c.Next()
			return
		}

		ip := getClientIPFromCDNHeaders(c)
		now := time.Now()

		// 计数与封禁判断在单条记录锁内完成，避免并发读写竞争
		var cnt int64
		blocked, newlyBlocked := false, false
		var blockUntil time.Time
		if st := loadOrTrackOffender(ip, now, cfg.MaxOffenders); st != nil {
			st.mu.Lock()
			if now.Before(st.BlockUntil) {
				blocked = true
			} else {
				// 简单固定窗口：超过窗口则重置计数起点
				if now.Sub(st.FirstSeen) > cfg.BlockWindow {
					st.FirstSeen = now
					st.Count = 0
				}
				st.Count++
				if int(st.Count) >= cfg.BlockThreshold {
					st.BlockUntil = now.Add(cfg.BlockDuration)
					newlyBlocked = true
				}
			}
			st.LastSeen = now
			cnt = st.Count
			blockUntil = st.BlockUntil
			st.mu.Unlock()
		} else {
			cnt = 1 // 超出跟踪上限：不计数，仅施加基础延迟
		}

		// 如果在封禁期内，直接 429
		if blocked {
			atomic.AddUint64(&honeyBlocksTotal, 1)
			if cfg.EnableLog {
				log.Printf("[Honeytrap] block 429 ip=%s path=%s until=%s", ip, path, blockUntil.Format(time.RFC3339))
			}
			c.AbortWithStatus(429)
			return
		}
		if newlyBlocked {
			atomic.AddUint64(&honeyBlocksTotal, 1)
			if cfg.EnableLog {
				log.Printf("[Honeytrap] soft block ip=%s path=%s count=%d duration=%s", ip, path, cnt, cfg.BlockDuration)
			}
			c.AbortWithStatus(429)
			return
		}

		// 计算延迟：基础随机 + 惩罚（次方增长并封顶）
		baseDelay := jitter(cfg.BaseDelayMinMS, cfg.BaseDelayMaxMS)
		penalty := backoffPenalty(int(cnt), cfg.MaxPenaltyMS)
		totalSleep := baseDelay + penalty
		atomic.AddUint64(&honeyPenaltyMsTotal, uint64(totalSleep))
		atomic.AddUint64(&honeyHitsTotal, 1)
		time.Sleep(time.Duration(totalSleep) * time.Millisecond)

		// 可能返回 200 假内容
		if rand.Float64() < cfg.FakeOKProb {
			atomic.AddUint64(&honeyFakeOKTotal, 1)
			if cfg.EnableLog {
				log.Printf("[Honeytrap] fake200 ip=%s path=%s count=%d sleep=%dms", ip, path, cnt, totalSleep)
			}
			c.Header("Cache-Control", "no-store")
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Server", pickServerHeader())
			c.Data(200, "text/html; charset=utf-8", []byte(fakeOKHTML()))
			c.Abort()
			return
		}

		if cfg.EnableLog {
			log.Printf("[Honeytrap] tarpit ip=%s path=%s count=%d sleep=%dms", ip, path, cnt, totalSleep)
		}

		c.Next()
	}
}

// loadOrTrackOffender 返回来源的统计记录；超出跟踪上限的新来源返回 nil
func loadOrTrackOffender(ip string, now time.Time, maxOffenders int) *offenderStat {
	if v, ok := offenders.Load(ip); ok {
		return v.(*offenderStat)
	}
	if atomic.LoadInt64(&trackedOffenders) >= int64(maxOffenders) {
		return nil
	}
	v, loaded := offenders.LoadOrStore(ip, &offenderStat{FirstSeen: now, LastSeen: now})
	if !loaded {
		atomic.AddInt64(&trackedOffenders, 1)
	}
	return v.(*offenderStat)
}

// offenderJanitor 定期清理窗口已过且未处于封禁期的记录，防止 offenders 无限增长
func offenderJanitor(cfg HoneytrapConfig) {
	ticker := time.NewTicker(cfg.BlockWindow)
	defer ticker.Stop()
	for now := range ticker.C {
		pruneOffenders(now, cfg.BlockWindow)
	}
}

func pruneOffenders(now time.Time, window time.Duration) {
	offenders.Range(func(k, v any) bool {
		st := v.(*offenderStat)
		st.mu.Lock()
		stale := now.Sub(st.LastSeen) > window && !now.Before(st.BlockUntil)
		st.mu.Unlock()
		if stale && offenders.CompareAndDelete(k, v) {
			atomic.AddInt64(&trackedOffenders, -1)
		}
		return true
	})
}

func pickServerHeader() string {
	candidates := []string{"nginx", "Apache", "Caddy"}
	return candidates[rand.IntN(len(candidates))]
}

func jitter(minMS, maxMS int) int {
	if maxMS <= minMS {
		return minMS
	}
	return minMS + rand.IntN(maxMS-minMS+1)
}

func backoffPenalty(count, maxMS int) int {
	pen := 0
	if count > 1 {
		pen = 50 << (count - 2)
	}
	if pen > maxMS {
		return maxMS
	}
	if pen < 0 {
		return 0
	}
	return pen
}

func fakeOKHTML() string {
	return "<!doctype html><meta charset=utf-8>\n<title>OK</title><div style=\"padding:24px;font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif\"><p>OK</p><p>Request received.</p></div>"
}

// HoneytrapEnabledFromEnv 读取是否启用
func HoneytrapEnabledFromEnv() bool {
	env := strings.TrimSpace(os.Getenv("HONEYTRAP_ENABLED"))
	if env == "" {
		return true
	}
	v, err := strconv.ParseBool(env)
	if err != nil {
		return true
	}
	return v
}

// HoneytrapConfigFromEnv 从环境变量读取配置
func HoneytrapConfigFromEnv() HoneytrapConfig {
	cfg := HoneytrapConfig{
		Enabled:        HoneytrapEnabledFromEnv(),
		SuspiciousPath: DefaultSuspiciousRegex(),
		BaseDelayMinMS: getEnvInt("HONEYTRAP_BASE_DELAY_MIN_MS", 40),
		BaseDelayMaxMS: getEnvInt("HONEYTRAP_BASE_DELAY_MAX_MS", 220),
		MaxPenaltyMS:   getEnvInt("HONEYTRAP_MAX_PENALTY_MS", 1200),
		FakeOKProb:     getEnvFloat("HONEYTRAP_FAKEOK", 0.2),
		EnableLog:      getEnvBool("HONEYTRAP_LOG", true),

		BlockThreshold: getEnvInt("HONEYTRAP_BLOCK_THRESHOLD", 16),
		BlockWindow:    time.Duration(getEnvInt("HONEYTRAP_BLOCK_WINDOW_SEC", 60)) * time.Second,
		BlockDuration:  time.Duration(getEnvInt("HONEYTRAP_BLOCK_DURATION_SEC", 180)) * time.Second,
		MaxOffenders:   getEnvInt("HONEYTRAP_MAX_OFFENDERS", 100000),
	}
	return cfg
}

func getEnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func getEnvFloat(key string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func getEnvBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// HoneytrapMetricsSnapshot 返回蜜罐指标快照
func HoneytrapMetricsSnapshot() (hits, fakeOK, blocks, penaltyTotal uint64, offendersCount int) {
	offendersCount = int(atomic.LoadInt64(&trackedOffenders))
	return atomic.LoadUint64(&honeyHitsTotal), atomic.LoadUint64(&honeyFakeOKTotal), atomic.LoadUint64(&honeyBlocksTotal), atomic.LoadUint64(&honeyPenaltyMsTotal), offendersCount
}
