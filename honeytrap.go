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
}

// 运行时状态
var (
	// offenders: key=ip|ua, val=*offenderStat
	offenders sync.Map

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
		ua := c.Request.Header.Get("User-Agent")
		if ua == "" {
			ua = "-"
		}
		if len(ua) > 128 {
			ua = ua[:128]
		}
		key := ip + "|" + ua

		val, _ := offenders.LoadOrStore(key, &offenderStat{FirstSeen: time.Now(), LastSeen: time.Now()})
		st := val.(*offenderStat)

		// 如果在封禁期内，直接 429
		if time.Now().Before(st.BlockUntil) {
			atomic.AddUint64(&honeyBlocksTotal, 1)
			if cfg.EnableLog {
				log.Printf("[Honeytrap] block 429 ip=%s path=%s until=%s", ip, path, st.BlockUntil.Format(time.RFC3339))
			}
			c.AbortWithStatus(429)
			return
		}

		// 命中计数与窗口判断
		now := time.Now()
		atomic.AddInt64(&st.Count, 1)
		st.LastSeen = now

		// 简单滑动窗口：如果窗口之外，重置计数起点
		// 使用 FirstSeen 作为窗口起点；超过窗口则重置
		if now.Sub(st.FirstSeen) > cfg.BlockWindow {
			st.FirstSeen = now
			atomic.StoreInt64(&st.Count, 1)
		}

		cnt := atomic.LoadInt64(&st.Count)
		if int(cnt) >= cfg.BlockThreshold {
			st.BlockUntil = now.Add(cfg.BlockDuration)
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
	// 估算 offenders 数量
	offendersCount = 0
	offenders.Range(func(_, _ any) bool {
		offendersCount++
		return true
	})
	return atomic.LoadUint64(&honeyHitsTotal), atomic.LoadUint64(&honeyFakeOKTotal), atomic.LoadUint64(&honeyBlocksTotal), atomic.LoadUint64(&honeyPenaltyMsTotal), offendersCount
}
