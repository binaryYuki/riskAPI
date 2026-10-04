// Package honeytrap 对扫描器常探测的可疑路径做延迟（tarpit）、伪造 200 与软封禁。
package honeytrap

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Config 可疑路径、延迟与软封策略
type Config struct {
	Enabled        bool
	SuspiciousPath *regexp.Regexp // 为 nil 时使用 DefaultSuspiciousRegex
	BaseDelayMinMS int
	BaseDelayMaxMS int
	MaxPenaltyMS   int
	FakeOKProb     float64 // 返回伪造 200 页面的概率
	EnableLog      bool
	Decoys         bool // 是否注册诱饵路由

	// 软封参数（在窗口期内命中次数达到阈值则一段时间内 429）
	BlockThreshold int           // 次数阈值
	BlockWindow    time.Duration // 统计窗口
	BlockDuration  time.Duration // 封禁时长

	MaxOffenders int // 最多跟踪的来源数，超出后新来源不再计数（仍施加基础延迟）
}

// withDefaults 为未设置的字段填充默认值
func (cfg Config) withDefaults() Config {
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
	return cfg
}

type offenderStat struct {
	mu         sync.Mutex
	count      int64
	firstSeen  time.Time
	lastSeen   time.Time
	blockUntil time.Time
}

// Trap 蜜罐实例，持有来源统计与指标
type Trap struct {
	cfg Config
	log *slog.Logger

	offenders sync.Map // 客户端 IP → *offenderStat
	tracked   atomic.Int64

	hits      atomic.Uint64
	fakeOK    atomic.Uint64
	blocks    atomic.Uint64
	penaltyMS atomic.Uint64
}

// Stats 蜜罐指标快照
type Stats struct {
	Hits      uint64 `json:"hits_total"`
	FakeOK    uint64 `json:"fake_ok_total"`
	Blocks    uint64 `json:"blocks_total"`
	PenaltyMS uint64 `json:"penalty_ms_total"`
	Offenders int    `json:"unique_offenders_cnt"`
}

// New 创建蜜罐
func New(cfg Config, log *slog.Logger) *Trap {
	return &Trap{cfg: cfg.withDefaults(), log: log}
}

// Stats 返回指标快照
func (t *Trap) Stats() Stats {
	return Stats{
		Hits:      t.hits.Load(),
		FakeOK:    t.fakeOK.Load(),
		Blocks:    t.blocks.Load(),
		PenaltyMS: t.penaltyMS.Load(),
		Offenders: int(t.tracked.Load()),
	}
}

// RunJanitor 定期清理窗口已过且未处于封禁期的记录，防止来源表无限增长；ctx 取消时退出
func (t *Trap) RunJanitor(ctx context.Context) {
	ticker := time.NewTicker(t.cfg.BlockWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.prune(now)
		}
	}
}

// Middleware 返回 gin 中间件；clientIP 用于识别来源（按 IP 计数，与 UA 无关）
func (t *Trap) Middleware(clientIP func(*gin.Context) string) gin.HandlerFunc {
	cfg := t.cfg
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

		ip := clientIP(c)
		now := time.Now()

		// 计数与封禁判断在单条记录锁内完成，避免并发读写竞争
		var cnt int64 = 1 // 超出跟踪上限时不计数，仅施加基础延迟
		blocked, newlyBlocked := false, false
		var blockUntil time.Time
		if st := t.loadOrTrack(ip, now); st != nil {
			st.mu.Lock()
			if now.Before(st.blockUntil) {
				blocked = true
			} else {
				// 固定窗口：超过窗口则重置计数起点
				if now.Sub(st.firstSeen) > cfg.BlockWindow {
					st.firstSeen = now
					st.count = 0
				}
				st.count++
				if int(st.count) >= cfg.BlockThreshold {
					st.blockUntil = now.Add(cfg.BlockDuration)
					newlyBlocked = true
				}
			}
			st.lastSeen = now
			cnt = st.count
			blockUntil = st.blockUntil
			st.mu.Unlock()
		}

		if blocked || newlyBlocked {
			t.blocks.Add(1)
			if cfg.EnableLog {
				if blocked {
					t.log.Info("honeytrap block", "ip", ip, "path", path, "until", blockUntil.Format(time.RFC3339))
				} else {
					t.log.Info("honeytrap soft block", "ip", ip, "path", path, "count", cnt, "duration", cfg.BlockDuration)
				}
			}
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		// 延迟：基础随机 + 惩罚（指数增长并封顶）
		totalSleep := jitter(cfg.BaseDelayMinMS, cfg.BaseDelayMaxMS) + backoffPenalty(int(cnt), cfg.MaxPenaltyMS)
		t.penaltyMS.Add(uint64(totalSleep))
		t.hits.Add(1)
		time.Sleep(time.Duration(totalSleep) * time.Millisecond)

		// 按概率返回伪造的 200 页面
		if rand.Float64() < cfg.FakeOKProb {
			t.fakeOK.Add(1)
			if cfg.EnableLog {
				t.log.Info("honeytrap fake200", "ip", ip, "path", path, "count", cnt, "sleep_ms", totalSleep)
			}
			c.Header("Cache-Control", "no-store")
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Server", pickServerHeader())
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fakeOKHTML))
			c.Abort()
			return
		}

		if cfg.EnableLog {
			t.log.Info("honeytrap tarpit", "ip", ip, "path", path, "count", cnt, "sleep_ms", totalSleep)
		}
		c.Next()
	}
}

// loadOrTrack 返回来源的统计记录；超出跟踪上限的新来源返回 nil
func (t *Trap) loadOrTrack(ip string, now time.Time) *offenderStat {
	if v, ok := t.offenders.Load(ip); ok {
		return v.(*offenderStat)
	}
	if t.tracked.Load() >= int64(t.cfg.MaxOffenders) {
		return nil
	}
	v, loaded := t.offenders.LoadOrStore(ip, &offenderStat{firstSeen: now, lastSeen: now})
	if !loaded {
		t.tracked.Add(1)
	}
	return v.(*offenderStat)
}

func (t *Trap) prune(now time.Time) {
	window := t.cfg.BlockWindow
	t.offenders.Range(func(k, v any) bool {
		st := v.(*offenderStat)
		st.mu.Lock()
		stale := now.Sub(st.lastSeen) > window && !now.Before(st.blockUntil)
		st.mu.Unlock()
		if stale && t.offenders.CompareAndDelete(k, v) {
			t.tracked.Add(-1)
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

// backoffPenalty 第 n 次命中惩罚 50·2^(n-2) 毫秒，封顶 maxMS
func backoffPenalty(count, maxMS int) int {
	if count <= 1 {
		return 0
	}
	if count-2 >= 30 { // 避免移位溢出
		return maxMS
	}
	return min(50<<(count-2), maxMS)
}

const fakeOKHTML = "<!doctype html><meta charset=utf-8>\n<title>OK</title><div style=\"padding:24px;font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif\"><p>OK</p><p>Request received.</p></div>"
