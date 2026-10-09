// Package honeytrap 识别扫描器常探测的路径并按来源计分：
// 规则表（rules.go）给路径定权重，漏桶（score.go）按来源累计分数，
// 本文件按分数分级响应——延迟（tarpit）、伪造内容（bait.go）、标记、软封禁。
// 伪造内容中的假凭据会被登记（creds.go），之后在请求中再次出现时即可认出；
// 全部过程以事件形式输出（events.go）。
package honeytrap

import (
	"context"
	"crypto/rand"
	"hash/maphash"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Source 被蜜罐标记的来源在风险判定中使用的来源名
const Source = "honeytrap"

const (
	scoredKey   = "honeytrap_scored" // gin.Context 键：本次请求已由 Middleware 计分
	maxDelaying = 1024               // 同时处于延迟中的请求上限，超出后不再延迟，避免拖住自身

	maxEventPathLen = 512 // 事件中保留的路径与 UA 长度
	maxEventUALen   = 256
)

// Config 规则、延迟、伪造内容与分级策略
type Config struct {
	Enabled        bool
	Rules          []Rule // 为 nil 时使用 DefaultRules
	BaseDelayMinMS int
	BaseDelayMaxMS int
	MaxPenaltyMS   int
	FakeOKProb     float64 // 命中规则时返回伪造内容的概率；按来源与路径确定，同一来源重复请求结果一致
	EnableLog      bool

	// 分级参数：分数达到 FlagThreshold 的来源被标记（Flagged 返回 true），
	// 达到 BlockThreshold 的来源在 BlockDuration 内一律 429
	FlagThreshold  int
	FlagDuration   time.Duration
	BlockThreshold int
	BlockWindow    time.Duration // 分数从 BlockThreshold 漏空所需的时间
	BlockDuration  time.Duration

	MaxOffenders int // 最多跟踪的来源数，超出后淘汰最久未活动的来源

	Sink Sink // 可选：接收全部蜜罐事件，用于持久化；为 nil 时事件只写日志
}

// withDefaults 为未设置的字段填充默认值
func (cfg Config) withDefaults() Config {
	if cfg.Rules == nil {
		cfg.Rules = DefaultRules()
	}
	if cfg.BaseDelayMinMS <= 0 {
		cfg.BaseDelayMinMS = 40
	}
	if cfg.BaseDelayMaxMS < cfg.BaseDelayMinMS {
		cfg.BaseDelayMaxMS = cfg.BaseDelayMinMS + 180
	}
	if cfg.MaxPenaltyMS <= 0 {
		cfg.MaxPenaltyMS = 1200
	}
	cfg.FakeOKProb = min(max(cfg.FakeOKProb, 0), 1)
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 16
	}
	if cfg.BlockWindow <= 0 {
		cfg.BlockWindow = 60 * time.Second
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 3 * time.Minute
	}
	if cfg.FlagThreshold <= 0 {
		cfg.FlagThreshold = int(WeightHigh)
	}
	cfg.FlagThreshold = min(cfg.FlagThreshold, cfg.BlockThreshold) // 被封禁的来源必然已被标记
	if cfg.FlagDuration <= 0 {
		cfg.FlagDuration = time.Hour
	}
	if cfg.MaxOffenders <= 0 {
		cfg.MaxOffenders = 100000
	}
	return cfg
}

// Trap 蜜罐实例，持有规则表、来源分数与指标
type Trap struct {
	cfg    Config
	log    *slog.Logger
	rules  *RuleSet
	scores *scorer
	creds  *credRegistry // 已签发的假凭据，用于在后续请求中认出它们

	hashSeed  maphash.Seed // 路径去重与伪造决策
	tokenSeed []byte       // 假凭据，进程内保持不变

	delaying  atomic.Int64
	hits      atomic.Uint64
	fakeOK    atomic.Uint64
	blocks    atomic.Uint64
	flags     atomic.Uint64
	logins    atomic.Uint64
	reuses    atomic.Uint64
	penaltyMS atomic.Uint64
}

// Stats 蜜罐指标快照
type Stats struct {
	Hits      uint64 `json:"hits_total"`
	FakeOK    uint64 `json:"fake_ok_total"`
	Blocks    uint64 `json:"blocks_total"`
	Flags     uint64 `json:"flags_total"`
	Logins    uint64 `json:"login_attempts_total"`
	Reuses    uint64 `json:"credential_reuse_total"`
	PenaltyMS uint64 `json:"penalty_ms_total"`
	Offenders int    `json:"unique_offenders_cnt"`
	Flagged   int    `json:"flagged_sources_cnt"`
	Issued    int    `json:"issued_credentials_cnt"`
}

// New 创建蜜罐
func New(cfg Config, log *slog.Logger) *Trap {
	cfg = cfg.withDefaults()
	tokenSeed := make([]byte, 16)
	_, _ = rand.Read(tokenSeed)
	return &Trap{
		cfg:   cfg,
		log:   log,
		rules: NewRuleSet(cfg.Rules),
		scores: newScorer(scoreConfig{
			flagThreshold:  float64(cfg.FlagThreshold),
			blockThreshold: float64(cfg.BlockThreshold),
			leakPerSec:     float64(cfg.BlockThreshold) / cfg.BlockWindow.Seconds(),
			flagDuration:   cfg.FlagDuration,
			blockDuration:  cfg.BlockDuration,
			idle:           cfg.BlockWindow,
			maxSources:     cfg.MaxOffenders,
		}),
		creds:     newCredRegistry(maxIssuedCreds),
		hashSeed:  maphash.MakeSeed(),
		tokenSeed: tokenSeed,
	}
}

// Stats 返回指标快照
func (t *Trap) Stats() Stats {
	tracked, flagged := t.scores.counts(time.Now())
	return Stats{
		Hits:      t.hits.Load(),
		FakeOK:    t.fakeOK.Load(),
		Blocks:    t.blocks.Load(),
		Flags:     t.flags.Load(),
		Logins:    t.logins.Load(),
		Reuses:    t.reuses.Load(),
		PenaltyMS: t.penaltyMS.Load(),
		Offenders: tracked,
		Flagged:   flagged,
		Issued:    t.creds.len(),
	}
}

// Rules 返回编译后的规则表（蜜罐关闭时同样可用）
func (t *Trap) Rules() *RuleSet {
	return t.rules
}

// Flagged 判断 IP 所属来源当前是否被蜜罐标记，供风险判定使用；IPv6 按 /64 归并
func (t *Trap) Flagged(ip string) bool {
	if !t.cfg.Enabled {
		return false
	}
	key, ok := sourceKey(ip)
	return ok && t.scores.flagged(key, time.Now())
}

// RunJanitor 定期清理分数已漏空且未被标记的来源；ctx 取消时退出
func (t *Trap) RunJanitor(ctx context.Context) {
	ticker := time.NewTicker(t.cfg.BlockWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.scores.prune(now)
		}
	}
}

// Middleware 返回 gin 中间件：命中规则的请求按权重计分，随后延迟并返回伪造内容；
// clientIP 用于识别来源（按 IP 计分，与 UA 无关）
func (t *Trap) Middleware(clientIP func(*gin.Context) string) gin.HandlerFunc {
	cfg := t.cfg
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		rule, ok := t.rules.Match(path)
		if !ok {
			c.Next()
			return
		}
		c.Set(scoredKey, true)

		ip := clientIP(c)
		ev := t.newEvent(c, ip, rule.Name)
		baiting := rule.Bait != BaitNone && t.shouldBait(ip, path)

		// 只有要返回伪造内容时才查看请求内容：查找登录尝试，以及本服务签发过的假凭据
		var in inspection
		if baiting {
			in = t.creds.inspect(c.Request)
			ev.Session = in.session
		}
		// 正在使用假凭据或假会话的来源已经被标记，后续交互只按重复计分，让它继续暴露行为
		weight := rule.Weight
		if in.engaged() {
			weight = min(weight, repeatWeight)
		}
		out := t.score(&ev, path, weight)
		t.recordCredentials(ev, in)
		if t.reject(c, ev, out) {
			return
		}

		// 延迟：基础随机 + 惩罚（随已有分数指数增长并封顶）
		ev.SleepMS = jitter(cfg.BaseDelayMinMS, cfg.BaseDelayMaxMS) + backoffPenalty(out.prior, cfg.MaxPenaltyMS)
		t.hits.Add(1)
		if t.delay(c.Request.Context(), ev.SleepMS) {
			t.penaltyMS.Add(uint64(ev.SleepMS))
		} else {
			ev.SleepMS = 0
		}

		if baiting {
			tok := tokens{seed: t.tokenSeed, source: ip, issue: func(label, value string) {
				t.creds.issue(value, IssuedCred{Label: label, Source: ip, At: ev.Time})
				if label != sessionLabel && !slices.Contains(ev.Issued, label) {
					ev.Issued = append(ev.Issued, label)
				}
			}}
			resp, ok := render(rule.Bait, baitRequest{
				method:  c.Request.Method,
				host:    c.Request.Host,
				path:    path,
				tok:     tok,
				login:   in.login,
				reused:  len(in.reused) > 0,
				session: in.session,
			})
			if ok {
				t.fakeOK.Add(1)
				ev.Kind, ev.Status = EventBait, resp.status
				t.emit(ev)
				serveBait(c, resp)
				return
			}
		}

		ev.Kind = EventTarpit
		t.emit(ev)
		c.Next()
	}
}

// NotFound 返回放在 NoRoute 链首的处理函数：未命中规则的 404 按低权重计分，
// 来源处于封禁期时返回 429；其余情况交给后续处理函数输出 404
func (t *Trap) NotFound(clientIP func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !t.cfg.Enabled || c.GetBool(scoredKey) {
			return
		}
		ev := t.newEvent(c, clientIP(c), "not-found")
		t.reject(c, ev, t.score(&ev, c.Request.URL.Path, WeightLow))
	}
}

// newEvent 填好一次请求的公共字段；客户端输入在这里统一清洗
func (t *Trap) newEvent(c *gin.Context, ip, rule string) Event {
	ev := Event{
		Time:      time.Now(),
		IP:        ip,
		Method:    cleanText(c.Request.Method, 16),
		Path:      cleanText(c.Request.URL.Path, maxEventPathLen),
		Rule:      rule,
		UserAgent: cleanText(c.Request.UserAgent(), maxEventUALen),
	}
	if key, ok := sourceKey(ip); ok {
		ev.Source = key.String()
	}
	return ev
}

// score 为来源记一次命中，把结果写回事件，并处理标记状态的变化；无法解析的 IP 不计分。
// 路径去重用未截断的原始路径，避免超长路径共用同一个哈希
func (t *Trap) score(ev *Event, path string, weight float64) outcome {
	key, ok := sourceKey(ev.IP)
	if !ok {
		return outcome{}
	}
	out := t.scores.observe(key, maphash.String(t.hashSeed, path), weight, ev.Time)
	ev.Score = out.score
	if out.newlyFlagged {
		t.flagged(*ev)
	}
	return out
}

func (t *Trap) flagged(ev Event) {
	t.flags.Add(1)
	until := ev.Time.Add(t.cfg.FlagDuration)
	ev.Kind, ev.Until = EventFlagged, &until
	t.emit(ev)
}

// recordCredentials 记录登录尝试与假凭据重用。
// 重用本服务签发的假凭据是确定的恶意信号：不论分数多少，使用它的来源立即被标记
func (t *Trap) recordCredentials(ev Event, in inspection) {
	if in.login != nil {
		t.logins.Add(1)
		e := ev
		e.Kind = EventLoginAttempt
		e.Username, e.PasswordHash, e.PasswordLen = in.login.username, in.login.passwordHash(), len(in.login.password)
		t.emit(e)
	}
	if len(in.reused) == 0 {
		return
	}
	for _, cred := range in.reused {
		t.reuses.Add(1)
		e := ev
		e.Kind = EventCredentialReuse
		e.Credential, e.IssuedTo, e.IssuedAt = cred.Label, cred.Source, &cred.At
		t.emit(e)
	}
	if key, ok := sourceKey(ev.IP); ok && t.scores.mark(key, ev.Time) {
		t.flagged(ev)
	}
}

// reject 来源处于封禁期（或本次命中触发封禁）时返回 429 并中止请求
func (t *Trap) reject(c *gin.Context, ev Event, out outcome) bool {
	if !out.blocked && !out.newlyBlocked {
		return false
	}
	t.blocks.Add(1)
	ev.Kind, ev.Until = EventSoftBlock, &out.blockUntil
	if out.blocked {
		ev.Kind = EventBlock
	}
	t.emit(ev)
	c.AbortWithStatus(http.StatusTooManyRequests)
	return true
}

// delay 等待 ms 毫秒，请求被取消时提前返回；延迟中的请求过多时不等待并返回 false
func (t *Trap) delay(ctx context.Context, ms int) bool {
	if t.delaying.Add(1) > maxDelaying {
		t.delaying.Add(-1)
		return false
	}
	defer t.delaying.Add(-1)
	timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return true
}

// shouldBait 按 FakeOKProb 决定是否伪造内容；结果由来源与路径确定，
// 避免同一来源对同一路径时而得到伪造内容、时而得到真实响应
func (t *Trap) shouldBait(ip, path string) bool {
	switch p := t.cfg.FakeOKProb; {
	case p >= 1:
		return true
	case p <= 0:
		return false
	default:
		var h maphash.Hash
		h.SetSeed(t.hashSeed)
		_, _ = h.WriteString(ip)
		_ = h.WriteByte(0)
		_, _ = h.WriteString(path)
		return float64(h.Sum64())/float64(math.MaxUint64) < p
	}
}

// serveBait 输出伪造响应，并去掉会暴露真实服务的响应头
func serveBait(c *gin.Context, resp baitResponse) {
	h := c.Writer.Header()
	h.Del("X-Request-ID")
	h.Del("Cross-Origin-Resource-Policy")
	h.Set("Cache-Control", "no-store")
	h.Set("Server", fakeServer)
	if resp.poweredBy != "" {
		h.Set("X-Powered-By", resp.poweredBy)
	}
	if resp.location != "" {
		h.Set("Location", resp.location)
	}
	if resp.cookie != "" {
		h.Set("Set-Cookie", resp.cookie)
	}
	if resp.wwwAuth != "" {
		h.Set("WWW-Authenticate", resp.wwwAuth)
	}
	c.Data(resp.status, resp.contentType, []byte(resp.body))
	c.Abort()
}

func jitter(minMS, maxMS int) int {
	if maxMS <= minMS {
		return minMS
	}
	return minMS + mrand.IntN(maxMS-minMS+1)
}

// backoffPenalty 按命中前已有的分数计算惩罚：每 2 分翻倍，从 50 毫秒起，封顶 maxMS
func backoffPenalty(prior float64, maxMS int) int {
	steps := int(prior / 2)
	if steps < 1 {
		return 0
	}
	if steps-1 >= 30 { // 避免移位溢出
		return maxMS
	}
	return min(50<<(steps-1), maxMS)
}
