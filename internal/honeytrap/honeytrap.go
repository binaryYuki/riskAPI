// Package honeytrap 识别扫描器常探测的路径并按来源计分：
// 规则表（rules.go）给路径定权重，漏桶（score.go）按来源累计分数，
// 本文件按分数分级响应——延迟（tarpit）、伪造内容（bait.go）、标记、软封禁。
// 伪造内容中的假凭据会被登记（creds.go），之后在请求中再次出现时即可认出。
// 被标记的来源进入蜜罐自己的风险列表（flaglist.go），可落盘并在实例间共享；
// 列表、文件和事件日志（events.go）里的来源都经过混淆（obfuscate.go）。
package honeytrap

import (
	"context"
	"crypto/rand"
	"hash/maphash"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Source 被蜜罐标记的来源在风险判定中使用的来源名
const Source = "honeytrap"

const (
	scoredKey       = "honeytrap_scored" // gin.Context 键：本次请求已由 Middleware 计分
	maxDelaying     = 1024               // 同时处于延迟中的请求上限，超出后不再延迟，避免拖住自身
	maxEventPathLen = 512                // 事件中保留的路径长度
)

// Config 延迟、伪造内容、分级策略与标记的保存方式
type Config struct {
	Enabled        bool
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

	// Secret 混淆来源所用的密钥。为空时使用随机密钥：日志里的标识重启后无法还原，
	// 也不会写标记文件
	Secret string
	// FlagFile 保存被标记来源的文件（JSON Lines）；为空时标记只在内存中。
	// 多个实例使用相同的 Secret 并共用这个文件即可共享标记
	FlagFile string
}

// withDefaults 为未设置的字段填充默认值
func (cfg Config) withDefaults() Config {
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

// Trap 蜜罐实例，持有规则表、来源分数、风险列表与指标
type Trap struct {
	cfg    Config
	log    *slog.Logger
	rules  *RuleSet
	scores *scorer
	creds  *credRegistry // 已签发的假凭据，用于在后续请求中认出它们
	obf    *obfuscator
	flags  *flagList // 被标记的来源（混淆后）

	hashSeed  maphash.Seed // 路径去重与伪造决策
	tokenSeed []byte       // 假凭据，进程内保持不变

	delaying  atomic.Int64
	hits      atomic.Uint64
	fakeOK    atomic.Uint64
	blocks    atomic.Uint64
	flagged   atomic.Uint64
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

// New 创建蜜罐；启用且配置了标记文件时读回其中未到期的标记
func New(cfg Config, log *slog.Logger) *Trap {
	cfg = cfg.withDefaults()
	if cfg.Enabled && cfg.Secret == "" {
		log.Warn("HONEYTRAP_SECRET is not set: obfuscated sources and sealed log lines cannot be revealed after a restart")
		if cfg.FlagFile != "" {
			log.Warn("HONEYTRAP_FLAG_FILE is ignored without HONEYTRAP_SECRET", "path", cfg.FlagFile)
			cfg.FlagFile = ""
		}
	}
	if !cfg.Enabled {
		cfg.FlagFile = ""
	}
	tokenSeed := make([]byte, 16)
	_, _ = rand.Read(tokenSeed)
	t := &Trap{
		cfg:   cfg,
		log:   log,
		rules: NewRuleSet(DefaultRules()),
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
		obf:       newObfuscator(cfg.Secret),
		flags:     newFlagList(cfg.FlagFile, cfg.MaxOffenders, cfg.FlagDuration/2, log),
		hashSeed:  maphash.MakeSeed(),
		tokenSeed: tokenSeed,
	}
	if cfg.FlagFile != "" {
		now := time.Now()
		t.flags.sync(now)
		t.flags.compact(now)
		log.Info("honeytrap flag file loaded", "path", cfg.FlagFile, "flagged_sources", t.flags.len())
	}
	return t
}

// Stats 返回指标快照
func (t *Trap) Stats() Stats {
	return Stats{
		Hits:      t.hits.Load(),
		FakeOK:    t.fakeOK.Load(),
		Blocks:    t.blocks.Load(),
		Flags:     t.flagged.Load(),
		Logins:    t.logins.Load(),
		Reuses:    t.reuses.Load(),
		PenaltyMS: t.penaltyMS.Load(),
		Offenders: t.scores.len(),
		Flagged:   t.flags.len(),
		Issued:    t.creds.len(),
	}
}

// Rules 返回编译后的规则表（蜜罐关闭时同样可用）
func (t *Trap) Rules() *RuleSet {
	return t.rules
}

// Flagged 判断 IP 所属来源当前是否在蜜罐的风险列表中，供风险判定使用；IPv6 按 /64 归并
func (t *Trap) Flagged(ip string) bool {
	if !t.cfg.Enabled {
		return false
	}
	key, ok := sourceKey(ip)
	return ok && t.flags.has(t.obf.hide(key), time.Now())
}

// Hit 报告本次请求是否命中了蜜罐规则（由 Middleware 计过分）
func Hit(c *gin.Context) bool {
	return c.GetBool(scoredKey)
}

// Seal 把一行日志封存为不透明的字符串，供访问日志隐藏命中蜜罐的请求
func (t *Trap) Seal(line string) string {
	return t.obf.seal(line)
}

// Unseal 还原 Seal 的结果；不是用当前密钥封存的内容返回 false
func (t *Trap) Unseal(sealed string) (string, bool) {
	return t.obf.unseal(sealed)
}

// FlaggedSource 蜜罐风险列表中的一项
type FlaggedSource struct {
	ID    string    // 混淆后的来源，与蜜罐日志中的 source 字段一致
	Until time.Time // 标记到期时间
}

// FlaggedSources 返回当前被标记的全部来源（混淆后），按标识排序
func (t *Trap) FlaggedSources() []FlaggedSource {
	recs := t.flags.snapshot(time.Now())
	out := make([]FlaggedSource, len(recs))
	for i, rec := range recs {
		out[i] = FlaggedSource{ID: rec.Source, Until: rec.Until}
	}
	return out
}

// Reveal 把日志或标记文件中混淆后的来源还原为地址（IPv4）或网段（IPv6 /64）。
// 标识无效，或不是用当前密钥生成的，返回 false
func (t *Trap) Reveal(source string) (string, bool) {
	addr, ok := t.obf.reveal(source)
	if !ok {
		return "", false
	}
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).String(), true
	}
	return addr.String(), true
}

// RunJanitor 定期清理不再需要跟踪的来源和已到期的标记，并读入其他实例写入标记文件的新标记；
// ctx 取消时退出
func (t *Trap) RunJanitor(ctx context.Context) {
	ticker := time.NewTicker(t.cfg.BlockWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.scores.prune(now)
			t.flags.prune(now)
			t.flags.sync(now)
		}
	}
}

// hit 一次被计分的请求
type hit struct {
	ip   string
	key  netip.Addr // 计分来源；ok 为 false 时无效
	ok   bool
	path string // 原始请求路径
	ev   event
}

// newHit 填好一次请求的公共字段；写入事件的客户端输入在这里统一清洗，来源在这里混淆
func (t *Trap) newHit(c *gin.Context, ip, rule string) hit {
	h := hit{ip: ip, path: c.Request.URL.Path}
	h.ev = event{
		time:   time.Now(),
		method: cleanText(c.Request.Method, 16),
		path:   cleanText(h.path, maxEventPathLen),
		rule:   rule,
	}
	if h.key, h.ok = sourceKey(ip); h.ok {
		h.ev.source = t.obf.hide(h.key)
	}
	return h
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
		h := t.newHit(c, ip, rule.Name)
		baiting := rule.Bait != BaitNone && t.shouldBait(ip, path)

		// 只有要返回伪造内容时才查看请求内容：查找登录尝试，以及本服务签发过的假凭据
		var in inspection
		if baiting {
			in = t.creds.inspect(c.Request)
			h.ev.session = in.session
		}
		// 正在使用假凭据或假会话的来源已经被标记，后续交互只按重复计分，让它继续暴露行为
		weight := rule.Weight
		if in.engaged() {
			weight = min(weight, repeatWeight)
		}
		out := t.score(&h, weight)
		t.recordCredentials(h, in)
		if t.reject(c, h, out) {
			return
		}

		// 延迟：基础随机 + 惩罚（随已有分数指数增长并封顶）
		h.ev.sleepMS = jitter(cfg.BaseDelayMinMS, cfg.BaseDelayMaxMS) + backoffPenalty(out.prior, cfg.MaxPenaltyMS)
		t.hits.Add(1)
		if t.delay(c.Request.Context(), h.ev.sleepMS) {
			t.penaltyMS.Add(uint64(h.ev.sleepMS))
		} else {
			h.ev.sleepMS = 0
		}

		if baiting {
			tok := tokens{seed: t.tokenSeed, source: ip, issue: func(label, value string) {
				t.creds.issue(value, issuedCred{label: label, source: h.ev.source, at: h.ev.time})
				if label != sessionLabel && !slices.Contains(h.ev.issued, label) {
					h.ev.issued = append(h.ev.issued, label)
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
				h.ev.kind, h.ev.status = eventBait, resp.status
				t.emit(h.ev)
				serveBait(c, resp)
				return
			}
		}

		h.ev.kind = eventTarpit
		t.emit(h.ev)
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
		h := t.newHit(c, clientIP(c), "not-found")
		t.reject(c, h, t.score(&h, WeightLow))
	}
}

// score 为来源记一次命中，把分数写回事件，并在来源处于标记期时更新风险列表；
// 无法解析的 IP 不计分
func (t *Trap) score(h *hit, weight float64) outcome {
	if !h.ok {
		return outcome{}
	}
	out := t.scores.observe(h.key, maphash.String(t.hashSeed, h.path), weight, h.ev.time)
	h.ev.score = out.score
	if !out.flagUntil.IsZero() {
		t.flag(*h, out.flagUntil, out.newlyFlagged)
	}
	return out
}

// flag 把来源记入风险列表（已在其中时延后到期时间）；首次标记时输出事件
func (t *Trap) flag(h hit, until time.Time, newly bool) {
	t.flags.flag(h.ev.source, until, h.ev.time)
	if newly {
		t.flagged.Add(1)
		h.ev.kind, h.ev.until = eventFlagged, until
		t.emit(h.ev)
	}
}

// recordCredentials 记录登录尝试与假凭据重用。
// 重用本服务签发的假凭据是确定的恶意信号：不论分数多少，使用它的来源立即被标记
func (t *Trap) recordCredentials(h hit, in inspection) {
	if in.login != nil {
		t.logins.Add(1)
		e := h.ev
		e.kind, e.login = eventLoginAttempt, in.login
		t.emit(e)
	}
	if len(in.reused) == 0 {
		return
	}
	for _, cred := range in.reused {
		t.reuses.Add(1)
		e := h.ev
		e.kind = eventCredentialReuse
		e.credential, e.issuedTo, e.issuedAt = cred.label, cred.source, cred.at
		t.emit(e)
	}
	if h.ok {
		if until, newly := t.scores.mark(h.key, h.ev.time); !until.IsZero() {
			t.flag(h, until, newly)
		}
	}
}

// reject 来源处于封禁期（或本次命中触发封禁）时返回 429 并中止请求
func (t *Trap) reject(c *gin.Context, h hit, out outcome) bool {
	if !out.blocked && !out.newlyBlocked {
		return false
	}
	t.blocks.Add(1)
	h.ev.kind, h.ev.until = eventSoftBlock, out.blockUntil
	if out.blocked {
		h.ev.kind = eventBlock
	}
	t.emit(h.ev)
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
