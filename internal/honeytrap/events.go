package honeytrap

import (
	"context"
	"log/slog"
	"time"
)

// eventKind 蜜罐事件类型，同时是日志消息 "honeytrap <kind>" 的后半部分
type eventKind string

const (
	eventTarpit          eventKind = "tarpit"           // 命中规则，延迟后交给后续处理
	eventBait            eventKind = "bait"             // 命中规则，延迟后返回伪造内容
	eventLoginAttempt    eventKind = "login_attempt"    // 向伪造的登录入口提交了凭据
	eventCredentialReuse eventKind = "credential_reuse" // 请求中出现了本服务签发的假凭据
	eventFlagged         eventKind = "flagged"          // 来源被标记
	eventSoftBlock       eventKind = "soft_block"       // 本次命中触发封禁
	eventBlock           eventKind = "block"            // 封禁期内的请求被拒绝
)

// event 一条蜜罐事件，输出为一行结构化日志。
// 来源一律是混淆后的标识，不出现真实地址；客户端输入（路径、用户名）已去除控制字符并截断，
// 密码只保留长度和哈希
type event struct {
	time   time.Time
	kind   eventKind
	source string // 混淆后的计分来源；IP 无法解析时为空
	method string
	path   string
	rule   string
	score  float64

	status  int      // bait：伪造响应的状态码
	sleepMS int      // bait / tarpit：实际延迟
	session bool     // 请求带有本服务签发的假会话
	issued  []string // bait：本次响应中给出的假凭据种类

	login *loginAttempt // login_attempt

	credential string    // credential_reuse：凭据种类
	issuedTo   string    // credential_reuse：当初拿到该凭据的来源（混淆后）
	issuedAt   time.Time // credential_reuse

	until time.Time // flagged / soft_block / block：状态持续到何时
}

// emit 把事件写入日志。标记与假凭据重用始终记录，其余受 EnableLog 控制
func (t *Trap) emit(e event) {
	if !t.cfg.EnableLog && e.kind != eventFlagged && e.kind != eventCredentialReuse {
		return
	}
	attrs := []slog.Attr{
		slog.String("source", e.source),
		slog.String("method", e.method),
		slog.String("path", e.path),
		slog.String("rule", e.rule),
		slog.Float64("score", e.score),
	}
	if e.status != 0 {
		attrs = append(attrs, slog.Int("status", e.status))
	}
	if e.sleepMS != 0 {
		attrs = append(attrs, slog.Int("sleep_ms", e.sleepMS))
	}
	if e.session {
		attrs = append(attrs, slog.Bool("session", true))
	}
	if len(e.issued) > 0 {
		attrs = append(attrs, slog.Any("issued", e.issued))
	}
	if e.login != nil {
		attrs = append(attrs,
			slog.String("username", e.login.username),
			slog.String("password_hash", e.login.passwordHash()),
			slog.Int("password_len", len(e.login.password)))
	}
	if e.credential != "" {
		attrs = append(attrs,
			slog.String("credential", e.credential),
			slog.String("issued_to", e.issuedTo),
			slog.Time("issued_at", e.issuedAt))
	}
	if !e.until.IsZero() {
		attrs = append(attrs, slog.Time("until", e.until))
	}
	t.log.LogAttrs(context.Background(), slog.LevelInfo, "honeytrap "+string(e.kind), attrs...)
}
