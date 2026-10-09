package honeytrap

import (
	"context"
	"log/slog"
	"time"
)

// EventKind 蜜罐事件类型
type EventKind string

const (
	EventTarpit          EventKind = "tarpit"           // 命中规则，延迟后交给后续处理
	EventBait            EventKind = "bait"             // 命中规则，延迟后返回伪造内容
	EventLoginAttempt    EventKind = "login_attempt"    // 向伪造的登录入口提交了凭据
	EventCredentialReuse EventKind = "credential_reuse" // 请求中出现了本服务签发的假凭据
	EventFlagged         EventKind = "flagged"          // 来源被标记
	EventSoftBlock       EventKind = "soft_block"       // 本次命中触发封禁
	EventBlock           EventKind = "block"            // 封禁期内的请求被拒绝
)

// Event 一条蜜罐事件。字段与 JSON 名称是对外的稳定格式，供 Sink 持久化；
// 其中的客户端输入（路径、UA、用户名）已去除控制字符并截断，密码只保留哈希
type Event struct {
	Time      time.Time `json:"time"`
	Kind      EventKind `json:"kind"`
	IP        string    `json:"ip"`
	Source    string    `json:"source,omitempty"` // 计分来源：IPv4 地址或 IPv6 /64
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Rule      string    `json:"rule"`
	UserAgent string    `json:"user_agent,omitempty"`
	Score     float64   `json:"score"`

	Status  int      `json:"status,omitempty"`   // bait：伪造响应的状态码
	SleepMS int      `json:"sleep_ms,omitempty"` // bait / tarpit：实际延迟
	Session bool     `json:"session,omitempty"`  // 请求带有本服务签发的假会话
	Issued  []string `json:"issued,omitempty"`   // bait：本次响应中给出的假凭据种类

	Username     string `json:"username,omitempty"`      // login_attempt
	PasswordHash string `json:"password_hash,omitempty"` // login_attempt：SHA-256 前 16 个十六进制字符
	PasswordLen  int    `json:"password_len,omitempty"`  // login_attempt

	Credential string     `json:"credential,omitempty"` // credential_reuse：凭据种类
	IssuedTo   string     `json:"issued_to,omitempty"`  // credential_reuse：当初拿到该凭据的 IP
	IssuedAt   *time.Time `json:"issued_at,omitempty"`  // credential_reuse

	Until *time.Time `json:"until,omitempty"` // flagged / soft_block / block：状态持续到何时
}

// Sink 接收蜜罐事件，用于持久化或转发。
// Record 在请求处理路径上被同步调用，必须立即返回：需要做 I/O 的实现应自行缓冲并在队列满时丢弃
type Sink interface {
	Record(Event)
}

// emit 记录日志并把事件交给 Sink。标记与假凭据重用始终记日志，其余受 EnableLog 控制
func (t *Trap) emit(e Event) {
	if t.cfg.EnableLog || e.Kind == EventFlagged || e.Kind == EventCredentialReuse {
		t.log.LogAttrs(context.Background(), slog.LevelInfo, "honeytrap "+string(e.Kind), e.attrs()...)
	}
	if t.cfg.Sink != nil {
		t.cfg.Sink.Record(e)
	}
}

// attrs 返回事件中非空字段对应的日志属性
func (e Event) attrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.String("rule", e.Rule),
		slog.Float64("score", e.Score),
	}
	str := func(key, value string) {
		if value != "" {
			attrs = append(attrs, slog.String(key, value))
		}
	}
	if e.Source != e.IP {
		str("source", e.Source)
	}
	if e.Status != 0 {
		attrs = append(attrs, slog.Int("status", e.Status))
	}
	if e.SleepMS != 0 {
		attrs = append(attrs, slog.Int("sleep_ms", e.SleepMS))
	}
	if e.Session {
		attrs = append(attrs, slog.Bool("session", true))
	}
	if len(e.Issued) > 0 {
		attrs = append(attrs, slog.Any("issued", e.Issued))
	}
	if e.Kind == EventLoginAttempt {
		attrs = append(attrs, slog.String("username", e.Username), slog.String("password_hash", e.PasswordHash), slog.Int("password_len", e.PasswordLen))
	}
	str("credential", e.Credential)
	str("issued_to", e.IssuedTo)
	if e.IssuedAt != nil {
		attrs = append(attrs, slog.Time("issued_at", *e.IssuedAt))
	}
	if e.Until != nil {
		attrs = append(attrs, slog.Time("until", *e.Until))
	}
	return attrs
}
