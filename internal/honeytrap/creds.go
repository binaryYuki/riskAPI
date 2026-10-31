package honeytrap

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxIssuedCreds   = 50000   // 登记的假凭据上限，超出后淘汰最早登记的
	minCredLen       = 16      // 更短的值容易与正常内容相撞，不登记也不查找
	maxInspectBody   = 8 << 10 // 为查找假凭据最多读取的请求体字节数
	maxInspectHeader = 4 << 10
	maxUsernameLen   = 64
	sessionLabel     = "session" // 假会话在登记表中的标签
)

// issuedCred 一个已签发的假凭据的去向
type issuedCred struct {
	label  string    // 凭据种类，如 db_pass、aws_secret
	source string    // 当初拿到它的来源（混淆后）
	at     time.Time // 最近一次签发时间
}

// credRegistry 假凭据登记表：值 → 签发记录。容量固定，按登记顺序淘汰
type credRegistry struct {
	mu      sync.Mutex
	max     int
	byValue map[string]issuedCred
	ring    []string // 按登记顺序排列的值，写满后循环覆盖
	next    int
}

func newCredRegistry(max int) *credRegistry {
	return &credRegistry{max: max, byValue: make(map[string]issuedCred)}
}

// issue 登记一个假凭据；同一个值重复登记只刷新签发时间
func (r *credRegistry) issue(value string, cred issuedCred) {
	if len(value) < minCredLen {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byValue[value]; !ok {
		if len(r.ring) < r.max {
			r.ring = append(r.ring, value)
		} else {
			delete(r.byValue, r.ring[r.next])
			r.ring[r.next] = value
			r.next = (r.next + 1) % r.max
		}
	}
	r.byValue[value] = cred
}

func (r *credRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byValue)
}

// scan 在若干段文本中查找登记过的假凭据，返回命中的凭据（去重）以及其中是否有假会话
func (r *credRegistry) scan(texts ...string) (creds []issuedCred, session bool) {
	var candidates []string
	for _, text := range texts {
		candidates = appendCandidates(candidates, text)
	}
	if len(candidates) == 0 {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]struct{})
	for _, value := range candidates {
		cred, ok := r.byValue[value]
		if _, dup := seen[value]; !ok || dup {
			continue
		}
		seen[value] = struct{}{}
		if cred.label == sessionLabel {
			session = true
		} else {
			creds = append(creds, cred)
		}
	}
	return creds, session
}

// appendCandidates 把文本按凭据字符集（字母、数字、+、/）切段，保留够长的片段
func appendCandidates(dst []string, text string) []string {
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && isCredChar(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minCredLen {
			dst = append(dst, text[start:i])
		}
		start = -1
	}
	return dst
}

func isCredChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// loginAttempt 请求提交的一组登录凭据
type loginAttempt struct {
	username, password string
}

// passwordHash 返回密码 SHA-256 的前 16 个十六进制字符：足以比对相同的密码，又不保存明文
func (l *loginAttempt) passwordHash() string {
	sum := sha256.Sum256([]byte(l.password))
	return hex.EncodeToString(sum[:8])
}

var (
	usernameFields = []string{"log", "pma_username", "username", "user", "email", "login", "j_username"}
	passwordFields = []string{"pwd", "pma_password", "password", "pass", "passwd", "j_password"}
	xmlrpcString   = regexp.MustCompile(`<string>([^<]{0,256})</string>`)
)

// loginFromForm 从表单中取出登录凭据；没有密码字段时返回 nil
func loginFromForm(form url.Values) *loginAttempt {
	first := func(keys []string) (string, bool) {
		for _, k := range keys {
			if v, ok := form[k]; ok && len(v) > 0 {
				return v[0], true
			}
		}
		return "", false
	}
	password, ok := first(passwordFields)
	if !ok {
		return nil
	}
	username, _ := first(usernameFields)
	return &loginAttempt{username: cleanText(username, maxUsernameLen), password: password}
}

// loginFromXMLRPC 从 XML-RPC 调用（如 wp.getUsersBlogs）的前两个字符串参数中取出登录凭据
func loginFromXMLRPC(body string) *loginAttempt {
	if !strings.Contains(body, "<methodCall>") {
		return nil
	}
	params := xmlrpcString.FindAllStringSubmatch(body, 2)
	if len(params) < 2 {
		return nil
	}
	return &loginAttempt{username: cleanText(params[0][1], maxUsernameLen), password: params[1][1]}
}

// cleanText 去掉控制字符并截断，用于写入日志、事件和伪造页面的客户端输入
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// inspection 一次请求中与假凭据有关的发现
type inspection struct {
	login   *loginAttempt // 提交的登录凭据（表单、Basic 认证或 XML-RPC）
	reused  []issuedCred  // 请求中出现的、由本服务签发的假凭据
	session bool          // 请求带有本服务签发的假会话
}

// engaged 请求方是否正在使用本服务给出的假凭据或假会话。
// 只有先拿到过诱饵内容的来源才可能满足，无法凭空伪造
func (in inspection) engaged() bool {
	return in.session || len(in.reused) > 0
}

// inspect 在请求的查询串、Cookie、Authorization 和请求体中查找假凭据与登录尝试。
// 只对命中规则的请求调用；读取量有上限，内容只做查找，不执行、不转发
func (r *credRegistry) inspect(req *http.Request) inspection {
	var in inspection
	capped := func(s string) string {
		return s[:min(len(s), maxInspectHeader)]
	}
	unescape := func(s string) string {
		if u, err := url.QueryUnescape(s); err == nil {
			return u
		}
		return s
	}

	texts := []string{capped(req.Header.Get("Cookie")), unescape(capped(req.URL.RawQuery))}
	if user, pass, ok := req.BasicAuth(); ok {
		in.login = &loginAttempt{username: cleanText(user, maxUsernameLen), password: pass}
		texts = append(texts, capped(user), capped(pass))
	} else {
		texts = append(texts, capped(req.Header.Get("Authorization")))
	}

	if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch) {
		raw, _ := io.ReadAll(io.LimitReader(req.Body, maxInspectBody))
		body := string(raw)
		texts = append(texts, body, unescape(body))
		if form, err := url.ParseQuery(body); err == nil {
			if login := loginFromForm(form); login != nil {
				in.login = login
			}
		}
		if in.login == nil {
			in.login = loginFromXMLRPC(body)
		}
	}

	in.reused, in.session = r.scan(texts...)
	return in
}
