package honeytrap

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memSink 收集事件的测试用 Sink
type memSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *memSink) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *memSink) of(kind EventKind) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

type reqOpt func(*http.Request)

func withForm(form url.Values) reqOpt {
	return func(r *http.Request) {
		r.Method = http.MethodPost
		r.Body = io.NopCloser(strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

func withBody(body string) reqOpt {
	return func(r *http.Request) {
		r.Method = http.MethodPost
		r.Body = io.NopCloser(strings.NewReader(body))
	}
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func request(r *gin.Engine, path, remote string, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	req.Host = "example.com"
	for _, o := range opts {
		o(req)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// envValue 从伪造的 .env 中取出某个变量的值
func envValue(t *testing.T, env, key string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + key + `=(.+)$`).FindStringSubmatch(env)
	require.NotNil(t, m, key)
	return m[1]
}

// sessionCookie 返回响应发放的假会话 Cookie（name=value）
func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	cookie := w.Header().Get("Set-Cookie")
	require.NotEmpty(t, cookie)
	assert.Contains(t, cookie, "HttpOnly")
	return strings.SplitN(cookie, ";", 2)[0]
}

func TestCredRegistry_IssueScanEvict(t *testing.T) {
	r := newCredRegistry(3)
	now := time.Now()
	value := func(i int) string { return fmt.Sprintf("credential-value-%04d", i) }

	r.issue("too-short", IssuedCred{Label: "x"})
	assert.Zero(t, r.len(), "short values are never registered")

	for i := range 3 {
		r.issue(strings.ReplaceAll(value(i), "-", "0"), IssuedCred{Label: "db_pass", Source: "1.1.1.1", At: now})
	}
	// 重复登记只刷新时间，不占用新位置
	later := now.Add(time.Minute)
	first := strings.ReplaceAll(value(0), "-", "0")
	r.issue(first, IssuedCred{Label: "db_pass", Source: "1.1.1.1", At: later})
	assert.Equal(t, 3, r.len())
	creds, _ := r.scan("password=" + first + "&x=1")
	require.Len(t, creds, 1)
	assert.Equal(t, later, creds[0].At)

	// 写满后淘汰最早登记的
	r.issue(strings.ReplaceAll(value(3), "-", "0"), IssuedCred{Label: "jwt"})
	assert.Equal(t, 3, r.len())
	creds, _ = r.scan(first)
	assert.Empty(t, creds)
	creds, _ = r.scan(strings.ReplaceAll(value(3), "-", "0"))
	assert.Len(t, creds, 1)
}

func TestCredRegistry_ScanFindsValuesInContext(t *testing.T) {
	r := newCredRegistry(10)
	secret := "abcDEF123+/xyzXYZ789+/qrs"
	session := "SessionValue0123456789abcd"
	r.issue(secret, IssuedCred{Label: "aws_secret", Source: "1.1.1.1"})
	r.issue(session, IssuedCred{Label: sessionLabel, Source: "1.1.1.1"})

	for _, text := range []string{
		secret,
		`{"key":"` + secret + `"}`,
		"a=1&secret=" + secret + "&b=2",
		"Bearer " + secret,
		"<value><string>" + secret + "</string></value>",
	} {
		creds, session := r.scan(text)
		assert.Len(t, creds, 1, text)
		assert.False(t, session)
	}

	// 同一个值出现多次只算一次；会话单独报告，不算作凭据
	creds, hasSession := r.scan(secret+" "+secret, "sid="+session)
	assert.Len(t, creds, 1)
	assert.True(t, hasSession)

	// 只是包含登记值的更长字符串、或登记值的一部分，都不算命中
	for _, text := range []string{secret + "A", "A" + secret, secret[:20], "", "short"} {
		creds, _ := r.scan(text)
		assert.Empty(t, creds, text)
	}
}

func TestLoginExtraction(t *testing.T) {
	login := loginFromForm(url.Values{"log": {"admin"}, "pwd": {"hunter2"}})
	require.NotNil(t, login)
	assert.Equal(t, "admin", login.username)
	assert.Equal(t, "hunter2", login.password)
	assert.Len(t, login.passwordHash(), 16)
	assert.NotContains(t, login.passwordHash(), "hunter2")

	assert.Nil(t, loginFromForm(url.Values{"q": {"search"}}), "no password field")

	login = loginFromForm(url.Values{"email": {"a\x00b\r\n" + strings.Repeat("x", 200)}, "password": {"p"}})
	assert.Len(t, login.username, maxUsernameLen)
	assert.NotContains(t, login.username, "\n")

	login = loginFromXMLRPC(`<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>letmein</string></value></param></params></methodCall>`)
	require.NotNil(t, login)
	assert.Equal(t, "admin", login.username)
	assert.Equal(t, "letmein", login.password)
	assert.Nil(t, loginFromXMLRPC("<string>a</string><string>b</string>"))
}

func TestLocalPath(t *testing.T) {
	assert.Equal(t, "/phpmyadmin/", localPath("/phpmyadmin/"))
	assert.Equal(t, "/evil.com/phpmyadmin", localPath("//evil.com/phpmyadmin"), "never a scheme-relative URL")
	assert.Equal(t, "/evil.com/login", localPath(`/\evil.com/login`))
	assert.NotContains(t, localPath("/login\r\nSet-Cookie: x=1"), "\n")
}

// 完整链路：拿到假 .env → 用其中的数据库密码登录 phpMyAdmin → 带着假会话进入后台
func TestDeepInteraction_HarvestLoginSession(t *testing.T) {
	sink := &memSink{}
	trap, r := newTestTrap(fastCfg(func(c *Config) { c.Sink = sink }))
	const src = "8.8.8.8:1"

	env := request(r, "/.env", src).Body.String()
	dbPass := envValue(t, env, "DB_PASSWORD")
	bait := sink.of(EventBait)
	require.Len(t, bait, 1)
	assert.ElementsMatch(t, []string{"app_key", "db_pass", "admin_pass", "mail_pass", "aws_id", "aws_secret"}, bait[0].Issued)
	assert.Equal(t, 6, trap.Stats().Issued)

	// 登录页，然后是错误的密码：留在登录页并显示错误，用户名经过转义
	assert.Contains(t, request(r, "/phpmyadmin/", src).Body.String(), "pma_username")
	w := request(r, "/phpmyadmin/", src, withForm(url.Values{"pma_username": {`<b>root</b>`}, "pma_password": {"wrong-password"}}))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Access denied for user '&lt;b&gt;root&lt;/b&gt;'@'localhost'")
	assert.Empty(t, w.Header().Get("Set-Cookie"))
	assert.Zero(t, trap.Stats().Reuses)

	// 用假 .env 里的密码："登录成功"，发放假会话
	w = request(r, "/phpmyadmin/", src, withForm(url.Values{"pma_username": {"app"}, "pma_password": {dbPass}}))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/phpmyadmin/", w.Header().Get("Location"))
	cookie := sessionCookie(t, w)

	// 带着假会话看到的是后台首页；不带则仍是登录页
	w = request(r, "/phpmyadmin/", src, withHeader("Cookie", cookie))
	assert.Contains(t, w.Body.String(), "Server version: 8.0.36")
	assert.Contains(t, request(r, "/phpmyadmin/", src).Body.String(), "pma_username")

	stats := trap.Stats()
	assert.Equal(t, uint64(2), stats.Logins)
	assert.Equal(t, uint64(1), stats.Reuses)
	assert.Zero(t, stats.Blocks, "an engaged source is not cut off by the block threshold")

	reuse := sink.of(EventCredentialReuse)
	require.Len(t, reuse, 1)
	assert.Equal(t, "db_pass", reuse[0].Credential)
	assert.Equal(t, "8.8.8.8", reuse[0].IssuedTo)
	assert.Equal(t, "8.8.8.8", reuse[0].IP)
	require.NotNil(t, reuse[0].IssuedAt)

	// 事件里不出现明文密码
	attempts := sink.of(EventLoginAttempt)
	require.Len(t, attempts, 2)
	assert.Equal(t, "<b>root</b>", attempts[0].Username)
	assert.Equal(t, len("wrong-password"), attempts[0].PasswordLen)
	all, err := json.Marshal(sink.events)
	require.NoError(t, err)
	assert.NotContains(t, string(all), "wrong-password")
	assert.NotContains(t, string(all), dbPass)
}

func TestDeepInteraction_CredentialUsedByAnotherSource(t *testing.T) {
	sink := &memSink{}
	trap, r := newTestTrap(fastCfg(func(c *Config) { c.Sink = sink }))

	adminPass := envValue(t, request(r, "/.env", "1.1.1.1:1").Body.String(), "ADMIN_PASSWORD")

	// 另一个来源此前没有任何命中，仅凭使用这个密码就被立即标记
	assert.False(t, trap.Flagged("2.2.2.2"))
	w := request(r, "/wp-login.php", "2.2.2.2:1", withForm(url.Values{"log": {"admin"}, "pwd": {adminPass}}))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/wp-admin/", w.Header().Get("Location"))
	assert.True(t, trap.Flagged("2.2.2.2"))

	reuse := sink.of(EventCredentialReuse)
	require.Len(t, reuse, 1)
	assert.Equal(t, "admin_pass", reuse[0].Credential)
	assert.Equal(t, "1.1.1.1", reuse[0].IssuedTo, "the event links the user of a credential to the source that harvested it")
	assert.Equal(t, "2.2.2.2", reuse[0].IP)
	assert.Len(t, sink.of(EventFlagged), 2)

	// 假会话在别的来源手里同样有效，进入的是假的 WordPress 后台
	w = request(r, "/wp-admin/", "3.3.3.3:1", withHeader("Cookie", sessionCookie(t, w)))
	assert.Contains(t, w.Body.String(), "At a Glance")
}

func TestDeepInteraction_OtherEntryPoints(t *testing.T) {
	sink := &memSink{}
	trap, r := newTestTrap(fastCfg(func(c *Config) { c.Sink = sink }))
	env := request(r, "/.env", "1.1.1.1:1").Body.String()
	adminPass, awsID := envValue(t, env, "ADMIN_PASSWORD"), envValue(t, env, "AWS_ACCESS_KEY_ID")

	// 通用登录页：失败 → 成功 → 控制台
	w := request(r, "/login", "2.2.2.2:1", withForm(url.Values{"email": {"admin@example.com"}, "password": {"nope"}}))
	assert.Contains(t, w.Body.String(), "These credentials do not match our records.")
	assert.Contains(t, w.Body.String(), `value="admin@example.com"`)
	w = request(r, "/login", "2.2.2.2:1", withForm(url.Values{"email": {"admin@example.com"}, "password": {adminPass}}))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, request(r, "/login", "2.2.2.2:1", withHeader("Cookie", sessionCookie(t, w))).Body.String(), "Recent sign-ins")

	// Tomcat Manager：先要求 Basic 认证，提交假凭据后放行
	w = request(r, "/manager/html", "4.4.4.4:1")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic realm=")
	w = request(r, "/manager/html", "4.4.4.4:1", func(req *http.Request) { req.SetBasicAuth("tomcat", "tomcat") })
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	w = request(r, "/manager/html", "4.4.4.4:1", func(req *http.Request) { req.SetBasicAuth("admin", adminPass) })
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Tomcat Web Application Manager")

	// XML-RPC 暴力破解：记录尝试并返回认证失败
	w = request(r, "/xmlrpc.php", "5.5.5.5:1", withBody(`<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>123456</string></value></param></params></methodCall>`))
	assert.Contains(t, w.Body.String(), "Incorrect username or password.")

	// 假凭据出现在查询串或 Authorization 里同样会被认出
	request(r, "/actuator/env?key="+url.QueryEscape(awsID), "6.6.6.6:1")
	assert.True(t, trap.Flagged("6.6.6.6"))
	request(r, "/wp-json/wp/v2/users", "7.7.7.7:1", withHeader("Authorization", "Bearer "+envValue(t, env, "AWS_SECRET_ACCESS_KEY")))
	assert.True(t, trap.Flagged("7.7.7.7"))

	assert.Equal(t, uint64(4), trap.Stats().Reuses)
	assert.Equal(t, uint64(5), trap.Stats().Logins)
}

func TestInspection_IsBoundedAndScoped(t *testing.T) {
	trap, r := newTestTrap(fastCfg())
	dbPass := envValue(t, request(r, "/.env", "1.1.1.1:1").Body.String(), "DB_PASSWORD")

	// 超过读取上限之后的内容不会被查看
	padding := strings.Repeat("a=1&", maxInspectBody/4+1)
	request(r, "/phpmyadmin/", "2.2.2.2:1", withBody(padding+url.Values{"pma_password": {dbPass}}.Encode()))
	assert.Zero(t, trap.Stats().Reuses)

	// 真实路由的请求内容从不被查看
	w := request(r, "/api/v1/ip", "3.3.3.3:1", withHeader("Authorization", "Bearer "+dbPass), withHeader("Cookie", "x="+dbPass))
	assert.Equal(t, "real", w.Body.String())
	assert.Zero(t, trap.Stats().Reuses)
	assert.False(t, trap.Flagged("3.3.3.3"))

	// 不返回伪造内容时同样不查看
	trap, r = newTestTrap(fastCfg(func(c *Config) { c.FakeOKProb = 0 }))
	trap.creds.issue(dbPass, IssuedCred{Label: "db_pass", Source: "1.1.1.1"})
	request(r, "/phpmyadmin/", "2.2.2.2:1", withForm(url.Values{"pma_password": {dbPass}}))
	assert.Zero(t, trap.Stats().Reuses)
	assert.Zero(t, trap.Stats().Logins)
}

func TestEngagement_DoesNotLowerScoreForUnknownSources(t *testing.T) {
	trap, r := newTestTrap(fastCfg())
	// 没有拿到过假凭据的来源，随便提交表单或伪造 Cookie 不能降低计分
	for i := range 4 {
		request(r, fmt.Sprintf("/scan-%d.php", i), "9.9.9.9:1",
			withForm(url.Values{"password": {"x"}}), withHeader("Cookie", "phpMyAdmin=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	}
	assert.Equal(t, http.StatusTooManyRequests, request(r, "/scan-9.php", "9.9.9.9:1").Code)
	assert.NotZero(t, trap.Stats().Blocks)
}

func TestEmit_LogsWithoutSink(t *testing.T) {
	var buf strings.Builder
	gin.SetMode(gin.TestMode)
	trap := New(fastCfg(func(c *Config) { c.EnableLog = false }), slog.New(slog.NewTextHandler(&buf, nil)))
	r := gin.New()
	r.Use(trap.Middleware(func(c *gin.Context) string { return c.RemoteIP() }))

	request(r, "/wp-login.php", "8.8.8.8:1")
	assert.Empty(t, buf.String(), "per-hit logging is off")
	request(r, "/.env", "8.8.8.8:1")
	assert.Contains(t, buf.String(), `msg="honeytrap flagged"`, "flagging is always logged")
	assert.Contains(t, buf.String(), "ip=8.8.8.8")
}
