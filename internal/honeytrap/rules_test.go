package honeytrap

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleSet_Match(t *testing.T) {
	rs := NewRuleSet(DefaultRules())
	for path, want := range map[string]string{
		"/.env":             "env-file",
		"/.ENV":             "env-file",
		"/.env.bak":         "env-file",
		"/api/.env.local":   "env-file",
		"/.aws/credentials": "secret-file",
		"/app/.aws/config":  "secret-file",
		"/.ssh/id_rsa":      "secret-file",
		"/id_rsa.pub":       "secret-file",
		"/.git":             "vcs",
		"/.git/config":      "vcs",
		"/dump.sql":         "db-dump",
		"/site.bak":         "db-dump",
		"/wp-config.php":    "webshell",
		"/shell.php":        "webshell",
		"/package.json":     "app-config",
		"/.DS_Store":        "dotfile",
		"/vendor/autoload":  "dotfile",
		"/admin":            "admin",
		"/admin/":           "admin",
		"/login":            "login-panel",
		"/wp-login.php":     "wordpress",
		"/blog/wp-admin/":   "wordpress",
		"/phpmyadmin/":      "phpmyadmin",
		"/manager/html":     "tomcat-manager",
		"/jenkins/login":    "ops-console",
		"/actuator/env":     "actuator",
		"/cgi-bin/luci":     "server-internals",
		"/index.php":        "script",
		"/static/x.jsp":     "script",
		"/npci-upi":         "payment-portal",
		"/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php": "server-internals",
	} {
		rule, ok := rs.Match(path)
		if assert.True(t, ok, path) {
			assert.Equal(t, want, rule.Name, path)
		}
	}

	for _, path := range []string{
		// 真实路由
		"/", "/api/v1/ip", "/api/v1/ip/8.8.8.8", "/api/v1/ip/2001:DB8::1", "/api/v1/info", "/api/v1/parse", "/filter-proxies",
		"/cdn/all", "/cdn/cloudflare", "/api/status", "/api/ready", "/version", "/api/metrics", "/metrics", "/api/export",
		"/api/qqwry/stats", "/api/cache/flush", "/api/cache/flush/risk/1.2.3.0/24",
		"/swagger.json", "/swagger-ui.html", "/api/swagger.json", "/v2/api-docs", "/favicon.ico", "/robots.txt",
		// 只是以关键词开头或包含关键词，不是完整的路径段
		"/environment", "/login-help", "/administrator", "/api/login", "/api/admin", "/debugger", "/pmax", "/envoy",
		"/ctsomething", "/my.env", "/gitignore",
	} {
		_, ok := rs.Match(path)
		assert.False(t, ok, path)
	}
}

func TestRuleSet_PrefersHeavierRule(t *testing.T) {
	rs := NewRuleSet(DefaultRules())
	rule, _ := rs.Match("/admin/.env")
	assert.Equal(t, "env-file", rule.Name)
	assert.Equal(t, WeightHigh, rule.Weight)
	rule, _ = rs.Match("/wp-admin/setup-config.php")
	assert.Equal(t, "wordpress", rule.Name, "equal weights keep the earlier rule")
}

// 原敏感路径拦截名单中的路径都必须仍然标记为 Forbidden
func TestRuleSet_ForbiddenCoversFormerSensitivePaths(t *testing.T) {
	rs := NewRuleSet(DefaultRules())
	for _, name := range strings.Fields(`.env .git .svn .hg .DS_Store config.json config.yml config.yaml wp-config.php
		composer.json composer.lock package.json yarn.lock docker-compose.yml id_rsa id_rsa.pub .bash_history .htaccess
		.htpasswd .ssh .aws .npmrc .dockerignore .gitignore .idea vendor/x node_modules/x backup db.sqlite db.sql dump.sql
		phpinfo.php test.php debug.php admin admin.php webshell.php shell.php cmd.php`) {
		rule, ok := rs.Match("/" + name)
		if assert.True(t, ok, name) {
			assert.True(t, rule.Forbidden, name)
		}
	}
	rule, _ := rs.Match("/wp-login.php")
	assert.False(t, rule.Forbidden)
}

func TestRender(t *testing.T) {
	tok := tokens{seed: []byte("seed"), source: "8.8.8.8"}
	cases := []struct {
		bait         Bait
		method, path string
		status       int
		contains     string
	}{
		{BaitEnv, http.MethodGet, "/.env", 200, "AWS_ACCESS_KEY_ID=AKIA"},
		{BaitSecret, http.MethodGet, "/.aws/credentials", 200, "aws_secret_access_key = "},
		{BaitSecret, http.MethodGet, "/.ssh/id_rsa", 200, "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{BaitSecret, http.MethodGet, "/.ssh/id_rsa.pub", 200, "ssh-ed25519 "},
		{BaitSecret, http.MethodGet, "/.npmrc", 200, "_authToken=npm_"},
		{BaitSecret, http.MethodGet, "/.ssh/", 403, "403 Forbidden"},
		{BaitGit, http.MethodGet, "/.git/HEAD", 200, "ref: refs/heads/main"},
		{BaitGit, http.MethodGet, "/.git/config", 200, "git@git.example.com:web/app.git"},
		{BaitGit, http.MethodGet, "/.git/packed-refs", 200, "refs/remotes/origin/main"},
		{BaitGit, http.MethodGet, "/.git/logs/HEAD", 200, "clone: from git@git.example.com"},
		{BaitGit, http.MethodGet, "/.git/", 403, "403 Forbidden"},
		{BaitBasicAuth, http.MethodGet, "/manager/html", 401, "HTTP Status 401"},
		{BaitSQL, http.MethodGet, "/dump.sql", 200, "-- MySQL dump"},
		{BaitSQL, http.MethodGet, "/db.sqlite", 403, "403 Forbidden"},
		{BaitManifest, http.MethodGet, "/package.json", 200, `"dependencies"`},
		{BaitManifest, http.MethodGet, "/config.json", 200, `"jwtSecret"`},
		{BaitManifest, http.MethodGet, "/yarn.lock", 403, "403 Forbidden"},
		{BaitWordPress, http.MethodGet, "/wp-login.php", 200, `id="loginform"`},
		{BaitWordPress, http.MethodGet, "/xmlrpc.php", 405, "XML-RPC server accepts POST requests only."},
		{BaitWordPress, http.MethodPost, "/xmlrpc.php", 200, "<methodResponse>"},
		{BaitWordPress, http.MethodGet, "/wp-json/wp/v2/users", 200, `"namespaces"`},
		{BaitPHPMyAdmin, http.MethodGet, "/phpmyadmin/", 200, "pma_username"},
		{BaitLogin, http.MethodGet, "/admin", 200, `name="_token"`},
		{BaitActuator, http.MethodGet, "/actuator", 200, `"_links"`},
		{BaitActuator, http.MethodGet, "/actuator/health", 200, `"UP"`},
		{BaitActuator, http.MethodGet, "/actuator/heap\"dump", 404, `"path":"/actuator/heap\"dump"`},
		{BaitScript, http.MethodGet, "/phpinfo.php", 200, "phpinfo()"},
		{BaitScript, http.MethodGet, "/shell.php", 200, ""},
		{BaitForbidden, http.MethodGet, "/server-status", 403, "403 Forbidden"},
	}
	for _, tc := range cases {
		resp, ok := render(tc.bait, baitRequest{method: tc.method, host: "example.com", path: tc.path, tok: tok})
		assert.True(t, ok, tc.path)
		assert.Equal(t, tc.status, resp.status, tc.path)
		assert.Contains(t, resp.body, tc.contains, tc.path)
		assert.NotEmpty(t, resp.contentType, tc.path)
		assert.NotContains(t, resp.body, "{{", "unfilled placeholder in %s", tc.path)
	}

	_, ok := render(BaitNone, baitRequest{method: http.MethodGet, host: "example.com", path: "/x", tok: tok})
	assert.False(t, ok)

	// 每条默认规则都能给出伪造内容
	for _, rule := range DefaultRules() {
		_, ok := render(rule.Bait, baitRequest{method: http.MethodGet, host: "example.com", path: "/x", tok: tok})
		assert.True(t, ok, rule.Name)
	}
}

func TestRender_HostIsSanitized(t *testing.T) {
	tok := tokens{seed: []byte("seed"), source: "8.8.8.8"}
	resp, _ := render(BaitLogin, baitRequest{method: http.MethodGet, host: `"><script>alert(1)</script>`, path: "/login", tok: tok})
	assert.NotContains(t, resp.body, "<script>alert")
	assert.Contains(t, resp.body, "Sign in - localhost")
	assert.Equal(t, "example.com:8443", safeHost("example.com:8443"))
}

func TestTokens_StablePerSource(t *testing.T) {
	a := tokens{seed: []byte("seed"), source: "8.8.8.8"}
	b := tokens{seed: []byte("seed"), source: "9.9.9.9"}
	assert.Equal(t, a.str("db_pass", 20, alphaNum), a.str("db_pass", 20, alphaNum))
	assert.NotEqual(t, a.str("db_pass", 20, alphaNum), b.str("db_pass", 20, alphaNum))
	assert.NotEqual(t, a.str("db_pass", 20, alphaNum), a.str("jwt", 20, alphaNum))
	assert.Len(t, a.str("long", 400, hexDigits), 400)
}
