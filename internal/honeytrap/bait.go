package honeytrap

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
)

// Bait 命中规则后伪造的内容类型
type Bait int

const (
	BaitNone       Bait = iota // 不伪造，交给后续处理
	BaitEnv                    // .env 环境变量文件
	BaitSecret                 // 云凭据、SSH 密钥、.npmrc、.htpasswd 等
	BaitGit                    // 版本库元数据
	BaitSQL                    // 数据库导出
	BaitManifest               // 配置与依赖清单
	BaitWordPress              // WordPress 登录页、后台、XML-RPC、REST 根
	BaitPHPMyAdmin             // phpMyAdmin 登录页与首页
	BaitLogin                  // 通用后台登录页与控制台
	BaitBasicAuth              // HTTP Basic 认证保护的管理页（Tomcat Manager）
	BaitActuator               // Spring Boot Actuator
	BaitScript                 // PHP/ASP/JSP 脚本
	BaitForbidden              // 仿 nginx 的 403 页面
)

const (
	alphaNum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperNum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexDigits  = "0123456789abcdef"
	base64Std  = alphaNum + "+/"
	fakeServer = "nginx"
	fakePHP    = "PHP/8.2.20"
)

// baitRequest 生成伪造响应所需的请求信息
type baitRequest struct {
	method, host, path string
	tok                tokens
	login              *loginAttempt // 请求提交的登录凭据
	reused             bool          // 请求中带有本服务签发的假凭据
	session            bool          // 请求带有本服务签发的假会话
}

// baitResponse 一次伪造响应
type baitResponse struct {
	status      int
	contentType string
	body        string
	poweredBy   string // 非空时写入 X-Powered-By
	location    string // 非空时写入 Location
	cookie      string // 非空时写入 Set-Cookie
	wwwAuth     string // 非空时写入 WWW-Authenticate
}

// tokens 为某个来源生成稳定的假凭据：同一来源每次看到相同的值，不同来源互不相同，
// 日后这些值在别处出现时可以反查到来源
type tokens struct {
	seed   []byte
	source string
	issue  func(label, value string) // 登记可回收的假凭据；为 nil 时不登记
}

// str 返回由 label 决定的 n 个字符，取自 alphabet
func (t tokens) str(label string, n int, alphabet string) string {
	var b strings.Builder
	b.Grow(n)
	var counter [4]byte
	for block := uint32(0); b.Len() < n; block++ {
		binary.BigEndian.PutUint32(counter[:], block)
		h := sha256.New()
		h.Write(t.seed)
		h.Write([]byte(t.source))
		h.Write([]byte{0})
		h.Write([]byte(label))
		h.Write(counter[:])
		for _, c := range h.Sum(nil) {
			if b.Len() == n {
				break
			}
			b.WriteByte(alphabet[int(c)%len(alphabet)])
		}
	}
	return b.String()
}

// cred 与 str 相同，并把结果登记为可回收的假凭据：之后它出现在任何请求中都能认出来
func (t tokens) cred(label string, n int, alphabet string) string {
	return t.issued(label, t.str(label, n, alphabet))
}

// issued 登记一个已生成的假凭据并原样返回
func (t tokens) issued(label, value string) string {
	if t.issue != nil {
		t.issue(label, value)
	}
	return value
}

func (t tokens) awsID() string {
	return t.issued("aws_id", "AKIA"+t.str("aws_id", 16, upperNum))
}

// safeHost 返回可安全写入伪造内容的主机名：Host 头由客户端控制，含其他字符时改用占位值
func safeHost(host string) string {
	if host == "" || len(host) > 253 {
		return "localhost"
	}
	for _, c := range []byte(host) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':':
		default:
			return "localhost"
		}
	}
	return host
}

// localPath 把请求路径规整为只能指向本站的重定向目标
func localPath(path string) string {
	return (&url.URL{Path: "/" + strings.TrimLeft(path, `/\`)}).EscapedPath()
}

// render 生成伪造响应。登录类诱饵分三步：登录页 → 提交凭据（失败页）→
// 提交的是本服务签发的假凭据时"登录成功"，发放假会话并展示后台页面
func render(b Bait, rq baitRequest) (baitResponse, bool) {
	path, tok := rq.path, rq.tok
	base := baseName(path)
	lower := strings.ToLower(path)
	host := safeHost(rq.host)
	text := func(body string) (baitResponse, bool) {
		return baitResponse{status: http.StatusOK, contentType: "text/plain; charset=utf-8", body: body}, true
	}
	page := func(body string) (baitResponse, bool) {
		return baitResponse{status: http.StatusOK, contentType: "text/html; charset=UTF-8", body: body}, true
	}
	jsonBody := func(body string) (baitResponse, bool) {
		return baitResponse{status: http.StatusOK, contentType: "application/json", body: body}, true
	}
	php := func(r baitResponse, ok bool) (baitResponse, bool) {
		r.poweredBy = fakePHP
		return r, ok
	}
	// signIn 发放假会话并跳转；会话值同样是登记过的假凭据，后续请求带上它即可被认出
	signIn := func(location, cookieName string) (baitResponse, bool) {
		return baitResponse{
			status:      http.StatusFound,
			contentType: "text/html; charset=UTF-8",
			location:    location,
			cookie:      cookieName + "=" + tok.cred(sessionLabel, 40, alphaNum) + "; Path=/; HttpOnly; SameSite=Lax",
		}, true
	}
	fill := func(tpl string, extra ...string) string {
		return strings.NewReplacer(append([]string{"{{host}}", host}, extra...)...).Replace(tpl)
	}

	submitted := rq.method == http.MethodPost && rq.login != nil
	user := ""
	if rq.login != nil {
		user = html.EscapeString(rq.login.username)
	}

	switch b {
	case BaitEnv:
		return text(fill(envFile,
			"{{app_key}}", tok.cred("app_key", 43, base64Std)+"=",
			"{{db_pass}}", tok.cred("db_pass", 20, alphaNum),
			"{{admin_pass}}", tok.cred("admin_pass", 18, alphaNum),
			"{{mail_pass}}", tok.cred("mail_pass", 24, hexDigits),
			"{{aws_id}}", tok.awsID(),
			"{{aws_secret}}", tok.cred("aws_secret", 40, base64Std),
		))

	case BaitSecret:
		switch {
		case base == "credentials":
			return text(fill(awsCredentials,
				"{{aws_id}}", tok.awsID(),
				"{{aws_secret}}", tok.cred("aws_secret", 40, base64Std)))
		case base == "config" && strings.Contains(lower, "/.aws/"):
			return text("[default]\nregion = us-east-1\noutput = json\n")
		case base == ".npmrc":
			return text("//registry.npmjs.org/:_authToken=npm_" + tok.cred("npm", 36, alphaNum) + "\nregistry=https://registry.npmjs.org/\nalways-auth=true\n")
		case base == ".htpasswd":
			return text("admin:$apr1$" + tok.str("ht_salt", 8, alphaNum) + "$" + tok.str("ht_hash", 22, alphaNum) + "\n")
		case base == ".bash_history":
			return text(fill(bashHistory, "{{db_pass}}", tok.cred("db_pass", 20, alphaNum)))
		case strings.HasSuffix(base, ".pub"):
			return text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + tok.str("ssh_pub", 43, alphaNum) + " deploy@" + host + "\n")
		case strings.HasPrefix(base, "id_"):
			return text(sshPrivateKey(tok))
		}

	case BaitGit:
		head := tok.str("git_head", 40, hexDigits)
		switch {
		case strings.HasSuffix(lower, "/.git/head"):
			return text("ref: refs/heads/main\n")
		case strings.HasSuffix(lower, "/.git/config"):
			return text(fill(gitConfig))
		case strings.HasSuffix(lower, "/.git/refs/heads/main"), strings.HasSuffix(lower, "/.git/orig_head"):
			return text(head + "\n")
		case strings.HasSuffix(lower, "/.git/packed-refs"):
			return text("# pack-refs with: peeled fully-peeled sorted \n" + head + " refs/remotes/origin/main\n")
		case strings.HasSuffix(lower, "/.git/logs/head"):
			return text(strings.Repeat("0", 40) + " " + head + " deploy <deploy@" + host + "> 1716279273 +0000\tclone: from git@git." + host + ":web/app.git\n")
		case strings.HasSuffix(lower, "/.git/description"):
			return text("Unnamed repository; edit this file 'description' to name the repository.\n")
		case strings.HasSuffix(lower, "/.git/commit_editmsg"):
			return text("update production config\n")
		}

	case BaitSQL:
		if strings.HasSuffix(base, ".sql") {
			return text(fill(sqlDump,
				"{{hash1}}", tok.str("sql_hash1", 53, alphaNum),
				"{{hash2}}", tok.str("sql_hash2", 53, alphaNum)))
		}

	case BaitManifest:
		switch base {
		case "package.json":
			return jsonBody(packageJSON)
		case "composer.json":
			return jsonBody(composerJSON)
		case "config.json":
			return jsonBody(fill(configJSON,
				"{{db_pass}}", tok.cred("db_pass", 20, alphaNum),
				"{{jwt}}", tok.cred("jwt", 48, hexDigits)))
		case "config.yml", "config.yaml":
			return text(fill(configYAML,
				"{{db_pass}}", tok.cred("db_pass", 20, alphaNum),
				"{{jwt}}", tok.cred("jwt", 48, hexDigits)))
		case "docker-compose.yml":
			return text(fill(composeYAML, "{{db_pass}}", tok.cred("db_pass", 20, alphaNum)))
		}

	case BaitWordPress:
		switch {
		case base == "xmlrpc.php" && submitted:
			return php(baitResponse{status: http.StatusOK, contentType: "text/xml; charset=UTF-8", body: xmlrpcAuthFault}, true)
		case base == "xmlrpc.php" && rq.method == http.MethodPost:
			return php(baitResponse{status: http.StatusOK, contentType: "text/xml; charset=UTF-8", body: xmlrpcFault}, true)
		case base == "xmlrpc.php":
			return php(baitResponse{status: http.StatusMethodNotAllowed, contentType: "text/plain; charset=UTF-8", body: "XML-RPC server accepts POST requests only."}, true)
		case strings.Contains(lower, "/wp-json"):
			return php(jsonBody(fill(wpJSON)))
		case rq.session && strings.Contains(lower, "/wp-admin"):
			return php(page(fill(wpDashboard)))
		case submitted && rq.reused:
			return php(signIn("/wp-admin/", "wordpress_logged_in_"+tok.str("wp_cookie", 32, hexDigits)))
		case submitted:
			return php(page(fill(wpLogin, "{{error}}", fill(wpLoginError, "{{user}}", user), "{{user}}", user)))
		default:
			return php(page(fill(wpLogin, "{{error}}", "", "{{user}}", "")))
		}

	case BaitPHPMyAdmin:
		token := tok.str("pma_token", 32, hexDigits)
		switch {
		case rq.session:
			return php(page(fill(pmaMain, "{{token}}", token)))
		case submitted && rq.reused:
			return php(signIn(localPath(path), "phpMyAdmin"))
		case submitted:
			return php(page(fill(pmaLogin, "{{token}}", token, "{{error}}", fill(pmaError, "{{user}}", user))))
		default:
			return php(page(fill(pmaLogin, "{{token}}", token, "{{error}}", "")))
		}

	case BaitLogin:
		csrf := tok.str("csrf", 40, alphaNum)
		switch {
		case rq.session:
			return page(fill(appDashboard, "{{csrf}}", csrf))
		case submitted && rq.reused:
			return signIn(localPath(path), "app_session")
		case submitted:
			return page(fill(loginPage, "{{csrf}}", csrf, "{{error}}", loginError, "{{user}}", user))
		default:
			return page(fill(loginPage, "{{csrf}}", csrf, "{{error}}", "", "{{user}}", ""))
		}

	case BaitBasicAuth:
		if rq.reused {
			return page(fill(tomcatManager))
		}
		return baitResponse{
			status:      http.StatusUnauthorized,
			contentType: "text/html;charset=utf-8",
			body:        tomcatUnauthorized,
			wwwAuth:     `Basic realm="Tomcat Manager Application"`,
		}, true

	case BaitActuator:
		switch base {
		case "health":
			return jsonBody(`{"status":"UP"}`)
		case "env":
			return jsonBody(actuatorEnv)
		case "actuator":
			return jsonBody(fill(actuatorIndex))
		}
		quoted, _ := json.Marshal(path)
		return baitResponse{status: http.StatusNotFound, contentType: "application/json", body: fill(actuatorNotFound, "{{path}}", string(quoted))}, true

	case BaitScript:
		if base == "phpinfo.php" {
			return php(page(fill(phpInfo)))
		}
		// 多数被探测的脚本（配置、探针、木马）被直接访问时输出空页面
		return php(page(""))

	case BaitForbidden:
		// 始终使用下方的 403 页面

	case BaitNone:
		return baitResponse{}, false
	}

	// 该类型下没有对应内容的路径：与真实站点一样拒绝访问
	return baitResponse{status: http.StatusForbidden, contentType: "text/html", body: nginxForbidden}, true
}

// sshPrivateKey 生成外观上像 OpenSSH 私钥的文本（内容不是有效密钥）
func sshPrivateKey(tok tokens) string {
	body := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW" + tok.str("ssh_key", 326, alphaNum)
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(body) > 70 {
		b.WriteString(body[:70] + "\n")
		body = body[70:]
	}
	b.WriteString(body + "=\n-----END OPENSSH PRIVATE KEY-----\n")
	return b.String()
}

const envFile = `APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:{{app_key}}
APP_DEBUG=false
APP_URL=https://{{host}}

LOG_CHANNEL=stack
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app
DB_PASSWORD={{db_pass}}

ADMIN_EMAIL=admin@{{host}}
ADMIN_PASSWORD={{admin_pass}}

CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis
SESSION_LIFETIME=120

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.{{host}}
MAIL_PORT=587
MAIL_USERNAME=no-reply@{{host}}
MAIL_PASSWORD={{mail_pass}}
MAIL_ENCRYPTION=tls

AWS_ACCESS_KEY_ID={{aws_id}}
AWS_SECRET_ACCESS_KEY={{aws_secret}}
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=app-production-assets
`

const awsCredentials = `[default]
aws_access_key_id = {{aws_id}}
aws_secret_access_key = {{aws_secret}}
`

const bashHistory = `cd /var/www/html
git pull origin main
composer install --no-dev
php artisan migrate --force
mysql -u app -p'{{db_pass}}' app_production
sudo systemctl restart php8.2-fpm
sudo nginx -t && sudo systemctl reload nginx
tail -f storage/logs/laravel.log
exit
`

const gitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@git.{{host}}:web/app.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`

const sqlDump = `-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: app_production
-- ------------------------------------------------------
-- Server version	8.0.36-0ubuntu0.22.04.1

/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET TIME_ZONE='+00:00' */;

--
-- Table structure for table ` + "`users`" + `
--

DROP TABLE IF EXISTS ` + "`users`" + `;
CREATE TABLE ` + "`users`" + ` (
  ` + "`id`" + ` bigint unsigned NOT NULL AUTO_INCREMENT,
  ` + "`name`" + ` varchar(255) NOT NULL,
  ` + "`email`" + ` varchar(255) NOT NULL,
  ` + "`password`" + ` varchar(255) NOT NULL,
  ` + "`created_at`" + ` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (` + "`id`" + `),
  UNIQUE KEY ` + "`users_email_unique`" + ` (` + "`email`" + `)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table ` + "`users`" + `
--

LOCK TABLES ` + "`users`" + ` WRITE;
INSERT INTO ` + "`users`" + ` VALUES (1,'Administrator','admin@{{host}}','$2y$10${{hash1}}','2023-03-14 09:21:07'),(2,'Support','support@{{host}}','$2y$10${{hash2}}','2023-03-14 09:25:42');
UNLOCK TABLES;
`

const packageJSON = `{
  "name": "app",
  "version": "1.4.2",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "start": "node server/index.js"
  },
  "dependencies": {
    "axios": "^1.6.8",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "mysql2": "^3.9.7",
    "vue": "^3.4.21"
  },
  "devDependencies": {
    "vite": "^5.2.8"
  }
}
`

const composerJSON = `{
    "name": "laravel/laravel",
    "type": "project",
    "require": {
        "php": "^8.2",
        "guzzlehttp/guzzle": "^7.8",
        "laravel/framework": "^10.48",
        "laravel/sanctum": "^3.3"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.5"
    },
    "autoload": {
        "psr-4": {
            "App\\": "app/"
        }
    }
}
`

const configJSON = `{
  "env": "production",
  "port": 3000,
  "database": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "app",
    "password": "{{db_pass}}",
    "name": "app_production"
  },
  "redis": {
    "host": "127.0.0.1",
    "port": 6379
  },
  "jwtSecret": "{{jwt}}",
  "baseUrl": "https://{{host}}"
}
`

const configYAML = `env: production
server:
  port: 3000
  base_url: https://{{host}}
database:
  host: 127.0.0.1
  port: 3306
  user: app
  password: {{db_pass}}
  name: app_production
redis:
  host: 127.0.0.1
  port: 6379
jwt_secret: {{jwt}}
`

const composeYAML = `services:
  app:
    image: registry.{{host}}/web/app:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      DB_HOST: db
      DB_USER: app
      DB_PASSWORD: {{db_pass}}
    depends_on:
      - db
  db:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: app_production
      MYSQL_USER: app
      MYSQL_PASSWORD: {{db_pass}}
    volumes:
      - db_data:/var/lib/mysql
volumes:
  db_data:
`

const xmlrpcFault = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
`

const wpJSON = `{"name":"{{host}}","description":"","url":"https:\/\/{{host}}","home":"https:\/\/{{host}}","gmt_offset":"0","timezone_string":"","namespaces":["oembed\/1.0","wp\/v2","wp-site-health\/v1","wp-block-editor\/v1"],"authentication":{"application-passwords":{"endpoints":{"authorization":"https:\/\/{{host}}\/wp-admin\/authorize-application.php"}}},"routes":{"\/":{"namespace":"","methods":["GET"]},"\/wp\/v2":{"namespace":"wp\/v2","methods":["GET"]},"\/wp\/v2\/posts":{"namespace":"wp\/v2","methods":["GET","POST"]},"\/wp\/v2\/users":{"namespace":"wp\/v2","methods":["GET","POST"]}}}`

const wpLogin = `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {{host}} &#8212; WordPress</title>
<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
<link rel='stylesheet' id='dashicons-css' href='https://{{host}}/wp-includes/css/dashicons.min.css?ver=6.5.3' type='text/css' media='all' />
<link rel='stylesheet' id='buttons-css' href='https://{{host}}/wp-includes/css/buttons.min.css?ver=6.5.3' type='text/css' media='all' />
<link rel='stylesheet' id='forms-css' href='https://{{host}}/wp-admin/css/forms.min.css?ver=6.5.3' type='text/css' media='all' />
<link rel='stylesheet' id='login-css' href='https://{{host}}/wp-admin/css/login.min.css?ver=6.5.3' type='text/css' media='all' />
<meta name='referrer' content='strict-origin-when-cross-origin' />
<meta name="viewport" content="width=device-width" />
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
<script type="text/javascript">document.body.className = document.body.className.replace('no-js','js');</script>
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{{error}}<form name="loginform" id="loginform" action="https://{{host}}/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="{{user}}" size="20" autocapitalize="off" autocomplete="username" required="required" />
</p>
<div class="user-pass-wrap">
<label for="user_pass">Password</label>
<div class="wp-pwd">
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
</div>
</div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="https://{{host}}/wp-admin/" />
<input type="hidden" name="testcookie" value="1" />
</p>
</form>
<p id="nav"><a class="wp-login-lost-password" href="https://{{host}}/wp-login.php?action=lostpassword">Lost your password?</a></p>
<p id="backtoblog"><a href="https://{{host}}/">&larr; Go to {{host}}</a></p>
</div>
</body>
</html>
`

const pmaLogin = `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow,notranslate">
<link rel="icon" href="favicon.ico" type="image/x-icon">
<link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/theme.css?v=5.2.1">
<title>phpMyAdmin</title>
</head>
<body id="loginform">
<div class="container">
<div class="row">
<div class="col-12 text-center">
<a href="./url.php?url=https%3A%2F%2Fwww.phpmyadmin.net%2F" target="_blank" rel="noopener noreferrer" class="logo">
<img src="./themes/pmahomme/img/logo_right.png" id="imLogo" name="imLogo" alt="phpMyAdmin" border="0">
</a>
<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>
</div>
</div>
{{error}}<form method="post" id="login_form" action="index.php?route=/" name="login_form" class="disableAjax hide js-show">
<input type="hidden" name="route" value="/">
<input type="hidden" name="token" value="{{token}}">
<input type="hidden" name="set_session" value="{{token}}">
<div class="card mb-4">
<div class="card-header">Log in</div>
<div class="card-body">
<div class="row mb-3">
<label for="input_username" class="col-sm-4 col-form-label">Username:</label>
<div class="col-sm-8"><input type="text" name="pma_username" id="input_username" value="" class="form-control" autocomplete="username" spellcheck="false" autofocus></div>
</div>
<div class="row">
<label for="input_password" class="col-sm-4 col-form-label">Password:</label>
<div class="col-sm-8"><input type="password" name="pma_password" id="input_password" value="" class="form-control" autocomplete="current-password" spellcheck="false"></div>
</div>
<input type="hidden" name="server" value="1">
</div>
<div class="card-footer"><input class="btn btn-primary" value="Log in" type="submit" id="input_go"></div>
</div>
</form>
</div>
</body>
</html>
`

const loginPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{csrf}}">
<meta name="robots" content="noindex, nofollow">
<title>Sign in - {{host}}</title>
<link rel="stylesheet" href="/assets/css/app.css?id=4f1c2a9e">
</head>
<body class="auth">
<main class="auth-card">
<h1>Sign in</h1>
{{error}}<form method="POST" action="/login" autocomplete="off">
<input type="hidden" name="_token" value="{{csrf}}">
<label for="email">Email address</label>
<input id="email" type="email" name="email" value="{{user}}" required autofocus>
<label for="password">Password</label>
<input id="password" type="password" name="password" required>
<label class="remember"><input type="checkbox" name="remember"> Remember me</label>
<button type="submit">Sign in</button>
</form>
<p class="muted"><a href="/password/reset">Forgot your password?</a></p>
</main>
<script src="/assets/js/app.js?id=9b7d03c1"></script>
</body>
</html>
`

const actuatorIndex = `{"_links":{"self":{"href":"https://{{host}}/actuator","templated":false},"health":{"href":"https://{{host}}/actuator/health","templated":false},"health-path":{"href":"https://{{host}}/actuator/health/{*path}","templated":true},"info":{"href":"https://{{host}}/actuator/info","templated":false},"env":{"href":"https://{{host}}/actuator/env","templated":false},"metrics":{"href":"https://{{host}}/actuator/metrics","templated":false}}}`

const actuatorEnv = `{"activeProfiles":["prod"],"propertySources":[{"name":"server.ports","properties":{"local.server.port":{"value":8080}}},{"name":"systemEnvironment","properties":{"SPRING_PROFILES_ACTIVE":{"value":"prod","origin":"System Environment Property \"SPRING_PROFILES_ACTIVE\""},"SPRING_DATASOURCE_URL":{"value":"jdbc:mysql://127.0.0.1:3306/app_production","origin":"System Environment Property \"SPRING_DATASOURCE_URL\""},"SPRING_DATASOURCE_USERNAME":{"value":"app","origin":"System Environment Property \"SPRING_DATASOURCE_USERNAME\""},"SPRING_DATASOURCE_PASSWORD":{"value":"******","origin":"System Environment Property \"SPRING_DATASOURCE_PASSWORD\""},"JWT_SECRET":{"value":"******","origin":"System Environment Property \"JWT_SECRET\""}}}]}`

const actuatorNotFound = `{"timestamp":"2024-05-21T08:14:33.512+00:00","status":404,"error":"Not Found","path":{{path}}}`

const phpInfo = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}
.center {text-align: center;}
.center table {margin: 1em auto; text-align: left;}
td, th {border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}
.e {background-color: #ccf; width: 300px; font-weight: bold;}
.h {background-color: #99c; font-weight: bold;}
.v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
</style>
<title>PHP 8.2.20 - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
<body><div class="center">
<table>
<tr class="h"><td><h1 class="p">PHP Version 8.2.20</h1></td></tr>
</table>
<table>
<tr><td class="e">System </td><td class="v">Linux web-01 5.15.0-107-generic #117-Ubuntu SMP x86_64 </td></tr>
<tr><td class="e">Build Date </td><td class="v">Jun  8 2024 21:40:52 </td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>
<tr><td class="e">Configuration File (php.ini) Path </td><td class="v">/etc/php/8.2/fpm </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/8.2/fpm/php.ini </td></tr>
<tr><td class="e">PHP API </td><td class="v">20220829 </td></tr>
<tr><td class="e">Zend Extension Build </td><td class="v">API420220829,NTS </td></tr>
</table>
<h2>PHP Variables</h2>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">$_SERVER['SERVER_SOFTWARE']</td><td class="v">nginx/1.24.0</td></tr>
<tr><td class="e">$_SERVER['SERVER_NAME']</td><td class="v">{{host}}</td></tr>
<tr><td class="e">$_SERVER['DOCUMENT_ROOT']</td><td class="v">/var/www/html/public</td></tr>
</table>
</div></body></html>
`

const nginxForbidden = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

const xmlrpcAuthFault = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
`

const wpLoginError = `<div id="login_error" class="notice notice-error"><p><strong>Error:</strong> The password you entered for the username <strong>{{user}}</strong> is incorrect. <a href="https://{{host}}/wp-login.php?action=lostpassword">Lost your password?</a></p></div>
`

const wpDashboard = `<!DOCTYPE html>
<html class="wp-toolbar" lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Dashboard &lsaquo; {{host}} &#8212; WordPress</title>
<link rel='stylesheet' id='dashicons-css' href='https://{{host}}/wp-includes/css/dashicons.min.css?ver=6.5.3' type='text/css' media='all' />
<link rel='stylesheet' id='admin-bar-css' href='https://{{host}}/wp-includes/css/admin-bar.min.css?ver=6.5.3' type='text/css' media='all' />
<link rel='stylesheet' id='common-css' href='https://{{host}}/wp-admin/css/common.min.css?ver=6.5.3' type='text/css' media='all' />
</head>
<body class="wp-admin wp-core-ui no-js index-php auto-fold admin-bar branch-6-5 version-6-5-3 admin-color-fresh locale-en-us">
<div id="wpwrap">
<div id="adminmenumain" role="navigation" aria-label="Main menu">
<ul id="adminmenu">
<li class="wp-first-item current menu-top menu-icon-dashboard" id="menu-dashboard"><a href='index.php' class="menu-top"><div class="wp-menu-name">Dashboard</div></a></li>
<li class="menu-top menu-icon-post" id="menu-posts"><a href='edit.php' class="menu-top"><div class="wp-menu-name">Posts</div></a></li>
<li class="menu-top menu-icon-media" id="menu-media"><a href='upload.php' class="menu-top"><div class="wp-menu-name">Media</div></a></li>
<li class="menu-top menu-icon-page" id="menu-pages"><a href='edit.php?post_type=page' class="menu-top"><div class="wp-menu-name">Pages</div></a></li>
<li class="menu-top menu-icon-plugins" id="menu-plugins"><a href='plugins.php' class="menu-top"><div class="wp-menu-name">Plugins <span class="update-plugins count-3"><span class="plugin-count">3</span></span></div></a></li>
<li class="menu-top menu-icon-users" id="menu-users"><a href='users.php' class="menu-top"><div class="wp-menu-name">Users</div></a></li>
<li class="menu-top menu-icon-settings" id="menu-settings"><a href='options-general.php' class="menu-top"><div class="wp-menu-name">Settings</div></a></li>
</ul>
</div>
<div id="wpcontent">
<div id="wpbody" role="main">
<div id="wpbody-content">
<div class="wrap">
<h1>Dashboard</h1>
<div id="dashboard-widgets-wrap">
<div id="dashboard_right_now" class="postbox"><div class="postbox-header"><h2 class="hndle">At a Glance</h2></div>
<div class="inside"><div class="main"><ul><li class="post-count"><a href="edit.php?post_type=post">14 Posts</a></li><li class="page-count"><a href="edit.php?post_type=page">6 Pages</a></li></ul>
<p id="wp-version-message"><span id="wp-version">WordPress 6.5.3 running <a href="themes.php">Twenty Twenty-Four</a> theme.</span></p></div></div></div>
<div id="dashboard_site_health" class="postbox"><div class="postbox-header"><h2 class="hndle">Site Health Status</h2></div>
<div class="inside"><p>Your site has a critical issue that should be addressed as soon as possible to improve its performance and security.</p></div></div>
</div>
</div>
</div>
</div>
<div id="wpfooter" role="contentinfo"><p id="footer-left" class="alignleft">Thank you for creating with <a href="https://wordpress.org/">WordPress</a>.</p><p id="footer-upgrade" class="alignright">Version 6.5.3</p></div>
</div>
</div>
</body>
</html>
`

const pmaError = `<div class="alert alert-danger" role="alert"><img src="themes/dot.gif" title="" alt="" class="icon ic_s_error"> Cannot log in to the MySQL server</div>
<div class="alert alert-danger" role="alert"><img src="themes/dot.gif" title="" alt="" class="icon ic_s_error"> mysqli::real_connect(): (HY000/1045): Access denied for user '{{user}}'@'localhost' (using password: YES)</div>
`

const pmaMain = `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow,notranslate">
<link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/theme.css?v=5.2.1">
<title>localhost | phpMyAdmin 5.2.1</title>
</head>
<body>
<div id="pma_navigation" data-config-navigation-width="240">
<div id="pma_navigation_header"><a class="hide navigation_url" href="index.php?route=/navigation&ajax_request=1&token={{token}}"></a>
<div id="serverChoice"></div></div>
<div id="pma_navigation_tree" class="list_container synced highlight autoexpand">
<div id="pma_navigation_tree_content"><ul>
<li class="database"><a class="hover_show_full" href="index.php?route=/database/structure&db=app_production">app_production</a></li>
<li class="database"><a class="hover_show_full" href="index.php?route=/database/structure&db=information_schema">information_schema</a></li>
<li class="database"><a class="hover_show_full" href="index.php?route=/database/structure&db=performance_schema">performance_schema</a></li>
</ul></div>
</div>
</div>
<div id="page_content">
<div class="container-fluid">
<div class="row mb-3">
<div class="col-lg-7 col-12">
<div class="card mt-4"><div class="card-header">General settings</div>
<ul class="list-group list-group-flush"><li id="li_select_mysql_collation" class="list-group-item">Server connection collation: utf8mb4_unicode_ci</li></ul></div>
</div>
<div class="col-lg-5 col-12">
<div class="card mt-4"><div class="card-header">Database server</div>
<ul class="list-group list-group-flush">
<li class="list-group-item">Server: Localhost via UNIX socket</li>
<li class="list-group-item">Server type: MySQL</li>
<li class="list-group-item">Server version: 8.0.36-0ubuntu0.22.04.1 - (Ubuntu)</li>
<li class="list-group-item">User: app@localhost</li>
<li class="list-group-item">Server charset: UTF-8 Unicode (utf8mb4)</li>
</ul></div>
<div class="card mt-4"><div class="card-header">phpMyAdmin</div>
<ul class="list-group list-group-flush"><li id="li_pma_version" class="list-group-item">Version information: <span class="version">5.2.1</span></li></ul></div>
</div>
</div>
</div>
</div>
</body>
</html>
`

const loginError = `<p class="error" role="alert">These credentials do not match our records.</p>
`

const appDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{csrf}}">
<meta name="robots" content="noindex, nofollow">
<title>Dashboard - {{host}}</title>
<link rel="stylesheet" href="/assets/css/app.css?id=4f1c2a9e">
</head>
<body class="app">
<nav class="sidebar">
<a class="active" href="/dashboard">Dashboard</a>
<a href="/admin/users">Users</a>
<a href="/admin/orders">Orders</a>
<a href="/admin/settings">Settings</a>
<a href="/admin/logs">Logs</a>
</nav>
<main>
<header><h1>Dashboard</h1><span class="user">Administrator</span></header>
<section class="cards">
<div class="card"><h2>Users</h2><p>1,284</p></div>
<div class="card"><h2>Orders today</h2><p>37</p></div>
<div class="card"><h2>Queue</h2><p>0 pending</p></div>
</section>
<section>
<h2>Recent sign-ins</h2>
<table><thead><tr><th>User</th><th>IP</th><th>Time</th></tr></thead>
<tbody><tr><td>admin@{{host}}</td><td>10.0.3.17</td><td>2 minutes ago</td></tr><tr><td>support@{{host}}</td><td>10.0.3.22</td><td>3 hours ago</td></tr></tbody></table>
</section>
</main>
<script src="/assets/js/app.js?id=9b7d03c1"></script>
</body>
</html>
`

const tomcatUnauthorized = `<!doctype html><html lang="en"><head><title>HTTP Status 401 – Unauthorized</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 401 – Unauthorized</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Description</b> The request has not been applied to the target resource because it lacks valid authentication credentials for that resource.</p><hr class="line" /><h3>Apache Tomcat/9.0.89</h3></body></html>`

const tomcatManager = `<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<link href="/manager/css/manager.css" rel="stylesheet" type="text/css" />
<title>/manager</title>
</head>
<body bgcolor="#FFFFFF">
<table cellspacing="4" border="0">
 <tr><td colspan="2"><a href="https://tomcat.apache.org/"><img border="0" alt="The Tomcat Servlet/JSP Container" align="left" src="/manager/images/tomcat.svg" style="width: 266px; height: 83px;"></a></td></tr>
</table>
<hr size="1" noshade="noshade">
<table cellspacing="4" border="0">
 <tr><td class="page-title" bordercolor="#000000" align="left" nowrap><font size="+2">Tomcat Web Application Manager</font></td></tr>
</table>
<br>
<table border="1" cellspacing="0" cellpadding="3">
 <tr><td class="row-left" width="10%"><small><strong>Message:</strong></small>&nbsp;</td><td class="row-left"><pre>OK</pre></td></tr>
</table>
<br>
<table border="1" cellspacing="0" cellpadding="3">
<tr><td colspan="6" class="title">Applications</td></tr>
<tr><td class="header-left"><small>Path</small></td><td class="header-left"><small>Version</small></td><td class="header-center"><small>Display Name</small></td><td class="header-center"><small>Running</small></td><td class="header-left"><small>Sessions</small></td><td class="header-left"><small>Commands</small></td></tr>
<tr><td class="row-left" bgcolor="#FFFFFF"><small><a href="/">/</a></small></td><td class="row-left" bgcolor="#FFFFFF"><small><i>None specified</i></small></td><td class="row-left" bgcolor="#FFFFFF"><small>app</small></td><td class="row-center" bgcolor="#FFFFFF"><small>true</small></td><td class="row-center" bgcolor="#FFFFFF"><small><a href="/manager/html/sessions?path=/">4</a></small></td><td class="row-left" bgcolor="#FFFFFF"><small>Start Stop Reload Undeploy</small></td></tr>
<tr><td class="row-left" bgcolor="#C3F3C3"><small><a href="/manager">/manager</a></small></td><td class="row-left" bgcolor="#C3F3C3"><small><i>None specified</i></small></td><td class="row-left" bgcolor="#C3F3C3"><small>Tomcat Manager Application</small></td><td class="row-center" bgcolor="#C3F3C3"><small>true</small></td><td class="row-center" bgcolor="#C3F3C3"><small><a href="/manager/html/sessions?path=/manager">1</a></small></td><td class="row-left" bgcolor="#C3F3C3"><small>Start Stop Reload Undeploy</small></td></tr>
</table>
<br>
<table border="1" cellspacing="0" cellpadding="3">
<tr><td colspan="8" class="title">Server Information</td></tr>
<tr><td class="header-center"><small>Tomcat Version</small></td><td class="header-center"><small>JVM Version</small></td><td class="header-center"><small>OS Name</small></td><td class="header-center"><small>OS Architecture</small></td><td class="header-center"><small>Hostname</small></td></tr>
<tr><td class="row-center"><small>Apache Tomcat/9.0.89</small></td><td class="row-center"><small>17.0.11+9-Ubuntu-122.04.1</small></td><td class="row-center"><small>Linux</small></td><td class="row-center"><small>amd64</small></td><td class="row-center"><small>{{host}}</small></td></tr>
</table>
</body>
</html>
`
