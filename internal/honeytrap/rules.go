package honeytrap

import "strings"

// 规则权重：来源的分数累计到阈值后被标记 / 封禁
const (
	WeightHigh   = 8.0 // 正常用户不可能访问的诱饵：凭据、密钥、版本库、数据库导出
	WeightMedium = 4.0 // 常被扫描的后台、CMS、运维面板与脚本
	WeightLow    = 1.0 // 未命中任何规则的 404

	repeatWeight = 0.25 // 桶内已出现过的路径再次命中
)

// Rule 一条路径规则。匹配不区分大小写，各匹配字段之间为"或"关系
type Rule struct {
	Name      string
	Weight    float64
	Bait      Bait // 命中后伪造的内容类型
	Forbidden bool // 未返回伪造内容时（蜜罐关闭或概率未命中）直接 403，而不是落到路由

	Files    []string // 末段文件名；同时匹配 name.<后缀>，如 .env.bak
	Segments []string // 任意层级的完整路径段
	Root     []string // 仅首个路径段
	Exts     []string // 末段扩展名（不含点）
}

// DefaultRules 返回默认规则表
func DefaultRules() []Rule {
	return []Rule{
		// 高权重：凭据与密钥
		{Name: "env-file", Weight: WeightHigh, Bait: BaitEnv, Forbidden: true,
			Files: []string{".env"}},
		{Name: "secret-file", Weight: WeightHigh, Bait: BaitSecret, Forbidden: true,
			Files:    []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".htpasswd", ".bash_history"},
			Segments: []string{".aws", ".ssh"}},
		{Name: "vcs", Weight: WeightHigh, Bait: BaitGit, Forbidden: true,
			Segments: []string{".git", ".svn", ".hg"}},
		{Name: "db-dump", Weight: WeightHigh, Bait: BaitSQL, Forbidden: true,
			Files: []string{"db.sql", "dump.sql", "backup.sql", "db.sqlite"},
			Exts:  []string{"sql", "sqlite", "bak"}},
		{Name: "webshell", Weight: WeightHigh, Bait: BaitScript, Forbidden: true,
			Files: []string{"wp-config.php", "phpinfo.php", "test.php", "debug.php", "admin.php", "webshell.php", "shell.php", "cmd.php"}},

		// 中权重：配置清单与工程文件
		{Name: "app-config", Weight: WeightMedium, Bait: BaitManifest, Forbidden: true,
			Files: []string{"config.json", "config.yml", "config.yaml", "composer.json", "composer.lock", "package.json", "yarn.lock", "docker-compose.yml"}},
		{Name: "dotfile", Weight: WeightMedium, Bait: BaitForbidden, Forbidden: true,
			Files:    []string{".ds_store", ".htaccess", ".gitignore", ".dockerignore"},
			Segments: []string{".idea"},
			Root:     []string{"backup", "vendor", "node_modules"}},

		// 中权重：后台、CMS 与运维面板
		{Name: "admin", Weight: WeightMedium, Bait: BaitLogin, Forbidden: true,
			Root: []string{"admin"}},
		{Name: "login-panel", Weight: WeightMedium, Bait: BaitLogin,
			Root: []string{"login", "console", "dashboard"}},
		{Name: "wordpress", Weight: WeightMedium, Bait: BaitWordPress,
			Files:    []string{"wp-login.php", "xmlrpc.php"},
			Segments: []string{"wp-admin", "wp-login", "wp-json"}},
		{Name: "phpmyadmin", Weight: WeightMedium, Bait: BaitPHPMyAdmin,
			Segments: []string{"phpmyadmin", "pma"}},
		{Name: "ops-console", Weight: WeightMedium, Bait: BaitLogin,
			Segments: []string{"jenkins", "hudson", "druid", "solr", "kibana", "grafana"},
			Root:     []string{"manager"}},
		{Name: "actuator", Weight: WeightMedium, Bait: BaitActuator,
			Segments: []string{"actuator"},
			Root:     []string{"env"}},
		{Name: "server-internals", Weight: WeightMedium, Bait: BaitForbidden,
			Segments: []string{"server-status", "cgi-bin", "phpunit"},
			Root:     []string{"debug"}},
		{Name: "script", Weight: WeightMedium, Bait: BaitScript,
			Exts: []string{"php", "asp", "aspx", "jsp"}},

		// UPI / NPCI 支付入口关键词
		{Name: "payment-portal", Weight: WeightMedium, Bait: BaitLogin,
			Segments: concat(
				[]string{"npci", "imps", "neft", "bhim", "cts"},
				joined("unified", "payments", "interface"), joined("unified", "payment", "interface"),
				joined("npci", "upi"), joined("imps", "npci"), joined("neft", "npci"), joined("bhim", "npci"), joined("cts", "npci"),
				joined("cheque", "truncation", "system"), joined("national", "payments", "corporation"),
			)},
	}
}

// joined 返回各部分以 ""、"-"、"_" 连接的三种写法
func joined(parts ...string) []string {
	return []string{strings.Join(parts, ""), strings.Join(parts, "-"), strings.Join(parts, "_")}
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// RuleSet 编译后的规则表，匹配只做若干次 map 查找
type RuleSet struct {
	files, segments, root, exts map[string]*Rule
}

// NewRuleSet 编译规则表；同一关键字出现在多条规则时取权重高者，权重相同取靠前者
func NewRuleSet(rules []Rule) *RuleSet {
	rs := &RuleSet{
		files:    make(map[string]*Rule),
		segments: make(map[string]*Rule),
		root:     make(map[string]*Rule),
		exts:     make(map[string]*Rule),
	}
	for i := range rules {
		r := &rules[i]
		add := func(index map[string]*Rule, keys []string) {
			for _, k := range keys {
				k = strings.ToLower(k)
				index[k] = heavier(index[k], r)
			}
		}
		add(rs.files, r.Files)
		add(rs.segments, r.Segments)
		add(rs.root, r.Root)
		add(rs.exts, r.Exts)
	}
	return rs
}

// heavier 返回权重更高的规则，相同时保留 cur
func heavier(cur, next *Rule) *Rule {
	if next != nil && (cur == nil || next.Weight > cur.Weight) {
		return next
	}
	return cur
}

// Match 返回路径命中的规则；多条命中时取权重最高者
func (rs *RuleSet) Match(path string) (*Rule, bool) {
	var best *Rule
	last := ""
	first := true
	for rest := strings.ToLower(path); rest != ""; {
		seg, tail, _ := strings.Cut(rest, "/")
		rest = tail
		if seg == "" {
			continue
		}
		if first {
			best = heavier(best, rs.root[seg])
			first = false
		}
		best = heavier(best, rs.segments[seg])
		last = seg
	}
	if last != "" {
		best = heavier(best, rs.files[last])
		// 从 1 开始：开头的点属于文件名本身（.env），不是后缀分隔符
		for i := 1; i < len(last); i++ {
			if last[i] == '.' {
				best = heavier(best, rs.files[last[:i]])
			}
		}
		if i := strings.LastIndexByte(last, '.'); i > 0 {
			best = heavier(best, rs.exts[last[i+1:]])
		}
	}
	return best, best != nil
}

// baseName 返回小写后的末段路径
func baseName(path string) string {
	p := strings.TrimRight(strings.ToLower(path), "/")
	return p[strings.LastIndexByte(p, '/')+1:]
}
