package main

import "regexp"

// DefaultSuspiciousRegex 返回默认可疑路径匹配
func DefaultSuspiciousRegex() *regexp.Regexp {
	// 常见扫描器路径 + 敏感文件 + 常见控制台端点 + UPI/NPCI 相关关键词
	p := `(?i)(` +
		`(^|/)(wp-admin|wp-login|wp-json|xmlrpc\.php)` + `|` +
		`(^|/)(phpmyadmin|pma|server-status|hudson|jenkins|actuator|env|debug|druid|admin|login|console|dashboard|solr|kibana|grafana)` + `|` +
		`(^|/)(\.git|\.env|\.DS_Store|id_rsa|composer\.json|composer\.lock|package\.json|yarn\.lock|\.htaccess|\.htpasswd|\.svn|\.hg|\.idea|vendor/|node_modules/)` + `|` +
		`(^|/)(_next|static|assets)/.*\.(php|asp|aspx|jsp)$` + `|` +
		`(^|/)(unified[-_]?payments?interface|npci(?:[-_]?upi)?|imps(?:[-_]?npci)?|neft(?:[-_]?npci)?|bhim(?:[-_]?npci)?|cts(?:[-_]?npci)?|cheque[-_]?truncation[-_]?system|national[-_]?payments[-_]?corporation)` +
		`)`
	return regexp.MustCompile(p)
}
