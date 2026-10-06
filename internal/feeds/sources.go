// Package feeds 抓取公开风险 IP 数据源，维护可并发查询的风险前缀表。
package feeds

// Format 数据源的响应格式
type Format int

const (
	// FormatText 每行一个 IP/CIDR，支持 # 和 ; 注释（含行内注释）与 Tor exit-addresses 格式
	FormatText Format = iota
	// FormatRSS Project Honey Pot RSS，IP 位于 <item><title>
	FormatRSS
)

// Feed 单个风险数据源；ID 作为命中原因返回给调用方
type Feed struct {
	ID     string
	URL    string
	Format Format
}

// DefaultFeeds 默认数据源。合并时按此顺序进行，同一前缀出现在多个源时后者的 ID 生效。
var DefaultFeeds = []Feed{
	{ID: "X4BNet-datacenter", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"},
	{ID: "X4BNet-vpn", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"},
	{ID: "torproject-exit", URL: "https://check.torproject.org/exit-addresses"},
	{ID: "dan.me.uk-tor", URL: "https://www.dan.me.uk/torlist/"},
	{ID: "data-center-list", URL: "https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt"},
	{ID: "projecthoneypot", URL: "https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1", Format: FormatRSS},
	{ID: "tor-bulk-exit", URL: "https://check.torproject.org/torbulkexitlist"},
	{ID: "danger.rulez.sk", URL: "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"},
	{ID: "spamhaus", URL: "https://www.spamhaus.org/drop/drop.txt"},
	{ID: "cinsscore", URL: "https://cinsscore.com/list/ci-badguys.txt"},
	{ID: "blocklist.de", URL: "https://lists.blocklist.de/lists/all.txt"},
	{ID: "firehol-cybercrime", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset"},
	{ID: "firehol-level1", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
	{ID: "firehol-level2", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"},
	{ID: "firehol-level3", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"},
	{ID: "firehol-level4", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset"},
	{ID: "greensnow", URL: "https://blocklist.greensnow.co/greensnow.txt"},
	// ipsum 第 N 级 = 出现在至少 N 个黑名单中，低级别包含高级别；按升序排列使每个 IP 取到其最高级别
	{ID: "ipsum-level2", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/2.txt"},
	{ID: "ipsum-level3", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/3.txt"},
	{ID: "ipsum-level4", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt"},
	{ID: "ipsum-level5", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt"},
	{ID: "ipsum-level6", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt"},
	{ID: "ipsum-level7", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/7.txt"},
	{ID: "ipsum-level8", URL: "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/8.txt"},
}
