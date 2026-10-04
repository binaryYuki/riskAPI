package ipset

import "net/netip"

// mustParsePrefixes 解析包级常量网段，格式错误直接 panic（属于编码错误）
func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefixes[i] = netip.MustParsePrefix(c)
	}
	return prefixes
}

// 特殊/保留用途网段（仅用于统计分类，不视为 bogon）
var specialPrefixes = mustParsePrefixes(
	"64:ff9b::/96", // IPv4/IPv6 转换
	"100::/64",     // Discard prefix
	"2001:10::/28", // ORCHID（已废弃）
	"2001:20::/28", // ORCHIDv2
	"2001::/32",    // Teredo
	"2002::/16",    // 6to4
	"::/96",        // IPv4-compatible（已废弃）
)

// 私有 / 保留 / bogon 网段，启动时一次性解析
var bogonPrefixes = mustParsePrefixes(
	// IPv4 私有 / 内部 / 回环 / 链路本地 / CGNAT
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
	"127.0.0.0/8",    // 回环
	"169.254.0.0/16", // 链路本地
	"100.64.0.0/10",  // CGNAT（视为非公网）
	// IPv4 公共但特殊/测试/文档/多播等
	"0.0.0.0/8",          // 无效源
	"192.0.0.0/24",       // IETF 协议分配
	"192.0.2.0/24",       // TEST-NET-1
	"198.18.0.0/15",      // 基准测试（RFC 2544）
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"224.0.0.0/4",        // 多播
	"240.0.0.0/4",        // 未来保留
	"255.255.255.255/32", // 广播
	// IPv6（Teredo / 6to4 / ORCHID / 64:ff9b::/96 等过渡网段不标记为 bogon，保持透明）
	"::1/128",       // 回环
	"fe80::/10",     // 链路本地
	"fc00::/7",      // 唯一本地地址
	"::/128",        // 未指定地址
	"2001:db8::/32", // 文档
	"ff00::/8",      // 多播
)

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsSpecial 判断是否属于特殊/保留用途网段
func IsSpecial(addr netip.Addr) bool {
	return containsAddr(specialPrefixes, addr)
}

// IsBogonOrPrivate 判断是否为私网/保留地址；IPv4-mapped IPv6 按 IPv4 处理
func IsBogonOrPrivate(ip string) bool {
	addr, ok := ParseAddr(ip)
	if !ok {
		return false
	}
	return containsAddr(bogonPrefixes, addr)
}
