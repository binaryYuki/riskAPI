package feeds

import "fmt"

// 可信源被篡改的代价远大于风险源（等于给攻击者开豁免），入表前做以下校验，不通过时整源拒收、沿用上次数据。
// 列表中的私网/bogon 条目无需过滤：判定时私网地址先于可信表返回
const (
	// trustedMinBitsV4 / trustedMinBitsV6 可信前缀的最短掩码；官方列表中最宽的为 PayPal 的 /20
	trustedMinBitsV4 = 20
	trustedMinBitsV6 = 48
	// trustedMaxEntries 单个可信源的条目上限；现有最大的 duckduckbot 约 500 条
	trustedMaxEntries = 4096
)

// checkTrusted 校验可信源数据：出现过宽前缀或条目过多时返回错误
func checkTrusted(d *feedData) error {
	if len(d.prefixes) > trustedMaxEntries {
		return fmt.Errorf("trusted source has %d entries, limit %d", len(d.prefixes), trustedMaxEntries)
	}
	for _, p := range d.prefixes {
		minBits := trustedMinBitsV4
		if p.Addr().Is6() {
			minBits = trustedMinBitsV6
		}
		if p.Bits() < minBits {
			return fmt.Errorf("trusted source contains overly broad prefix %s (minimum /%d)", p, minBits)
		}
	}
	return nil
}
