package ipset

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSet_LongestPrefixMatch(t *testing.T) {
	s := New()
	s.Insert("10.0.0.0/8", "wide")
	s.Insert("10.1.0.0/16", "narrow")
	s.Insert("10.1.2.3", "single")

	cases := map[string]string{
		"10.9.9.9": "wide",
		"10.1.9.9": "narrow",
		"10.1.2.3": "single",
	}
	for ip, want := range cases {
		got, ok := s.Lookup(ip)
		assert.True(t, ok, ip)
		assert.Equal(t, want, got, ip)
	}
	_, ok := s.Lookup("11.0.0.1")
	assert.False(t, ok)
}

// InsertPrefix 不要求调用方先规范化：未清零主机位、IPv4-mapped 的前缀都应能被查到
func TestSet_InsertPrefixNormalizes(t *testing.T) {
	s := New()
	assert.True(t, s.InsertPrefix(netip.MustParsePrefix("1.2.3.4/24"), "unmasked"))
	assert.True(t, s.InsertPrefix(netip.MustParsePrefix("::ffff:5.6.7.0/120"), "mapped"))
	assert.False(t, s.InsertPrefix(netip.MustParsePrefix("::ffff:5.6.7.0/64"), "too-wide"))
	assert.False(t, s.InsertPrefix(netip.Prefix{}, "invalid"))

	got, ok := s.Lookup("1.2.3.200")
	assert.True(t, ok)
	assert.Equal(t, "unmasked", got)
	got, ok = s.Lookup("5.6.7.8")
	assert.True(t, ok)
	assert.Equal(t, "mapped", got)
	assert.Equal(t, 2, s.Len())

	// 与字符串入口写入的是同一个前缀
	viaString := New()
	viaString.Insert("1.2.3.4/24", "x")
	for p := range viaString.All() {
		_, exists := s.table.Get(p)
		assert.True(t, exists, p)
	}
}

func TestSet_IPv4MappedAndIPv6(t *testing.T) {
	s := New()
	s.Insert("1.2.3.0/24", "v4")
	s.Insert("2001:db8:1::/48", "v6")

	got, ok := s.Lookup("::ffff:1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, "v4", got)

	got, ok = s.Lookup("2001:db8:1:2::1")
	assert.True(t, ok)
	assert.Equal(t, "v6", got)

	// 非规范 CIDR（主机位不为 0）按网络地址处理
	s.Insert("5.6.7.8/24", "noncanonical")
	got, ok = s.Lookup("5.6.7.200")
	assert.True(t, ok)
	assert.Equal(t, "noncanonical", got)
}

func TestSet_InvalidInput(t *testing.T) {
	s := New()
	assert.False(t, s.Insert("not-an-ip", "x"))
	assert.False(t, s.Insert("1.2.3.0/33", "x"))
	_, ok := s.Lookup("not-an-ip")
	assert.False(t, ok)

	var nilSet *Set
	_, ok = nilSet.Lookup("1.2.3.4")
	assert.False(t, ok, "nil set must be safe before initialization")
	assert.Equal(t, 0, nilSet.Len())
	_, removed := nilSet.Without("1.2.3.4")
	assert.False(t, removed)
}

func TestSet_InsertIfAbsentKeepsFirst(t *testing.T) {
	s := New()
	s.InsertIfAbsent("1.2.3.0/24", "first")
	s.InsertIfAbsent("1.2.3.0/24", "second")
	got, _ := s.Lookup("1.2.3.4")
	assert.Equal(t, "first", got)
}

func TestSet_WithoutIsCopyOnWrite(t *testing.T) {
	s := New()
	s.Insert("1.2.3.0/24", "a")
	s.Insert("4.5.6.7", "b")

	next, removed := s.Without("1.2.3.0/24")
	assert.True(t, removed)
	_, ok := next.Lookup("1.2.3.4")
	assert.False(t, ok)
	_, ok = s.Lookup("1.2.3.4")
	assert.True(t, ok, "original set must stay unchanged for concurrent readers")

	_, removed = next.Without("9.9.9.0/24")
	assert.False(t, removed)
}

func TestSet_AllSorted(t *testing.T) {
	s := New()
	s.Insert("9.0.0.0/8", "b")
	s.Insert("1.2.3.0/24", "a")
	var got []string
	for p, label := range s.All() {
		got = append(got, p.String()+"="+label)
	}
	assert.Equal(t, []string{"1.2.3.0/24=a", "9.0.0.0/8=b"}, got)
}

func TestIsBogonOrPrivate(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":               true,
		"192.168.0.1":            true,
		"127.0.0.1":              true,
		"100.64.1.1":             true,
		"203.0.113.9":            true,
		"255.255.255.255":        true,
		"::ffff:192.168.1.1":     true, // IPv4-mapped 按 IPv4 处理
		"::1":                    true,
		"fe80::1":                true,
		"fd00::1":                true,
		"2001:db8::1":            true,
		"8.8.8.8":                false,
		"2001:4860:4860::8888":   false,
		"2002::1":                false, // 6to4 保持透明
		"not-an-ip":              false,
		"::ffff:8.8.8.8":         false,
		"172.32.0.1":             false,
		"2001:0:4136:e378::1234": false, // Teredo 保持透明
	}
	for ip, want := range cases {
		assert.Equal(t, want, IsBogonOrPrivate(ip), ip)
	}
}

func TestIsSpecial(t *testing.T) {
	assert.True(t, IsSpecial(netip.MustParseAddr("2002::1")))
	assert.False(t, IsSpecial(netip.MustParseAddr("8.8.8.8")))
}
