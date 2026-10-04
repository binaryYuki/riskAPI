// Package ipset 提供 IP/CIDR → 标签 的最长前缀匹配表，以及 IP 解析与 bogon 判断。
package ipset

import (
	"iter"
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"
)

// Set 是 IP/CIDR → 标签 的查找表，基于 bart 多比特前缀树做最长前缀匹配，
// 查询复杂度与条目数无关。约定发布后只读：更新时构建新表并整体替换（通常配合
// atomic.Pointer），查询路径无锁。单个 IP 以 /32、/128 前缀存储。
// nil *Set 可安全查询，视为空表。
type Set struct {
	table bart.Table[string]
}

// New 返回空表
func New() *Set {
	return &Set{}
}

// ParseEntry 将 IP 或 CIDR 字符串解析为规范化前缀（IPv4-mapped 地址统一转为 IPv4）
func ParseEntry(entry string) (netip.Prefix, bool) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, false
		}
		addr, bits := p.Addr(), p.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, false
			}
			addr, bits = addr.Unmap(), bits-96
		}
		return netip.PrefixFrom(addr, bits).Masked(), true
	}
	addr, ok := ParseAddr(entry)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// ParseAddr 解析查询用的 IP：去掉 zone，IPv4-mapped 转为 IPv4
func ParseAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

// Insert 写入条目，同一前缀后写覆盖先写；仅用于构建阶段
func (s *Set) Insert(entry, label string) bool {
	p, ok := ParseEntry(entry)
	if !ok {
		return false
	}
	s.table.Insert(p, label)
	return true
}

// InsertIfAbsent 写入条目，同一前缀保留先写入的标签；仅用于构建阶段
func (s *Set) InsertIfAbsent(entry, label string) bool {
	p, ok := ParseEntry(entry)
	if !ok {
		return false
	}
	s.table.Modify(p, func(old string, exists bool) (string, bool) {
		if exists {
			return old, false
		}
		return label, false
	})
	return true
}

// Lookup 返回包含该 IP 的最具体前缀对应的标签
func (s *Set) Lookup(ip string) (string, bool) {
	if s == nil {
		return "", false
	}
	addr, ok := ParseAddr(ip)
	if !ok {
		return "", false
	}
	return s.table.Lookup(addr)
}

// Without 返回删除指定条目后的新表（写时复制，原表不变）
func (s *Set) Without(entry string) (*Set, bool) {
	if s == nil {
		return s, false
	}
	p, ok := ParseEntry(entry)
	if !ok {
		return s, false
	}
	if _, exists := s.table.Get(p); !exists {
		return s, false
	}
	return &Set{table: *s.table.DeletePersist(p)}, true
}

// Len 返回前缀数量
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return s.table.Size()
}

// All 按地址顺序遍历全部前缀
func (s *Set) All() iter.Seq2[netip.Prefix, string] {
	if s == nil {
		return func(func(netip.Prefix, string) bool) {}
	}
	return s.table.AllSorted()
}
