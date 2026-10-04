package main

import (
	"bufio"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

// prefixSet 是 IP/CIDR → 标签 的查找表，基于 bart 多比特前缀树做最长前缀匹配，
// 查询复杂度与条目数无关。发布后只读：更新时构建新表并通过 atomic.Pointer 整体替换，
// 查询路径无锁。单个 IP 以 /32、/128 前缀存储。
type prefixSet struct {
	table bart.Table[string]
}

func newPrefixSet() *prefixSet {
	return &prefixSet{}
}

// parseEntry 将 IP 或 CIDR 字符串解析为规范化前缀（IPv4-mapped 地址统一转为 IPv4）
func parseEntry(entry string) (netip.Prefix, bool) {
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
	addr, ok := parseAddr(entry)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// parseAddr 解析查询用的 IP：去掉 zone，IPv4-mapped 转为 IPv4
func parseAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

// insert 写入条目，同一前缀后写覆盖先写；仅用于构建阶段
func (s *prefixSet) insert(entry, label string) bool {
	p, ok := parseEntry(entry)
	if !ok {
		return false
	}
	s.table.Insert(p, label)
	return true
}

// insertIfAbsent 写入条目，同一前缀保留先写入的标签；仅用于构建阶段
func (s *prefixSet) insertIfAbsent(entry, label string) bool {
	p, ok := parseEntry(entry)
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

// lookup 返回包含该 IP 的最具体前缀对应的标签
func (s *prefixSet) lookup(ip string) (string, bool) {
	if s == nil {
		return "", false
	}
	addr, ok := parseAddr(ip)
	if !ok {
		return "", false
	}
	return s.table.Lookup(addr)
}

// without 返回删除指定条目后的新表（写时复制，原表不变）
func (s *prefixSet) without(entry string) (*prefixSet, bool) {
	p, ok := parseEntry(entry)
	if !ok {
		return s, false
	}
	if _, exists := s.table.Get(p); !exists {
		return s, false
	}
	return &prefixSet{table: *s.table.DeletePersist(p)}, true
}

func (s *prefixSet) size() int {
	if s == nil {
		return 0
	}
	return s.table.Size()
}

// all 按地址顺序遍历全部前缀
func (s *prefixSet) all() iter.Seq2[netip.Prefix, string] {
	if s == nil {
		return func(func(netip.Prefix, string) bool) {}
	}
	return s.table.AllSorted()
}

// ---------------------------------------------------------------------------
// 风险 IP 表
// ---------------------------------------------------------------------------

var (
	riskySet     atomic.Pointer[prefixSet]
	riskyWriteMu sync.Mutex // 串行化写操作（整表替换 / 单条删除），读操作无需加锁
)

func storeRiskySet(s *prefixSet) {
	riskyWriteMu.Lock()
	defer riskyWriteMu.Unlock()
	riskySet.Store(s)
}

// ---------------------------------------------------------------------------
// CDN / IDC 表（数据来自 data/cdn、data/idc 下的文本文件）
// ---------------------------------------------------------------------------

// 提供商顺序即同一前缀出现在多家时的优先级
var (
	cdnProviders = []string{"edgeone", "cloudflare", "fastly"}
	idcProviders = []string{"aws", "azure", "gcp", "akamai", "apple", "digitalocean", "linode", "oracle", "zscaler"}

	cdnSet atomic.Pointer[prefixSet]
	idcSet atomic.Pointer[prefixSet]
)

// loadProviderSet 读取 dir/<provider>.txt 构建查找表
func loadProviderSet(dir string, providers []string) *prefixSet {
	s := newPrefixSet()
	for _, provider := range providers {
		filePath := fmt.Sprintf("%s/%s.txt", dir, provider)
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("Warning: Could not open %s: %v\n", filePath, err)
			continue
		}
		loaded := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if s.insertIfAbsent(line, provider) {
				loaded++
			}
		}
		_ = file.Close()
		fmt.Printf("Loaded %s: %d entries\n", provider, loaded)
	}
	return s
}
