// Package netlists 加载 CDN 与 IDC（云厂商）网段列表，提供按提供商的 IP 归属查询。
package netlists

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"risky_ip_filter/internal/ipset"
)

// 提供商顺序即同一前缀出现在多家时的优先级
var (
	CDNProviders = []string{"edgeone", "cloudflare", "fastly"}
	IDCProviders = []string{"aws", "azure", "gcp", "akamai", "apple", "digitalocean", "linode", "oracle", "zscaler"}
)

// Lists CDN/IDC 查找表。数据来自 <dataDir>/cdn、<dataDir>/idc 下的 <provider>.txt，
// 随镜像发布、运行期不变；Reload 构建新表后原子替换，查询无锁。
type Lists struct {
	dataDir string
	log     *slog.Logger
	cdn     atomic.Pointer[ipset.Set]
	idc     atomic.Pointer[ipset.Set]
}

// New 创建空列表，需调用 Reload 加载
func New(dataDir string, log *slog.Logger) *Lists {
	return &Lists{dataDir: dataDir, log: log}
}

// Reload 重新加载全部 CDN 与 IDC 列表
func (l *Lists) Reload() {
	l.cdn.Store(l.load("cdn", CDNProviders))
	l.idc.Store(l.load("idc", IDCProviders))
}

// CDN 返回 IP 所属的 CDN 提供商
func (l *Lists) CDN(ip string) (provider string, ok bool) {
	return l.cdn.Load().Lookup(ip)
}

// IDC 返回 IP 所属的云厂商
func (l *Lists) IDC(ip string) (provider string, ok bool) {
	return l.idc.Load().Lookup(ip)
}

// Sizes 返回 CDN、IDC 表的前缀数量
func (l *Lists) Sizes() (cdn, idc int) {
	return l.cdn.Load().Len(), l.idc.Load().Len()
}

// CDNFile 返回某 CDN 提供商的数据文件路径；未知提供商返回 false
func (l *Lists) CDNFile(provider string) (string, bool) {
	for _, p := range CDNProviders {
		if p == provider {
			return filepath.Join(l.dataDir, "cdn", provider+".txt"), true
		}
	}
	return "", false
}

func (l *Lists) load(kind string, providers []string) *ipset.Set {
	s := ipset.New()
	for _, provider := range providers {
		path := filepath.Join(l.dataDir, kind, provider+".txt")
		file, err := os.Open(path)
		if err != nil {
			l.log.Warn("could not open provider list", "path", path, "err", err)
			continue
		}
		loaded := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if s.InsertIfAbsent(line, provider) {
				loaded++
			}
		}
		_ = file.Close()
		l.log.Info("provider list loaded", "kind", kind, "provider", provider, "entries", loaded)
	}
	return s
}
