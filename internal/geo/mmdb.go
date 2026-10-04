package geo

import (
	"errors"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// errMMDBUnavailable 表示 MMDB 文件不存在或为空（未下载），调用方静默跳过
var errMMDBUnavailable = errors.New("mmdb file unavailable")

// mmdbReader 返回缓存的 reader。MMDB 随镜像发布、更新依赖重新部署，
// 因此 reader 在进程生命周期内常驻，不关闭。
func (s *Service) mmdbReader(path string) (*maxminddb.Reader, error) {
	if r, ok := s.readers.Load(path); ok {
		return r.(*maxminddb.Reader), nil
	}
	if !fileNonEmpty(path) {
		return nil, errMMDBUnavailable
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	if actual, loaded := s.readers.LoadOrStore(path, reader); loaded {
		_ = reader.Close() // 并发首次打开时只保留一个
		return actual.(*maxminddb.Reader), nil
	}
	return reader, nil
}

// lookupMMDB 以通用结构解析 MMDB（不定义固定 struct），返回 map / slice / 基本类型构成的结构
func (s *Service) lookupMMDB(path string, ip net.IP) (any, error) {
	reader, err := s.mmdbReader(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := reader.Lookup(ip, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// fileNonEmpty 检查文件是否存在且大小>0
func fileNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}
