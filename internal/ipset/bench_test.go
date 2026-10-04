package ipset

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

var (
	benchOnce sync.Once
	benchSet  *Set
)

// loadBenchSet 构造与线上规模相当的表：约 12 万 CIDR（取自真实 IDC 文件）+ 20 万单 IP
func loadBenchSet(b *testing.B) *Set {
	b.Helper()
	benchOnce.Do(func() {
		s := New()
		n := 0
		for _, p := range []string{"azure", "aws", "linode", "apple"} {
			f, err := os.Open("../../data/idc/" + p + ".txt")
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() && n < 120000 {
				line := strings.TrimSpace(sc.Text())
				if strings.Contains(line, "/") && s.Insert(line, p) {
					n++
				}
			}
			_ = f.Close()
		}
		for i := 0; i < 200000; i++ {
			s.Insert(fmt.Sprintf("11.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff), "single")
		}
		benchSet = s
	})
	return benchSet
}

// 未命中是线性扫描实现的最坏情况
func BenchmarkSetLookup_Miss(b *testing.B) {
	s := loadBenchSet(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup("203.0.114.77"); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkSetLookup_SingleHit(b *testing.B) {
	s := loadBenchSet(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup("11.1.2.3"); !ok {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkIsBogonOrPrivate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsBogonOrPrivate("8.8.8.8")
		IsBogonOrPrivate("2001:4860:4860::8888")
	}
}
