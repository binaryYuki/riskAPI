package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

var benchSetupOnce sync.Once

// setupBenchData 构造与线上规模相当的数据：
// 风险库 ≈ 12 万 CIDR（取自 IDC 文件）+ 20 万单 IP；CDN/IDC 使用真实数据文件
func setupBenchData(b *testing.B) {
	b.Helper()
	benchSetupOnce.Do(func() {
		if appCache == nil {
			appCache = NewRadixCache()
		}
		initCDNIDCCache()

		var assocs []IPAssociation
		for _, p := range []string{"azure", "aws", "linode", "apple"} {
			f, err := os.Open("data/idc/" + p + ".txt")
			if err != nil {
				continue
			}
			s := bufio.NewScanner(f)
			for s.Scan() && len(assocs) < 120000 {
				line := strings.TrimSpace(s.Text())
				if strings.Contains(line, "/") {
					assocs = append(assocs, IPAssociation{Entry: line, Reason: "bench-" + p})
				}
			}
			_ = f.Close()
		}
		for i := 0; i < 200000; i++ {
			ip := fmt.Sprintf("11.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
			assocs = append(assocs, IPAssociation{Entry: ip, Reason: "bench-single"})
		}
		processIPAssociations(assocs)
	})
}

// 未命中是最坏情况：旧实现需要扫描全部条目
const benchMissIP = "203.0.114.77"

func BenchmarkIsRiskyIP_Miss(b *testing.B) {
	setupBenchData(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := isRiskyIP(benchMissIP); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkIsRiskyIP_SingleHit(b *testing.B) {
	setupBenchData(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := isRiskyIP("11.1.2.3"); !ok {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkIsIDCIP_Miss(b *testing.B) {
	setupBenchData(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := isIDCIP(benchMissIP); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkIsCDNIP_Miss(b *testing.B) {
	setupBenchData(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := isCDNIP(benchMissIP); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkIsBogonOrPrivateIP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isBogonOrPrivateIP("8.8.8.8")
		isBogonOrPrivateIP("2001:4860:4860::8888")
	}
}

func BenchmarkLookupGenericMMDB(b *testing.B) {
	const db = "providers/maxmind/GeoLite2-Country.mmdb"
	if !statOk(db) {
		b.Skip("mmdb not present")
	}
	ip := net.ParseIP("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := lookupGeneric(db, ip); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMetricsAddLineParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			metricsAddLine()
		}
	})
}
