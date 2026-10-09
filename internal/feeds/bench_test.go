package feeds

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"risky_ip_filter/internal/ipset"
)

// 基准：对比"抓取时只解析一次、直接存 netip.Prefix"重构前后，解析与建表的耗时和内存。
// legacy* 是重构前实现的原样拷贝，只作为基线，不参与生产代码。
//
//	go test -run '^$' -bench FeedPipeline -benchmem ./internal/feeds

const (
	benchSources        = 8
	benchLinesPerSource = 40000
)

var (
	benchCorpusOnce sync.Once
	benchCorpusData [][]byte
)

// benchTags 各源的标记，模拟线上"少数源带 IDC/代理标记、多数只进风险表"的比例
func benchTags(i int) Tag {
	switch i {
	case 0:
		return TagIDC
	case 1:
		return TagProxy
	}
	return 0
}

// benchCorpus 生成与线上规模相当的数据：8 个源共 32 万行，各源从同一个地址池取样（源之间有重叠），
// 行格式混合了纯 IP、带行尾注释的 IP、带注释的 CIDR、IPv6、注释行与非法行。固定随机种子，结果可复现。
func benchCorpus() [][]byte {
	benchCorpusOnce.Do(func() {
		r := rand.New(rand.NewSource(1))
		pool := make([][4]byte, 200000)
		for i := range pool {
			pool[i] = [4]byte{byte(1 + r.Intn(222)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))}
		}
		for range benchSources {
			var buf bytes.Buffer
			buf.WriteString("# generated benchmark feed\n")
			for range benchLinesPerSource {
				ip := pool[r.Intn(len(pool))]
				switch n := r.Intn(100); {
				case n < 70:
					fmt.Fprintf(&buf, "%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3])
				case n < 80: // BruteForceBlocker 风格
					fmt.Fprintf(&buf, "%d.%d.%d.%d\t\t# 2026-09-29 12:02:10\t\t26\t2855073\n", ip[0], ip[1], ip[2], ip[3])
				case n < 90: // Spamhaus DROP 风格
					fmt.Fprintf(&buf, "%d.%d.%d.0/24 ; SBL%d\n", ip[0], ip[1], ip[2], 100000+r.Intn(900000))
				case n < 95:
					fmt.Fprintf(&buf, "2a%02x:%x:%x::%x\n", ip[0], uint16(ip[1])<<8|uint16(ip[2]), r.Intn(65536), 1+r.Intn(65535))
				case n < 98:
					buf.WriteString("# comment line\n")
				default:
					buf.WriteString("<html>rate limited</html>\n")
				}
			}
			benchCorpusData = append(benchCorpusData, buf.Bytes())
		}
	})
	return benchCorpusData
}

// ---- 重构前的实现（基线） ----

// legacyClassify 重构前的 Stats.classify：为了统计把条目再解析一遍
func legacyClassify(s *Stats, entry string) {
	p, ok := ipset.ParseEntry(entry)
	if !ok {
		return
	}
	if p.IsSingleIP() && !strings.Contains(entry, "/") {
		s.parsedIPs.Add(1)
	} else {
		s.parsedCIDRs.Add(1)
	}
	if ipset.IsSpecial(p.Addr()) {
		s.specialRanges.Add(1)
	}
}

// legacyParseLine 重构前的 parseLine：用 net 包校验，条目以字符串保存
func legacyParseLine(s *Stats, line, source string) (Entry, bool) {
	s.totalLines.Add(1)
	if _, _, err := net.ParseCIDR(line); err != nil && net.ParseIP(line) == nil {
		return Entry{}, false
	}
	legacyClassify(s, line)
	return Entry{Value: line, Source: source}, true
}

// legacyParseText 重构前的 parseText
func legacyParseText(s *Stats, body io.Reader, source string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		line = fields[0]
		if line == "ExitAddress" && len(fields) >= 2 {
			line = fields[1]
		}
		if e, ok := legacyParseLine(s, line, source); ok {
			entries = append(entries, e)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return entries, nil
}

type legacyBatch struct {
	entries []Entry
	tags    Tag
}

// legacyBuild 重构前 Store.replace 的建表循环：写入时第三次解析字符串
func legacyBuild(batches []legacyBatch) *tables {
	next := emptyTables()
	for _, b := range batches {
		for _, e := range b.entries {
			if !next.risk.Insert(e.Value, e.Source) {
				continue
			}
			if b.tags&TagProxy != 0 {
				next.proxy.Insert(e.Value, e.Source)
			}
			if b.tags&TagIDC != 0 {
				next.idc.Insert(e.Value, e.Source)
			}
		}
	}
	return next
}

func legacyParseAll(corpus [][]byte) []legacyBatch {
	var st Stats
	batches := make([]legacyBatch, len(corpus))
	for i, c := range corpus {
		entries, err := legacyParseText(&st, bytes.NewReader(c), fmt.Sprintf("feed-%d", i))
		if err != nil {
			panic(err)
		}
		batches[i] = legacyBatch{entries: entries, tags: benchTags(i)}
	}
	return batches
}

// ---- 当前实现 ----

func currentParseAll(s *Store, corpus [][]byte) []batch {
	batches := make([]batch, len(corpus))
	for i, c := range corpus {
		data, err := s.parseText(bytes.NewReader(c), false)
		if err != nil {
			panic(err)
		}
		batches[i] = batch{source: fmt.Sprintf("feed-%d", i), data: data, tags: benchTags(i)}
	}
	return batches
}

func benchStore() *Store { return NewStore(nil, fastFetch, discardLog()) }

// retainedPerEntry 解析结果常驻内存时，平均每条记录占用的堆字节数（对应 lastGood 的长期占用）
func retainedPerEntry[T any](parse func() T, count func(T) int) float64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := parse()
	runtime.GC()
	runtime.ReadMemStats(&after)
	n := count(v)
	runtime.KeepAlive(v)
	return float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)) / float64(n)
}

func BenchmarkFeedPipeline(b *testing.B) {
	corpus := benchCorpus()
	var size int64
	for _, c := range corpus {
		size += int64(len(c))
	}

	// 解析：抓取到的文本 → 待建表的条目
	b.Run("parse/legacy", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(size)
		for b.Loop() {
			legacyParseAll(corpus)
		}
		b.ReportMetric(retainedPerEntry(
			func() []legacyBatch { return legacyParseAll(corpus) },
			func(bs []legacyBatch) (n int) {
				for _, x := range bs {
					n += len(x.entries)
				}
				return n
			}), "retained-B/entry")
	})
	b.Run("parse/current", func(b *testing.B) {
		s := benchStore()
		b.ReportAllocs()
		b.SetBytes(size)
		for b.Loop() {
			currentParseAll(s, corpus)
		}
		b.ReportMetric(retainedPerEntry(
			func() []batch { return currentParseAll(s, corpus) },
			func(bs []batch) (n int) {
				for _, x := range bs {
					n += len(x.data.prefixes)
				}
				return n
			}), "retained-B/entry")
	})

	// 建表：已解析的条目 → 三张前缀表
	b.Run("build/legacy", func(b *testing.B) {
		batches := legacyParseAll(corpus)
		b.ReportAllocs()
		for b.Loop() {
			legacyBuild(batches)
		}
	})
	b.Run("build/current", func(b *testing.B) {
		s := benchStore()
		batches := currentParseAll(s, corpus)
		b.ReportAllocs()
		for b.Loop() {
			s.replace(batches)
		}
	})

	// 一轮完整更新：解析 + 建表
	b.Run("total/legacy", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			legacyBuild(legacyParseAll(corpus))
		}
	})
	b.Run("total/current", func(b *testing.B) {
		s := benchStore()
		b.ReportAllocs()
		for b.Loop() {
			s.replace(currentParseAll(s, corpus))
		}
	})
}

// 基线与当前实现在同一份数据上必须建出完全相同的表，否则基准对比的不是同一件事
func TestBenchBaseline_SameTablesAsCurrent(t *testing.T) {
	corpus := benchCorpus()
	want := legacyBuild(legacyParseAll(corpus))
	s := benchStore()
	s.replace(currentParseAll(s, corpus))
	got := s.set.Load()

	type row struct{ prefix, label string }
	pairs := map[string][2]*ipset.Set{
		"risk":  {want.risk, got.risk},
		"proxy": {want.proxy, got.proxy},
		"idc":   {want.idc, got.idc},
	}
	for name, pair := range pairs {
		var w, g []row
		for p, label := range pair[0].All() {
			w = append(w, row{p.String(), label})
		}
		for p, label := range pair[1].All() {
			g = append(g, row{p.String(), label})
		}
		assert.NotEmpty(t, w, name)
		assert.Equal(t, len(w), len(g), name)
		assert.True(t, assert.ObjectsAreEqual(w, g), "%s table differs between baseline and current", name)
	}
}
