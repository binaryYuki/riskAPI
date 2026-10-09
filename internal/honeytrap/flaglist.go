package honeytrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxFlagFileRead = 32 << 20 // 单次从标记文件读取的上限

// flagRecord 标记文件中的一行（JSON Lines）
type flagRecord struct {
	Source string    `json:"source"` // 混淆后的来源
	Until  time.Time `json:"until"`  // 标记到期时间
}

type flagEntry struct {
	until     time.Time
	persisted time.Time // 已写入文件的到期时间
}

// flagList 蜜罐自己的风险列表：混淆后的来源 → 标记到期时间。
// 配置了文件时，新标记追加写入文件，启动时读回；多个实例共用同一个文件时，
// 各实例定期读取文件中新增的行，从而看到彼此的标记
type flagList struct {
	max     int
	refresh time.Duration // 内存中的到期时间比文件中的晚这么多时，再写一行
	path    string        // 为空时只在内存中
	log     *slog.Logger

	mu      sync.RWMutex
	entries map[string]*flagEntry

	fileMu sync.Mutex // 串行化文件读写
	offset int64      // 文件中已读取到的位置
}

func newFlagList(path string, max int, refresh time.Duration, log *slog.Logger) *flagList {
	return &flagList{max: max, refresh: refresh, path: path, log: log, entries: make(map[string]*flagEntry)}
}

// flag 标记来源到 until，必要时写入文件
func (f *flagList) flag(source string, until time.Time, now time.Time) {
	if !f.set(source, until, now, false) {
		return
	}
	f.appendRecord(flagRecord{Source: source, Until: until})
}

// set 更新内存中的到期时间（只延后不提前），返回是否需要写入文件。
// fromFile 表示这条记录来自文件，本身已经落盘
func (f *flagList) set(source string, until, now time.Time, fromFile bool) (persist bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entries[source]
	if e == nil {
		if len(f.entries) >= f.max {
			f.pruneLocked(now)
		}
		if len(f.entries) >= f.max {
			return false
		}
		e = &flagEntry{}
		f.entries[source] = e
	}
	if until.After(e.until) {
		e.until = until
	}
	if fromFile {
		if until.After(e.persisted) {
			e.persisted = until
		}
		return false
	}
	if f.path == "" || e.until.Sub(e.persisted) < f.refresh {
		return false
	}
	e.persisted = e.until
	return true
}

// has 来源当前是否处于标记期
func (f *flagList) has(source string, now time.Time) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e := f.entries[source]
	return e != nil && now.Before(e.until)
}

func (f *flagList) len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.entries)
}

// snapshot 返回当前未到期的标记，按来源标识排序
func (f *flagList) snapshot(now time.Time) []flagRecord {
	f.mu.RLock()
	recs := make([]flagRecord, 0, len(f.entries))
	for source, e := range f.entries {
		if now.Before(e.until) {
			recs = append(recs, flagRecord{Source: source, Until: e.until})
		}
	}
	f.mu.RUnlock()
	slices.SortFunc(recs, func(a, b flagRecord) int { return strings.Compare(a.Source, b.Source) })
	return recs
}

// prune 清理已到期的标记
func (f *flagList) prune(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLocked(now)
}

func (f *flagList) pruneLocked(now time.Time) {
	for source, e := range f.entries {
		if !now.Before(e.until) {
			delete(f.entries, source)
		}
	}
}

// appendRecord 向文件追加一行。每次写入都重新打开文件：标记不频繁，
// 而且这样在文件被其他实例压缩替换后不会继续写到旧文件里
func (f *flagList) appendRecord(rec flagRecord) {
	f.fileMu.Lock()
	defer f.fileMu.Unlock()
	line, _ := json.Marshal(rec)
	file, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = file.Write(append(line, '\n'))
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		f.log.Warn("honeytrap flag file write failed", "path", f.path, "err", err)
	}
}

// sync 读取文件中上次之后新增的完整行，把其中未到期的标记并入内存
func (f *flagList) sync(now time.Time) {
	if f.path == "" {
		return
	}
	f.fileMu.Lock()
	defer f.fileMu.Unlock()

	file, err := os.Open(f.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			f.log.Warn("honeytrap flag file read failed", "path", f.path, "err", err)
		}
		return
	}
	defer func() { _ = file.Close() }()

	if info, err := file.Stat(); err == nil && info.Size() < f.offset {
		f.offset = 0 // 文件被压缩替换过，从头读
	}
	data, err := io.ReadAll(io.NewSectionReader(file, f.offset, maxFlagFileRead))
	if err != nil {
		f.log.Warn("honeytrap flag file read failed", "path", f.path, "err", err)
		return
	}
	end := bytes.LastIndexByte(data, '\n') + 1 // 末尾不完整的行留到下次
	for _, line := range bytes.Split(data[:end], []byte{'\n'}) {
		var rec flagRecord
		if json.Unmarshal(line, &rec) == nil && len(rec.Source) == 32 && rec.Until.After(now) {
			f.set(rec.Source, rec.Until, now, true)
		}
	}
	f.offset += int64(end)
}

// compact 用当前未到期的标记重写文件，丢掉已到期和重复的行；只在启动时调用
func (f *flagList) compact(now time.Time) {
	if f.path == "" {
		return
	}
	f.fileMu.Lock()
	defer f.fileMu.Unlock()
	if _, err := os.Stat(f.path); err != nil {
		return
	}

	var buf bytes.Buffer
	f.mu.RLock()
	for source, e := range f.entries {
		if now.Before(e.until) {
			line, _ := json.Marshal(flagRecord{Source: source, Until: e.until})
			buf.Write(line)
			buf.WriteByte('\n')
		}
	}
	f.mu.RUnlock()

	tmp := f.path + ".tmp"
	err := os.WriteFile(tmp, buf.Bytes(), 0o600)
	if err == nil {
		err = os.Rename(tmp, f.path)
	}
	if err != nil {
		f.log.Warn("honeytrap flag file compaction failed", "path", f.path, "err", err)
		return
	}
	f.offset = int64(buf.Len())
}
