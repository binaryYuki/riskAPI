package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

/*
	纯真（QQWry）数据库解析（最优实践实现）

	关键点：
	- 索引：index = [startIP(LE,4)] [recordOffset(LE,3)]
	- 记录：record = [endIP(LE,4)] [flag(1)] [country/area 按 flag 组织]
	  flag == 0：country\0 area\0
	  flag == 1：重定向到“完整块”（继续按 flag 解析）
	  flag == 2：后 3 字节为 country 指针，area 从当前偏移+4 处读取（可再次重定向）
	- 所有 IP 数值均为小端；查询 IP 也要转为小端以便可比
	- ValOff 传 “flag 字节位置”（recordOffset+4），让解析函数按 flag 跳转
	- GBK → UTF-8 解码；占位串（如 CZ88.NET）清洗为“未知”
*/

// 常量
const (
	indexSize     = 7    // 每个索引记录大小 (4 字节 startIP + 3 字节 recordOffset)
	recordHeadLen = 5    // 记录头部 (4 字节 endIP + 1 字节 flag)
	redirectMode1 = 0x01 // 重定向模式 1
	redirectMode2 = 0x02 // 重定向模式 2
)

// 结构体
type qqWryRecord struct {
	StartIP uint32 // 小端
	EndIP   uint32 // 小端
	ValOff  uint32 // 指向 flag 字节
}

type bucketInfo struct {
	Start int // 在 Records 中的起始下标
	Count int // 该桶内记录数
}

type qqWryIndex struct {
	Records   []qqWryRecord
	DataFile  []byte
	IndexOff  uint32
	RecordNum uint32
	Buckets   [65536]bucketInfo
}

// 包级状态
var (
	qqwryOnce  sync.Once
	qqwryIndex *qqWryIndex
	qqwryErr   error
)

// 将 IPv4 转为“小端 uint32”，以与数据文件一致
func ipToUint32LE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[3]) | uint32(ip[2])<<8 | uint32(ip[1])<<16 | uint32(ip[0])<<24
}

// 读取 3 字节无符号整数（小端）
func readUint24LE(data []byte, offset uint32) (uint32, bool) {
	if offset+3 > uint32(len(data)) {
		return 0, false
	}
	return uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16, true
}

// 读取 4 字节无符号整数（小端）
func readUint32LE(data []byte, offset uint32) (uint32, bool) {
	if offset+4 > uint32(len(data)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[offset:]), true
}

// 从 offset 读取以 0 结尾的 GBK 字符串，并返回 UTF-8 字符串
func readGBKString(data []byte, offset uint32) (string, bool) {
	if offset >= uint32(len(data)) {
		return "", false
	}
	start := offset
	for offset < uint32(len(data)) && data[offset] != 0 {
		offset++
	}
	if start == offset {
		return "", true // 空串
	}
	gbkBytes := data[start:offset]
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, _, err := transform.Bytes(decoder, gbkBytes)
	if err != nil {
		// 回退：直接按原样（ASCII 等）
		return string(gbkBytes), true
	}
	return string(utf8Bytes), true
}

// 与上同，但返回“原始字节长度（含 0 终止）”，用于定位下一个字段的起点
func readGBKStringWithLen(data []byte, offset uint32) (str string, rawLen uint32, ok bool) {
	if offset >= uint32(len(data)) {
		return "", 0, false
	}
	start := offset
	for offset < uint32(len(data)) && data[offset] != 0 {
		offset++
	}
	if start == offset {
		return "", 0, true // 空串，但仍视为成功
	}
	rawLen = offset - start + 1 // 包含 '\0'
	gbkBytes := data[start:offset]
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, _, err := transform.Bytes(decoder, gbkBytes)
	if err != nil {
		return string(gbkBytes), rawLen, true
	}
	return string(utf8Bytes), rawLen, true
}

// 清洗占位字符串
func cleanField(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "未知"
	}
	switch s {
	case "CZ88.NET", "纯真网络", "纯真", "未登记", "未知", "本机地址":
		return "未知"
	}
	return s
}

// —— 对外函数 ——

// InitQQWryDatabase 初始化纯真数据库（只加载一次）
// 优先使用环境变量 QQWRY_PATH；否则默认 "providers/qqwry/qqwry.dat"
func InitQQWryDatabase() error {
	qqwryOnce.Do(func() {
		path := os.Getenv("QQWRY_PATH")
		if strings.TrimSpace(path) == "" {
			path = "providers/qqwry/qqwry.dat"
		}
		qqwryErr = loadQQWryDatabase(path)
	})
	return qqwryErr
}

// QueryQQWryIP 查询 IP 的地理信息（国家/地区）
// 若解析失败，返回 "未知"/"未知" 与错误
func QueryQQWryIP(ip string) (country, area string, err error) {
	if qqwryIndex == nil {
		if err = InitQQWryDatabase(); err != nil {
			return "未知", "未知", err
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "未知", "未知", fmt.Errorf("invalid IP: %s", ip)
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return "未知", "未知", fmt.Errorf("not an IPv4 address: %s", ip)
	}

	key := ipToUint32LE(ipv4)
	if key == 0 {
		return "未知", "未知", fmt.Errorf("invalid IPv4 (zero): %s", ip)
	}

	rec := findRecord(key)
	if rec == nil {
		return "未知", "未知", nil
	}

	country, area = parseLocationInfo(rec.ValOff)
	country = cleanField(country)
	area = cleanField(area)
	return country, area, nil
}

// GetQQWryStats 返回加载统计
func GetQQWryStats() map[string]interface{} {
	if qqwryIndex == nil {
		return map[string]interface{}{"loaded": false}
	}
	stats := map[string]interface{}{
		"loaded":        true,
		"total_records": len(qqwryIndex.Records),
		"file_size":     len(qqwryIndex.DataFile),
		"memory_usage":  unsafe.Sizeof(*qqwryIndex) + uintptr(len(qqwryIndex.Records))*unsafe.Sizeof(qqWryRecord{}) + uintptr(len(qqwryIndex.DataFile)),
		"buckets_used":  countNonEmptyBuckets(),
	}
	return stats
}

// —— 加载与索引 ——

// 加载 qqwry.dat，解析所有记录并构建 /16 桶索引
func loadQQWryDatabase(filePath string) error {
	log.Printf("[qqwry] loading from %s", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open qqwry.dat failed: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat qqwry.dat failed: %w", err)
	}
	if st.Size() < 8 {
		return errors.New("qqwry.dat too small")
	}

	data := make([]byte, st.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return fmt.Errorf("read qqwry.dat failed: %w", err)
	}

	firstIndexOffset, ok1 := readUint32LE(data, 0)
	lastIndexOffset, ok2 := readUint32LE(data, 4)
	if !ok1 || !ok2 {
		return errors.New("invalid index header")
	}
	if firstIndexOffset >= uint32(len(data)) || lastIndexOffset >= uint32(len(data)) || firstIndexOffset > lastIndexOffset {
		return errors.New("invalid index offsets")
	}

	recordNum := (lastIndexOffset-firstIndexOffset)/indexSize + 1
	if recordNum == 0 {
		return errors.New("no records")
	}

	idx := &qqWryIndex{
		Records:   make([]qqWryRecord, 0, recordNum),
		DataFile:  data,
		IndexOff:  firstIndexOffset,
		RecordNum: recordNum,
	}

	for i := uint32(0); i < recordNum; i++ {
		indexOff := firstIndexOffset + i*indexSize
		if indexOff+indexSize > uint32(len(data)) {
			break
		}
		startIP, okA := readUint32LE(data, indexOff)
		recOff, okB := readUint24LE(data, indexOff+4)
		if !okA || !okB {
			continue
		}
		// record = [endIP(4)][flag(1)]...
		if recOff+recordHeadLen > uint32(len(data)) {
			continue
		}
		endIP, okC := readUint32LE(data, recOff)
		if !okC {
			continue
		}
		valOff := recOff + 4 // flag 字节位置
		idx.Records = append(idx.Records, qqWryRecord{
			StartIP: startIP,
			EndIP:   endIP,
			ValOff:  valOff,
		})
	}

	// 防御性排序（通常文件已排好）
	sort.Slice(idx.Records, func(i, j int) bool {
		return idx.Records[i].StartIP < idx.Records[j].StartIP
	})

	// 构建 /16 桶
	for i := range idx.Buckets {
		idx.Buckets[i] = bucketInfo{Start: -1, Count: 0}
	}
	for i, rec := range idx.Records {
		bkt := rec.StartIP >> 16
		if bkt >= 65536 {
			continue
		}
		if idx.Buckets[bkt].Start == -1 {
			idx.Buckets[bkt].Start = i
		}
		idx.Buckets[bkt].Count++
	}

	qqwryIndex = idx
	log.Printf("[qqwry] loaded: records=%d buckets_used=%d", len(idx.Records), countNonEmptyBuckets())
	return nil
}

func countNonEmptyBuckets() int {
	if qqwryIndex == nil {
		return 0
	}
	n := 0
	for _, b := range qqwryIndex.Buckets {
		if b.Count > 0 {
			n++
		}
	}
	return n
}

// —— 查询 ——

// 在桶范围内做“前驱二分”，并校验 IP 落在 [StartIP, EndIP] 内
func findRecord(ipLE uint32) *qqWryRecord {
	if qqwryIndex == nil || len(qqwryIndex.Records) == 0 {
		return nil
	}
	bkt := ipLE >> 16
	if bkt >= 65536 {
		return nil
	}
	binfo := qqwryIndex.Buckets[bkt]
	if binfo.Count == 0 {
		// 就近回退到前一个非空桶，兼容稀疏段
		for i := int(bkt) - 1; i >= 0; i-- {
			if qqwryIndex.Buckets[i].Count > 0 {
				binfo = qqwryIndex.Buckets[i]
				break
			}
		}
		if binfo.Count == 0 {
			return nil
		}
	}

	start := binfo.Start
	end := start + binfo.Count

	// 适度并到下一个非空桶尾，缓解跨桶边界
	for next := bkt + 1; next < 65536 && end < len(qqwryIndex.Records); next++ {
		if qqwryIndex.Buckets[next].Count > 0 {
			nextEnd := qqwryIndex.Buckets[next].Start + qqwryIndex.Buckets[next].Count
			if nextEnd > end && nextEnd-end <= 128 {
				end = nextEnd
			}
			break
		}
	}

	if end > len(qqwryIndex.Records) {
		end = len(qqwryIndex.Records)
	}

	// 二分找“最后一个 startIP <= 目标”的记录
	l, r := start, end
	var cand *qqWryRecord
	for l < r {
		m := l + (r-l)/2
		rec := &qqwryIndex.Records[m]
		if rec.StartIP <= ipLE {
			cand = rec
			l = m + 1
		} else {
			r = m
		}
	}
	if cand == nil {
		return nil
	}
	// 验证区间
	if cand.EndIP >= ipLE {
		return cand
	}
	return nil
}

// —— 解析值区（按 flag）——

func parseLocationInfo(offset uint32) (country, area string) {
	if qqwryIndex == nil || offset >= uint32(len(qqwryIndex.DataFile)) {
		return "未知", "未知"
	}
	data := qqwryIndex.DataFile

	flag := data[offset]
	switch flag {
	case redirectMode1:
		// 模式 1：重定向到一个“完整块”（再按 flag 解析）
		if offset+4 > uint32(len(data)) {
			return "未知", "未知"
		}
		to, ok := readUint24LE(data, offset+1)
		if !ok || to >= uint32(len(data)) {
			return "未知", "未知"
		}
		c, a := parseLocationInfo(to)

		// 兼容某些版本：area 也可能跟在 offset+4
		areaOff := offset + 4
		if a == "未知" && areaOff < uint32(len(data)) {
			af := data[areaOff]
			if af == redirectMode1 || af == redirectMode2 {
				if areaOff+4 <= uint32(len(data)) {
					if to2, ok := readUint24LE(data, areaOff+1); ok {
						if s, ok := readGBKString(data, to2); ok {
							if strings.TrimSpace(s) != "" {
								a = s
							}
						}
					}
				}
			} else {
				if s, ok := readGBKString(data, areaOff); ok && strings.TrimSpace(s) != "" {
					a = s
				}
			}
		}
		return c, a

	case redirectMode2:
		// 模式 2：country 重定向，area 紧跟 offset+4（其处也可能重定向）
		if offset+4 > uint32(len(data)) {
			return "未知", "未知"
		}
		to, ok := readUint24LE(data, offset+1)
		if !ok {
			return "未知", "未知"
		}
		if s, ok := readGBKString(data, to); ok {
			country = s
		}

		areaOff := offset + 4
		if areaOff < uint32(len(data)) {
			areaFlag := data[areaOff]
			if areaFlag == redirectMode1 || areaFlag == redirectMode2 {
				if areaOff+4 <= uint32(len(data)) {
					if to2, ok := readUint24LE(data, areaOff+1); ok {
						if s, ok := readGBKString(data, to2); ok {
							area = s
						}
					}
				}
			} else {
				if s, ok := readGBKString(data, areaOff); ok {
					area = s
				}
			}
		}
		return country, area

	default:
		// 普通模式：country\0 area\0
		c, rawLen, ok := readGBKStringWithLen(data, offset)
		if !ok {
			return "未知", "未知"
		}
		if rawLen == 0 {
			return "未知", "未知"
		}
		areaOff := offset + rawLen
		if areaOff < uint32(len(data)) {
			af := data[areaOff]
			if af == redirectMode1 || af == redirectMode2 {
				if areaOff+4 <= uint32(len(data)) {
					if to2, ok := readUint24LE(data, areaOff+1); ok {
						if s, ok := readGBKString(data, to2); ok {
							return c, s
						}
					}
				}
				return c, "未知"
			}
			if s, ok := readGBKString(data, areaOff); ok {
				return c, s
			}
		}
		return c, "未知"
	}
}

// ParseQQWryCountry 把 "中国–广东–广州" 这种字符串拆解成结构
// 返回 map: {"country": "中国", "province": "广东", "city": "广州"}
// 如果没有那么多层级，则缺省字段为空字符串
func ParseQQWryCountry(s string) map[string]string {
	parts := strings.Split(s, "–")
	result := map[string]string{
		"country":  "",
		"province": "",
		"city":     "",
	}

	switch len(parts) {
	case 0:
		return result
	case 1:
		result["country"] = parts[0]
	case 2:
		result["country"] = parts[0]
		result["province"] = parts[1]
	default:
		result["country"] = parts[0]
		result["province"] = parts[1]
		result["city"] = parts[2]
	}
	return result
}
