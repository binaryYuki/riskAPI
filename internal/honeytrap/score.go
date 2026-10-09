package honeytrap

import (
	"container/list"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	maxSeenPaths = 32 // 每个来源记住的不同路径数上限，超出后的新路径仍按全额计分
	evictScan    = 8  // 表满时从最久未活动一端最多检查的记录数，优先淘汰未被标记的来源
)

// sourceKey 把客户端 IP 归并为计分来源：IPv4 按单个地址，IPv6 按 /64
func sourceKey(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr, true
}

// scoreConfig 漏桶与分级参数
type scoreConfig struct {
	flagThreshold  float64
	blockThreshold float64
	leakPerSec     float64 // 每秒漏掉的分数
	flagDuration   time.Duration
	blockDuration  time.Duration
	idle           time.Duration // 分数漏空且超过该时长未活动的记录可清理
	maxSources     int
}

type sourceStat struct {
	key        netip.Addr
	elem       *list.Element
	score      float64
	leakedAt   time.Time // 上次结算漏桶的时间
	lastSeen   time.Time
	seen       []uint64 // 桶内出现过的路径哈希
	flagUntil  time.Time
	blockUntil time.Time
}

// leak 按经过的整秒数漏掉分数；漏空后忘记已见过的路径。
// 按整秒结算使同一秒内的连续命中不被漏桶削减，分数恰好等于权重之和
func (st *sourceStat) leak(now time.Time, perSec float64) {
	if secs := now.Sub(st.leakedAt) / time.Second; secs > 0 {
		st.score -= float64(secs) * perSec
		st.leakedAt = st.leakedAt.Add(secs * time.Second)
	}
	if st.score <= 0 {
		st.score = 0
		st.seen = st.seen[:0]
	}
}

func (st *sourceStat) marked(now time.Time) bool {
	return now.Before(st.flagUntil) || now.Before(st.blockUntil)
}

// outcome 一次计分的结果
type outcome struct {
	prior, score float64 // 本次计分前 / 后的分数
	blocked      bool    // 请求到达时已在封禁期内（不再计分）
	newlyBlocked bool
	newlyFlagged bool
	flagUntil    time.Time // 本次命中使来源处于标记期时，标记的到期时间
	blockUntil   time.Time
}

// scorer 按来源维护带权重的漏桶，表满时淘汰最久未活动的来源
type scorer struct {
	cfg scoreConfig

	mu      sync.RWMutex
	sources map[netip.Addr]*sourceStat
	lru     *list.List // 队首为最近活动的来源
}

func newScorer(cfg scoreConfig) *scorer {
	return &scorer{cfg: cfg, sources: make(map[netip.Addr]*sourceStat), lru: list.New()}
}

// observe 为来源记一次命中：同一路径在桶内重复出现只按 repeatWeight 计分
func (s *scorer) observe(key netip.Addr, pathHash uint64, weight float64, now time.Time) outcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.sources[key]
	if st == nil {
		if len(s.sources) >= s.cfg.maxSources {
			s.evict(now)
		}
		st = &sourceStat{key: key, leakedAt: now}
		st.elem = s.lru.PushFront(st)
		s.sources[key] = st
	} else {
		s.lru.MoveToFront(st.elem)
	}
	st.lastSeen = now

	if now.Before(st.blockUntil) {
		return outcome{prior: st.score, score: st.score, blocked: true, blockUntil: st.blockUntil}
	}

	st.leak(now, s.cfg.leakPerSec)
	out := outcome{prior: st.score}
	if slices.Contains(st.seen, pathHash) {
		weight = min(weight, repeatWeight)
	} else if len(st.seen) < maxSeenPaths {
		st.seen = append(st.seen, pathHash)
	}
	st.score += weight
	out.score = st.score

	if st.score >= s.cfg.flagThreshold || st.score >= s.cfg.blockThreshold {
		out.newlyFlagged = !now.Before(st.flagUntil)
		st.flagUntil = now.Add(s.cfg.flagDuration)
		out.flagUntil = st.flagUntil
	}
	if st.score >= s.cfg.blockThreshold {
		st.blockUntil = now.Add(s.cfg.blockDuration)
		out.newlyBlocked, out.blockUntil = true, st.blockUntil
	}
	return out
}

// mark 不看分数直接标记一个已在跟踪中的来源，返回标记的到期时间以及它此前是否未被标记
func (s *scorer) mark(key netip.Addr, now time.Time) (until time.Time, newly bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sources[key]
	if st == nil {
		return time.Time{}, false
	}
	newly = !now.Before(st.flagUntil)
	st.flagUntil = now.Add(s.cfg.flagDuration)
	return st.flagUntil, newly
}

// evict 淘汰最久未活动的来源；尽量跳过仍被标记或封禁的记录
func (s *scorer) evict(now time.Time) {
	victim := s.lru.Back()
	for e, i := victim, 0; e != nil && i < evictScan; e, i = e.Prev(), i+1 {
		if !e.Value.(*sourceStat).marked(now) {
			victim = e
			break
		}
	}
	if victim != nil {
		s.remove(victim.Value.(*sourceStat))
	}
}

func (s *scorer) remove(st *sourceStat) {
	s.lru.Remove(st.elem)
	delete(s.sources, st.key)
}

// prune 清理分数已漏空、未被标记且长时间未活动的来源
func (s *scorer) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 从最久未活动的一端开始，遇到仍在活动期内的记录即可停止
	for e := s.lru.Back(); e != nil; {
		st := e.Value.(*sourceStat)
		if now.Sub(st.lastSeen) <= s.cfg.idle {
			break
		}
		e = e.Prev()
		if st.marked(now) {
			continue
		}
		if st.leak(now, s.cfg.leakPerSec); st.score == 0 {
			s.remove(st)
		}
	}
}

// len 返回当前跟踪的来源数
func (s *scorer) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sources)
}
