package telemetry

import (
	"log/slog"
	"sync"
	"time"
)

// errorLogInterval 导出失败日志的最小间隔。后端长时间不可用时每秒都会失败，
// 不限流会刷满 stdout（容器日志轮转后把有用的日志挤掉）
const errorLogInterval = time.Minute

// throttledErrorLogger 把 OpenTelemetry 内部错误写到 stdout logger，同一间隔内只写一条并统计被省略的次数。
// 只写本地 logger：经 OTLP 上报会形成循环。
type throttledErrorLogger struct {
	log      *slog.Logger
	interval time.Duration
	now      func() time.Time

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func newThrottledErrorLogger(log *slog.Logger, interval time.Duration) *throttledErrorLogger {
	return &throttledErrorLogger{log: log, interval: interval, now: time.Now}
}

func (l *throttledErrorLogger) Handle(err error) {
	l.mu.Lock()
	now := l.now()
	if !l.last.IsZero() && now.Sub(l.last) < l.interval {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := l.suppressed
	l.last, l.suppressed = now, 0
	l.mu.Unlock()

	l.log.Warn("opentelemetry export error", "err", err, "suppressed", suppressed)
}
