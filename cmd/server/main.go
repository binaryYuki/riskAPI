// Command server 启动风险 IP 检测与地理位置查询 HTTP 服务。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"risky_ip_filter/internal/cache"
	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/geo"
	"risky_ip_filter/internal/geo/qqwry"
	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/httpapi"
	"risky_ip_filter/internal/netlists"
	"risky_ip_filter/internal/telemetry"
)

// version 由构建参数注入：-ldflags "-X main.version=..."
var version = "dev"

func main() {
	cfg := config.Load()
	tel := telemetry.Setup(context.Background(), cfg, version)
	log := tel.Log
	slog.SetDefault(log)
	err := run(cfg, tel)
	if err != nil {
		log.Error("server exited with error", "err", err)
	}
	// os.Exit 不执行 defer，须先发出排队中的日志与 span
	if serr := tel.Shutdown(); serr != nil {
		log.Warn("opentelemetry shutdown incomplete", "err", serr)
	}
	if err != nil {
		os.Exit(1)
	}
}

func run(cfg config.Config, tel *telemetry.Telemetry) error {
	log := tel.Log
	// SIGINT / SIGTERM（容器平台停止实例时发送）触发优雅停机
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 外部请求复用连接
	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConns = 1000
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 90 * time.Second
	// 须在上面的类型断言之后：包装后 DefaultTransport 不再是 *http.Transport
	tel.InstrumentDefaultTransport()

	qq, err := qqwry.Open(cfg.QQWryPath)
	if err != nil {
		log.Warn("qqwry database unavailable", "path", cfg.QQWryPath, "err", err)
	} else {
		log.Info("qqwry database loaded", "path", cfg.QQWryPath)
	}

	// CDN/IDC 列表随镜像发布、运行期不变，启动时加载一次即可（/api/cache/flush/all 可手动重载）
	lists := netlists.New(cfg.DataDir, log)
	lists.Reload()

	risk := feeds.NewStore(cfg.Feeds, cfg.FeedFetch, log)
	go risk.Run(ctx, cfg.FeedUpdateInterval)

	trap := honeytrap.New(cfg.Honeytrap, log)
	if cfg.Honeytrap.Enabled {
		go trap.RunJanitor(ctx)
	}

	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	server := httpapi.New(httpapi.Deps{
		Config:    cfg,
		Version:   version,
		Log:       log,
		Risk:      risk,
		Lists:     lists,
		Geo:       geo.New(cfg.ProvidersDir, qq, cfg.InfoLookupTimeout, log),
		InfoCache: cache.New(cfg.InfoCacheMaxEntries, cfg.InfoCacheTTL),
		Trap:      trap,
		// 为 nil 时不加载 otelgin 中间件
		TracerProvider: tel.TracerProvider,
	})

	srv := &http.Server{
		Addr:           cfg.Addr,
		Handler:        server.Handler(),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	log.Info("server started", "addr", cfg.Addr, "version", version)

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutdown signal received, draining in-flight requests", "timeout", cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown incomplete", "err", err)
	}
	log.Info("server stopped")
	return nil
}
