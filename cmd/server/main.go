// Command server 启动风险 IP 检测与地理位置查询 HTTP 服务。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"risky_ip_filter/internal/cache"
	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/geo"
	"risky_ip_filter/internal/geo/ipsb"
	"risky_ip_filter/internal/geo/qqwry"
	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/httpapi"
	"risky_ip_filter/internal/netlists"
	"risky_ip_filter/internal/risktoken"
	"risky_ip_filter/internal/shared"
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

	// 多副本共用出口 IP 时，通过 Redis 共享风险数据快照、info 缓存与 ip.sb 限速，避免重复请求外部数据源被限流
	var sh *shared.Client
	if cfg.RedisURL != "" {
		if sh, err = shared.Open(ctx, cfg.RedisURL, cfg.RedisKeyPrefix, log); err != nil {
			return fmt.Errorf("REDIS_URL: %w", err)
		}
		defer func() { _ = sh.Close() }()
	}

	risk := feeds.NewStore(cfg.Feeds, cfg.FeedFetch, log)
	if sh != nil {
		risk.SetCoordinator(sh.Snapshots("feeds"))
	}
	go risk.Run(ctx, cfg.FeedUpdateInterval)

	trap := honeytrap.New(cfg.Honeytrap, log)
	if cfg.Honeytrap.Enabled {
		go trap.RunJanitor(ctx)
	}

	signer, err := newSigner(cfg.RiskToken)
	if err != nil {
		return err
	}
	if signer != nil {
		log.Info("risk token signing enabled", "kid", signer.KeyID(), "ttl", cfg.RiskToken.TTL)
	}

	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	deps := httpapi.Deps{
		Config:    cfg,
		Version:   version,
		Log:       log,
		Risk:      risk,
		Lists:     lists,
		Geo:       geo.New(cfg.ProvidersDir, qq, newIPSBLimiter(cfg, sh), cfg.InfoLookupTimeout, log),
		InfoCache: cache.New(cfg.InfoCacheMaxEntries, cfg.InfoCacheTTL),
		Trap:      trap,
		// 为 nil 时不加载 otelgin 中间件
		TracerProvider: tel.TracerProvider,
		Signer:         signer,
	}
	if sh != nil {
		deps.SharedInfoCache = sh.Cache("info")
	}
	server := httpapi.New(deps)

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

// newIPSBLimiter 配置 Redis 时所有实例共享 IPSB_RATE_PER_SEC，Redis 不可用时每个实例按 IPSB_FALLBACK_RATE_PER_SEC；
// 未配置 Redis 时每个实例按 IPSB_RATE_PER_SEC。速率 <= 0 表示不限速
func newIPSBLimiter(cfg config.Config, sh *shared.Client) ipsb.Limiter {
	if cfg.IPSBRatePerSecond <= 0 {
		return nil
	}
	if sh == nil {
		return rate.NewLimiter(rate.Limit(cfg.IPSBRatePerSecond), 1)
	}
	fallback := rate.NewLimiter(rate.Inf, 1)
	if cfg.IPSBFallbackRatePerSecond > 0 {
		fallback = rate.NewLimiter(rate.Limit(cfg.IPSBFallbackRatePerSecond), 1)
	}
	return sh.RateLimiter("ipsb", cfg.IPSBRatePerSecond, fallback)
}

// newSigner 未配置 RISK_SIGNING_KEY 时返回 nil（v2 不签发令牌）；配置有误时启动失败，避免静默降级
func newSigner(cfg config.RiskTokenConfig) (*risktoken.Signer, error) {
	if cfg.SigningKey == "" {
		return nil, nil
	}
	priv, err := risktoken.ParsePrivateKey(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("RISK_SIGNING_KEY: %w", err)
	}
	extra, err := risktoken.ParsePublishedKeys(cfg.PublishedKeys)
	if err != nil {
		return nil, fmt.Errorf("RISK_PUBLISHED_KEYS: %w", err)
	}
	return risktoken.NewSigner(priv, cfg.KeyID, cfg.TTL, extra)
}
