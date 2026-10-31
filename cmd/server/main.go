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

	sh, err := openCluster(ctx, cfg, log)
	if err != nil {
		return err
	}
	if sh != nil {
		defer func() { _ = sh.Close() }()
	}

	risk := feeds.NewStore(cfg.Feeds, cfg.FeedFetch, log)
	if sh != nil {
		risk.SetCoordinator(sh.Snapshots("feeds"))
	}
	go risk.Run(ctx, cfg.FeedUpdateInterval)

	trap, err := newTrap(ctx, cfg, sh, log)
	if err != nil {
		return err
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
	var bus *shared.Bus
	if sh != nil {
		bus = sh.Bus("admin")
		deps.SharedInfoCache = sh.Cache("info")
		deps.Broadcaster = bus
	}
	server := httpapi.New(deps)
	if bus != nil {
		go bus.Run(ctx, server.HandleClusterMessage)
	}

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

// openCluster CLUSTER_MODE=1 时连接 Redis：多副本共用出口 IP，通过 Redis 共享风险数据快照、info 缓存与 ip.sb 限速，
// 避免重复请求外部数据源被限流。未开启时返回 nil；开启但缺少或写错 REDIS_URL 时启动失败，避免静默退化为单机模式
func openCluster(ctx context.Context, cfg config.Config, log *slog.Logger) (*shared.Client, error) {
	if !cfg.ClusterMode {
		if cfg.RedisURL != "" {
			log.Warn("REDIS_URL is ignored because CLUSTER_MODE is not enabled")
		}
		return nil, nil
	}
	if cfg.RedisURL == "" {
		return nil, errors.New("CLUSTER_MODE=1 requires REDIS_URL")
	}
	sh, err := shared.Open(ctx, cfg.RedisURL, cfg.RedisKeyPrefix, log)
	if err != nil {
		return nil, fmt.Errorf("REDIS_URL: %w", err)
	}
	return sh, nil
}

// newTrap 创建蜜罐。集群模式下被标记的来源通过 Redis 广播给其它实例，否则多副本的风险判定会因 Pod 而异；
// 广播需要各实例使用相同的 HONEYTRAP_SECRET。蜜罐标记参与风险判定却无法在实例间共享时启动失败
func newTrap(ctx context.Context, cfg config.Config, sh *shared.Client, log *slog.Logger) (*honeytrap.Trap, error) {
	hc := cfg.Honeytrap
	if hc.Enabled && hc.AffectsVerdict && sh != nil && hc.Secret == "" {
		return nil, errors.New("HONEYTRAP_AFFECTS_VERDICT=1 with CLUSTER_MODE=1 requires HONEYTRAP_SECRET (shared by all instances)")
	}
	trap := honeytrap.New(hc, log)
	if !hc.Enabled {
		return trap, nil
	}
	go trap.RunJanitor(ctx)
	if sh == nil {
		return trap, nil
	}
	bus := sh.Bus("honeytrap")
	sharing := trap.ShareFlags(func(payload []byte) {
		// 广播在后台进行，Redis 故障时不拖慢请求；消息丢失只影响其它实例，本实例的标记不受影响
		go func() {
			if err := bus.Publish(context.WithoutCancel(ctx), payload); err != nil {
				log.Warn("honeytrap flag broadcast failed", "err", err)
			}
		}()
	})
	if sharing {
		go bus.Run(ctx, trap.HandlePeerFlag)
	} else {
		log.Warn("honeytrap flags are not shared across instances without HONEYTRAP_SECRET")
	}
	return trap, nil
}

// newIPSBLimiter 集群模式下所有实例共享 IPSB_RATE_PER_SEC，Redis 不可用时每个实例按 IPSB_FALLBACK_RATE_PER_SEC；
// 单机模式下每个实例按 IPSB_RATE_PER_SEC。速率 <= 0 表示不限速
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
