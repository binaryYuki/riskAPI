package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"risky_ip_filter/internal/config"
)

func TestOpenCluster(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// 未开启集群模式：即使配置了 REDIS_URL 也不连接
	sh, err := openCluster(ctx, config.Config{RedisURL: "redis://127.0.0.1:1"}, log)
	require.NoError(t, err)
	assert.Nil(t, sh)

	// 开启但缺少 / 写错 REDIS_URL：启动失败
	_, err = openCluster(ctx, config.Config{ClusterMode: true}, log)
	assert.ErrorContains(t, err, "requires REDIS_URL")
	_, err = openCluster(ctx, config.Config{ClusterMode: true, RedisURL: "http://x"}, log)
	assert.ErrorContains(t, err, "REDIS_URL")

	mr := miniredis.RunT(t)
	sh, err = openCluster(ctx, config.Config{ClusterMode: true, RedisURL: "redis://" + mr.Addr()}, log)
	require.NoError(t, err)
	require.NotNil(t, sh)
	_ = sh.Close()
}
