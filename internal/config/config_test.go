package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoad_Defaults(t *testing.T) {
	for _, k := range []string{"ALLOWED_CORS", "ADMIN_TOKEN", "TRUSTED_PROXIES", "PARSE_VV_SECRET", "PARSE_RATE_LIMIT_PER_MIN", "INFO_CACHE_MAX_ENTRIES", "HONEYTRAP_ENABLED", "HONEYTRAP_BLOCK_THRESHOLD", "HONEYTRAP_FLAG_THRESHOLD", "HONEYTRAP_FLAG_DURATION_SEC", "HONEYTRAP_FAKEOK", "HONEYTRAP_SECRET", "HONEYTRAP_FLAG_FILE", "QQWRY_PATH", "LISTEN_ADDR"} {
		t.Setenv(k, "")
	}
	cfg := Load()
	assert.Equal(t, ":8080", cfg.Addr)
	assert.Equal(t, []string{"catyuki.com", "tzpro.xyz"}, cfg.AllowedCORS)
	assert.Empty(t, cfg.AdminToken)
	assert.Empty(t, cfg.ParseSecret)
	assert.Equal(t, DefaultTrustedProxies, cfg.TrustedProxies)
	assert.Equal(t, 30, cfg.ParseRateLimitPerMin)
	assert.Equal(t, 20000, cfg.InfoCacheMaxEntries)
	assert.Equal(t, "providers/qqwry/qqwry.dat", cfg.QQWryPath)
	assert.True(t, cfg.Honeytrap.Enabled)
	assert.Equal(t, 16, cfg.Honeytrap.BlockThreshold)
	assert.Equal(t, 180*time.Second, cfg.Honeytrap.BlockDuration)
	assert.Equal(t, 8, cfg.Honeytrap.FlagThreshold)
	assert.Equal(t, time.Hour, cfg.Honeytrap.FlagDuration)
	assert.Equal(t, 1.0, cfg.Honeytrap.FakeOKProb)
	assert.Empty(t, cfg.Honeytrap.Secret)
	assert.Empty(t, cfg.Honeytrap.FlagFile)
	assert.NotEmpty(t, cfg.Feeds)
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("ALLOWED_CORS", " a.com , b.com ")
	t.Setenv("ADMIN_TOKEN", "tok")
	t.Setenv("PARSE_RATE_LIMIT_PER_MIN", "0")
	t.Setenv("HONEYTRAP_ENABLED", "false")
	t.Setenv("HONEYTRAP_FAKEOK", "0.5")
	t.Setenv("HONEYTRAP_FLAG_THRESHOLD", "12")
	t.Setenv("HONEYTRAP_SECRET", " keep spaces ")
	t.Setenv("HONEYTRAP_FLAG_FILE", "/var/lib/riskapi/flagged.jsonl")
	t.Setenv("HONEYTRAP_FLAG_DURATION_SEC", "600")
	t.Setenv("INFO_CACHE_MAX_ENTRIES", "not-a-number") // 非法值回退默认
	cfg := Load()
	assert.Equal(t, []string{"a.com", "b.com"}, cfg.AllowedCORS)
	assert.Equal(t, "tok", cfg.AdminToken)
	assert.Equal(t, 0, cfg.ParseRateLimitPerMin)
	assert.False(t, cfg.Honeytrap.Enabled)
	assert.Equal(t, 0.5, cfg.Honeytrap.FakeOKProb)
	assert.Equal(t, 12, cfg.Honeytrap.FlagThreshold)
	assert.Equal(t, " keep spaces ", cfg.Honeytrap.Secret)
	assert.Equal(t, "/var/lib/riskapi/flagged.jsonl", cfg.Honeytrap.FlagFile)
	assert.Equal(t, 10*time.Minute, cfg.Honeytrap.FlagDuration)
	assert.Equal(t, 20000, cfg.InfoCacheMaxEntries)
}
