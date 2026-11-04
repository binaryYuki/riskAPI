package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/feeds"
	"risky_ip_filter/internal/honeytrap"
	"risky_ip_filter/internal/risktoken"
)

// trustedEnv 机房类风险源整段命中 34.22.0.0/16，其中 34.22.85.0/27 为 googlebot 可信网段（同时位于 data/idc/gcp）
func trustedEnv(t *testing.T, mutate ...func(*config.Config)) *testEnv {
	t.Helper()
	serve := func(body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	dc, bot := serve("34.22.0.0/16\n"), serve("34.22.85.0/27\n")
	env := newTestEnv(t, append([]func(*config.Config){func(c *config.Config) {
		c.Feeds = []feeds.Feed{
			{ID: "X4BNet-datacenter", URL: dc, Tags: feeds.TagIDC},
			{ID: "googlebot", URL: bot, Trusted: true},
		}
	}}, mutate...)...)
	require.True(t, env.risk.Update(context.Background()))
	return env
}

func TestCheckIP_TrustedBotOverridesRiskList(t *testing.T) {
	env := trustedEnv(t)
	cases := map[string]string{
		// 可信：不判定为风险，status 按 CDN/IDC 照常给出，isIdc 照常标记
		"34.22.85.1": `{"status":"idc","message":"IP belongs to IDC: gcp","ip":"34.22.85.1","isRisky":false,"isIdc":true,"isProxy":false,"isTrustedBot":"googlebot"}`,
		// 同一机房段的其它地址仍为风险，且不带 isTrustedBot
		"34.22.86.1": `{"status":"risky","message":"IP is in risky list: X4BNet-datacenter","ip":"34.22.86.1","isRisky":true,"isIdc":true,"isProxy":false}`,
	}
	for ip, want := range cases {
		assert.JSONEq(t, want, env.do(http.MethodGet, "/api/v1/ip/"+ip).Body.String(), ip)
	}

	w := env.do(http.MethodGet, "/api/v1/ip", withRemote("34.22.85.1:1"))
	assert.JSONEq(t, `{"status":"idc","message":"Client IP belongs to IDC: gcp","ip":"34.22.85.1","isRisky":false,"isIdc":true,"isProxy":false,"isTrustedBot":"googlebot"}`, w.Body.String())

	w = env.do(http.MethodPost, "/filter-proxies", withBody(`[{"name":"bot","server":"34.22.85.1:80"},{"name":"dc","server":"34.22.86.1:80"}]`, "application/json"))
	assert.JSONEq(t, `{"status":"ok","message":{"filtered_count":1,"proxies":[{"name":"bot","server":"34.22.85.1:80"}]}}`, w.Body.String())

	var ready struct {
		Message map[string]any `json:"message"`
	}
	require.NoError(t, json.Unmarshal(env.do(http.MethodGet, "/api/ready").Body.Bytes(), &ready))
	assert.EqualValues(t, 1, ready.Message["trusted_prefixes"])
	assert.Contains(t, env.do(http.MethodGet, "/metrics").Body.String(), "riskapi_trusted_prefixes 1\n")
}

// 可信网段触发蜜罐（爬虫顺着链接抓到诱饵路径）也不判定为风险
func TestCheckIP_TrustedBotIgnoresHoneytrapFlag(t *testing.T) {
	env := trustedEnv(t, trapConfig(func(c *honeytrap.Config) { c.AffectsVerdict = true }))
	for _, ip := range []string{"34.22.85.1", "34.22.200.1"} {
		env.do(http.MethodGet, "/.git/config", withRemote(ip+":1"))
		require.True(t, env.server.trap.Risky(ip), ip)
	}
	var resp ResponseWithIP
	require.NoError(t, json.Unmarshal(env.do(http.MethodGet, "/api/v1/ip/34.22.85.1", withRemote("9.9.9.9:1")).Body.Bytes(), &resp))
	assert.False(t, resp.IsRisky)
	assert.Equal(t, "googlebot", resp.TrustedBot)
}

func TestV2_TrustedBotIsSigned(t *testing.T) {
	env := trustedEnv(t, withSigning())
	verify := func(remote string) (SignedIPResponse, risktoken.Claims) {
		w := env.do(http.MethodGet, "/api/v2/ip?aud=gdue-ca.paperee.guru&nonce="+testNonce,
			withRemote(remote), withHeader("Origin", "https://gdue-ca.paperee.guru"))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp SignedIPResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		claims, err := risktoken.Verify(resp.Token, testPublicKeys(), time.Now())
		require.NoError(t, err)
		return resp, claims
	}
	resp, claims := verify("34.22.85.1:1")
	assert.Equal(t, "googlebot", resp.TrustedBot)
	assert.Equal(t, "googlebot", claims.TrustedBot)
	assert.False(t, claims.IsRisky)
	assert.True(t, claims.IsIDC)

	_, claims = verify("34.22.86.1:1")
	assert.Empty(t, claims.TrustedBot)
	assert.True(t, claims.IsRisky)
}
