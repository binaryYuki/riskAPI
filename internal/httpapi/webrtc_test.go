package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func srflx(ip string) string {
	return "candidate:842163049 1 udp 1677729535 " + ip + " 54321 typ srflx raddr 0.0.0.0 rport 0 generation 0"
}

func TestParseICECandidate(t *testing.T) {
	cases := []struct {
		in, ip, typ string
		ok          bool
	}{
		{srflx("45.10.10.10"), "45.10.10.10", "srflx", true},
		{"a=candidate:1 1 udp 2122260223 192.168.1.5 50000 typ host", "192.168.1.5", "host", true},
		{"candidate:1 1 udp 2122260223 2001:db8::1 50000 typ host", "2001:db8::1", "host", true},
		{"candidate:1 1 udp 2122260223 abc.local 50000 typ host", "abc.local", "host", true},
		{"candidate:1 1 udp 2122260223 1.2.3.4 50000 foo host", "", "", false},
		{"candidate:1 1 udp", "", "", false},
		{"1.2.3.4", "", "", false},
	}
	for _, c := range cases {
		ip, typ, ok := parseICECandidate(c.in)
		assert.Equal(t, c.ok, ok, c.in)
		assert.Equal(t, c.ip, ip, c.in)
		assert.Equal(t, c.typ, typ, c.in)
	}
}

func (e *testEnv) webrtc(remote string, body any) (*WebRTCResponse, int) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(e.t, err)
	w := e.do(http.MethodPost, "/api/v1/webrtc", withRemote(remote), withBody(string(raw), "application/json"))
	if w.Code != http.StatusOK {
		return nil, w.Code
	}
	var resp WebRTCResponse
	require.NoError(e.t, json.Unmarshal(w.Body.Bytes(), &resp))
	return &resp, w.Code
}

func TestWebRTCCheck(t *testing.T) {
	env := newTestEnv(t)
	env.setRisky(map[string]string{"5.6.7.8": "Test reason"})

	t.Run("no leak when srflx equals request ip", func(t *testing.T) {
		resp, code := env.webrtc("8.8.4.4:1", WebRTCRequest{Candidates: []string{
			srflx("8.8.4.4"),
			"candidate:1 1 udp 2122260223 192.168.1.5 50000 typ host",
			"candidate:1 1 udp 2122260223 0a1b2c3d.local 50000 typ host",
		}})
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "ok", resp.Status)
		assert.False(t, resp.Leak)
		assert.False(t, resp.IsRisky)
		require.Len(t, resp.Candidates, 2) // mDNS 主机名被跳过
		assert.True(t, resp.Candidates[0].SameAsRequest)
		assert.Equal(t, "private", resp.Candidates[1].Status)
	})

	t.Run("leak when public srflx differs", func(t *testing.T) {
		resp, _ := env.webrtc("8.8.4.4:1", WebRTCRequest{Candidates: []string{srflx("45.10.10.10")}})
		assert.Equal(t, "leak", resp.Status)
		assert.True(t, resp.Leak)
		assert.Equal(t, "srflx", resp.Candidates[0].Type)
	})

	t.Run("cross family is not a leak", func(t *testing.T) {
		resp, _ := env.webrtc("8.8.4.4:1", WebRTCRequest{IPs: []string{"2606:4700::1111"}})
		assert.False(t, resp.Leak)
		require.Len(t, resp.Candidates, 1)
	})

	t.Run("risky candidate marks response risky", func(t *testing.T) {
		resp, _ := env.webrtc("8.8.4.4:1", WebRTCRequest{IPs: []string{"5.6.7.8", "5.6.7.8"}})
		assert.True(t, resp.IsRisky)
		require.Len(t, resp.Candidates, 1) // 去重
		assert.Equal(t, "risky", resp.Candidates[0].Status)
		assert.Equal(t, "Test reason", resp.Candidates[0].Message)
	})

	t.Run("risky request ip", func(t *testing.T) {
		resp, _ := env.webrtc("5.6.7.8:1", WebRTCRequest{})
		assert.Equal(t, "risky", resp.RequestStatus)
		assert.True(t, resp.IsRisky)
		assert.NotNil(t, resp.Candidates)
	})

	t.Run("candidate cap", func(t *testing.T) {
		var ips []string
		for i := 0; i < 100; i++ {
			ips = append(ips, "10.0."+strconv.Itoa(i)+".1")
		}
		resp, _ := env.webrtc("8.8.4.4:1", WebRTCRequest{IPs: ips})
		assert.Len(t, resp.Candidates, webrtcMaxCandidates)
	})

	t.Run("geo info from cache", func(t *testing.T) {
		seed := func(ip, country string) {
			env.cache.SetWithTTL(infoCachePrefix+ip, InfoResponse{Status: "ok", IP: ip,
				Results: map[string]any{"ipinfo": map[string]any{"country": country}}}, time.Hour)
		}
		seed("8.8.4.4", "US")
		seed("45.10.10.10", "DE")
		resp, _ := env.webrtc("8.8.4.4:1", WebRTCRequest{Candidates: []string{
			srflx("8.8.4.4"),
			srflx("45.10.10.10"),
			"candidate:1 1 udp 2122260223 192.168.1.5 50000 typ host",
		}})
		require.Len(t, resp.Candidates, 3)
		assert.Equal(t, "US", resp.RequestInfo["ipinfo"].(map[string]any)["country"])
		assert.Equal(t, resp.RequestInfo, resp.Candidates[0].Info) // 同请求 IP 复用
		assert.Equal(t, "DE", resp.Candidates[1].Info["ipinfo"].(map[string]any)["country"])
		assert.Nil(t, resp.Candidates[2].Info) // 私网不查询
	})

	t.Run("invalid body", func(t *testing.T) {
		w := env.do(http.MethodPost, "/api/v1/webrtc", withBody("{", "application/json"))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("oversized body", func(t *testing.T) {
		big := `{"ips":["` + strings.Repeat("a", webrtcMaxBody) + `"]}`
		w := env.do(http.MethodPost, "/api/v1/webrtc", withBody(big, "application/json"))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebRTCScript(t *testing.T) {
	env := newTestEnv(t)

	w := env.do(http.MethodGet, "/api/v1/webrtc")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/javascript; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, webrtcScriptCacheControl, w.Header().Get("Cache-Control"))
	assert.Equal(t, webrtcScriptCDNCache, w.Header().Get("CDN-Cache-Control"))
	etag := w.Header().Get("ETag")
	assert.Regexp(t, `^"[0-9a-f]{32}"$`, etag)
	assert.Equal(t, webrtcScript, w.Body.Bytes())
	assert.Contains(t, w.Body.String(), "RiskWebRTC")

	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		w = env.do(http.MethodGet, "/api/v1/webrtc", withHeader("If-None-Match", inm))
		assert.Equal(t, http.StatusNotModified, w.Code, inm)
		assert.Empty(t, w.Body.String(), inm)
		assert.Equal(t, etag, w.Header().Get("ETag"), inm)
		assert.Equal(t, webrtcScriptCacheControl, w.Header().Get("Cache-Control"), inm)
	}

	w = env.do(http.MethodGet, "/api/v1/webrtc", withHeader("If-None-Match", `"stale"`))
	assert.Equal(t, http.StatusOK, w.Code)

	w = env.do(http.MethodHead, "/api/v1/webrtc")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, etag, w.Header().Get("ETag"))

	// POST 检测结果因人而异，仍不可缓存
	w = env.do(http.MethodPost, "/api/v1/webrtc", withRemote("8.8.4.4:1"), withBody(`{}`, "application/json"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "private, no-cache, no-store, max-age=0, must-revalidate", w.Header().Get("Cache-Control"))
}
