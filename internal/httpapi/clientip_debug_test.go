package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientIPDebugBody struct {
	Status  string `json:"status"`
	Message struct {
		ClientIP      string            `json:"client_ip"`
		Source        string            `json:"source"`
		Peer          ipDebugInfo       `json:"peer"`
		Candidates    []headerCandidate `json:"candidates"`
		XForwardedFor struct {
			Raw  string        `json:"raw"`
			Hops []ipDebugInfo `json:"hops"`
		} `json:"x_forwarded_for"`
		Headers map[string]string `json:"headers"`
	} `json:"message"`
}

func TestClientIPDebug_RequiresAdmin(t *testing.T) {
	env := newTestEnv(t)
	assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodGet, "/api/debug/clientip").Code)
}

// 单值头是 CDN 节点被跳过、回退到 XFF：输出要能看出每个候选头的值、是否被当作 CDN、最终来源
func TestClientIPDebug_ShowsResolution(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/debug/clientip", asAdmin(),
		withRemote("10.42.0.17:41234"),
		withHeader("CF-Connecting-IP", "64.252.83.221"),
		withHeader("X-Forwarded-For", "1.2.3.4, 64.252.83.221"),
		withHeader("Cookie", "secret=1"),
	)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	var body clientIPDebugBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	m := body.Message
	assert.Equal(t, "1.2.3.4", m.ClientIP)
	assert.Equal(t, clientIPSourceForwardedFor, m.Source)
	assert.Equal(t, ipDebugInfo{IP: "10.42.0.17", TrustedProxy: true}, m.Peer)
	assert.Equal(t, []headerCandidate{{Header: "CF-Connecting-IP", Value: "64.252.83.221", IP: "64.252.83.221", CDN: "cloudfront"}}, m.Candidates)
	assert.Equal(t, []ipDebugInfo{
		{IP: "1.2.3.4"},
		{IP: "64.252.83.221", TrustedProxy: true, CDN: "cloudfront"},
	}, m.XForwardedFor.Hops)
	assert.Equal(t, "[redacted]", m.Headers["Authorization"])
	assert.Equal(t, "[redacted]", m.Headers["Cookie"])
	assert.NotContains(t, w.Body.String(), testAdminToken)
}

func TestClientIPDebug_SourceIsHeaderName(t *testing.T) {
	env := newTestEnv(t)
	w := env.do(http.MethodGet, "/api/debug/clientip", asAdmin(),
		withRemote("10.42.0.17:41234"),
		withHeader("ali-real-client-ip", "120.230.60.88"),
	)
	var body clientIPDebugBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "120.230.60.88", body.Message.ClientIP)
	assert.Equal(t, "ali-real-client-ip", body.Message.Source)

	// 对端不可信时不看任何头
	w = env.do(http.MethodGet, "/api/debug/clientip", asAdmin(),
		withRemote("8.8.8.8:1234"),
		withHeader("ali-real-client-ip", "120.230.60.88"),
	)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "8.8.8.8", body.Message.ClientIP)
	assert.Equal(t, clientIPSourcePeer, body.Message.Source)
}
