package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"risky_ip_filter/internal/config"
	"risky_ip_filter/internal/risktoken"
)

var testSigningSeed = make([]byte, ed25519.SeedSize)

func withSigning(audiences ...string) func(*config.Config) {
	return func(c *config.Config) {
		c.RiskToken.SigningKey = base64.StdEncoding.EncodeToString(testSigningSeed)
		c.RiskToken.KeyID = "2026-10"
		c.RiskToken.Audiences = audiences
	}
}

func testPublicKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{
		"2026-10": ed25519.NewKeyFromSeed(testSigningSeed).Public().(ed25519.PublicKey),
	}
}

const testNonce = "n0nce-abcdef"

func TestCheckRequestIPV2SignsVerdict(t *testing.T) {
	env := newTestEnv(t, withSigning())
	env.setRisky(map[string]string{"8.8.8.8": "Test reason"})

	for _, tc := range []struct {
		remote    string
		wantRisky bool
		status    string
	}{
		{"8.8.8.8:1", true, "banned"},
		{"8.8.4.4:1", false, "ok"},
	} {
		w := env.do(http.MethodGet, "/api/v2/ip?aud=gdue-ca.paperee.guru&nonce="+testNonce,
			withRemote(tc.remote), withHeader("Origin", "https://gdue-ca.paperee.guru"))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))

		var resp SignedIPResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, tc.status, resp.Status)
		require.NotEmpty(t, resp.Token)

		claims, err := risktoken.Verify(resp.Token, testPublicKeys(), time.Now())
		require.NoError(t, err)
		assert.Equal(t, resp.IP, claims.IP)
		assert.Equal(t, tc.wantRisky, claims.IsRisky)
		assert.Equal(t, tc.status, claims.Status)
		assert.Equal(t, "gdue-ca.paperee.guru", claims.Aud)
		assert.Equal(t, testNonce, claims.Nonce)
		assert.Equal(t, "2026-10", claims.Kid)
		assert.Equal(t, int64(120), claims.Exp-claims.Iat)
	}
}

func TestCheckRequestIPV2WithoutTokenParams(t *testing.T) {
	env := newTestEnv(t) // 未配置签名也能不带 aud/nonce 使用
	w := env.do(http.MethodGet, "/api/v2/ip", withRemote("8.8.4.4:1"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","message":"IP is not listed as risky.","ip":"8.8.4.4","isRisky":false,"isIdc":false,"isProxy":false}`, w.Body.String())
}

func TestV2TokenParamValidation(t *testing.T) {
	signed := newTestEnv(t, withSigning("gdue-ca.paperee.guru"))
	unsigned := newTestEnv(t)
	tests := []struct {
		name   string
		env    *testEnv
		query  string
		origin string
		want   int
	}{
		{"aud only", signed, "aud=gdue-ca.paperee.guru", "", http.StatusBadRequest},
		{"nonce only", signed, "nonce=" + testNonce, "", http.StatusBadRequest},
		{"aud with scheme", signed, "aud=https://gdue-ca.paperee.guru&nonce=" + testNonce, "", http.StatusBadRequest},
		{"aud with port", signed, "aud=gdue-ca.paperee.guru:443&nonce=" + testNonce, "", http.StatusBadRequest},
		{"short nonce", signed, "aud=gdue-ca.paperee.guru&nonce=abc", "", http.StatusBadRequest},
		{"nonce bad chars", signed, "aud=gdue-ca.paperee.guru&nonce=abc%22def%3Cghi", "", http.StatusBadRequest},
		{"not configured", unsigned, "aud=gdue-ca.paperee.guru&nonce=" + testNonce, "", http.StatusServiceUnavailable},
		{"aud not allowed", signed, "aud=evil.example&nonce=" + testNonce, "https://evil.example", http.StatusForbidden},
		{"origin mismatch", signed, "aud=gdue-ca.paperee.guru&nonce=" + testNonce, "https://evil.example", http.StatusForbidden},
		{"null origin", signed, "aud=gdue-ca.paperee.guru&nonce=" + testNonce, "null", http.StatusForbidden},
		{"aud case-insensitive", signed, "aud=GDUE-CA.paperee.guru&nonce=" + testNonce, "https://gdue-ca.paperee.guru", http.StatusOK},
		{"server-side call", signed, "aud=gdue-ca.paperee.guru&nonce=" + testNonce, "", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 私网对端：/api/v2/info 不触发外部地理位置查询
			opts := []reqOpt{withRemote("192.168.1.5:1")}
			if tt.origin != "" {
				opts = append(opts, withHeader("Origin", tt.origin))
			}
			for _, path := range []string{"/api/v2/ip", "/api/v2/info"} {
				w := tt.env.do(http.MethodGet, path+"?"+tt.query, opts...)
				assert.Equal(t, tt.want, w.Code, "%s: %s", path, w.Body.String())
			}
		})
	}
}

func TestIPInfoV2(t *testing.T) {
	env := newTestEnv(t, withSigning())
	// 私网地址不触发外部查询
	w := env.do(http.MethodGet, "/api/v2/info?aud=gdue-ca.paperee.guru&nonce="+testNonce, withRemote("192.168.1.5:1"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp SignedInfoResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "192.168.1.5", resp.IP)
	assert.Equal(t, true, resp.Results["private_bogon"])

	claims, err := risktoken.Verify(resp.Token, testPublicKeys(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.5", claims.IP)
	assert.False(t, claims.IsRisky)

	// v2/info 只查询请求方自身
	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/api/v2/info/8.8.8.8").Code)
}

func TestRiskKeys(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, newTestEnv(t).do(http.MethodGet, riskKeysPath).Code)

	env := newTestEnv(t, withSigning())
	w := env.do(http.MethodGet, riskKeysPath, withHeader("Origin", "https://anywhere.example"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

	var set risktoken.KeySet
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "2026-10", set.Keys[0].Kid)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(testPublicKeys()["2026-10"]), set.Keys[0].X)

	// 其余 /.well-known/ 路径仍然 404
	assert.Equal(t, http.StatusNotFound, env.do(http.MethodGet, "/.well-known/security.txt").Code)
}

func TestV2CORSPreflightAndV1Unchanged(t *testing.T) {
	env := newTestEnv(t, withSigning())
	w := env.do(http.MethodOptions, "/api/v2/ip",
		withHeader("Origin", "https://gdue-ca.paperee.guru"),
		withHeader("Access-Control-Request-Method", "GET"))
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	// v1 仍只允许白名单来源
	w = env.do(http.MethodGet, "/api/v1/ip", withRemote("8.8.4.4:1"), withHeader("Origin", "https://gdue-ca.paperee.guru"))
	assert.Equal(t, http.StatusForbidden, w.Code)
}
