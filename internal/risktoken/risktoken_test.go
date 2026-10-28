package risktoken

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

func keysOf(s *Signer) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, k := range s.published {
		m[k.Kid] = k.Key
	}
	return m
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := NewSigner(testKey(t), "2026-10", 2*time.Minute, nil)
	require.NoError(t, err)
	now := time.Unix(1791979000, 0)
	s.now = func() time.Time { return now }

	token, claims := s.Sign(Claims{IP: "2a00::1", Status: "ok", Aud: "a.example", Nonce: "nonce-123"})
	assert.Equal(t, 1, claims.V)
	assert.Equal(t, "2026-10", claims.Kid)
	assert.Equal(t, int64(1791979000), claims.Iat)
	assert.Equal(t, int64(1791979120), claims.Exp)

	got, err := Verify(token, keysOf(s), now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, claims, got)

	_, err = Verify(token, keysOf(s), now.Add(2*time.Minute))
	assert.ErrorIs(t, err, ErrExpired)
}

func TestPayloadFieldOrder(t *testing.T) {
	s, err := NewSigner(testKey(t), "k", time.Minute, nil)
	require.NoError(t, err)
	token, _ := s.Sign(Claims{IP: "1.1.1.1"})
	head, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	require.NoError(t, err)
	assert.Regexp(t, `^\{"v":1,"kid":"k","ip":"1\.1\.1\.1","status":"","isRisky":false,"isIdc":false,"isProxy":false,"aud":"","nonce":"","iat":\d+,"exp":\d+\}$`, string(raw))
}

func TestVerifyRejectsTampering(t *testing.T) {
	s, err := NewSigner(testKey(t), "k", time.Minute, nil)
	require.NoError(t, err)
	token, _ := s.Sign(Claims{IP: "1.1.1.1", IsRisky: true})
	head, sig, _ := strings.Cut(token, ".")

	raw, _ := base64.RawURLEncoding.DecodeString(head)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["isRisky"] = false
	forged, _ := json.Marshal(m)
	forgedToken := base64.RawURLEncoding.EncodeToString(forged) + "." + sig

	_, err = Verify(forgedToken, keysOf(s), time.Now())
	assert.ErrorIs(t, err, ErrBadSignature)

	_, err = NewSigner(ed25519.PrivateKey("short"), "k", time.Minute, nil)
	assert.Error(t, err)

	_, err = Verify(token, map[string]ed25519.PublicKey{"other": s.published[0].Key}, time.Now())
	assert.ErrorIs(t, err, ErrUnknownKey)

	for _, bad := range []string{"", "abc", "a.b.c", head + ".!!", "!!." + sig} {
		_, err = Verify(bad, keysOf(s), time.Now())
		assert.ErrorIs(t, err, ErrMalformed, bad)
	}
}

func TestDefaultKidAndKeySet(t *testing.T) {
	priv := testKey(t)
	oldPub := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1)).Public().(ed25519.PublicKey)
	s, err := NewSigner(priv, "", time.Minute, []PublicKey{{Kid: "old", Key: oldPub}})
	require.NoError(t, err)
	assert.Equal(t, Fingerprint(priv.Public().(ed25519.PublicKey)), s.KeyID())

	set := s.KeySet()
	require.Len(t, set.Keys, 2)
	assert.Equal(t, s.KeyID(), set.Keys[0].Kid)
	assert.Equal(t, "OKP", set.Keys[0].Kty)
	assert.Equal(t, "Ed25519", set.Keys[0].Crv)
	assert.Equal(t, "old", set.Keys[1].Kid)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(oldPub), set.Keys[1].X)

	_, err = NewSigner(priv, "dup", time.Minute, []PublicKey{{Kid: "dup", Key: oldPub}})
	assert.Error(t, err)
}

func TestParsePrivateKey(t *testing.T) {
	priv := testKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	for name, in := range map[string]string{
		"seed std":    base64.StdEncoding.EncodeToString(priv.Seed()),
		"seed url":    base64.RawURLEncoding.EncodeToString(priv.Seed()),
		"64-byte key": base64.StdEncoding.EncodeToString(priv),
		"pkcs8 der":   base64.StdEncoding.EncodeToString(der),
		"pem":         pemStr,
	} {
		got, err := ParsePrivateKey(in)
		require.NoError(t, err, name)
		assert.True(t, priv.Equal(got), name)
	}

	bad := append([]byte{}, priv...)
	bad[63] ^= 1
	for _, in := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(bad), base64.StdEncoding.EncodeToString([]byte("short"))} {
		_, err := ParsePrivateKey(in)
		assert.Error(t, err, in)
	}
}

func TestParsePublishedKeys(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))
	keys, err := ParsePublishedKeys([]string{"2026-09=" + pub, " ", ""})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "2026-09", keys[0].Kid)

	for _, in := range [][]string{{pub}, {"=" + pub}, {"k=abc"}, {"k=" + pub, "k=" + pub}} {
		_, err := ParsePublishedKeys(in)
		assert.Error(t, err, in)
	}
}
