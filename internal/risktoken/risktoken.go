// Package risktoken 为风险检测结果签发 Ed25519 签名令牌。
//
// 令牌格式：base64url(payload JSON) "." base64url(Ed25519 签名)，均不带填充。
// 签名覆盖第一段的 ASCII 字节。浏览器只负责把令牌原样转交给接入站点的服务端，
// 接入方用 /.well-known/risk-keys.json 公布的公钥（按 kid 选择）验签，无需共享密钥。
package risktoken

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version 当前 payload 版本
const Version = 1

// Claims 令牌 payload；字段顺序即序列化顺序
type Claims struct {
	V       int    `json:"v"`
	Kid     string `json:"kid"`
	IP      string `json:"ip"`     // 接口看到的访客 IP，接入方与自己看到的 IP 比对（IPv6 建议按 /64）
	Status  string `json:"status"` // 与接口响应的 status 相同（ok / banned / cdn / idc）
	IsRisky bool   `json:"isRisky"`
	IsIDC   bool   `json:"isIdc"`
	IsProxy bool   `json:"isProxy"`
	Aud     string `json:"aud"`   // 接入站点域名，防止跨站使用
	Nonce   string `json:"nonce"` // 接入站点下发的一次性随机串，防重放
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
}

// PublicKey 按 kid 公布的公钥
type PublicKey struct {
	Kid string
	Key ed25519.PublicKey
}

// Signer 持有当前签名私钥及需要公布的全部公钥
type Signer struct {
	kid       string
	priv      ed25519.PrivateKey
	ttl       time.Duration
	published []PublicKey // 第一个为当前密钥，其余为轮换期间仍需公布的旧公钥
	now       func() time.Time
}

// NewSigner 由私钥创建签名器。kid 为空时由公钥指纹派生；extra 为轮换期间额外公布的旧公钥
func NewSigner(priv ed25519.PrivateKey, kid string, ttl time.Duration, extra []PublicKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("risktoken: invalid ed25519 private key")
	}
	if ttl <= 0 {
		return nil, errors.New("risktoken: ttl must be positive")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if kid == "" {
		kid = Fingerprint(pub)
	}
	published := []PublicKey{{Kid: kid, Key: pub}}
	for _, k := range extra {
		if k.Kid == kid {
			return nil, fmt.Errorf("risktoken: published key id %q duplicates the signing key id", k.Kid)
		}
		published = append(published, k)
	}
	return &Signer{kid: kid, priv: priv, ttl: ttl, published: published, now: time.Now}, nil
}

// KeyID 当前签名密钥的 kid
func (s *Signer) KeyID() string { return s.kid }

// Sign 填充 v/kid/iat/exp 并签名，返回令牌与最终的 claims
func (s *Signer) Sign(c Claims) (string, Claims) {
	now := s.now()
	c.V = Version
	c.Kid = s.kid
	c.Iat = now.Unix()
	c.Exp = now.Add(s.ttl).Unix()
	payload, _ := json.Marshal(c) // 结构体只含基本类型，不会失败
	head := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(s.priv, []byte(head))
	return head + "." + base64.RawURLEncoding.EncodeToString(sig), c
}

// KeySet /.well-known/risk-keys.json 的内容（JWK Set，OKP/Ed25519）
type KeySet struct {
	Keys []JWK `json:"keys"`
}

// JWK 单个 Ed25519 公钥（RFC 8037）
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// KeySet 返回需要公布的全部公钥
func (s *Signer) KeySet() KeySet {
	set := KeySet{Keys: make([]JWK, 0, len(s.published))}
	for _, k := range s.published {
		set.Keys = append(set.Keys, JWK{
			Kty: "OKP", Crv: "Ed25519", Alg: "EdDSA", Use: "sig",
			Kid: k.Kid, X: base64.RawURLEncoding.EncodeToString(k.Key),
		})
	}
	return set
}

// 校验错误
var (
	ErrMalformed    = errors.New("risktoken: malformed token")
	ErrUnknownKey   = errors.New("risktoken: unknown key id")
	ErrBadSignature = errors.New("risktoken: invalid signature")
	ErrExpired      = errors.New("risktoken: token expired")
)

// Verify 校验签名与有效期，返回 claims。aud/nonce/ip 的比对由接入方自行完成
func Verify(token string, keys map[string]ed25519.PublicKey, now time.Time) (Claims, error) {
	var c Claims
	head, sigPart, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(sigPart, ".") {
		return c, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return c, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.V != Version {
		return Claims{}, ErrMalformed
	}
	key, ok := keys[c.Kid]
	if !ok || len(key) != ed25519.PublicKeySize {
		return Claims{}, ErrUnknownKey
	}
	if !ed25519.Verify(key, []byte(head), sig) {
		return Claims{}, ErrBadSignature
	}
	if now.Unix() >= c.Exp {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// Fingerprint 公钥指纹：base64url(SHA-256(pub)) 前 11 个字符，用作默认 kid
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:11]
}

// ParsePrivateKey 解析私钥，接受：
//   - PEM（PKCS#8，"BEGIN PRIVATE KEY"）
//   - base64/base64url（可带填充）编码的 32 字节种子、64 字节私钥或 PKCS#8 DER
//
// 生成示例：openssl genpkey -algorithm ed25519 -outform DER | base64
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return parsePKCS8(block.Bytes)
	}
	raw, err := decodeBase64(s)
	if err != nil {
		return nil, errors.New("risktoken: private key is neither PEM nor base64")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		priv := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !priv.Equal(ed25519.PrivateKey(raw)) {
			return nil, errors.New("risktoken: 64-byte private key has mismatched public half")
		}
		return priv, nil
	default:
		return parsePKCS8(raw)
	}
}

func parsePKCS8(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("risktoken: parse PKCS#8 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("risktoken: PKCS#8 key is not ed25519")
	}
	return priv, nil
}

// ParsePublishedKeys 解析 "kid=base64公钥" 列表（轮换期间继续公布的旧公钥）
func ParsePublishedKeys(items []string) ([]PublicKey, error) {
	var keys []PublicKey
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kid, enc, ok := strings.Cut(item, "=")
		kid = strings.TrimSpace(kid)
		if !ok || kid == "" {
			return nil, fmt.Errorf("risktoken: published key %q must be kid=base64", item)
		}
		raw, err := decodeBase64(strings.TrimSpace(enc))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("risktoken: published key %q is not a base64 32-byte ed25519 public key", kid)
		}
		if seen[kid] {
			return nil, fmt.Errorf("risktoken: duplicate published key id %q", kid)
		}
		seen[kid] = true
		keys = append(keys, PublicKey{Kid: kid, Key: ed25519.PublicKey(raw)})
	}
	return keys, nil
}

// decodeBase64 兼容标准与 URL 安全字母表、有无填充
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}
