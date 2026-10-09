package honeytrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
)

// obfuscator 用密钥把计分来源变成不透明的标识。
// 同一来源始终得到同一标识，所以标识之间可以直接比对；持有密钥时可以还原出来源。
// 日志和标记文件里只出现标识，不出现真实地址。
//
// 来源正好是一个 AES 分组（16 字节），这里就是对单个分组做一次 AES-256 加密
type obfuscator struct {
	block cipher.Block
	lines cipher.AEAD // 整行日志用 AES-256-GCM 封存，密钥与来源标识的密钥相互独立
}

// newObfuscator 由密钥派生加密密钥；secret 为空时使用随机密钥，
// 此时标识只在本进程内有效，重启后既无法比对也无法还原
func newObfuscator(secret string) *obfuscator {
	if secret == "" {
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		secret = string(random)
	}
	derive := func(purpose string) cipher.Block {
		key := sha256.Sum256([]byte("riskapi/honeytrap/" + purpose + "/v1\x00" + secret))
		block, _ := aes.NewCipher(key[:]) // 32 字节密钥不会出错
		return block
	}
	lines, _ := cipher.NewGCM(derive("line"))
	return &obfuscator{block: derive("source"), lines: lines}
}

// seal 把一段文本封存为不透明的字符串（URL 安全的 Base64）。每次结果都不同，
// 所以相同的内容在日志里也无法互相比对
func (o *obfuscator) seal(plain string) string {
	nonce := make([]byte, o.lines.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(o.lines.Seal(nonce, nonce, []byte(plain), nil))
}

// unseal 还原 seal 的结果；内容被改动过，或不是用当前密钥封存的，返回 false
func (o *obfuscator) unseal(sealed string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < o.lines.NonceSize() {
		return "", false
	}
	nonce, box := raw[:o.lines.NonceSize()], raw[o.lines.NonceSize():]
	plain, err := o.lines.Open(nil, nonce, box, nil)
	if err != nil {
		return "", false
	}
	return string(plain), true
}

// hide 返回来源的标识：32 个十六进制字符
func (o *obfuscator) hide(source netip.Addr) string {
	plain := source.As16()
	var sealed [16]byte
	o.block.Encrypt(sealed[:], plain[:])
	return hex.EncodeToString(sealed[:])
}

// reveal 还原标识对应的来源。来源只有两种形态（IPv4 地址，或后 64 位为零的 IPv6 /64），
// 解密结果不符合时说明标识无效或密钥不对
func (o *obfuscator) reveal(token string) (netip.Addr, bool) {
	sealed, err := hex.DecodeString(token)
	if err != nil || len(sealed) != 16 {
		return netip.Addr{}, false
	}
	var plain [16]byte
	o.block.Decrypt(plain[:], sealed)
	addr := netip.AddrFrom16(plain)
	if addr.Is4In6() {
		return addr.Unmap(), true
	}
	if [8]byte(plain[8:]) == [8]byte{} {
		return addr, true
	}
	return netip.Addr{}, false
}
