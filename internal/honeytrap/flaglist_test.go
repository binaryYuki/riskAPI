package honeytrap

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestObfuscator_RoundTrip(t *testing.T) {
	o := newObfuscator("secret")
	for _, ip := range []string{"8.8.8.8", "0.0.0.0", "255.255.255.255", "2001:db8:1:2:3:4:5:6", "::1"} {
		key, _ := sourceKey(ip)
		token := o.hide(key)
		assert.Len(t, token, 32, ip)
		assert.NotContains(t, token, ip)
		assert.Equal(t, token, o.hide(key), "the same source always maps to the same token")
		got, ok := o.reveal(token)
		assert.True(t, ok, ip)
		assert.Equal(t, key, got, ip)
	}
	a, _ := sourceKey("8.8.8.8")
	b, _ := sourceKey("8.8.8.9")
	assert.NotEqual(t, o.hide(a), o.hide(b))

	// 同一密钥在不同实例上得到相同的标识
	assert.Equal(t, o.hide(a), newObfuscator("secret").hide(a))
}

func TestObfuscator_RejectsForeignTokens(t *testing.T) {
	o := newObfuscator("secret")
	key, _ := sourceKey("8.8.8.8")

	for _, token := range []string{"", "zz", "abcd", strings.Repeat("0", 31), strings.Repeat("g", 32)} {
		_, ok := o.reveal(token)
		assert.False(t, ok, token)
	}
	// 用别的密钥生成的标识解不出合法的来源；没有配置密钥时每个实例的密钥都不同
	for _, other := range []*obfuscator{newObfuscator("other"), newObfuscator(""), newObfuscator("")} {
		token := other.hide(key)
		assert.NotEqual(t, o.hide(key), token)
		_, ok := o.reveal(token)
		assert.False(t, ok)
	}
}

func TestObfuscator_SealLines(t *testing.T) {
	o := newObfuscator("secret")
	line := `{"client_ip":"8.8.8.8","path":"/.env"}`

	sealed := o.seal(line)
	assert.NotContains(t, sealed, "8.8.8.8")
	assert.NotEqual(t, sealed, o.seal(line), "sealing the same line twice gives different strings")
	plain, ok := o.unseal(sealed)
	assert.True(t, ok)
	assert.Equal(t, line, plain)

	// 同一密钥的另一个实例可以还原；换密钥、被改动、或根本不是封存结果的内容都还原不了
	plain, ok = newObfuscator("secret").unseal(sealed)
	assert.True(t, ok)
	assert.Equal(t, line, plain)
	tampered := sealed[:len(sealed)-2] + "AA"
	for _, s := range []string{"", "x", "not base64 !", tampered, newObfuscator("other").seal(line)} {
		_, ok := o.unseal(s)
		assert.False(t, ok, s)
	}
}

func TestFlagList_MemoryOnly(t *testing.T) {
	f := newFlagList("", 2, time.Minute, quietLog())
	now := time.Now()

	f.flag("a", now.Add(time.Hour), now)
	assert.True(t, f.has("a", now))
	assert.False(t, f.has("a", now.Add(2*time.Hour)))
	assert.False(t, f.has("b", now))

	// 到期时间只延后不提前
	f.flag("a", now.Add(time.Minute), now)
	assert.True(t, f.has("a", now.Add(30*time.Minute)))

	// 写满后先清理已到期的，仍然满则不再接收
	f.flag("b", now.Add(time.Minute), now)
	f.flag("c", now.Add(time.Hour), now)
	assert.False(t, f.has("c", now))
	f.flag("c", now.Add(3*time.Hour), now.Add(2*time.Minute))
	assert.True(t, f.has("c", now.Add(2*time.Minute)), "expired entries make room")
	assert.Equal(t, 2, f.len())

	f.prune(now.Add(2 * time.Hour))
	assert.Equal(t, 1, f.len())
}

func readFlagFile(t *testing.T, path string) []flagRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var recs []flagRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec flagRecord
		require.NoError(t, json.Unmarshal([]byte(line), &rec), line)
		recs = append(recs, rec)
	}
	return recs
}

func TestFlagList_FileAppendSyncCompact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flagged.jsonl")
	now := time.Now().Truncate(time.Second)
	src := func(c string) string { return strings.Repeat(c, 32) }

	a := newFlagList(path, 100, 30*time.Minute, quietLog())
	a.sync(now) // 文件还不存在
	a.flag(src("a"), now.Add(time.Hour), now)
	a.flag(src("b"), now.Add(time.Minute), now)
	// 小幅延后不重写文件，延后超过 refresh 才再写一行
	a.flag(src("a"), now.Add(time.Hour+10*time.Minute), now)
	assert.Len(t, readFlagFile(t, path), 2)
	a.flag(src("a"), now.Add(2*time.Hour), now)
	assert.Len(t, readFlagFile(t, path), 3)

	// 另一个实例读同一个文件：看到未到期的标记，取最晚的到期时间
	b := newFlagList(path, 100, 30*time.Minute, quietLog())
	later := now.Add(5 * time.Minute)
	b.sync(later)
	assert.True(t, b.has(src("a"), now.Add(90*time.Minute)))
	assert.False(t, b.has(src("b"), later), "expired records are not loaded")
	assert.Equal(t, 1, b.len())

	// a 之后新增的标记，b 在下一次同步时读到；已读过的部分不会重复处理
	a.flag(src("c"), now.Add(time.Hour), now)
	offset := b.offset
	b.sync(later)
	assert.True(t, b.has(src("c"), later))
	assert.Greater(t, b.offset, offset)

	// 末尾不完整的行留到写完之后再读
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, _ = file.WriteString(`{"source":"` + src("d") + `","until":"`)
	b.sync(later)
	assert.False(t, b.has(src("d"), later))
	_, _ = file.WriteString(now.Add(time.Hour).Format(time.RFC3339) + "\"}\nnot json\n")
	require.NoError(t, file.Close())
	b.sync(later)
	assert.True(t, b.has(src("d"), later), "garbage lines are skipped")

	// 压缩后文件里只剩未到期的标记，每个来源一行
	b.compact(later)
	recs := readFlagFile(t, path)
	assert.Len(t, recs, 3)
	for _, rec := range recs {
		assert.True(t, rec.Until.After(later))
	}

	// 文件被压缩变短后，其他实例从头重读，之后仍能继续追加
	a.sync(later)
	assert.True(t, a.has(src("d"), later))
	a.flag(src("e"), now.Add(time.Hour), later)
	b.sync(later)
	assert.True(t, b.has(src("e"), later))
}

func TestTrap_FlagsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flagged.jsonl")
	persistent := func(c *Config) { c.Secret, c.FlagFile = "secret", path }

	trap, r := newTestTrap(fastCfg(persistent))
	get(r, "/.env", "8.8.8.8:1")
	get(r, "/.git/config", "[2001:db8:1:2::1]:1")
	require.True(t, trap.Flagged("8.8.8.8"))

	// 文件里只有混淆后的来源
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "8.8.8.8")
	assert.NotContains(t, string(data), "2001:db8")
	recs := readFlagFile(t, path)
	require.Len(t, recs, 2)
	assert.Equal(t, hidden(trap, "8.8.8.8"), recs[0].Source)

	// 重启：同一密钥、同一文件，标记仍在；没碰过蜜罐的地址不受影响
	restarted, _ := newTestTrap(fastCfg(persistent))
	assert.True(t, restarted.Flagged("8.8.8.8"))
	assert.True(t, restarted.Flagged("2001:db8:1:2:ffff::9"))
	assert.False(t, restarted.Flagged("9.9.9.9"))
	assert.Equal(t, 2, restarted.Stats().Flagged)
	assert.Zero(t, restarted.Stats().Offenders, "scores are not restored, only flags")

	// 换了密钥：文件里的标识对不上任何地址，不会误标
	rekeyed, _ := newTestTrap(fastCfg(func(c *Config) { c.Secret, c.FlagFile = "other", path }))
	assert.False(t, rekeyed.Flagged("8.8.8.8"))
}

func TestTrap_FlagFileNeedsSecretAndEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flagged.jsonl")

	trap, r := newTestTrap(fastCfg(func(c *Config) { c.FlagFile = path }))
	get(r, "/.env", "8.8.8.8:1")
	assert.True(t, trap.Flagged("8.8.8.8"), "flags still work in memory")
	assert.NoFileExists(t, path, "without a secret nothing is written")

	trap, _ = newTestTrap(Config{Enabled: false, Secret: "secret", FlagFile: path})
	assert.Empty(t, trap.flags.path)
}

func TestTrap_InstancesShareFlagFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flagged.jsonl")
	shared := func(c *Config) { c.Secret, c.FlagFile = "secret", path }
	a, ra := newTestTrap(fastCfg(shared))
	b, _ := newTestTrap(fastCfg(shared))

	get(ra, "/.env", "8.8.8.8:1")
	assert.True(t, a.Flagged("8.8.8.8"))
	assert.False(t, b.Flagged("8.8.8.8"))
	b.flags.sync(time.Now()) // RunJanitor 每个周期做一次
	assert.True(t, b.Flagged("8.8.8.8"))
}

func TestTrap_Reveal(t *testing.T) {
	trap, _ := newTestTrap(fastCfg(func(c *Config) { c.Secret = "secret" }))

	got, ok := trap.Reveal(hidden(trap, "8.8.8.8"))
	assert.True(t, ok)
	assert.Equal(t, "8.8.8.8", got)

	got, ok = trap.Reveal(hidden(trap, "2001:db8:1:2:3:4:5:6"))
	assert.True(t, ok)
	assert.Equal(t, "2001:db8:1:2::/64", got)
	assert.Equal(t, netip.MustParsePrefix(got).Addr().String(), "2001:db8:1:2::")

	_, ok = trap.Reveal("nope")
	assert.False(t, ok)
}
