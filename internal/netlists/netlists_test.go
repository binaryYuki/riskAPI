package netlists

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLists_ReloadAndLookup(t *testing.T) {
	dir := t.TempDir()
	for kind, files := range map[string]map[string]string{
		"cdn": {"cloudflare": "104.16.0.0/13\n", "edgeone": "# comment\n104.16.1.0/24\n"},
		"idc": {"aws": "3.5.140.0/22\n2600:1f00::/24\n", "gcp": "3.5.140.0/22\n"},
	} {
		assert.NoError(t, os.MkdirAll(filepath.Join(dir, kind), 0o755))
		for name, content := range files {
			assert.NoError(t, os.WriteFile(filepath.Join(dir, kind, name+".txt"), []byte(content), 0o644))
		}
	}
	l := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))

	_, ok := l.CDN("104.16.0.1")
	assert.False(t, ok, "empty before Reload")

	l.Reload()
	p, ok := l.CDN("104.16.0.1")
	assert.True(t, ok)
	assert.Equal(t, "cloudflare", p)
	p, _ = l.CDN("104.16.1.1")
	assert.Equal(t, "edgeone", p, "more specific prefix wins")

	p, _ = l.IDC("3.5.140.1")
	assert.Equal(t, "aws", p, "same prefix in two providers: earlier provider in IDCProviders wins")
	p, _ = l.IDC("2600:1f00::1")
	assert.Equal(t, "aws", p)

	cdn, idc := l.Sizes()
	assert.Equal(t, 2, cdn)
	assert.Equal(t, 2, idc)

	path, ok := l.CDNFile("edgeone")
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(dir, "cdn", "edgeone.txt"), path)
	_, ok = l.CDNFile("../../etc/passwd")
	assert.False(t, ok)
}
