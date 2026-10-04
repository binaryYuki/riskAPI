package geo

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const providersDir = "../../providers"

func newTestService() *Service {
	return New(providersDir, nil, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestMMDBReaderIsReused(t *testing.T) {
	db := filepath.Join(providersDir, "maxmind/GeoLite2-Country.mmdb")
	if !fileNonEmpty(db) {
		t.Skip("mmdb not present")
	}
	s := newTestService()
	r1, err := s.mmdbReader(db)
	assert.NoError(t, err)
	r2, err := s.mmdbReader(db)
	assert.NoError(t, err)
	assert.Same(t, r1, r2)

	_, err = s.lookupMMDB(db, net.ParseIP("8.8.8.8"))
	assert.NoError(t, err)

	_, err = s.mmdbReader(filepath.Join(providersDir, "does-not-exist.mmdb"))
	assert.ErrorIs(t, err, errMMDBUnavailable)
}

func TestIsChina(t *testing.T) {
	assert.True(t, isChina(map[string]any{"ipinfo": map[string]any{"country": "CN"}}))
	assert.True(t, isChina(map[string]any{"maxmind": map[string]any{"country": map[string]any{"iso_code": "CN"}}}))
	assert.True(t, isChina(map[string]any{"iplocate": map[string]any{"country_code": "CN"}}))
	assert.False(t, isChina(map[string]any{"ipinfo": map[string]any{"country": "US"}}))
}

func TestMergeGenericAndRemoveIPKey(t *testing.T) {
	dst := map[string]any{"country": map[string]any{"iso_code": "US"}}
	mergeGeneric(dst, map[string]any{"country": map[string]any{"names": "x"}, "asn": 15169, "ip": "8.8.8.8"})
	mergeGeneric(dst, []any{1})
	mergeGeneric(dst, "scalar")
	removeIPKey(dst)
	assert.Equal(t, map[string]any{
		"country": map[string]any{"iso_code": "US", "names": "x"},
		"asn":     15169,
		"_list":   []any{1},
		"_value":  []any{"scalar"},
	}, dst)
}
