package qqwry

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const datPath = "../../../providers/qqwry/qqwry.dat"

func TestOpenAndQuery(t *testing.T) {
	if _, err := os.Stat(datPath); err != nil {
		t.Skip("qqwry.dat not present")
	}
	db, err := Open(datPath)
	assert.NoError(t, err)

	country, area, err := db.Query("114.114.114.114")
	assert.NoError(t, err)
	assert.NotEmpty(t, country)
	assert.NotEmpty(t, area)

	_, _, err = db.Query("2001:db8::1")
	assert.Error(t, err, "IPv6 is not supported")

	stats := db.Stats()
	assert.Equal(t, true, stats["loaded"])
}

func TestNilDBIsSafe(t *testing.T) {
	var db *DB
	_, _, err := db.Query("1.2.3.4")
	assert.Error(t, err)
	assert.Equal(t, false, db.Stats()["loaded"])
}

func TestParseCountry(t *testing.T) {
	assert.Equal(t, map[string]string{"country": "中国", "province": "广东", "city": "广州"}, ParseCountry("中国–广东–广州"))
	assert.Equal(t, map[string]string{"country": "美国", "province": "", "city": ""}, ParseCountry("美国"))
}
