package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCache_EvictsOldestOverCapacity(t *testing.T) {
	c := New(3, time.Hour)
	for i := 0; i < 5; i++ {
		c.Set(fmt.Sprintf("info:%d", i), i)
	}
	assert.Equal(t, 3, c.Len())
	_, ok := c.Get("info:0")
	assert.False(t, ok)
	_, ok = c.Get("info:1")
	assert.False(t, ok)
	v, ok := c.Get("info:4")
	assert.True(t, ok)
	assert.Equal(t, 4, v)
}

func TestCache_Expires(t *testing.T) {
	c := New(0, 20*time.Millisecond)
	c.Set("info:a", "x")
	_, ok := c.Get("info:a")
	assert.True(t, ok)
	time.Sleep(40 * time.Millisecond)
	_, ok = c.Get("info:a")
	assert.False(t, ok)
	assert.Equal(t, 0, c.Len(), "expired entry is removed on read")
}

func TestCache_OverwriteKeepsLatest(t *testing.T) {
	c := New(2, time.Hour)
	c.Set("a", 1)
	c.Set("a", 2)
	c.Set("b", 3)
	v, ok := c.Get("a")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	assert.Equal(t, 2, c.Len())
}

func TestCache_SetWithTTL(t *testing.T) {
	c := New(10, time.Hour)
	c.SetWithTTL("short", 1, 20*time.Millisecond)
	c.Set("long", 2)
	time.Sleep(40 * time.Millisecond)
	_, ok := c.Get("short")
	assert.False(t, ok)
	_, ok = c.Get("long")
	assert.True(t, ok)
}

func TestCache_DeletePrefixAndFlush(t *testing.T) {
	c := New(0, 0)
	c.Set("info:1.1.1.1", 1)
	c.Set("info:2.2.2.2", 2)
	c.Set("other", 3)
	assert.Equal(t, 2, c.DeletePrefix("info:"))
	_, ok := c.Get("other")
	assert.True(t, ok)
	c.Flush()
	assert.Equal(t, 0, c.Len())
}
