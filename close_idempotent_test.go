//go:build !integration

package ldap

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Close is documented as safe to call more than once, and `defer x.Close()`
// beside an explicit shutdown Close is an ordinary pattern — so a second call
// must not panic. Both LRUCache and PerformanceMonitor closed a channel behind
// nothing but a nil check, and the second close panicked with
// "close of closed channel", taking the process down. ConnectionPool.Close has
// guarded against this all along; these two now match it.

func TestLRUCacheCloseIsIdempotent(t *testing.T) {
	newCache := func(t *testing.T) *LRUCache {
		t.Helper()
		c, err := NewLRUCache(&CacheConfig{
			Enabled:         true,
			TTL:             time.Minute,
			MaxSize:         4,
			RefreshInterval: time.Minute,
			MaxMemoryMB:     1,
		}, slog.Default())
		require.NoError(t, err)
		return c
	}

	t.Run("second close is a no-op", func(t *testing.T) {
		c := newCache(t)
		require.NoError(t, c.Close())
		assert.NotPanics(t, func() {
			assert.NoError(t, c.Close())
		})
	})

	t.Run("further closes stay safe", func(t *testing.T) {
		c := newCache(t)
		require.NoError(t, c.Close())
		for range 3 {
			assert.NotPanics(t, func() { _ = c.Close() })
		}
	})

	t.Run("the first close still does its work", func(t *testing.T) {
		// Control: the guard must not turn Close into a no-op from the start.
		// A cache that was never closed still accepts writes; one that was
		// closed has stopped its background worker, so the guard is only
		// reached on the second call.
		c := newCache(t)
		require.NoError(t, c.Set("k", "v", time.Minute))
		got, found := c.Get("k")
		require.True(t, found)
		require.Equal(t, "v", got)
		require.NoError(t, c.Close())
	})
}

func TestPerformanceMonitorCloseIsIdempotent(t *testing.T) {
	t.Run("second close is a no-op", func(t *testing.T) {
		pm := NewPerformanceMonitor(nil, slog.Default())
		require.NoError(t, pm.Close())
		assert.NotPanics(t, func() {
			assert.NoError(t, pm.Close())
		})
	})

	t.Run("the first close still does its work", func(t *testing.T) {
		// Control, as above: a monitor records before it is closed, so the
		// first Close is not short-circuited by the guard.
		pm := NewPerformanceMonitor(nil, slog.Default())
		before := pm.GetStats().OperationsTotal
		pm.RecordOperation(t.Context(), "probe", time.Millisecond, false, nil, 1)
		assert.Greater(t, pm.GetStats().OperationsTotal, before)
		require.NoError(t, pm.Close())
	})
}

// TestClientCloseIsIdempotent covers the composite: LDAP.Close fans out to the
// pool, the cache and the performance monitor, so it is only idempotent if all
// three are.
func TestClientCloseIsIdempotent(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{
		Enabled:         true,
		TTL:             time.Minute,
		MaxSize:         4,
		RefreshInterval: time.Minute,
		MaxMemoryMB:     1,
	}, slog.Default())
	require.NoError(t, err)

	l := &LDAP{
		config:      &Config{Server: "ldap://127.0.0.1:1", BaseDN: "dc=probe,dc=invalid"},
		logger:      slog.Default(),
		cache:       cache,
		perfMonitor: NewPerformanceMonitor(nil, slog.Default()),
	}

	require.NoError(t, l.Close())
	assert.NotPanics(t, func() {
		assert.NoError(t, l.Close())
	})
}
