package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// New must not write into the configuration structs the caller handed it.
// Config.Cache is covered beside this; Performance and Pool are the same class:
// New sets Enabled on the caller's PerformanceConfig, and NewConnectionPool
// writes its defaults into whatever PoolConfig it is given.

func TestPerformanceConfigForDoesNotMutateTheCallersConfig(t *testing.T) {
	supplied := &PerformanceConfig{Enabled: false, SlowQueryThreshold: 250 * time.Millisecond}

	resolved := performanceConfigFor(Config{Performance: supplied})

	require.NotNil(t, resolved)
	assert.True(t, resolved.Enabled, "monitoring was requested, so the copy must be enabled")
	assert.Equal(t, 250*time.Millisecond, resolved.SlowQueryThreshold)
	assert.False(t, supplied.Enabled, "Enabled was flipped in the caller's struct")
}

func TestPerformanceConfigForFallsBackToDefaults(t *testing.T) {
	defaults := DefaultPerformanceConfig()

	resolved := performanceConfigFor(Config{})

	require.NotNil(t, resolved)
	assert.True(t, resolved.Enabled)
	assert.Equal(t, defaults.SlowQueryThreshold, resolved.SlowQueryThreshold)
}

func TestPoolConfigForDoesNotMutateTheCallersConfig(t *testing.T) {
	// NewConnectionPool writes its defaults into the config it is handed, so a
	// caller who set only MaxConnections gets the rest written back at them.
	supplied := &PoolConfig{MaxConnections: 7}

	resolved := poolConfigFor(supplied)

	require.NotNil(t, resolved)
	assert.Equal(t, 7, resolved.MaxConnections)

	resolved.MaxIdleTime = 42 * time.Second
	assert.Equal(t, time.Duration(0), supplied.MaxIdleTime,
		"the resolved config shares storage with the caller's struct")
}

func TestPoolConfigForPassesNilThrough(t *testing.T) {
	// A nil PoolConfig means "no pool"; the caller decides, not this helper.
	assert.Nil(t, poolConfigFor(nil))
}
