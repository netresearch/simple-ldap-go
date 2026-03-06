//go:build !integration

package ldap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPerformanceMonitorStartOperation tests StartOperation convenience method
func TestPerformanceMonitorStartOperation(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SlowQueryThreshold = 10 * time.Millisecond
	config.SampleRate = 1.0 // Sample everything

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	done := pm.StartOperation(ctx, "search")

	// Simulate some work
	time.Sleep(5 * time.Millisecond)

	done(false, nil, 10)

	stats := pm.GetStats()
	assert.Equal(t, int64(1), stats.OperationsTotal)
	assert.Equal(t, int64(1), stats.OperationsByType["search"])
}

// TestPerformanceMonitorStartOperationWithError tests StartOperation with error
func TestPerformanceMonitorStartOperationWithError(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	done := pm.StartOperation(ctx, "bind")

	done(false, errors.New("auth failed"), 0)

	stats := pm.GetStats()
	assert.Equal(t, int64(1), stats.ErrorCount)
	assert.Equal(t, int64(1), stats.ErrorsByType["bind"])
}

// TestPerformanceMonitorSetConnectionPool tests SetConnectionPool
func TestPerformanceMonitorSetConnectionPool(t *testing.T) {
	pm := NewPerformanceMonitor(DefaultPerformanceConfig(), nil)
	defer func() { _ = pm.Close() }()

	// SetConnectionPool with nil should not panic
	pm.SetConnectionPool(nil)
	assert.Nil(t, pm.pool)
}

// TestPerformanceMonitorGetOperationHistory tests GetOperationHistory
func TestPerformanceMonitorGetOperationHistory(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "search", 5*time.Millisecond, false, nil, 3)
	pm.RecordOperation(ctx, "bind", 2*time.Millisecond, false, nil, 0)

	history := pm.GetOperationHistory()
	assert.Len(t, history, 2)
	assert.Equal(t, "search", history[0].Operation)
	assert.Equal(t, "bind", history[1].Operation)
}

// TestPerformanceMonitorReset tests Reset method
func TestPerformanceMonitorReset(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "search", 5*time.Millisecond, true, nil, 1)
	pm.RecordOperation(ctx, "search", 15*time.Millisecond, false, errors.New("err"), 0)

	// Verify stats exist before reset
	stats := pm.GetStats()
	assert.Equal(t, int64(2), stats.OperationsTotal)

	// Reset
	pm.Reset()

	stats = pm.GetStats()
	assert.Equal(t, int64(0), stats.OperationsTotal)
	assert.Equal(t, int64(0), stats.ErrorCount)
	assert.Equal(t, int64(0), stats.CacheHits)
	assert.Empty(t, stats.OperationsByType)

	history := pm.GetOperationHistory()
	assert.Empty(t, history)
}

// TestPerformanceMonitorCalculatePercentiles tests percentile calculation
func TestPerformanceMonitorCalculatePercentiles(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SlowQueryThreshold = 100 * time.Millisecond
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()

	// Record enough operations to trigger percentile calculation (>= 10)
	for i := 0; i < 20; i++ {
		duration := time.Duration(i+1) * time.Millisecond
		pm.RecordOperation(ctx, "search", duration, false, nil, 1)
	}

	stats := pm.GetStats()
	assert.Greater(t, stats.P50ResponseTime, time.Duration(0))
	assert.Greater(t, stats.P95ResponseTime, time.Duration(0))
	assert.Greater(t, stats.P99ResponseTime, time.Duration(0))
	assert.LessOrEqual(t, stats.P50ResponseTime, stats.P95ResponseTime)
	assert.LessOrEqual(t, stats.P95ResponseTime, stats.P99ResponseTime)
}

// TestPerformanceMonitorShouldSample tests sampling logic
func TestPerformanceMonitorShouldSample(t *testing.T) {
	t.Run("sample rate 0 never samples", func(t *testing.T) {
		config := DefaultPerformanceConfig()
		config.SampleRate = 0

		pm := NewPerformanceMonitor(config, nil)
		defer func() { _ = pm.Close() }()

		ctx := context.Background()
		pm.RecordOperation(ctx, "op", time.Millisecond, false, nil, 1)

		history := pm.GetOperationHistory()
		assert.Empty(t, history)
	})

	t.Run("sample rate 1 always samples", func(t *testing.T) {
		config := DefaultPerformanceConfig()
		config.SampleRate = 1.0

		pm := NewPerformanceMonitor(config, nil)
		defer func() { _ = pm.Close() }()

		ctx := context.Background()
		for i := 0; i < 5; i++ {
			pm.RecordOperation(ctx, "op", time.Millisecond, false, nil, 1)
		}

		history := pm.GetOperationHistory()
		assert.Len(t, history, 5)
	})

	t.Run("fractional sample rate samples subset", func(t *testing.T) {
		config := DefaultPerformanceConfig()
		config.SampleRate = 0.5 // Sample 50%

		pm := NewPerformanceMonitor(config, nil)
		defer func() { _ = pm.Close() }()

		ctx := context.Background()
		for i := 0; i < 10; i++ {
			pm.RecordOperation(ctx, "op", time.Millisecond, false, nil, 1)
		}

		history := pm.GetOperationHistory()
		// Should sample approximately 50%
		assert.Greater(t, len(history), 0)
		assert.Less(t, len(history), 10)
	})
}

// TestPerformanceMonitorUpdateMemoryStats tests updateMemoryStats
func TestPerformanceMonitorUpdateMemoryStats(t *testing.T) {
	pm := NewPerformanceMonitor(DefaultPerformanceConfig(), nil)
	defer func() { _ = pm.Close() }()

	pm.updateMemoryStats()

	stats := pm.GetStats()
	assert.Greater(t, stats.MemoryUsageMB, float64(0))
	assert.Greater(t, stats.GoroutineCount, 0)
}

// TestPerformanceMonitorCleanupOldMetrics tests cleanupOldMetrics
func TestPerformanceMonitorCleanupOldMetrics(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.MetricsRetention = 1 * time.Millisecond // Very short retention
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "old_op", time.Millisecond, false, nil, 1)

	// Wait for operations to become "old"
	time.Sleep(5 * time.Millisecond)

	pm.cleanupOldMetrics()

	history := pm.GetOperationHistory()
	assert.Empty(t, history)
}

// TestPerformanceMonitorFlush tests Flush method
func TestPerformanceMonitorFlush(t *testing.T) {
	t.Run("flush with pending operations", func(t *testing.T) {
		config := DefaultPerformanceConfig()
		config.SampleRate = 1.0

		pm := NewPerformanceMonitor(config, nil)
		defer func() { _ = pm.Close() }()

		ctx := context.Background()
		pm.RecordOperation(ctx, "op1", time.Millisecond, false, nil, 1)
		pm.RecordOperation(ctx, "op2", time.Millisecond, false, nil, 1)

		pm.Flush()

		history := pm.GetOperationHistory()
		assert.Empty(t, history) // Buffer should be cleared
	})

	t.Run("flush when disabled is no-op", func(t *testing.T) {
		config := DefaultPerformanceConfig()
		config.Enabled = false

		pm := NewPerformanceMonitor(config, nil)
		pm.Flush() // Should not panic
	})

	t.Run("flush on nil monitor does not panic", func(t *testing.T) {
		var pm *PerformanceMonitor
		pm.Flush() // Should not panic
	})
}

// TestPerformanceMonitorRecordOperationWithContext tests context value extraction
func TestPerformanceMonitorRecordOperationWithContext(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	t.Run("with client IP in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyClientIP, "10.0.0.1")
		pm.RecordOperation(ctx, "search", time.Millisecond, false, nil, 1)

		history := pm.GetOperationHistory()
		require.Len(t, history, 1)
		assert.Equal(t, "10.0.0.1", history[0].ClientIP)
	})

	t.Run("with user agent in context", func(t *testing.T) {
		pm.Reset()
		//nolint:staticcheck // SA1029: using string key intentionally for test
		ctx := context.WithValue(context.Background(), "user_agent", "TestAgent/1.0")
		pm.RecordOperation(ctx, "bind", time.Millisecond, false, nil, 0)

		history := pm.GetOperationHistory()
		require.Len(t, history, 1)
		assert.Equal(t, "TestAgent/1.0", history[0].UserAgent)
	})
}

// TestPerformanceMonitorDisabled tests monitor when disabled
func TestPerformanceMonitorDisabled(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.Enabled = false

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "search", time.Millisecond, false, nil, 1)

	stats := pm.GetStats()
	assert.Equal(t, int64(0), stats.OperationsTotal)
}

// TestPerformanceMonitorNewWithNils tests creating monitor with nil config/logger
func TestPerformanceMonitorNewWithNils(t *testing.T) {
	pm := NewPerformanceMonitor(nil, nil)
	require.NotNil(t, pm)
	defer func() { _ = pm.Close() }()

	assert.NotNil(t, pm.config)
	assert.NotNil(t, pm.logger)
}

// TestPerformanceMonitorSlowQuery tests slow query detection
func TestPerformanceMonitorSlowQuery(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SlowQueryThreshold = 5 * time.Millisecond

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "fast", 1*time.Millisecond, false, nil, 1)
	pm.RecordOperation(ctx, "slow", 10*time.Millisecond, false, nil, 1)

	stats := pm.GetStats()
	assert.Equal(t, int64(1), stats.SlowQueries)
}

// TestPerformanceMonitorBufferTrimming tests buffer overflow trimming
func TestPerformanceMonitorBufferTrimming(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.BufferSize = 5
	config.SampleRate = 1.0

	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		pm.RecordOperation(ctx, "op", time.Millisecond, false, nil, 1)
	}

	history := pm.GetOperationHistory()
	assert.LessOrEqual(t, len(history), 5)
}

// TestPerformanceMonitorTimingStats tests min/max/avg timing stats
func TestPerformanceMonitorTimingStats(t *testing.T) {
	config := DefaultPerformanceConfig()
	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "op", 10*time.Millisecond, false, nil, 1)
	pm.RecordOperation(ctx, "op", 20*time.Millisecond, false, nil, 1)
	pm.RecordOperation(ctx, "op", 5*time.Millisecond, false, nil, 1)

	stats := pm.GetStats()
	assert.Equal(t, 5*time.Millisecond, stats.MinResponseTime)
	assert.Equal(t, 20*time.Millisecond, stats.MaxResponseTime)
	assert.Greater(t, stats.AvgResponseTime, time.Duration(0))
}

// TestPerformanceMonitorCacheHitRatio tests cache hit ratio calculation
func TestPerformanceMonitorCacheHitRatio(t *testing.T) {
	config := DefaultPerformanceConfig()
	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "op", time.Millisecond, true, nil, 1)  // cache hit
	pm.RecordOperation(ctx, "op", time.Millisecond, false, nil, 1) // cache miss

	stats := pm.GetStats()
	assert.InDelta(t, 50.0, stats.CacheHitRatio, 0.1)
}

// TestDefaultSearchOptions tests DefaultSearchOptions
func TestDefaultSearchOptions(t *testing.T) {
	opts := DefaultSearchOptions()
	assert.True(t, opts.UseCache)
	assert.True(t, opts.RefreshStale)
	assert.False(t, opts.BackgroundLoad)
	assert.True(t, opts.UseNegativeCache)
	assert.Equal(t, 1000, opts.MaxResults)
	assert.Equal(t, 30*time.Second, opts.Timeout)
}

// TestPerformanceMonitorClose tests Close with background tasks
func TestPerformanceMonitorClose(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.MemoryStatsInterval = 50 * time.Millisecond
	config.FlushInterval = 50 * time.Millisecond

	pm := NewPerformanceMonitor(config, nil)

	// Let background tasks run briefly
	time.Sleep(100 * time.Millisecond)

	err := pm.Close()
	assert.NoError(t, err)
}

// TestPerformanceMonitorGetStatsResponseTimes tests that response times are included
func TestPerformanceMonitorGetStatsResponseTimes(t *testing.T) {
	config := DefaultPerformanceConfig()
	pm := NewPerformanceMonitor(config, nil)
	defer func() { _ = pm.Close() }()

	ctx := context.Background()
	pm.RecordOperation(ctx, "op", 5*time.Millisecond, false, nil, 1)

	stats := pm.GetStats()
	assert.Len(t, stats.ResponseTimes, 1)
	assert.Equal(t, 5*time.Millisecond, stats.ResponseTimes[0])
}
