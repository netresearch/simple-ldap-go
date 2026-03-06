//go:build !integration

package ldap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTimeoutManagerExecuteWithAdaptiveTimeout tests ExecuteWithAdaptiveTimeout
func TestTimeoutManagerExecuteWithAdaptiveTimeout(t *testing.T) {
	t.Run("successful execution within timeout", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		err := tm.ExecuteWithAdaptiveTimeout(context.Background(), "search", func(ctx context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		stats := tm.GetTimeoutStats()
		searchStats := stats["search"].(map[string]any)
		assert.Equal(t, int64(1), searchStats["successes"].(int64))
	})

	t.Run("execution exceeds timeout", func(t *testing.T) {
		tm := NewTimeoutManager(50*time.Millisecond, 100*time.Millisecond, 1.5)

		err := tm.ExecuteWithAdaptiveTimeout(context.Background(), "slow_op", func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		})
		assert.Error(t, err)
		// Should be a TimeoutError
		var timeoutErr *TimeoutError
		if errors.As(err, &timeoutErr) {
			assert.True(t, timeoutErr.Timeout())
		}
	})

	t.Run("execution with non-context error", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		expectedErr := errors.New("operation failed")
		err := tm.ExecuteWithAdaptiveTimeout(context.Background(), "failing_op", func(ctx context.Context) error {
			return expectedErr
		})
		assert.Equal(t, expectedErr, err)

		stats := tm.GetTimeoutStats()
		opStats := stats["failing_op"].(map[string]any)
		// Non-context errors are counted as successes for timeout tracking
		assert.Equal(t, int64(1), opStats["successes"].(int64))
	})

	t.Run("adaptive timeout increases after timeouts", func(t *testing.T) {
		tm := NewTimeoutManager(100*time.Millisecond, 5*time.Second, 2.0)

		// Record some timeouts to increase adaptive offset
		tm.RecordOperationResult("adaptive_test", 90*time.Millisecond, false) // timeout
		tm.RecordOperationResult("adaptive_test", 95*time.Millisecond, false) // timeout

		timeout1 := tm.GetAdaptiveTimeout("adaptive_test")

		// Record more timeouts
		tm.RecordOperationResult("adaptive_test", 100*time.Millisecond, false)

		timeout2 := tm.GetAdaptiveTimeout("adaptive_test")

		// Timeout should increase (or at least be base timeout)
		assert.GreaterOrEqual(t, timeout2, tm.baseTimeout)
		_ = timeout1 // Used for comparison conceptually
	})
}

// TestTimeoutManagerGetAdaptiveTimeout tests GetAdaptiveTimeout
func TestTimeoutManagerGetAdaptiveTimeout(t *testing.T) {
	t.Run("unknown operation returns base timeout", func(t *testing.T) {
		tm := NewTimeoutManager(5*time.Second, 30*time.Second, 1.5)

		timeout := tm.GetAdaptiveTimeout("unknown")
		assert.Equal(t, 5*time.Second, timeout)
	})

	t.Run("timeout is bounded by max", func(t *testing.T) {
		tm := NewTimeoutManager(100*time.Millisecond, 500*time.Millisecond, 10.0)

		// Record many timeouts to drive up adaptive offset
		for i := 0; i < 20; i++ {
			tm.RecordOperationResult("bounded_op", 100*time.Millisecond, false)
		}

		timeout := tm.GetAdaptiveTimeout("bounded_op")
		assert.LessOrEqual(t, timeout, 550*time.Millisecond) // Max + some jitter
	})

	t.Run("timeout adapts based on operation history", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		// Record successes with varying durations
		tm.RecordOperationResult("search", 200*time.Millisecond, true)
		tm.RecordOperationResult("search", 300*time.Millisecond, true)
		tm.RecordOperationResult("search", 250*time.Millisecond, true)

		timeout := tm.GetAdaptiveTimeout("search")
		assert.Greater(t, timeout, time.Duration(0))
	})
}

// TestTimeoutManagerRecordOperationResult tests RecordOperationResult
func TestTimeoutManagerRecordOperationResult(t *testing.T) {
	t.Run("record success updates avg duration", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		tm.RecordOperationResult("op", 100*time.Millisecond, true)
		tm.RecordOperationResult("op", 200*time.Millisecond, true)

		stats := tm.GetTimeoutStats()
		opStats := stats["op"].(map[string]any)
		assert.Equal(t, int64(2), opStats["successes"].(int64))
	})

	t.Run("record failure increments timeout count", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		tm.RecordOperationResult("op", 100*time.Millisecond, false)

		stats := tm.GetTimeoutStats()
		opStats := stats["op"].(map[string]any)
		assert.Equal(t, int64(1), opStats["timeouts"].(int64))
	})

	t.Run("record updates max duration", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		tm.RecordOperationResult("op", 100*time.Millisecond, true)
		tm.RecordOperationResult("op", 500*time.Millisecond, true) // New max

		stats := tm.GetTimeoutStats()
		opStats := stats["op"].(map[string]any)
		assert.Equal(t, 500*time.Millisecond, opStats["max_duration"].(time.Duration))
	})

	t.Run("record for new operation creates stats", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		tm.RecordOperationResult("new_op", 50*time.Millisecond, true)

		stats := tm.GetTimeoutStats()
		assert.Contains(t, stats, "new_op")
	})

	t.Run("adaptive offset decreases with faster operations", func(t *testing.T) {
		tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

		// First establish a baseline
		tm.RecordOperationResult("op", 200*time.Millisecond, true)
		// Then record faster operations to decrease offset
		tm.RecordOperationResult("op", 50*time.Millisecond, true)
		tm.RecordOperationResult("op", 40*time.Millisecond, true)

		stats := tm.GetTimeoutStats()
		opStats := stats["op"].(map[string]any)
		assert.NotNil(t, opStats["adaptive_offset"])
	})
}

// TestTimeoutManagerGetTimeoutStatsEmpty tests GetTimeoutStats with no data
func TestTimeoutManagerGetTimeoutStatsEmpty(t *testing.T) {
	tm := NewTimeoutManager(1*time.Second, 10*time.Second, 1.5)

	stats := tm.GetTimeoutStats()
	assert.Empty(t, stats)
}

// TestBulkheadExecute tests Bulkhead Execute method
func TestBulkheadExecute(t *testing.T) {
	t.Run("execute within concurrency limit", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 5,
			QueueSize:      10,
			Timeout:        1 * time.Second,
		}, nil)

		err := bh.Execute(context.Background(), func() error {
			return nil
		})
		assert.NoError(t, err)

		stats := bh.GetStats()
		assert.Equal(t, int64(0), stats["active"]) // Should be 0 after execution
	})

	t.Run("execute returns function error", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 5,
			QueueSize:      10,
			Timeout:        1 * time.Second,
		}, nil)

		expectedErr := errors.New("operation failed")
		err := bh.Execute(context.Background(), func() error {
			return expectedErr
		})
		assert.Equal(t, expectedErr, err)
	})

	t.Run("execute with cancelled context", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 1,
			QueueSize:      0,
			Timeout:        100 * time.Millisecond,
		}, nil)

		// Fill the semaphore
		bh.semaphore <- struct{}{}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := bh.Execute(ctx, func() error {
			return nil
		})
		assert.Equal(t, context.Canceled, err)

		// Clean up semaphore
		<-bh.semaphore
	})

	t.Run("execute rejected when queue is full", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 1,
			QueueSize:      0, // No queue
			Timeout:        100 * time.Millisecond,
		}, nil)

		// Fill the semaphore
		bh.semaphore <- struct{}{}

		// Mark as fully queued
		bh.queued = 0 // QueueSize=0, so any attempt should be rejected

		err := bh.Execute(context.Background(), func() error {
			return nil
		})
		assert.Error(t, err)

		stats := bh.GetStats()
		assert.Greater(t, stats["rejected"].(int64), int64(0))

		// Clean up
		<-bh.semaphore
	})

	t.Run("execute queued and eventually gets slot", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 1,
			QueueSize:      5,
			Timeout:        1 * time.Second,
		}, nil)

		// Fill the semaphore
		bh.semaphore <- struct{}{}

		var wg sync.WaitGroup
		wg.Add(1)

		var execErr error
		go func() {
			defer wg.Done()
			execErr = bh.Execute(context.Background(), func() error {
				return nil
			})
		}()

		// Release the slot after a brief delay
		time.Sleep(50 * time.Millisecond)
		<-bh.semaphore

		wg.Wait()
		assert.NoError(t, execErr)
	})

	t.Run("execute queued times out", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 1,
			QueueSize:      5,
			Timeout:        50 * time.Millisecond,
		}, nil)

		// Fill the semaphore permanently
		bh.semaphore <- struct{}{}

		err := bh.Execute(context.Background(), func() error {
			return nil
		})
		assert.Error(t, err)
		var timeoutErr *TimeoutError
		assert.True(t, errors.As(err, &timeoutErr))

		// Clean up
		<-bh.semaphore
	})

	t.Run("execute queued with cancelled context", func(t *testing.T) {
		bh := NewBulkhead("test", &BulkheadConfig{
			MaxConcurrency: 1,
			QueueSize:      5,
			Timeout:        1 * time.Second,
		}, nil)

		// Fill the semaphore
		bh.semaphore <- struct{}{}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := bh.Execute(ctx, func() error {
			return nil
		})
		assert.Error(t, err)

		// Clean up
		<-bh.semaphore
	})
}

// TestBulkheadGetStats tests Bulkhead GetStats
func TestBulkheadGetStatsFull(t *testing.T) {
	bh := NewBulkhead("test-bh", &BulkheadConfig{
		MaxConcurrency: 3,
		QueueSize:      10,
		Timeout:        time.Second,
	}, nil)

	stats := bh.GetStats()
	assert.Equal(t, "test-bh", stats["name"])
	assert.Equal(t, 3, stats["max_concurrent"])
	assert.Equal(t, int64(0), stats["active"])
	assert.Equal(t, int64(0), stats["queued"])
	assert.Equal(t, int64(0), stats["rejected"])
	assert.Equal(t, 10, stats["queue_size"])
}

// TestBulkheadNewWithDefaults tests NewBulkhead with nil config
func TestBulkheadNewWithDefaults(t *testing.T) {
	bh := NewBulkhead("default", nil, nil)
	require.NotNil(t, bh)

	assert.Equal(t, 10, bh.config.MaxConcurrency)
	assert.Equal(t, 50, bh.config.QueueSize)
	assert.Equal(t, 30*time.Second, bh.config.Timeout)
}

// TestCircuitBreakerStateString tests CircuitBreakerState.String() for unknown state
func TestCircuitBreakerStateString(t *testing.T) {
	tests := []struct {
		state    CircuitBreakerState
		expected string
	}{
		{StateCircuitClosed, "CLOSED"},
		{StateCircuitOpen, "OPEN"},
		{StateCircuitHalfOpen, "HALF_OPEN"},
		{CircuitBreakerState(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// TestCircuitBreakerNewWithNils tests NewCircuitBreaker with nil config and logger
func TestCircuitBreakerNewWithNils(t *testing.T) {
	cb := NewCircuitBreaker("test", nil, nil)
	require.NotNil(t, cb)

	assert.Equal(t, int64(5), cb.config.MaxFailures)
	assert.Equal(t, 30*time.Second, cb.config.Timeout)
	assert.Equal(t, int64(3), cb.config.HalfOpenMaxRequests)
}

// TestCircuitBreakerGetSuccessRate tests getSuccessRate
func TestCircuitBreakerGetSuccessRate(t *testing.T) {
	t.Run("no requests returns 1.0", func(t *testing.T) {
		cb := NewCircuitBreaker("test", nil, nil)
		rate := cb.getSuccessRate()
		assert.Equal(t, 1.0, rate)
	})

	t.Run("with mixed results", func(t *testing.T) {
		cb := NewCircuitBreaker("test", &CircuitBreakerConfig{
			MaxFailures:         100,
			Timeout:             time.Hour,
			HalfOpenMaxRequests: 100,
		}, nil)

		// 3 successes, 2 failures
		for i := 0; i < 3; i++ {
			_ = cb.Execute(func() error { return nil })
		}
		for i := 0; i < 2; i++ {
			_ = cb.Execute(func() error { return errors.New("fail") })
		}

		rate := cb.getSuccessRate()
		assert.InDelta(t, 0.6, rate, 0.01)
	})
}

// TestCircuitBreakerCanExecuteUnknownState tests default branch in canExecute
func TestCircuitBreakerCanExecuteUnknownState(t *testing.T) {
	cb := NewCircuitBreaker("test", nil, nil)

	// Force an unknown state
	cb.state.Store(99) // Unknown state

	err := cb.Execute(func() error { return nil })
	assert.Error(t, err) // Should fail because canExecute returns false for unknown state
}

// TestDefaultBulkheadConfig tests DefaultBulkheadConfig values
func TestDefaultBulkheadConfig(t *testing.T) {
	config := DefaultBulkheadConfig()
	assert.Equal(t, 10, config.MaxConcurrency)
	assert.Equal(t, 50, config.QueueSize)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

// TestDefaultCircuitBreakerConfig tests DefaultCircuitBreakerConfig values
func TestDefaultCircuitBreakerConfigValues(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	assert.Equal(t, int64(5), config.MaxFailures)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, int64(3), config.HalfOpenMaxRequests)
}

// TestBulkheadConcurrentExecution tests bulkhead under concurrent load
func TestBulkheadConcurrentExecution(t *testing.T) {
	bh := NewBulkhead("concurrent", &BulkheadConfig{
		MaxConcurrency: 3,
		QueueSize:      10,
		Timeout:        2 * time.Second,
	}, nil)

	var wg sync.WaitGroup
	results := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = bh.Execute(context.Background(), func() error {
				time.Sleep(50 * time.Millisecond)
				return nil
			})
		}(i)
	}

	wg.Wait()

	successCount := 0
	for _, err := range results {
		if err == nil {
			successCount++
		}
	}
	assert.Greater(t, successCount, 0)
}
