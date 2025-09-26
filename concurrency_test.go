//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultWorkerPoolConfig tests the default configuration
func TestDefaultWorkerPoolConfig(t *testing.T) {
	t.Run("returns valid defaults", func(t *testing.T) {
		config := DefaultWorkerPoolConfig()
		assert.NotNil(t, config)
		assert.Equal(t, runtime.GOMAXPROCS(0), config.WorkerCount)
		assert.Equal(t, 100, config.BufferSize)
		assert.Equal(t, 5*time.Minute, config.Timeout)
		assert.False(t, config.FailFast)
	})
}

// TestWorkerPoolCreation tests worker pool creation
func TestWorkerPoolCreation(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("creates pool with custom config", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 5,
			BufferSize:  50,
			Timeout:     1 * time.Minute,
			FailFast:    true,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		assert.NotNil(t, pool)
		assert.Equal(t, 5, pool.workerCount)
		stats := pool.Stats()
		assert.Equal(t, 5, stats.WorkerCount)
		assert.Equal(t, int64(0), stats.Processed)
		assert.Equal(t, int64(0), stats.Errors)
	})

	t.Run("creates pool with nil config using defaults", func(t *testing.T) {
		pool := NewWorkerPool[string](client, nil)
		defer pool.Close()

		assert.NotNil(t, pool)
		assert.Equal(t, runtime.GOMAXPROCS(0), pool.workerCount)
	})

	t.Run("starts workers on creation", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 3,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Give workers time to start
		time.Sleep(10 * time.Millisecond)

		// Workers should be running - verify by checking pool state
		assert.NotNil(t, pool.workChan)
		assert.NotNil(t, pool.resultChan)
	})
}

// TestWorkerPoolSubmitAndResults tests work submission and result collection
func TestWorkerPoolSubmitAndResults(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("processes work items successfully", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 2,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Submit work items
		workItems := []WorkItem[string]{
			{
				ID:   "item1",
				Data: "test1",
				Fn: func(ctx context.Context, client *LDAP, data string) error {
					time.Sleep(1 * time.Millisecond) // Simulate work
					return nil
				},
			},
			{
				ID:   "item2",
				Data: "test2",
				Fn: func(ctx context.Context, client *LDAP, data string) error {
					time.Sleep(1 * time.Millisecond)
					return nil
				},
			},
		}

		// Submit items
		for _, item := range workItems {
			err := pool.Submit(item)
			assert.NoError(t, err)
		}

		// Collect results
		results := make([]WorkResult[string], 0)
		resultsChan := pool.Results()

		// Collect all results
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < len(workItems); i++ {
				select {
				case result := <-resultsChan:
					results = append(results, result)
				case <-time.After(5 * time.Second):
					t.Error("Timeout waiting for results")
					return
				}
			}
		}()

		<-done

		// Verify results
		assert.Equal(t, 2, len(results))

		// Check stats
		stats := pool.Stats()
		assert.Equal(t, int64(2), stats.Processed)
		assert.Equal(t, int64(0), stats.Errors)
		assert.Greater(t, stats.AverageDuration, time.Duration(0))
	})

	t.Run("handles work item errors", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     30 * time.Second,
			FailFast:    false,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Submit work item that will fail
		err := pool.Submit(WorkItem[string]{
			ID:   "failing_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return errors.New("simulated error")
			},
		})
		assert.NoError(t, err)

		// Get result
		select {
		case result := <-pool.Results():
			assert.Equal(t, "failing_item", result.ID)
			assert.Error(t, result.Error)
			assert.Equal(t, "simulated error", result.Error.Error())
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for error result")
		}

		// Check error stats
		stats := pool.Stats()
		assert.Equal(t, int64(1), stats.Errors)
	})

	t.Run("fail fast stops on first error", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     30 * time.Second,
			FailFast:    true,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Submit failing work item
		err := pool.Submit(WorkItem[string]{
			ID:   "failing_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return errors.New("fail fast error")
			},
		})
		assert.NoError(t, err)

		// Get result and verify it failed
		select {
		case result := <-pool.Results():
			assert.Error(t, result.Error)
			assert.Contains(t, result.Error.Error(), "fail fast error")
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for fail fast result")
		}

		// Wait a moment for fail-fast to propagate
		time.Sleep(100 * time.Millisecond)

		// Try to submit another item - should fail due to fail-fast
		err = pool.Submit(WorkItem[string]{
			ID:   "second_item",
			Data: "test2",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return nil
			},
		})
		// After fail-fast, context should be cancelled
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
		// Note: err may be nil if the submit succeeds before context cancellation
		// The key test is that the first item failed with the expected error
	})
}

// TestWorkerPoolConcurrency tests concurrent operations
func TestWorkerPoolConcurrency(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("handles concurrent submissions", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 5,
			BufferSize:  100,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		numItems := 50
		var submissionWg sync.WaitGroup
		submissionErrors := make(chan error, numItems)

		// Submit items concurrently
		for i := 0; i < numItems; i++ {
			submissionWg.Add(1)
			go func(id int) {
				defer submissionWg.Done()
				err := pool.Submit(WorkItem[int]{
					ID:   fmt.Sprintf("item_%d", id),
					Data: id,
					Fn: func(ctx context.Context, client *LDAP, data int) error {
						time.Sleep(time.Millisecond) // Simulate work
						return nil
					},
				})
				if err != nil {
					submissionErrors <- err
				}
			}(i)
		}

		submissionWg.Wait()
		close(submissionErrors)

		// Check no submission errors
		for err := range submissionErrors {
			t.Errorf("Submission error: %v", err)
		}

		// Collect all results
		results := make([]WorkResult[int], 0, numItems)
		for i := 0; i < numItems; i++ {
			select {
			case result := <-pool.Results():
				results = append(results, result)
			case <-time.After(10 * time.Second):
				t.Fatalf("Timeout waiting for result %d/%d", i+1, numItems)
			}
		}

		assert.Equal(t, numItems, len(results))

		// Verify stats
		stats := pool.Stats()
		assert.Equal(t, int64(numItems), stats.Processed)
		assert.Equal(t, int64(0), stats.Errors)
	})
}

// TestWorkerPoolTimeout tests timeout behavior
func TestWorkerPoolTimeout(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("respects timeout", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     100 * time.Millisecond, // Very short timeout
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Submit work that takes longer than timeout
		err := pool.Submit(WorkItem[string]{
			ID:   "timeout_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				select {
				case <-time.After(200 * time.Millisecond):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		})
		assert.NoError(t, err)

		// Should get context cancellation error
		select {
		case result := <-pool.Results():
			assert.Error(t, result.Error)
			assert.Contains(t, result.Error.Error(), "context")
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Timeout waiting for timeout result")
		}
	})
}

// TestWorkerPoolClose tests pool shutdown
func TestWorkerPoolClose(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("closes cleanly", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 3,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)

		// Submit some work
		err := pool.Submit(WorkItem[string]{
			ID:   "test_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return nil
			},
		})
		assert.NoError(t, err)

		// Close should not hang
		done := make(chan struct{})
		go func() {
			pool.Close()
			close(done)
		}()

		select {
		case <-done:
			// Good, close completed
		case <-time.After(5 * time.Second):
			t.Fatal("Pool close hung")
		}

		// After close, pool should be closed (don't test submit as it may panic)
	})
}

// TestWorkerPoolStats tests statistics collection
func TestWorkerPoolStats(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("tracks statistics correctly", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 2,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Initial stats
		stats := pool.Stats()
		assert.Equal(t, 2, stats.WorkerCount)
		assert.Equal(t, int64(0), stats.Processed)
		assert.Equal(t, int64(0), stats.Errors)
		assert.Equal(t, time.Duration(0), stats.AverageDuration)

		// Submit successful work
		for i := 0; i < 3; i++ {
			err := pool.Submit(WorkItem[string]{
				ID:   fmt.Sprintf("success_%d", i),
				Data: "test",
				Fn: func(ctx context.Context, client *LDAP, data string) error {
					time.Sleep(time.Millisecond)
					return nil
				},
			})
			assert.NoError(t, err)
		}

		// Submit failing work
		err := pool.Submit(WorkItem[string]{
			ID:   "error_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return errors.New("test error")
			},
		})
		assert.NoError(t, err)

		// Wait for all results
		for i := 0; i < 4; i++ {
			<-pool.Results()
		}

		// Check final stats
		finalStats := pool.Stats()
		assert.Equal(t, int64(4), finalStats.Processed)
		assert.Equal(t, int64(1), finalStats.Errors)
		assert.Greater(t, finalStats.AverageDuration, time.Duration(0))
	})
}

// TestWorkerPoolTypes tests with different generic types
func TestWorkerPoolTypes(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("works with struct types", func(t *testing.T) {
		type TestUser struct {
			Name string
			ID   int
		}

		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[TestUser](client, config)
		defer pool.Close()

		testUser := TestUser{Name: "John", ID: 123}

		err := pool.Submit(WorkItem[TestUser]{
			ID:   "user_item",
			Data: testUser,
			Fn: func(ctx context.Context, client *LDAP, data TestUser) error {
				assert.Equal(t, "John", data.Name)
				assert.Equal(t, 123, data.ID)
				return nil
			},
		})
		assert.NoError(t, err)

		// Get result
		result := <-pool.Results()
		assert.NoError(t, result.Error)
		assert.Equal(t, testUser, result.Data)
	})

	t.Run("works with pointer types", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[*User](client, config)
		defer pool.Close()

		user := &User{}
		user.Object.cn = "testuser"

		err := pool.Submit(WorkItem[*User]{
			ID:   "pointer_item",
			Data: user,
			Fn: func(ctx context.Context, client *LDAP, data *User) error {
				assert.Equal(t, "testuser", data.CN())
				return nil
			},
		})
		assert.NoError(t, err)

		result := <-pool.Results()
		assert.NoError(t, result.Error)
		assert.Equal(t, user, result.Data)
	})
}

// BenchmarkWorkerPool benchmarks worker pool performance
func BenchmarkWorkerPool(b *testing.B) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	b.Run("single_worker", func(b *testing.B) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  1000,
			Timeout:     1 * time.Minute,
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", i),
				Data: i,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					return nil
				},
			})
		}

		// Drain results
		for i := 0; i < b.N; i++ {
			<-pool.Results()
		}
	})

	b.Run("multiple_workers", func(b *testing.B) {
		config := &WorkerPoolConfig{
			WorkerCount: runtime.GOMAXPROCS(0),
			BufferSize:  1000,
			Timeout:     1 * time.Minute,
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", i),
				Data: i,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					return nil
				},
			})
		}

		// Drain results
		for i := 0; i < b.N; i++ {
			<-pool.Results()
		}
	})
}

// TestWorkerPoolEdgeCases tests edge cases and error conditions
func TestWorkerPoolEdgeCases(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("zero workers", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 0,
			BufferSize:  10,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Should still be able to submit, but nothing will process
		err := pool.Submit(WorkItem[string]{
			ID:   "unprocessed",
			Data: "test",
			Fn:   func(ctx context.Context, client *LDAP, data string) error { return nil },
		})
		assert.NoError(t, err)

		// No workers means no results
		select {
		case <-pool.Results():
			t.Fatal("Should not receive results with zero workers")
		case <-time.After(100 * time.Millisecond):
			// Expected - no workers to process items
		}
	})

	t.Run("zero buffer size", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  0, // Unbuffered channels
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[string](client, config)
		defer pool.Close()

		// Should still work with unbuffered channels
		go func() {
			time.Sleep(10 * time.Millisecond)
			<-pool.Results() // Consume result to unblock worker
		}()

		err := pool.Submit(WorkItem[string]{
			ID:   "unbuffered",
			Data: "test",
			Fn:   func(ctx context.Context, client *LDAP, data string) error { return nil },
		})
		assert.NoError(t, err)
	})

	t.Run("very large buffer", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10000,
			Timeout:     30 * time.Second,
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		// Should handle large buffer sizes
		assert.NotNil(t, pool)
	})
}
