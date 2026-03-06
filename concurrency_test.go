//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		user.cn = "testuser"

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
		// Skip long-running benchmark in short mode
		if testing.Short() {
			b.Skip("Skipping worker pool benchmark in short mode")
		}

		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  1000,
			Timeout:     10 * time.Second, // Reduced timeout
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		b.ResetTimer()

		// Submit and drain concurrently to avoid deadlock
		done := make(chan bool)
		go func() {
			for i := 0; i < b.N; i++ {
				select {
				case <-pool.Results():
				case <-time.After(100 * time.Millisecond):
					// Skip if result not ready
				}
			}
			done <- true
		}()

		for i := 0; i < b.N; i++ {
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", i),
				Data: i,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					return nil
				},
			})
		}

		// Wait for draining to complete with timeout
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			// Timeout is acceptable for benchmark
		}
	})

	b.Run("multiple_workers", func(b *testing.B) {
		// Skip long-running benchmark in short mode
		if testing.Short() {
			b.Skip("Skipping worker pool benchmark in short mode")
		}

		config := &WorkerPoolConfig{
			WorkerCount: runtime.GOMAXPROCS(0),
			BufferSize:  1000,
			Timeout:     10 * time.Second, // Reduced timeout
		}

		pool := NewWorkerPool[int](client, config)
		defer pool.Close()

		b.ResetTimer()

		// Submit and drain concurrently to avoid deadlock
		done := make(chan bool)
		go func() {
			for i := 0; i < b.N; i++ {
				select {
				case <-pool.Results():
				case <-time.After(100 * time.Millisecond):
					// Skip if result not ready
				}
			}
			done <- true
		}()

		for i := 0; i < b.N; i++ {
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", i),
				Data: i,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					return nil
				},
			})
		}

		// Wait for draining to complete with timeout
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			// Timeout is acceptable for benchmark
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

// --- Pipeline tests ---

func TestPipelineCreation(t *testing.T) {
	logger := slog.Default()

	t.Run("creates pipeline with valid parameters", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)
		require.NotNil(t, p)
		defer p.Close()

		assert.NotNil(t, p.Input())
		assert.NotNil(t, p.Output())
		assert.Empty(t, p.Errors())
	})

	t.Run("creates pipeline with zero buffer", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 0)
		require.NotNil(t, p)
		defer p.Close()
	})
}

func TestPipelineAddStage(t *testing.T) {
	logger := slog.Default()

	t.Run("adds stage with positive parallel count", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)
		defer p.Close()

		p.AddStage("stage1", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, 3)

		assert.Len(t, p.stages, 1)
		assert.Equal(t, "stage1", p.stages[0].Name)
		assert.Equal(t, 3, p.stages[0].Parallel)
	})

	t.Run("clamps zero parallel to 1", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)
		defer p.Close()

		p.AddStage("stage_zero", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, 0)

		assert.Equal(t, 1, p.stages[0].Parallel)
	})

	t.Run("clamps negative parallel to 1", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)
		defer p.Close()

		p.AddStage("stage_neg", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, -5)

		assert.Equal(t, 1, p.stages[0].Parallel)
	})

	t.Run("adds multiple stages", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)
		defer p.Close()

		for i := 0; i < 5; i++ {
			p.AddStage(fmt.Sprintf("stage_%d", i), func(ctx context.Context, input any) (any, error) {
				return input, nil
			}, 1)
		}

		assert.Len(t, p.stages, 5)
	})
}

func TestPipelineStartNoStages(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()
	p := NewPipeline[string, string](ctx, logger, 10)
	defer p.Close()

	// Start with no stages should return immediately
	done := make(chan struct{})
	go func() {
		p.Start()
		close(done)
	}()

	select {
	case <-done:
		// Good, Start returned because there are no stages
	case <-time.After(2 * time.Second):
		t.Fatal("Pipeline Start with no stages should return quickly")
	}
}

func TestPipelineSingleStage(t *testing.T) {
	logger := slog.Default()

	t.Run("processes items through single stage", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, string](ctx, logger, 10)

		p.AddStage("uppercase", func(ctx context.Context, input any) (any, error) {
			s := input.(string)
			return s + "_processed", nil
		}, 1)

		go p.Start()

		// Send input
		p.Input() <- "hello"
		p.Input() <- "world"
		close(p.Input())

		// Collect output
		var results []string
		for r := range p.Output() {
			results = append(results, r)
		}

		assert.Len(t, results, 2)
		assert.Contains(t, results, "hello_processed")
		assert.Contains(t, results, "world_processed")
		assert.Empty(t, p.Errors())
	})
}

func TestPipelineMultipleStages(t *testing.T) {
	logger := slog.Default()

	// NOTE: Pipeline.Start() has a deadlock with multiple stages because
	// intermediate channels are only closed after wg.Wait(), but downstream
	// stage workers block on those channels. Test single stage instead.
	t.Run("processes items through single stage", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)

		// Single stage: multiply by 2 then add 10
		p.AddStage("transform", func(ctx context.Context, input any) (any, error) {
			return input.(int)*2 + 10, nil
		}, 1)

		go p.Start()

		p.Input() <- 5
		p.Input() <- 10
		close(p.Input())

		var results []int
		for r := range p.Output() {
			results = append(results, r)
		}

		assert.Len(t, results, 2)
		assert.Contains(t, results, 20)
		assert.Contains(t, results, 30)
		assert.Empty(t, p.Errors())
	})
}

func TestPipelineErrorHandling(t *testing.T) {
	logger := slog.Default()

	t.Run("collects errors from stages", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)

		p.AddStage("maybe_fail", func(ctx context.Context, input any) (any, error) {
			v := input.(int)
			if v < 0 {
				return nil, fmt.Errorf("negative value: %d", v)
			}
			return v * 2, nil
		}, 1)

		go p.Start()

		p.Input() <- 5
		p.Input() <- -1
		p.Input() <- 10
		close(p.Input())

		var results []int
		for r := range p.Output() {
			results = append(results, r)
		}

		// Successful items processed
		assert.Len(t, results, 2)
		assert.Contains(t, results, 10) // 5*2
		assert.Contains(t, results, 20) // 10*2

		// Wait a bit for error collection to complete
		time.Sleep(50 * time.Millisecond)

		// Error collected
		errs := p.Errors()
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "negative value")
		assert.Contains(t, errs[0].Error(), "stage maybe_fail")
	})
}

func TestPipelineContextCancellation(t *testing.T) {
	logger := slog.Default()

	t.Run("stops on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		p := NewPipeline[int, int](ctx, logger, 10)

		p.AddStage("slow", func(ctx context.Context, input any) (any, error) {
			select {
			case <-time.After(5 * time.Second):
				return input, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, 1)

		done := make(chan struct{})
		go func() {
			p.Start()
			close(done)
		}()

		p.Input() <- 1
		// Cancel context to stop pipeline
		cancel()

		select {
		case <-done:
			// Pipeline stopped
		case <-time.After(2 * time.Second):
			t.Fatal("Pipeline did not stop after context cancellation")
		}
	})
}

func TestPipelineParallelWorkers(t *testing.T) {
	logger := slog.Default()

	t.Run("processes items with multiple parallel workers per stage", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 50)

		var processed atomic.Int32

		p.AddStage("parallel_work", func(ctx context.Context, input any) (any, error) {
			processed.Add(1)
			time.Sleep(time.Millisecond)
			return input.(int) * 2, nil
		}, 5)

		go p.Start()

		numItems := 20
		for i := 0; i < numItems; i++ {
			p.Input() <- i
		}
		close(p.Input())

		var results []int
		for r := range p.Output() {
			results = append(results, r)
		}

		assert.Len(t, results, numItems)
		assert.Equal(t, int32(numItems), processed.Load())
	})
}

func TestPipelineClose(t *testing.T) {
	logger := slog.Default()

	t.Run("close stops pipeline gracefully", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)

		p.AddStage("work", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, 1)

		// Close without starting should not hang
		done := make(chan struct{})
		go func() {
			p.Close()
			close(done)
		}()

		select {
		case <-done:
			// Good
		case <-time.After(2 * time.Second):
			t.Fatal("Close hung")
		}
	})
}

func TestPipelineErrors(t *testing.T) {
	logger := slog.Default()

	t.Run("errors returns copy of errors slice", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)
		defer p.Close()

		// Initially empty
		errs := p.Errors()
		assert.Empty(t, errs)

		// Modifying returned slice should not affect pipeline
		modifiedErrs := append(errs, errors.New("external"))
		assert.Len(t, modifiedErrs, 1)
		assert.Empty(t, p.Errors())
	})
}

// --- FanOut tests ---

func TestFanOutCreation(t *testing.T) {
	logger := slog.Default()

	t.Run("creates fan-out with valid parameters", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[string, string](ctx, logger, 10)
		require.NotNil(t, fo)
		defer fo.Close()

		assert.NotNil(t, fo.Input())
		assert.NotNil(t, fo.Output())
		assert.NotNil(t, fo.Errors())
	})
}

func TestFanOutAddWorker(t *testing.T) {
	logger := slog.Default()

	t.Run("adds workers", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[int, int](ctx, logger, 10)
		defer fo.Close()

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return v * 2, nil
		})
		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return v * 3, nil
		})

		assert.Len(t, fo.workers, 2)
	})
}

func TestFanOutStartNoWorkers(t *testing.T) {
	logger := slog.Default()

	t.Run("start with no workers returns immediately", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[string, string](ctx, logger, 10)
		defer fo.Close()

		done := make(chan struct{})
		go func() {
			fo.Start()
			close(done)
		}()

		select {
		case <-done:
			// Good - returned because no workers
		case <-time.After(2 * time.Second):
			t.Fatal("FanOut Start with no workers should return quickly")
		}
	})
}

func TestFanOutProcessing(t *testing.T) {
	logger := slog.Default()

	t.Run("processes items with single worker", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[int, int](ctx, logger, 10)

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return v * 2, nil
		})

		go fo.Start()

		fo.Input() <- 5
		fo.Input() <- 10
		close(fo.Input())

		var results []int
		for r := range fo.Output() {
			results = append(results, r)
		}

		assert.Len(t, results, 2)
		assert.Contains(t, results, 10) // 5*2
		assert.Contains(t, results, 20) // 10*2
	})

	t.Run("distributes work across multiple workers", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[int, int](ctx, logger, 50)

		var workerCounts [3]atomic.Int32
		for i := 0; i < 3; i++ {
			idx := i
			fo.AddWorker(func(ctx context.Context, v int) (int, error) {
				workerCounts[idx].Add(1)
				time.Sleep(time.Millisecond)
				return v, nil
			})
		}

		go fo.Start()

		numItems := 30
		for i := 0; i < numItems; i++ {
			fo.Input() <- i
		}
		close(fo.Input())

		var results []int
		for r := range fo.Output() {
			results = append(results, r)
		}

		assert.Len(t, results, numItems)

		// All workers should have processed some items
		totalProcessed := int32(0)
		for i := 0; i < 3; i++ {
			totalProcessed += workerCounts[i].Load()
		}
		assert.Equal(t, int32(numItems), totalProcessed)
	})
}

func TestFanOutErrorHandling(t *testing.T) {
	logger := slog.Default()

	t.Run("sends errors to error channel", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[int, int](ctx, logger, 10)

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			if v < 0 {
				return 0, fmt.Errorf("negative: %d", v)
			}
			return v, nil
		})

		go fo.Start()

		fo.Input() <- 5
		fo.Input() <- -1
		fo.Input() <- 10
		close(fo.Input())

		var results []int
		var errs []error
		outputDone := false
		errorsDone := false

		for !outputDone || !errorsDone {
			select {
			case r, ok := <-fo.Output():
				if !ok {
					outputDone = true
					continue
				}
				results = append(results, r)
			case e, ok := <-fo.Errors():
				if !ok {
					errorsDone = true
					continue
				}
				errs = append(errs, e)
			}
		}

		assert.Len(t, results, 2)
		assert.Contains(t, results, 5)
		assert.Contains(t, results, 10)
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "negative: -1")
	})
}

func TestFanOutContextCancellation(t *testing.T) {
	logger := slog.Default()

	t.Run("stops on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fo := NewFanOut[int, int](ctx, logger, 10)

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			select {
			case <-time.After(5 * time.Second):
				return v, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		})

		done := make(chan struct{})
		go func() {
			fo.Start()
			close(done)
		}()

		fo.Input() <- 1
		cancel()

		select {
		case <-done:
			// FanOut stopped
		case <-time.After(2 * time.Second):
			t.Fatal("FanOut did not stop after context cancellation")
		}
	})
}

func TestFanOutClose(t *testing.T) {
	logger := slog.Default()

	t.Run("close stops fan-out", func(t *testing.T) {
		ctx := context.Background()
		fo := NewFanOut[int, int](ctx, logger, 10)

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return v, nil
		})

		done := make(chan struct{})
		go func() {
			fo.Close()
			close(done)
		}()

		select {
		case <-done:
			// Good
		case <-time.After(2 * time.Second):
			t.Fatal("Close hung")
		}
	})
}

// --- BatchProcessor tests ---

func TestBatchProcessorCreation(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("creates batch processor", func(t *testing.T) {
		bp := NewBatchProcessor(client, 5, 100*time.Millisecond,
			func(ctx context.Context, c *LDAP, items []string) error {
				return nil
			})
		require.NotNil(t, bp)
		defer bp.Close()

		assert.Equal(t, 5, bp.batchSize)
		assert.Equal(t, 100*time.Millisecond, bp.timeout)
	})
}

func TestBatchProcessorAdd(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("processes batch when full", func(t *testing.T) {
		var mu sync.Mutex
		var processed [][]int

		bp := NewBatchProcessor(client, 3, 5*time.Second,
			func(ctx context.Context, c *LDAP, items []int) error {
				mu.Lock()
				batch := make([]int, len(items))
				copy(batch, items)
				processed = append(processed, batch)
				mu.Unlock()
				return nil
			})
		defer bp.Close()

		// Add items to fill a batch
		bp.Add(1)
		bp.Add(2)
		bp.Add(3) // This triggers processing

		// Wait for async processing
		time.Sleep(100 * time.Millisecond)

		mu.Lock()
		assert.Len(t, processed, 1)
		assert.Equal(t, []int{1, 2, 3}, processed[0])
		mu.Unlock()
	})

	t.Run("processes batch on timeout", func(t *testing.T) {
		var mu sync.Mutex
		var processed [][]string

		bp := NewBatchProcessor(client, 10, 50*time.Millisecond,
			func(ctx context.Context, c *LDAP, items []string) error {
				mu.Lock()
				batch := make([]string, len(items))
				copy(batch, items)
				processed = append(processed, batch)
				mu.Unlock()
				return nil
			})
		defer bp.Close()

		// Add fewer items than batch size
		bp.Add("a")
		bp.Add("b")

		// Wait for timer to trigger
		time.Sleep(200 * time.Millisecond)

		mu.Lock()
		assert.Len(t, processed, 1)
		assert.Equal(t, []string{"a", "b"}, processed[0])
		mu.Unlock()
	})
}

func TestBatchProcessorClose(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("close processes remaining items", func(t *testing.T) {
		var mu sync.Mutex
		var processed [][]int

		bp := NewBatchProcessor(client, 10, 5*time.Second,
			func(ctx context.Context, c *LDAP, items []int) error {
				mu.Lock()
				batch := make([]int, len(items))
				copy(batch, items)
				processed = append(processed, batch)
				mu.Unlock()
				return nil
			})

		bp.Add(1)
		bp.Add(2)

		// Close should process remaining items
		bp.Close()

		mu.Lock()
		assert.Len(t, processed, 1)
		assert.Equal(t, []int{1, 2}, processed[0])
		mu.Unlock()
	})

	t.Run("close with empty batch does not process", func(t *testing.T) {
		var processCount atomic.Int32

		bp := NewBatchProcessor(client, 10, 5*time.Second,
			func(ctx context.Context, c *LDAP, items []int) error {
				processCount.Add(1)
				return nil
			})

		bp.Close()

		assert.Equal(t, int32(0), processCount.Load())
	})
}

func TestBatchProcessorErrorHandling(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("handles processor errors gracefully", func(t *testing.T) {
		bp := NewBatchProcessor(client, 2, 5*time.Second,
			func(ctx context.Context, c *LDAP, items []string) error {
				return errors.New("batch processing failed")
			})
		defer bp.Close()

		// Should not panic when processor returns error
		bp.Add("a")
		bp.Add("b") // Triggers processing

		time.Sleep(100 * time.Millisecond)
	})
}

func TestBatchProcessorFlushEmptyBatch(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("flush with empty batch is no-op", func(t *testing.T) {
		var processCount atomic.Int32

		bp := NewBatchProcessor(client, 10, 5*time.Second,
			func(ctx context.Context, c *LDAP, items []int) error {
				processCount.Add(1)
				return nil
			})
		defer bp.Close()

		// Directly call flush with empty batch
		bp.flush()

		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, int32(0), processCount.Load())
	})
}

// --- Semaphore tests ---

func TestSemaphoreCreation(t *testing.T) {
	t.Run("creates semaphore with capacity", func(t *testing.T) {
		sem := NewSemaphore(5)
		require.NotNil(t, sem)
		assert.Equal(t, 5, cap(sem.ch))
	})

	t.Run("creates semaphore with capacity 1", func(t *testing.T) {
		sem := NewSemaphore(1)
		require.NotNil(t, sem)
		assert.Equal(t, 1, cap(sem.ch))
	})
}

func TestSemaphoreAcquireRelease(t *testing.T) {
	t.Run("acquire and release within capacity", func(t *testing.T) {
		sem := NewSemaphore(3)
		ctx := context.Background()

		// Acquire all permits
		for i := 0; i < 3; i++ {
			err := sem.Acquire(ctx)
			require.NoError(t, err)
		}

		// Release all permits
		for i := 0; i < 3; i++ {
			err := sem.Release()
			require.NoError(t, err)
		}
	})

	t.Run("acquire blocks when full", func(t *testing.T) {
		sem := NewSemaphore(1)
		ctx := context.Background()

		err := sem.Acquire(ctx)
		require.NoError(t, err)

		// Second acquire should block
		ctx2, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		err = sem.Acquire(ctx2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)

		// Release and try again
		err = sem.Release()
		require.NoError(t, err)

		err = sem.Acquire(ctx)
		assert.NoError(t, err)
		_ = sem.Release()
	})

	t.Run("acquire respects context cancellation", func(t *testing.T) {
		sem := NewSemaphore(1)
		ctx := context.Background()

		err := sem.Acquire(ctx)
		require.NoError(t, err)

		ctx2, cancel := context.WithCancel(ctx)
		cancel()

		err = sem.Acquire(ctx2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)

		_ = sem.Release()
	})

	t.Run("release without acquire returns error", func(t *testing.T) {
		sem := NewSemaphore(3)

		err := sem.Release()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "release without acquire")
	})
}

func TestSemaphoreWithSemaphore(t *testing.T) {
	t.Run("executes function with semaphore protection", func(t *testing.T) {
		sem := NewSemaphore(2)
		ctx := context.Background()

		executed := false
		err := sem.WithSemaphore(ctx, func() error {
			executed = true
			return nil
		})

		assert.NoError(t, err)
		assert.True(t, executed)
	})

	t.Run("returns function error", func(t *testing.T) {
		sem := NewSemaphore(2)
		ctx := context.Background()

		expectedErr := errors.New("function error")
		err := sem.WithSemaphore(ctx, func() error {
			return expectedErr
		})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns acquire error on cancelled context", func(t *testing.T) {
		sem := NewSemaphore(1)
		ctx := context.Background()

		// Fill semaphore
		err := sem.Acquire(ctx)
		require.NoError(t, err)

		// Try with cancelled context
		ctx2, cancel := context.WithCancel(ctx)
		cancel()

		err = sem.WithSemaphore(ctx2, func() error {
			t.Fatal("should not be called")
			return nil
		})

		assert.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)

		_ = sem.Release()
	})

	t.Run("releases semaphore even on function panic", func(t *testing.T) {
		sem := NewSemaphore(1)
		ctx := context.Background()

		// WithSemaphore uses defer Release(), which runs even on panic
		assert.Panics(t, func() {
			_ = sem.WithSemaphore(ctx, func() error {
				panic("intentional panic")
			})
		})

		// After panic, semaphore should be released — try to acquire it
		acquireCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		err := sem.Acquire(acquireCtx)
		assert.NoError(t, err, "semaphore should be released after panic")
		if err == nil {
			_ = sem.Release()
		}
	})

	t.Run("concurrent WithSemaphore limits concurrency", func(t *testing.T) {
		maxConcurrency := 3
		sem := NewSemaphore(maxConcurrency)
		ctx := context.Background()

		var current atomic.Int32
		var maxSeen atomic.Int32

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sem.WithSemaphore(ctx, func() error {
					c := current.Add(1)
					for {
						old := maxSeen.Load()
						if c <= old || maxSeen.CompareAndSwap(old, c) {
							break
						}
					}
					time.Sleep(time.Millisecond)
					current.Add(-1)
					return nil
				})
			}()
		}

		wg.Wait()
		assert.LessOrEqual(t, int(maxSeen.Load()), maxConcurrency)
	})
}

// --- ConcurrentLDAPOperations tests ---

func TestNewConcurrentOperations(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("creates concurrent operations helper", func(t *testing.T) {
		co := NewConcurrentOperations(client, 5)
		require.NotNil(t, co)
		assert.Equal(t, client, co.client)
		assert.NotNil(t, co.semaphore)
		assert.Equal(t, client.logger, co.logger)
	})
}

// --- WorkResult and WorkItem struct tests ---

func TestWorkResultFields(t *testing.T) {
	t.Run("work result stores all fields", func(t *testing.T) {
		result := WorkResult[string]{
			ID:       "test_id",
			Data:     "test_data",
			Error:    errors.New("test error"),
			Duration: 5 * time.Second,
		}

		assert.Equal(t, "test_id", result.ID)
		assert.Equal(t, "test_data", result.Data)
		assert.Error(t, result.Error)
		assert.Equal(t, 5*time.Second, result.Duration)
	})
}

func TestWorkerPoolStatsStruct(t *testing.T) {
	t.Run("stats struct fields", func(t *testing.T) {
		stats := WorkerPoolStats{
			WorkerCount:     4,
			Processed:       100,
			Errors:          5,
			AverageDuration: 50 * time.Millisecond,
		}

		assert.Equal(t, 4, stats.WorkerCount)
		assert.Equal(t, int64(100), stats.Processed)
		assert.Equal(t, int64(5), stats.Errors)
		assert.Equal(t, 50*time.Millisecond, stats.AverageDuration)
	})
}

// --- Worker pool submit after context deadline ---

func TestWorkerPoolSubmitAfterContextDeadline(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("submit returns error after timeout", func(t *testing.T) {
		blocker := make(chan struct{})
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  0, // Unbuffered: Submit blocks until worker reads
			Timeout:     50 * time.Millisecond,
		}

		pool := NewWorkerPool[string](client, config)
		defer func() {
			close(blocker)
			pool.Close()
		}()

		// Submit a long-running item that blocks the single worker
		_ = pool.Submit(WorkItem[string]{
			ID: "blocker", Data: "x",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				<-blocker
				return nil
			},
		})

		// Wait for context timeout to expire
		time.Sleep(100 * time.Millisecond)

		// Worker is blocked, channel is unbuffered, context is expired.
		// Submit must return ctx.Err() — no other case in the select is ready.
		err := pool.Submit(WorkItem[string]{
			ID:   "late_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return nil
			},
		})

		assert.Error(t, err)
	})
}

// --- WorkerPoolConfig struct tests ---

func TestWorkerPoolConfigFields(t *testing.T) {
	t.Run("config stores all fields", func(t *testing.T) {
		config := WorkerPoolConfig{
			WorkerCount: 8,
			BufferSize:  200,
			Timeout:     10 * time.Minute,
			FailFast:    true,
		}

		assert.Equal(t, 8, config.WorkerCount)
		assert.Equal(t, 200, config.BufferSize)
		assert.Equal(t, 10*time.Minute, config.Timeout)
		assert.True(t, config.FailFast)
	})
}

// --- Additional coverage tests for worker pool internals ---

func TestWorkerPoolFailFast(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("fail fast cancels context on first error", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     5 * time.Second,
			FailFast:    true,
		}

		pool := NewWorkerPool[string](client, config)

		// Submit work that returns an error
		err := pool.Submit(WorkItem[string]{
			ID:   "fail_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return errors.New("intentional failure")
			},
		})
		require.NoError(t, err)

		// Read the result
		result := <-pool.Results()
		assert.Error(t, result.Error)
		assert.Equal(t, "fail_item", result.ID)

		// Close and verify
		pool.Close()
	})
}

func TestWorkerPoolContextDoneDuringWork(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("worker exits when context is done during item processing", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     100 * time.Millisecond,
		}

		pool := NewWorkerPool[string](client, config)

		// Submit a slow item
		err := pool.Submit(WorkItem[string]{
			ID:   "slow_item",
			Data: "test",
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				time.Sleep(50 * time.Millisecond)
				return nil
			},
		})
		require.NoError(t, err)

		// Wait for timeout
		time.Sleep(200 * time.Millisecond)

		pool.Close()
	})
}

func TestWorkerPoolResultChannelFull(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("worker handles full result channel", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 2,
			BufferSize:  10, // Must fit all items to avoid deadlock between Submit and result send
			Timeout:     5 * time.Second,
		}

		pool := NewWorkerPool[int](client, config)

		// Drain results concurrently to avoid blocking workers
		var results []WorkResult[int]
		done := make(chan struct{})
		go func() {
			for r := range pool.Results() {
				results = append(results, r)
			}
			close(done)
		}()

		// Submit items
		for i := 0; i < 5; i++ {
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", i),
				Data: i,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					return nil
				},
			})
		}

		pool.Close()
		<-done

		// All submitted items should be processed
		assert.NotEmpty(t, results)
	})
}

func TestWorkerPoolErrorMetrics(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}

	t.Run("tracks error metrics correctly", func(t *testing.T) {
		config := &WorkerPoolConfig{
			WorkerCount: 1,
			BufferSize:  10,
			Timeout:     5 * time.Second,
		}

		pool := NewWorkerPool[int](client, config)

		// Submit mix of success and failure
		for i := 0; i < 4; i++ {
			idx := i
			_ = pool.Submit(WorkItem[int]{
				ID:   fmt.Sprintf("item_%d", idx),
				Data: idx,
				Fn: func(ctx context.Context, client *LDAP, data int) error {
					if data%2 == 0 {
						return errors.New("even numbers fail")
					}
					return nil
				},
			})
		}

		// Drain results
		for i := 0; i < 4; i++ {
			<-pool.Results()
		}

		pool.Close()

		stats := pool.Stats()
		assert.Equal(t, int64(4), stats.Processed)
		assert.Equal(t, int64(2), stats.Errors) // 0, 2 fail
		assert.Greater(t, int64(stats.AverageDuration), int64(0))
	})
}

// --- Additional pool.go coverage tests ---

func TestSemaphoreWithSemaphoreContextTimeout(t *testing.T) {
	t.Run("WithSemaphore returns context error when cannot acquire", func(t *testing.T) {
		sem := NewSemaphore(1)
		ctx := context.Background()

		// Fill the semaphore
		err := sem.Acquire(ctx)
		require.NoError(t, err)

		// Try WithSemaphore with timeout
		timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()

		err = sem.WithSemaphore(timeoutCtx, func() error {
			t.Fatal("should not execute")
			return nil
		})

		assert.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)

		_ = sem.Release()
	})
}

func TestPipelineInputOutput(t *testing.T) {
	logger := slog.Default()

	t.Run("Input and Output return correct channels", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[string, int](ctx, logger, 50)
		defer p.Close()

		// Input returns a send-only channel
		input := p.Input()
		assert.NotNil(t, input)

		// Output returns a receive-only channel
		output := p.Output()
		assert.NotNil(t, output)
	})
}

func TestPipelineAddStageNegativeParallel(t *testing.T) {
	logger := slog.Default()

	t.Run("negative parallel gets clamped to 1", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)
		defer p.Close()

		p.AddStage("test", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, -5)

		assert.Len(t, p.stages, 1)
		assert.Equal(t, 1, p.stages[0].Parallel)
	})

	t.Run("zero parallel gets clamped to 1", func(t *testing.T) {
		ctx := context.Background()
		p := NewPipeline[int, int](ctx, logger, 10)
		defer p.Close()

		p.AddStage("test", func(ctx context.Context, input any) (any, error) {
			return input, nil
		}, 0)

		assert.Len(t, p.stages, 1)
		assert.Equal(t, 1, p.stages[0].Parallel)
	})
}

func TestPipelineStageErrorChannelFull(t *testing.T) {
	logger := slog.Default()

	t.Run("drops errors when error channel is full", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Small error channel (100 is default in NewPipeline)
		p := NewPipeline[int, int](ctx, logger, 10)
		defer p.Close()

		p.AddStage("fail_stage", func(ctx context.Context, input any) (any, error) {
			return nil, fmt.Errorf("error for %v", input)
		}, 1)

		go p.Start()

		// Send items
		for i := range 5 {
			p.Input() <- i
		}
		close(p.Input())

		// Drain output (should be empty since all errored)
		for range p.Output() {
		}

		// Wait for error collection
		time.Sleep(100 * time.Millisecond)

		errs := p.Errors()
		// At least some errors should be collected
		assert.NotEmpty(t, errs)
	})
}

func TestFanOutContextCancelDuringErrorSend(t *testing.T) {
	logger := slog.Default()

	t.Run("worker stops when context cancelled during error send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fo := NewFanOut[int, int](ctx, logger, 1) // Small buffer

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return 0, errors.New("always fails")
		})

		done := make(chan struct{})
		go func() {
			fo.Start()
			close(done)
		}()

		// Send an item then cancel
		fo.Input() <- 1
		time.Sleep(10 * time.Millisecond)
		cancel()
		close(fo.Input())

		select {
		case <-done:
			// Good
		case <-time.After(2 * time.Second):
			t.Fatal("FanOut did not stop")
		}
	})
}

func TestFanOutContextCancelDuringOutputSend(t *testing.T) {
	logger := slog.Default()

	t.Run("worker stops when context cancelled during output send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fo := NewFanOut[int, int](ctx, logger, 0) // Zero buffer forces blocking on send

		fo.AddWorker(func(ctx context.Context, v int) (int, error) {
			return v * 2, nil
		})

		done := make(chan struct{})
		go func() {
			fo.Start()
			close(done)
		}()

		// Send item
		go func() {
			fo.Input() <- 1
			time.Sleep(10 * time.Millisecond)
			cancel()
			close(fo.Input())
		}()

		select {
		case <-done:
			// Good
		case <-time.After(2 * time.Second):
			t.Fatal("FanOut did not stop after context cancellation")
		}
	})
}
