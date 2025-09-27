package ldap

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int32

const (
	StateCircuitClosed CircuitBreakerState = iota
	StateCircuitOpen
	StateCircuitHalfOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case StateCircuitClosed:
		return "CLOSED"
	case StateCircuitOpen:
		return "OPEN"
	case StateCircuitHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit
	MaxFailures int64 `json:"max_failures"`
	// Timeout is how long to wait before transitioning from open to half-open
	Timeout time.Duration `json:"timeout"`
	// HalfOpenMaxRequests is the maximum number of requests allowed in half-open state
	HalfOpenMaxRequests int64 `json:"half_open_max_requests"`
}

// DefaultCircuitBreakerConfig returns a sensible default configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             30 * time.Second,
		HalfOpenMaxRequests: 3,
	}
}

// CircuitBreaker implements the circuit breaker pattern for resilient error handling
type CircuitBreaker struct {
	config       *CircuitBreakerConfig
	logger       *slog.Logger
	name         string
	mu           sync.RWMutex
	state        atomic.Int32 // Use atomic for thread-safe state transitions
	failures     atomic.Int64 // Atomic counter for failures
	lastFailure  time.Time
	nextRetry    time.Time
	halfOpenReqs atomic.Int64 // Atomic counter for half-open requests
	requests     atomic.Int64 // Atomic counter for total requests
	successes    atomic.Int64 // Atomic counter for successes
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, config *CircuitBreakerConfig, logger *slog.Logger) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	cb := &CircuitBreaker{
		config: config,
		logger: logger,
		name:   name,
	}
	cb.state.Store(int32(StateCircuitClosed))
	return cb
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	// Check if we can execute
	if !cb.canExecute() {
		currentState := CircuitBreakerState(cb.state.Load())
		cb.logger.Debug("circuit_breaker_blocked",
			slog.String("name", cb.name),
			slog.String("state", currentState.String()),
			slog.Int64("failures", cb.failures.Load()))
		return &CircuitBreakerError{
			State:       currentState.String(),
			Failures:    int(cb.failures.Load()),
			LastFailure: cb.lastFailure,
			NextRetry:   cb.nextRetry,
		}
	}

	// Execute the function
	err := fn()
	cb.recordResult(err)

	return err
}

// canExecute determines if the circuit allows execution
func (cb *CircuitBreaker) canExecute() bool {
	cb.requests.Add(1)

	currentState := CircuitBreakerState(cb.state.Load())

	switch currentState {
	case StateCircuitClosed:
		return true
	case StateCircuitOpen:
		// Check if timeout has passed
		cb.mu.RLock()
		nextRetry := cb.nextRetry
		cb.mu.RUnlock()

		if time.Now().After(nextRetry) {
			// Try to transition from OPEN to HALF_OPEN using atomic compare-and-swap
			if cb.state.CompareAndSwap(int32(StateCircuitOpen), int32(StateCircuitHalfOpen)) {
				// Successfully transitioned to half-open
				cb.halfOpenReqs.Store(0)

				cb.logger.Info("circuit_breaker_transition",
					slog.String("name", cb.name),
					slog.String("from", "OPEN"),
					slog.String("to", "HALF_OPEN"))
				return true
			}
			// Another goroutine already transitioned it, check the new state
			return CircuitBreakerState(cb.state.Load()) == StateCircuitHalfOpen
		}
		return false
	case StateCircuitHalfOpen:
		// Allow limited requests in half-open state
		return cb.halfOpenReqs.Load() < cb.config.HalfOpenMaxRequests
	default:
		return false
	}
}

// recordResult records the result of an execution
func (cb *CircuitBreaker) recordResult(err error) {
	currentState := CircuitBreakerState(cb.state.Load())

	if err == nil {
		// Success
		cb.successes.Add(1)

		if currentState == StateCircuitHalfOpen {
			// If we have enough successful requests in half-open, try to close the circuit
			halfOpenCount := cb.halfOpenReqs.Add(1)
			if halfOpenCount >= cb.config.HalfOpenMaxRequests {
				// Try to transition from HALF_OPEN to CLOSED
				if cb.state.CompareAndSwap(int32(StateCircuitHalfOpen), int32(StateCircuitClosed)) {
					// Successfully closed the circuit
					cb.failures.Store(0)

					cb.logger.Info("circuit_breaker_closed",
						slog.String("name", cb.name),
						slog.String("reason", "successful_requests"))
				}
			}
		}
	} else {
		// Failure
		failureCount := cb.failures.Add(1)

		cb.mu.Lock()
		cb.lastFailure = time.Now()
		cb.mu.Unlock()

		switch currentState {
		case StateCircuitClosed:
			if failureCount >= cb.config.MaxFailures {
				cb.openCircuit()
			}
		case StateCircuitHalfOpen:
			// Any failure in half-open returns to open
			cb.openCircuit()
		}
	}
}

// openCircuit transitions the circuit to open state
func (cb *CircuitBreaker) openCircuit() {
	// Use atomic store for thread-safe state change
	cb.state.Store(int32(StateCircuitOpen))

	cb.mu.Lock()
	cb.nextRetry = time.Now().Add(cb.config.Timeout)
	nextRetry := cb.nextRetry
	cb.mu.Unlock()

	failures := cb.failures.Load()

	cb.logger.Warn("circuit_breaker_opened",
		slog.String("name", cb.name),
		slog.Int64("failures", failures),
		slog.Time("next_retry", nextRetry))
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	currentState := CircuitBreakerState(cb.state.Load())
	return map[string]interface{}{
		"name":           cb.name,
		"state":          currentState.String(),
		"failures":       cb.failures.Load(),
		"requests":       cb.requests.Load(),
		"successes":      cb.successes.Load(),
		"last_failure":   cb.lastFailure,
		"next_retry":     cb.nextRetry,
		"half_open_reqs": cb.halfOpenReqs.Load(),
		"success_rate":   cb.getSuccessRate(),
	}
}

// getSuccessRate calculates the success rate
func (cb *CircuitBreaker) getSuccessRate() float64 {
	requests := cb.requests.Load()
	if requests == 0 {
		return 1.0
	}
	successes := cb.successes.Load()
	return float64(successes) / float64(requests)
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	// Use atomic store for thread-safe state change
	cb.state.Store(int32(StateCircuitClosed))

	cb.failures.Store(0)
	cb.halfOpenReqs.Store(0)

	cb.logger.Info("circuit_breaker_reset", slog.String("name", cb.name))
}

// BulkheadConfig holds configuration for the bulkhead pattern
type BulkheadConfig struct {
	MaxConcurrency int           `json:"max_concurrency"`
	QueueSize      int           `json:"queue_size"`
	Timeout        time.Duration `json:"timeout"`
}

// DefaultBulkheadConfig returns a sensible default configuration
func DefaultBulkheadConfig() *BulkheadConfig {
	return &BulkheadConfig{
		MaxConcurrency: 10,
		QueueSize:      50,
		Timeout:        30 * time.Second,
	}
}

// Bulkhead implements the bulkhead pattern for resource isolation
type Bulkhead struct {
	config    *BulkheadConfig
	logger    *slog.Logger
	name      string
	semaphore chan struct{}
	active    int64
	queued    int64
	rejected  int64
}

// NewBulkhead creates a new bulkhead
func NewBulkhead(name string, config *BulkheadConfig, logger *slog.Logger) *Bulkhead {
	if config == nil {
		config = DefaultBulkheadConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Bulkhead{
		config:    config,
		logger:    logger,
		name:      name,
		semaphore: make(chan struct{}, config.MaxConcurrency),
	}
}

// Execute executes a function with bulkhead protection
func (b *Bulkhead) Execute(ctx context.Context, fn func() error) error {
	// Try to acquire a slot
	select {
	case b.semaphore <- struct{}{}:
		// Got a slot
		atomic.AddInt64(&b.active, 1)
		defer func() {
			<-b.semaphore
			atomic.AddInt64(&b.active, -1)
		}()

		return fn()

	case <-ctx.Done():
		atomic.AddInt64(&b.rejected, 1)
		b.logger.Debug("bulkhead_context_cancelled",
			slog.String("name", b.name),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()

	default:
		// No slot available, check if we should queue or reject
		if int(atomic.LoadInt64(&b.queued)) >= b.config.QueueSize {
			atomic.AddInt64(&b.rejected, 1)
			b.logger.Debug("bulkhead_rejected",
				slog.String("name", b.name),
				slog.String("reason", "queue_full"))
			return NewResourceExhaustionError("bulkhead_"+b.name,
				atomic.LoadInt64(&b.active),
				int64(b.config.MaxConcurrency),
				"reduce concurrent operations",
				true)
		}

		// Queue the request
		atomic.AddInt64(&b.queued, 1)
		defer atomic.AddInt64(&b.queued, -1)

		timer := time.NewTimer(b.config.Timeout)
		defer timer.Stop()

		select {
		case b.semaphore <- struct{}{}:
			atomic.AddInt64(&b.active, 1)
			defer func() {
				<-b.semaphore
				atomic.AddInt64(&b.active, -1)
			}()

			return fn()

		case <-timer.C:
			atomic.AddInt64(&b.rejected, 1)
			b.logger.Debug("bulkhead_timeout",
				slog.String("name", b.name),
				slog.Duration("timeout", b.config.Timeout))
			return NewTimeoutError("bulkhead_"+b.name, b.config.Timeout, b.config.Timeout, nil)

		case <-ctx.Done():
			atomic.AddInt64(&b.rejected, 1)
			return ctx.Err()
		}
	}
}

// GetStats returns bulkhead statistics
func (b *Bulkhead) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"name":           b.name,
		"max_concurrent": b.config.MaxConcurrency,
		"active":         atomic.LoadInt64(&b.active),
		"queued":         atomic.LoadInt64(&b.queued),
		"rejected":       atomic.LoadInt64(&b.rejected),
		"queue_size":     b.config.QueueSize,
	}
}

// TimeoutManager provides sophisticated timeout management
type TimeoutManager struct {
	baseTimeout    time.Duration
	maxTimeout     time.Duration
	backoffFactor  float64
	jitterEnabled  bool
	mu             sync.RWMutex
	operationStats map[string]*operationTimeouts
}

type operationTimeouts struct {
	avgDuration    time.Duration
	maxDuration    time.Duration
	timeouts       int64
	successes      int64
	adaptiveOffset time.Duration
}

// NewTimeoutManager creates a new timeout manager
func NewTimeoutManager(baseTimeout, maxTimeout time.Duration, backoffFactor float64) *TimeoutManager {
	return &TimeoutManager{
		baseTimeout:    baseTimeout,
		maxTimeout:     maxTimeout,
		backoffFactor:  backoffFactor,
		jitterEnabled:  true,
		operationStats: make(map[string]*operationTimeouts),
	}
}

// GetAdaptiveTimeout returns an adaptive timeout based on operation history
func (tm *TimeoutManager) GetAdaptiveTimeout(operation string) time.Duration {
	tm.mu.RLock()
	stats, exists := tm.operationStats[operation]
	tm.mu.RUnlock()

	if !exists {
		return tm.baseTimeout
	}

	// Calculate adaptive timeout based on historical performance
	adaptiveTimeout := stats.avgDuration + stats.adaptiveOffset

	// Apply backoff if there have been recent timeouts
	timeoutRate := float64(stats.timeouts) / float64(stats.successes+stats.timeouts)
	if timeoutRate > 0.1 {
		adaptiveTimeout = time.Duration(float64(adaptiveTimeout) * (1.0 + timeoutRate*tm.backoffFactor))
	}

	// Ensure timeout is within bounds
	if adaptiveTimeout < tm.baseTimeout {
		adaptiveTimeout = tm.baseTimeout
	}
	if adaptiveTimeout > tm.maxTimeout {
		adaptiveTimeout = tm.maxTimeout
	}

	// Add jitter if enabled
	if tm.jitterEnabled {
		jitter := time.Duration(float64(adaptiveTimeout) * 0.1 * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0))
		adaptiveTimeout += jitter
	}

	return adaptiveTimeout
}

// RecordOperationResult records the result of an operation for adaptive timeout calculation
func (tm *TimeoutManager) RecordOperationResult(operation string, duration time.Duration, success bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	stats, exists := tm.operationStats[operation]
	if !exists {
		stats = &operationTimeouts{
			avgDuration: duration,
			maxDuration: duration,
		}
		tm.operationStats[operation] = stats
	}

	// Update statistics
	if success {
		atomic.AddInt64(&stats.successes, 1)

		// Update average duration (exponential moving average)
		stats.avgDuration = time.Duration(0.9*float64(stats.avgDuration) + 0.1*float64(duration))

		// Update max duration
		if duration > stats.maxDuration {
			stats.maxDuration = duration
		}

		// Adjust adaptive offset based on performance
		if duration > stats.avgDuration {
			stats.adaptiveOffset = time.Duration(float64(stats.adaptiveOffset) * 1.1)
		} else {
			stats.adaptiveOffset = time.Duration(float64(stats.adaptiveOffset) * 0.95)
		}
	} else {
		atomic.AddInt64(&stats.timeouts, 1)
		// Increase adaptive offset for future operations
		stats.adaptiveOffset = time.Duration(float64(stats.adaptiveOffset) * 1.2)
	}
}

// ExecuteWithAdaptiveTimeout executes a function with adaptive timeout
func (tm *TimeoutManager) ExecuteWithAdaptiveTimeout(ctx context.Context, operation string, fn func(context.Context) error) error {
	timeout := tm.GetAdaptiveTimeout(operation)
	start := time.Now()

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := fn(timeoutCtx)
	duration := time.Since(start)

	// Record the result
	success := err == nil || !IsContextError(err)
	tm.RecordOperationResult(operation, duration, success)

	// Return timeout error if needed
	if IsContextError(err) && timeoutCtx.Err() == context.DeadlineExceeded {
		return NewTimeoutError(operation, timeout, duration, err)
	}

	return err
}

// GetTimeoutStats returns timeout statistics for all operations
func (tm *TimeoutManager) GetTimeoutStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := make(map[string]interface{})
	for operation, opStats := range tm.operationStats {
		stats[operation] = map[string]interface{}{
			"avg_duration":    opStats.avgDuration,
			"max_duration":    opStats.maxDuration,
			"timeouts":        atomic.LoadInt64(&opStats.timeouts),
			"successes":       atomic.LoadInt64(&opStats.successes),
			"adaptive_offset": opStats.adaptiveOffset,
		}
	}

	return stats
}
