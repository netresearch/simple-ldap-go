// Package pool provides modern concurrency patterns for LDAP operations.
package pool

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerPool provides a worker pool pattern for concurrent LDAP operations.
// This pattern is useful for bulk operations like creating multiple users or processing search results.
type WorkerPool[T any] struct {
	workerCount int
	workChan    chan WorkItem[T]
	resultChan  chan WorkResult[T]
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	client      *LDAP
	logger      *slog.Logger

	// Metrics
	processed   atomic.Int64
	errors      atomic.Int64
	avgDuration atomic.Int64 // in nanoseconds
}

// WorkItem represents a unit of work to be processed by the worker pool.
type WorkItem[T any] struct {
	ID   string
	Data T
	Fn   func(ctx context.Context, client *LDAP, data T) error
}

// WorkResult represents the result of processing a work item.
type WorkResult[T any] struct {
	ID       string
	Data     T
	Error    error
	Duration time.Duration
}

// WorkerPoolConfig configures a worker pool.
type WorkerPoolConfig struct {
	// WorkerCount is the number of concurrent workers
	WorkerCount int `json:"worker_count"`
	// BufferSize is the size of the work item buffer
	BufferSize int `json:"buffer_size"`
	// Timeout is the maximum time to wait for operations
	Timeout time.Duration `json:"timeout"`
	// FailFast determines if the pool should stop on first error
	FailFast bool `json:"fail_fast"`
}

// DefaultWorkerPoolConfig returns sensible defaults for a worker pool.
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		WorkerCount: runtime.GOMAXPROCS(0),
		BufferSize:  100,
		Timeout:     5 * time.Minute,
		FailFast:    false,
	}
}

// NewWorkerPool creates a new worker pool for concurrent LDAP operations.
//
// Example:
//
//	pool := NewWorkerPool[*FullUser](client, &WorkerPoolConfig{
//	    WorkerCount: 10,
//	    BufferSize: 50,
//	    Timeout: 2 * time.Minute,
//	})
//	defer pool.Close()
//
//	// Submit work items
//	for _, user := range users {
//	    pool.Submit(WorkItem[*FullUser]{
//	        ID: user.SAMAccountName,
//	        Data: user,
//	        Fn: func(ctx context.Context, client *LDAP, data *FullUser) error {
//	            _, err := client.CreateUserContext(ctx, *data, "defaultPassword")
//	            return err
//	        },
//	    })
//	}
//
//	// Collect results
//	results := pool.Results()
//	for result := range results {
//	    if result.Error != nil {
//	        log.Printf("Error processing %s: %v", result.ID, result.Error)
//	    }
//	}
func NewWorkerPool[T any](client *LDAP, config *WorkerPoolConfig) *WorkerPool[T] {
	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)

	pool := &WorkerPool[T]{
		workerCount: config.WorkerCount,
		workChan:    make(chan WorkItem[T], config.BufferSize),
		resultChan:  make(chan WorkResult[T], config.BufferSize),
		ctx:         ctx,
		cancel:      cancel,
		client:      client,
		logger:      client.logger,
	}

	// Start workers
	for i := 0; i < config.WorkerCount; i++ {
		pool.wg.Add(1)
		go pool.worker(i, config.FailFast)
	}

	return pool
}

// worker runs the worker goroutine that processes work items.
func (p *WorkerPool[T]) worker(id int, failFast bool) {
	defer p.wg.Done()

	p.logger.Debug("worker_started",
		slog.Int("worker_id", id))

	for {
		select {
		case <-p.ctx.Done():
			p.logger.Debug("worker_stopping_context_done",
				slog.Int("worker_id", id))
			return

		case item, ok := <-p.workChan:
			if !ok {
				p.logger.Debug("worker_stopping_channel_closed",
					slog.Int("worker_id", id))
				return
			}

			start := time.Now()
			err := item.Fn(p.ctx, p.client, item.Data)
			duration := time.Since(start)

			// Update metrics
			p.processed.Add(1)
			if err != nil {
				p.errors.Add(1)
				if failFast {
					p.logger.Error("worker_fail_fast_triggered",
						slog.Int("worker_id", id),
						slog.String("item_id", item.ID),
						slog.String("error", err.Error()))
					p.cancel()
				}
			}

			// Update average duration (simple moving average)
			oldAvg := p.avgDuration.Load()
			newAvg := (oldAvg + duration.Nanoseconds()) / 2
			p.avgDuration.Store(newAvg)

			// Send result
			select {
			case p.resultChan <- WorkResult[T]{
				ID:       item.ID,
				Data:     item.Data,
				Error:    err,
				Duration: duration,
			}:
			case <-p.ctx.Done():
				return
			}

			p.logger.Debug("worker_processed_item",
				slog.Int("worker_id", id),
				slog.String("item_id", item.ID),
				slog.Duration("duration", duration),
				slog.Bool("success", err == nil))
		}
	}
}

// Submit adds a work item to the pool for processing.
func (p *WorkerPool[T]) Submit(item WorkItem[T]) error {
	select {
	case p.workChan <- item:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// Results returns a channel that receives work results.
// The channel will be closed when all work is complete.
func (p *WorkerPool[T]) Results() <-chan WorkResult[T] {
	return p.resultChan
}

// Close shuts down the worker pool and waits for all workers to finish.
func (p *WorkerPool[T]) Close() {
	close(p.workChan)
	p.wg.Wait()
	close(p.resultChan)
	p.cancel()
}

// Stats returns worker pool statistics.
type WorkerPoolStats struct {
	WorkerCount     int
	Processed       int64
	Errors          int64
	AverageDuration time.Duration
}

// Stats returns current worker pool statistics.
func (p *WorkerPool[T]) Stats() WorkerPoolStats {
	return WorkerPoolStats{
		WorkerCount:     p.workerCount,
		Processed:       p.processed.Load(),
		Errors:          p.errors.Load(),
		AverageDuration: time.Duration(p.avgDuration.Load()),
	}
}

// Pipeline provides a pipeline pattern for streaming LDAP operations.
// This pattern is useful for processing large datasets with multiple stages.
type Pipeline[T, U any] struct {
	stages []PipelineStage[any, any]
	input  chan T
	output chan U
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger

	// Error handling
	errorChan chan error
	errors    []error
	errorMu   sync.RWMutex
}

// PipelineStage represents a stage in the pipeline.
type PipelineStage[T, U any] struct {
	Name      string
	Transform func(ctx context.Context, input T) (U, error)
	Parallel  int // Number of goroutines for this stage
}

// NewPipeline creates a new processing pipeline.
//
// Example:
//
//	pipeline := NewPipeline[string, *User](ctx, logger, 100)
//
//	// Add stages
//	pipeline.AddStage("parse", func(ctx context.Context, dn string) (*FullUser, error) {
//	    // Parse DN and create user object
//	    return parseUserFromDN(dn), nil
//	}, 5)
//
//	pipeline.AddStage("create", func(ctx context.Context, user *FullUser) (*User, error) {
//	    // Create user in LDAP
//	    dn, err := client.CreateUserContext(ctx, *user, "password")
//	    if err != nil {
//	        return nil, err
//	    }
//	    return client.FindUserByDNContext(ctx, dn)
//	}, 10)
//
//	// Process items
//	go pipeline.Start()
//
//	// Send input
//	for _, dn := range userDNs {
//	    pipeline.Input() <- dn
//	}
//	close(pipeline.Input())
//
//	// Receive output
//	for user := range pipeline.Output() {
//	    fmt.Printf("Created user: %s\n", user.CN())
//	}
func NewPipeline[T, U any](ctx context.Context, logger *slog.Logger, bufferSize int) *Pipeline[T, U] {
	pipelineCtx, cancel := context.WithCancel(ctx)

	return &Pipeline[T, U]{
		stages:    make([]PipelineStage[any, any], 0),
		input:     make(chan T, bufferSize),
		output:    make(chan U, bufferSize),
		ctx:       pipelineCtx,
		cancel:    cancel,
		logger:    logger,
		errorChan: make(chan error, 100),
		errors:    make([]error, 0),
	}
}

// AddStage adds a processing stage to the pipeline.
func (p *Pipeline[T, U]) AddStage(name string, transform func(context.Context, any) (any, error), parallel int) {
	if parallel <= 0 {
		parallel = 1
	}

	stage := PipelineStage[any, any]{
		Name:      name,
		Transform: transform,
		Parallel:  parallel,
	}

	p.stages = append(p.stages, stage)
}

// Input returns the input channel for the pipeline.
func (p *Pipeline[T, U]) Input() chan<- T {
	return p.input
}

// Output returns the output channel for the pipeline.
func (p *Pipeline[T, U]) Output() <-chan U {
	return p.output
}

// Start begins processing the pipeline.
func (p *Pipeline[T, U]) Start() {
	defer close(p.output)
	defer close(p.errorChan)

	if len(p.stages) == 0 {
		p.logger.Error("pipeline_no_stages")
		return
	}

	// Start error collector
	go p.collectErrors()

	// Build pipeline stages
	channels := make([]chan any, len(p.stages)+1)
	channels[0] = make(chan any, cap(p.input))
	for i := 1; i <= len(p.stages); i++ {
		channels[i] = make(chan any, 100)
	}

	// Convert input to first channel
	go func() {
		defer close(channels[0])
		for item := range p.input {
			select {
			case channels[0] <- any(item):
			case <-p.ctx.Done():
				return
			}
		}
	}()

	// Start stage processors
	for i, stage := range p.stages {
		inChan := channels[i]
		outChan := channels[i+1]

		// Start parallel workers for this stage
		for j := 0; j < stage.Parallel; j++ {
			p.wg.Add(1)
			go p.stageProcessor(stage, inChan, outChan)
		}
	}

	// Convert last channel to output
	go func() {
		defer close(p.output)
		lastChan := channels[len(p.stages)]
		for item := range lastChan {
			if result, ok := item.(U); ok {
				select {
				case p.output <- result:
				case <-p.ctx.Done():
					return
				}
			}
		}
	}()

	// Wait for all stages to complete
	p.wg.Wait()

	// Close intermediate channels
	for i := 1; i < len(channels); i++ {
		close(channels[i])
	}
}

// stageProcessor processes items for a single stage.
func (p *Pipeline[T, U]) stageProcessor(stage PipelineStage[any, any], input <-chan any, output chan<- any) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case item, ok := <-input:
			if !ok {
				return
			}

			start := time.Now()
			result, err := stage.Transform(p.ctx, item)
			duration := time.Since(start)

			if err != nil {
				p.logger.Error("pipeline_stage_error",
					slog.String("stage", stage.Name),
					slog.String("error", err.Error()),
					slog.Duration("duration", duration))

				select {
				case p.errorChan <- fmt.Errorf("stage %s: %w", stage.Name, err):
				default:
				}
				continue
			}

			p.logger.Debug("pipeline_stage_processed",
				slog.String("stage", stage.Name),
				slog.Duration("duration", duration))

			select {
			case output <- result:
			case <-p.ctx.Done():
				return
			}
		}
	}
}

// collectErrors collects errors from pipeline stages.
func (p *Pipeline[T, U]) collectErrors() {
	for err := range p.errorChan {
		p.errorMu.Lock()
		p.errors = append(p.errors, err)
		p.errorMu.Unlock()
	}
}

// Errors returns all errors collected during pipeline processing.
func (p *Pipeline[T, U]) Errors() []error {
	p.errorMu.RLock()
	defer p.errorMu.RUnlock()

	errorsCopy := make([]error, len(p.errors))
	copy(errorsCopy, p.errors)
	return errorsCopy
}

// Close stops the pipeline and cleans up resources.
func (p *Pipeline[T, U]) Close() {
	p.cancel()
	p.wg.Wait()
}

// FanOut provides a fan-out pattern for distributing work across multiple workers.
type FanOut[T, U any] struct {
	workers    []func(context.Context, T) (U, error)
	inputChan  chan T
	outputChan chan U
	errorChan  chan error
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	logger     *slog.Logger
}

// NewFanOut creates a new fan-out processor.
//
// Example:
//
//	fanOut := NewFanOut[string, *User](ctx, logger, 100)
//
//	// Add workers
//	fanOut.AddWorker(func(ctx context.Context, dn string) (*User, error) {
//	    return client.FindUserByDNContext(ctx, dn)
//	})
//	fanOut.AddWorker(func(ctx context.Context, dn string) (*User, error) {
//	    return client.FindUserByDNContext(ctx, dn)
//	})
//
//	go fanOut.Start()
//
//	// Send work
//	for _, dn := range userDNs {
//	    fanOut.Input() <- dn
//	}
//	close(fanOut.Input())
//
//	// Collect results
//	for user := range fanOut.Output() {
//	    fmt.Printf("Found user: %s\n", user.CN())
//	}
func NewFanOut[T, U any](ctx context.Context, logger *slog.Logger, bufferSize int) *FanOut[T, U] {
	fanOutCtx, cancel := context.WithCancel(ctx)

	return &FanOut[T, U]{
		workers:    make([]func(context.Context, T) (U, error), 0),
		inputChan:  make(chan T, bufferSize),
		outputChan: make(chan U, bufferSize),
		errorChan:  make(chan error, bufferSize),
		ctx:        fanOutCtx,
		cancel:     cancel,
		logger:     logger,
	}
}

// AddWorker adds a worker function to the fan-out.
func (f *FanOut[T, U]) AddWorker(worker func(context.Context, T) (U, error)) {
	f.workers = append(f.workers, worker)
}

// Input returns the input channel.
func (f *FanOut[T, U]) Input() chan<- T {
	return f.inputChan
}

// Output returns the output channel.
func (f *FanOut[T, U]) Output() <-chan U {
	return f.outputChan
}

// Errors returns the error channel.
func (f *FanOut[T, U]) Errors() <-chan error {
	return f.errorChan
}

// Start begins processing with fan-out pattern.
func (f *FanOut[T, U]) Start() {
	defer close(f.outputChan)
	defer close(f.errorChan)

	if len(f.workers) == 0 {
		f.logger.Error("fanout_no_workers")
		return
	}

	// Start workers
	for i, worker := range f.workers {
		f.wg.Add(1)
		go f.runWorker(i, worker)
	}

	f.wg.Wait()
}

// runWorker runs a single worker goroutine.
func (f *FanOut[T, U]) runWorker(id int, worker func(context.Context, T) (U, error)) {
	defer f.wg.Done()

	f.logger.Debug("fanout_worker_started",
		slog.Int("worker_id", id))

	for {
		select {
		case <-f.ctx.Done():
			f.logger.Debug("fanout_worker_stopping",
				slog.Int("worker_id", id))
			return

		case item, ok := <-f.inputChan:
			if !ok {
				f.logger.Debug("fanout_worker_input_closed",
					slog.Int("worker_id", id))
				return
			}

			start := time.Now()
			result, err := worker(f.ctx, item)
			duration := time.Since(start)

			if err != nil {
				f.logger.Error("fanout_worker_error",
					slog.Int("worker_id", id),
					slog.String("error", err.Error()),
					slog.Duration("duration", duration))

				select {
				case f.errorChan <- err:
				case <-f.ctx.Done():
					return
				}
				continue
			}

			f.logger.Debug("fanout_worker_success",
				slog.Int("worker_id", id),
				slog.Duration("duration", duration))

			select {
			case f.outputChan <- result:
			case <-f.ctx.Done():
				return
			}
		}
	}
}

// Close stops the fan-out processor.
func (f *FanOut[T, U]) Close() {
	f.cancel()
	f.wg.Wait()
}

// BatchProcessor provides efficient batch processing of LDAP operations.
type BatchProcessor[T any] struct {
	client    *LDAP
	batchSize int
	timeout   time.Duration
	processor func(context.Context, *LDAP, []T) error
	logger    *slog.Logger

	batch   []T
	batchMu sync.Mutex
	timer   *time.Timer
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewBatchProcessor creates a new batch processor.
//
// Example:
//
//	processor := NewBatchProcessor(client, 10, 1*time.Second,
//	    func(ctx context.Context, client *LDAP, users []*FullUser) error {
//	        // Process batch of users
//	        for _, user := range users {
//	            _, err := client.CreateUserContext(ctx, *user, "password")
//	            if err != nil {
//	                return err
//	            }
//	        }
//	        return nil
//	    })
//
//	defer processor.Close()
//
//	// Add items for processing
//	for _, user := range users {
//	    processor.Add(user)
//	}
func NewBatchProcessor[T any](client *LDAP, batchSize int, timeout time.Duration,
	processor func(context.Context, *LDAP, []T) error) *BatchProcessor[T] {

	ctx, cancel := context.WithCancel(context.Background())

	bp := &BatchProcessor[T]{
		client:    client,
		batchSize: batchSize,
		timeout:   timeout,
		processor: processor,
		logger:    client.logger,
		batch:     make([]T, 0, batchSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	bp.timer = time.AfterFunc(timeout, bp.flush)
	bp.timer.Stop() // Start stopped

	return bp
}

// Add adds an item to the batch for processing.
func (bp *BatchProcessor[T]) Add(item T) {
	bp.batchMu.Lock()
	defer bp.batchMu.Unlock()

	bp.batch = append(bp.batch, item)

	// Start timer on first item
	if len(bp.batch) == 1 {
		bp.timer.Reset(bp.timeout)
	}

	// Process when batch is full
	if len(bp.batch) >= bp.batchSize {
		bp.timer.Stop()
		go bp.processBatch()
	}
}

// flush processes the current batch (called by timer).
func (bp *BatchProcessor[T]) flush() {
	bp.batchMu.Lock()
	if len(bp.batch) > 0 {
		bp.batchMu.Unlock()
		go bp.processBatch()
	} else {
		bp.batchMu.Unlock()
	}
}

// processBatch processes the current batch.
func (bp *BatchProcessor[T]) processBatch() {
	bp.batchMu.Lock()
	if len(bp.batch) == 0 {
		bp.batchMu.Unlock()
		return
	}

	batch := make([]T, len(bp.batch))
	copy(batch, bp.batch)
	bp.batch = bp.batch[:0] // Reset batch
	bp.batchMu.Unlock()

	bp.wg.Add(1)
	defer bp.wg.Done()

	start := time.Now()
	err := bp.processor(bp.ctx, bp.client, batch)
	duration := time.Since(start)

	if err != nil {
		bp.logger.Error("batch_processor_error",
			slog.Int("batch_size", len(batch)),
			slog.String("error", err.Error()),
			slog.Duration("duration", duration))
	} else {
		bp.logger.Debug("batch_processor_success",
			slog.Int("batch_size", len(batch)),
			slog.Duration("duration", duration))
	}
}

// Close processes any remaining items and shuts down the processor.
func (bp *BatchProcessor[T]) Close() {
	bp.cancel()
	bp.timer.Stop()

	// Process remaining items
	bp.processBatch()

	// Wait for any running batch processing
	bp.wg.Wait()
}

// Semaphore provides a semaphore for controlling concurrent LDAP operations.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a new semaphore with the specified capacity.
func NewSemaphore(capacity int) *Semaphore {
	return &Semaphore{
		ch: make(chan struct{}, capacity),
	}
}

// Acquire acquires a semaphore permit.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release releases a semaphore permit.
// It returns an error if Release is called without a corresponding Acquire.
func (s *Semaphore) Release() error {
	select {
	case <-s.ch:
		return nil
	default:
		return fmt.Errorf("semaphore: release without acquire")
	}
}

// WithSemaphore executes a function with semaphore protection.
func (s *Semaphore) WithSemaphore(ctx context.Context, fn func() error) error {
	if err := s.Acquire(ctx); err != nil {
		return err
	}
	defer func() {
		// Log release error but don't override function error
		if err := s.Release(); err != nil {
			// This should never happen in normal operation
			// Log it for debugging purposes
			slog.Error("semaphore release failed", slog.String("error", err.Error()))
		}
	}()

	return fn()
}

// ConcurrentLDAPOperations provides common patterns for concurrent LDAP operations.
type ConcurrentLDAPOperations struct {
	client    *LDAP
	semaphore *Semaphore
	logger    *slog.Logger
}

// NewConcurrentOperations creates a new concurrent operations helper.
func NewConcurrentOperations(client *LDAP, maxConcurrency int) *ConcurrentLDAPOperations {
	return &ConcurrentLDAPOperations{
		client:    client,
		semaphore: NewSemaphore(maxConcurrency),
		logger:    client.logger,
	}
}

// BulkCreateUsers creates multiple users concurrently with rate limiting.
func (co *ConcurrentLDAPOperations) BulkCreateUsers(ctx context.Context, users []FullUser, password string) []error {
	var wg sync.WaitGroup
	errors := make([]error, len(users))

	for i, user := range users {
		wg.Add(1)
		go func(index int, u FullUser) {
			defer wg.Done()

			err := co.semaphore.WithSemaphore(ctx, func() error {
				_, err := co.client.CreateUserContext(ctx, u, password)
				return err
			})

			errors[index] = err
		}(i, user)
	}

	wg.Wait()
	return errors
}

// BulkFindUsers finds multiple users concurrently.
func (co *ConcurrentLDAPOperations) BulkFindUsers(ctx context.Context, dns []string) ([]*User, []error) {
	var wg sync.WaitGroup
	users := make([]*User, len(dns))
	errors := make([]error, len(dns))

	for i, dn := range dns {
		wg.Add(1)
		go func(index int, userDN string) {
			defer wg.Done()

			var user *User
			var err error

			semErr := co.semaphore.WithSemaphore(ctx, func() error {
				user, err = co.client.FindUserByDNContext(ctx, userDN)
				return err
			})

			if semErr != nil {
				errors[index] = semErr
			} else {
				users[index] = user
				errors[index] = err
			}
		}(i, dn)
	}

	wg.Wait()
	return users, errors
}

// BulkDeleteUsers deletes multiple users concurrently.
func (co *ConcurrentLDAPOperations) BulkDeleteUsers(ctx context.Context, dns []string) []error {
	var wg sync.WaitGroup
	errors := make([]error, len(dns))

	for i, dn := range dns {
		wg.Add(1)
		go func(index int, userDN string) {
			defer wg.Done()

			err := co.semaphore.WithSemaphore(ctx, func() error {
				return co.client.DeleteUserContext(ctx, userDN)
			})

			errors[index] = err
		}(i, dn)
	}

	wg.Wait()
	return errors
}
