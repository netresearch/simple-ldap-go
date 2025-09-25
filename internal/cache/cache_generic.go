package cache

import (
	"container/list"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// GenericCacheEntry represents a cached item with metadata for generic cache
type GenericCacheEntry[T any] struct {
	// Core data
	Key   string
	Value T

	// Timing information
	CreatedAt  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
	TTL        time.Duration

	// Metadata
	Size        int32 // Approximate size in bytes
	AccessCount int64 // Number of times accessed
	IsNegative  bool  // Whether this is a negative cache entry (not found result)
	Compressed  bool  // Whether the value is compressed

	// LRU list element
	element *list.Element
}

// IsExpired checks if the cache entry has expired
func (e *GenericCacheEntry[T]) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the cache entry is getting stale (75% of TTL elapsed)
func (e *GenericCacheEntry[T]) IsStale() bool {
	staleThreshold := e.CreatedAt.Add(time.Duration(float64(e.TTL) * 0.75))
	return time.Now().After(staleThreshold)
}

// GenericCache interface defines the caching operations with type safety
type GenericCache[T any] interface {
	// Basic operations
	Get(key string) (T, bool)
	Set(key string, value T, ttl time.Duration) error
	Delete(key string) bool
	Clear()

	// Context-aware operations
	GetContext(ctx context.Context, key string) (T, bool)
	SetContext(ctx context.Context, key string, value T, ttl time.Duration) error

	// Advanced operations
	GetWithRefresh(key string, refreshFunc func() (T, error)) (T, error)
	SetNegative(key string, ttl time.Duration) error

	// Statistics and management
	Stats() CacheStats
	Close() error
}

// GenericLRUCache implements a type-safe LRU cache with advanced features
type GenericLRUCache[T any] struct {
	config *CacheConfig
	logger *slog.Logger

	// Core data structures
	items   map[string]*GenericCacheEntry[T] // Key -> CacheEntry mapping
	lruList *list.List                       // LRU ordering
	mu      sync.RWMutex                     // Read-write mutex for thread safety

	// Statistics (atomic for thread safety)
	stats CacheStats

	// Background tasks
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Memory management
	memoryUsage int64 // Atomic counter for memory usage

	// Performance timing
	getTimes []time.Duration
	setTimes []time.Duration
	timingMu sync.Mutex

	// Zero value for type T
	zero T
}

// NewGenericLRUCache creates a new type-safe LRU cache with the specified configuration
func NewGenericLRUCache[T any](config *CacheConfig, logger *slog.Logger) (*GenericLRUCache[T], error) {
	if config == nil {
		config = DefaultCacheConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Validate and set defaults
	if config.TTL <= 0 {
		config.TTL = 5 * time.Minute
	}
	if config.MaxSize <= 0 {
		config.MaxSize = 1000
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 1 * time.Minute
	}
	if config.NegativeCacheTTL <= 0 {
		config.NegativeCacheTTL = 30 * time.Second
	}
	if config.MaxMemoryMB <= 0 {
		config.MaxMemoryMB = 64
	}
	if config.CompressionThreshold <= 0 {
		config.CompressionThreshold = 1024
	}

	cache := &GenericLRUCache[T]{
		config:   config,
		logger:   logger.With(slog.String("component", "generic_cache")),
		items:    make(map[string]*GenericCacheEntry[T]),
		lruList:  list.New(),
		stopChan: make(chan struct{}),
		getTimes: make([]time.Duration, 0, 100),
		setTimes: make([]time.Duration, 0, 100),
	}

	// Start background maintenance if cache is enabled
	if config.Enabled {
		cache.startBackgroundTasks()
		cache.logger.Info("Generic cache initialized",
			slog.Bool("enabled", config.Enabled),
			slog.Int("max_size", config.MaxSize),
			slog.Duration("ttl", config.TTL),
			slog.Int("max_memory_mb", config.MaxMemoryMB))
	} else {
		cache.logger.Info("Generic cache disabled")
	}

	return cache, nil
}

// Get retrieves a value from the cache
func (c *GenericLRUCache[T]) Get(key string) (T, bool) {
	if !c.config.Enabled {
		return c.zero, false
	}

	start := time.Now()
	defer func() {
		c.recordGetTime(time.Since(start))
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.stats.Misses, 1)
		c.updateHitRatio()
		return c.zero, false
	}

	// Check if expired
	if entry.IsExpired() {
		c.removeEntry(key)
		atomic.AddInt64(&c.stats.Expirations, 1)
		atomic.AddInt64(&c.stats.Misses, 1)
		c.updateHitRatio()
		return c.zero, false
	}

	// Update LRU and access info
	c.lruList.MoveToFront(entry.element)
	entry.LastAccess = time.Now()
	atomic.AddInt64(&entry.AccessCount, 1)

	// Update stats
	atomic.AddInt64(&c.stats.Hits, 1)
	if entry.IsNegative {
		atomic.AddInt64(&c.stats.NegativeHits, 1)
	}
	c.updateHitRatio()

	return entry.Value, true
}

// GetContext retrieves a value from the cache with context support
func (c *GenericLRUCache[T]) GetContext(ctx context.Context, key string) (T, bool) {
	select {
	case <-ctx.Done():
		return c.zero, false
	default:
		return c.Get(key)
	}
}

// Set stores a value in the cache
func (c *GenericLRUCache[T]) Set(key string, value T, ttl time.Duration) error {
	if !c.config.Enabled {
		return ErrCacheDisabled
	}

	start := time.Now()
	defer func() {
		c.recordSetTime(time.Since(start))
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for existing entry
	if entry, exists := c.items[key]; exists {
		// Update existing entry
		entry.Value = value
		entry.CreatedAt = time.Now()
		entry.LastAccess = time.Now()
		entry.TTL = ttl
		entry.ExpiresAt = time.Now().Add(ttl)
		entry.IsNegative = false
		c.lruList.MoveToFront(entry.element)
		return nil
	}

	// Check size limit
	if len(c.items) >= c.config.MaxSize {
		c.evictOldest()
	}

	// Check memory limit
	if c.checkMemoryLimit() {
		c.evictOldest()
		if c.checkMemoryLimit() {
			return ErrCacheFull
		}
	}

	// Create new entry
	entry := &GenericCacheEntry[T]{
		Key:        key,
		Value:      value,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		TTL:        ttl,
		IsNegative: false,
	}

	// Add to LRU list
	element := c.lruList.PushFront(entry)
	entry.element = element
	c.items[key] = entry

	// Update stats
	atomic.AddInt64(&c.stats.Sets, 1)
	atomic.StoreInt32(&c.stats.TotalEntries, int32(len(c.items)))
	if int32(len(c.items)) > atomic.LoadInt32(&c.stats.MaxEntries) {
		atomic.StoreInt32(&c.stats.MaxEntries, int32(len(c.items)))
	}

	return nil
}

// SetContext stores a value in the cache with context support
func (c *GenericLRUCache[T]) SetContext(ctx context.Context, key string, value T, ttl time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return c.Set(key, value, ttl)
	}
}

// Delete removes a value from the cache
func (c *GenericLRUCache[T]) Delete(key string) bool {
	if !c.config.Enabled {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[key]; exists {
		c.removeEntry(key)
		atomic.AddInt64(&c.stats.Deletes, 1)
		return true
	}

	return false
}

// Clear removes all entries from the cache
func (c *GenericLRUCache[T]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*GenericCacheEntry[T])
	c.lruList.Init()
	atomic.StoreInt32(&c.stats.TotalEntries, 0)
	atomic.StoreInt64(&c.memoryUsage, 0)
}

// GetWithRefresh retrieves a value from the cache, refreshing it if stale or missing
func (c *GenericLRUCache[T]) GetWithRefresh(key string, refreshFunc func() (T, error)) (T, error) {
	if !c.config.Enabled {
		return refreshFunc()
	}

	// Check cache first
	if value, found := c.Get(key); found {
		// Check if stale and refresh is enabled
		c.mu.RLock()
		entry := c.items[key]
		isStale := entry != nil && entry.IsStale()
		c.mu.RUnlock()

		if !isStale || !c.config.RefreshOnAccess {
			return value, nil
		}
	}

	// Refresh the value
	value, err := refreshFunc()
	if err != nil {
		return c.zero, err
	}

	// Store in cache
	if err := c.Set(key, value, c.config.TTL); err != nil {
		c.logger.Warn("Failed to cache refreshed value",
			slog.String("key", key),
			slog.String("error", err.Error()))
	}

	atomic.AddInt64(&c.stats.RefreshOps, 1)
	return value, nil
}

// SetNegative stores a negative (not found) result in the cache
func (c *GenericLRUCache[T]) SetNegative(key string, ttl time.Duration) error {
	if !c.config.Enabled {
		return ErrCacheDisabled
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for existing entry
	if entry, exists := c.items[key]; exists {
		// Update existing entry as negative
		entry.Value = c.zero
		entry.CreatedAt = time.Now()
		entry.LastAccess = time.Now()
		entry.TTL = ttl
		entry.ExpiresAt = time.Now().Add(ttl)
		entry.IsNegative = true
		c.lruList.MoveToFront(entry.element)
		atomic.AddInt32(&c.stats.NegativeEntries, 1)
		return nil
	}

	// Check size limit
	if len(c.items) >= c.config.MaxSize {
		c.evictOldest()
	}

	// Create new negative entry
	entry := &GenericCacheEntry[T]{
		Key:        key,
		Value:      c.zero,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		TTL:        ttl,
		IsNegative: true,
	}

	// Add to LRU list
	element := c.lruList.PushFront(entry)
	entry.element = element
	c.items[key] = entry

	// Update stats
	atomic.AddInt32(&c.stats.NegativeEntries, 1)
	atomic.StoreInt32(&c.stats.TotalEntries, int32(len(c.items)))

	return nil
}

// Stats returns current cache statistics
func (c *GenericLRUCache[T]) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.TotalEntries = int32(len(c.items))
	stats.MemoryUsageBytes = atomic.LoadInt64(&c.memoryUsage)
	stats.MemoryUsageMB = float64(stats.MemoryUsageBytes) / (1024 * 1024)

	// Calculate average times
	c.timingMu.Lock()
	if len(c.getTimes) > 0 {
		var total time.Duration
		for _, t := range c.getTimes {
			total += t
		}
		stats.AvgGetTime = total / time.Duration(len(c.getTimes))
	}
	if len(c.setTimes) > 0 {
		var total time.Duration
		for _, t := range c.setTimes {
			total += t
		}
		stats.AvgSetTime = total / time.Duration(len(c.setTimes))
	}
	c.timingMu.Unlock()

	return stats
}

// Close stops the cache and its background tasks
func (c *GenericLRUCache[T]) Close() error {
	if c.ticker != nil {
		c.ticker.Stop()
	}

	close(c.stopChan)
	c.wg.Wait()

	c.logger.Info("Generic cache closed",
		slog.Int64("total_hits", c.stats.Hits),
		slog.Int64("total_misses", c.stats.Misses),
		slog.Float64("hit_ratio", c.stats.HitRatio))

	return nil
}

// Private helper methods

func (c *GenericLRUCache[T]) removeEntry(key string) {
	if entry, exists := c.items[key]; exists {
		c.lruList.Remove(entry.element)
		delete(c.items, key)
		if entry.IsNegative {
			atomic.AddInt32(&c.stats.NegativeEntries, -1)
		}
		atomic.StoreInt32(&c.stats.TotalEntries, int32(len(c.items)))
	}
}

func (c *GenericLRUCache[T]) evictOldest() {
	if elem := c.lruList.Back(); elem != nil {
		entry := elem.Value.(*GenericCacheEntry[T])
		c.removeEntry(entry.Key)
		atomic.AddInt64(&c.stats.Evictions, 1)
	}
}

func (c *GenericLRUCache[T]) checkMemoryLimit() bool {
	maxMemoryBytes := int64(c.config.MaxMemoryMB) * 1024 * 1024
	return atomic.LoadInt64(&c.memoryUsage) >= maxMemoryBytes
}

func (c *GenericLRUCache[T]) updateHitRatio() {
	hits := atomic.LoadInt64(&c.stats.Hits)
	misses := atomic.LoadInt64(&c.stats.Misses)
	total := hits + misses
	if total > 0 {
		c.stats.HitRatio = float64(hits) / float64(total) * 100
	}
}

func (c *GenericLRUCache[T]) recordGetTime(d time.Duration) {
	c.timingMu.Lock()
	defer c.timingMu.Unlock()
	c.getTimes = append(c.getTimes, d)
	if len(c.getTimes) > 100 {
		c.getTimes = c.getTimes[1:]
	}
}

func (c *GenericLRUCache[T]) recordSetTime(d time.Duration) {
	c.timingMu.Lock()
	defer c.timingMu.Unlock()
	c.setTimes = append(c.setTimes, d)
	if len(c.setTimes) > 100 {
		c.setTimes = c.setTimes[1:]
	}
}

func (c *GenericLRUCache[T]) startBackgroundTasks() {
	c.ticker = time.NewTicker(c.config.RefreshInterval)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.ticker.C:
				c.performMaintenance()
			case <-c.stopChan:
				return
			}
		}
	}()
}

func (c *GenericLRUCache[T]) performMaintenance() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var keysToRemove []string

	// Find expired entries
	for key, entry := range c.items {
		if now.After(entry.ExpiresAt) {
			keysToRemove = append(keysToRemove, key)
		}
	}

	// Remove expired entries
	for _, key := range keysToRemove {
		c.removeEntry(key)
		atomic.AddInt64(&c.stats.Expirations, 1)
	}

	atomic.AddInt64(&c.stats.CleanupOps, 1)

	if len(keysToRemove) > 0 {
		c.logger.Debug("Cache maintenance completed",
			slog.Int("expired_entries", len(keysToRemove)),
			slog.Int("remaining_entries", len(c.items)))
	}
}

// StringCache provides a type-safe cache for string values
type StringCache = GenericLRUCache[string]

// NewStringCache creates a new cache specifically for string values
func NewStringCache(config *CacheConfig, logger *slog.Logger) (*StringCache, error) {
	return NewGenericLRUCache[string](config, logger)
}
