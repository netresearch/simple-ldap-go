package ldap

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrCacheDisabled is returned when cache operations are performed on a disabled cache
	ErrCacheDisabled = errors.New("cache is disabled")
	// ErrCacheKeyNotFound is returned when a cache key is not found
	ErrCacheKeyNotFound = errors.New("cache key not found")
	// ErrCacheFull is returned when the cache has reached its maximum size
	ErrCacheFull = errors.New("cache is full")
)

// CacheStats contains cache performance statistics
type CacheStats struct {
	Hits             int64         `json:"hits"`
	Misses           int64         `json:"misses"`
	HitRatio         float64       `json:"hit_ratio"`
	TotalEntries     int32         `json:"total_entries"`
	MaxEntries       int32         `json:"max_entries"`
	MemoryUsageMB    float64       `json:"memory_usage_mb"`
	MemoryUsageBytes int64         `json:"memory_usage_bytes"`
	AvgGetTime       time.Duration `json:"avg_get_time"`
	AvgSetTime       time.Duration `json:"avg_set_time"`
	Sets             int64         `json:"sets"`
	Deletes          int64         `json:"deletes"`
	Evictions        int64         `json:"evictions"`
	Expirations      int64         `json:"expirations"`
	NegativeHits     int64         `json:"negative_hits"`
	NegativeEntries  int32         `json:"negative_entries"`
	RefreshOps       int64         `json:"refresh_ops"`
	CleanupOps       int64         `json:"cleanup_ops"`
}

// CacheConfig holds the configuration for the intelligent caching system
type CacheConfig struct {
	// Enabled controls whether caching is active (default: false for backwards compatibility)
	Enabled bool
	// TTL is the default time-to-live for cache entries (default: 5 minutes)
	TTL time.Duration
	// MaxSize is the maximum number of cache entries (default: 1000)
	MaxSize int
	// RefreshInterval is how often to perform background cache maintenance (default: 1 minute)
	RefreshInterval time.Duration
	// RefreshOnAccess enables automatic refresh of stale entries on access (default: true)
	RefreshOnAccess bool
	// NegativeCacheTTL is the TTL for negative (not found) results (default: 30 seconds)
	NegativeCacheTTL time.Duration
	// MaxMemoryMB is the approximate maximum memory usage in MB (default: 64 MB)
	MaxMemoryMB int
	// CompressionEnabled enables gzip compression for large entries (default: false)
	CompressionEnabled bool
	// CompressionThreshold is the size threshold for compression in bytes (default: 1KB)
	CompressionThreshold int
}

// DefaultCacheConfig returns a CacheConfig with sensible defaults
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:              false, // Disabled by default for backwards compatibility
		TTL:                  5 * time.Minute,
		MaxSize:              1000,
		RefreshInterval:      1 * time.Minute,
		RefreshOnAccess:      true,
		NegativeCacheTTL:     30 * time.Second,
		MaxMemoryMB:          64,
		CompressionEnabled:   false,
		CompressionThreshold: 1024,
	}
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	// Core data
	Key   string
	Value interface{}

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
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the cache entry is getting stale (75% of TTL elapsed)
func (e *CacheEntry) IsStale() bool {
	staleThreshold := e.CreatedAt.Add(time.Duration(float64(e.TTL) * 0.75))
	return time.Now().After(staleThreshold)
}

// Cache interface defines the caching operations
type Cache interface {
	// Basic operations
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration) error
	Delete(key string) bool
	Clear()

	// Context-aware operations
	GetContext(ctx context.Context, key string) (interface{}, bool)
	SetContext(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	// Advanced operations
	GetWithRefresh(key string, refreshFunc func() (interface{}, error)) (interface{}, error)
	SetNegative(key string, ttl time.Duration) error

	// Statistics and management
	Stats() CacheStats
	Close() error
}

// LRUCache implements an intelligent LRU cache with advanced features
type LRUCache struct {
	config *CacheConfig
	logger *slog.Logger

	// Core data structures
	items   map[string]*CacheEntry // Key -> CacheEntry mapping
	lruList *list.List             // LRU ordering
	mu      sync.RWMutex           // Read-write mutex for thread safety

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
}

// NewLRUCache creates a new LRU cache with the specified configuration
func NewLRUCache(config *CacheConfig, logger *slog.Logger) (*LRUCache, error) {
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

	cache := &LRUCache{
		config:   config,
		logger:   logger,
		items:    make(map[string]*CacheEntry, config.MaxSize),
		lruList:  list.New(),
		stopChan: make(chan struct{}),
		getTimes: make([]time.Duration, 0, 1000),
		setTimes: make([]time.Duration, 0, 1000),
	}

	// Start background maintenance if cache is enabled
	if config.Enabled {
		cache.startBackgroundTasks()
		logger.Info("lru_cache_created",
			slog.Int("max_size", config.MaxSize),
			slog.Duration("ttl", config.TTL),
			slog.Int("max_memory_mb", config.MaxMemoryMB),
			slog.Bool("compression_enabled", config.CompressionEnabled))
	}

	return cache, nil
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	return c.GetContext(context.Background(), key)
}

// GetContext retrieves a value from the cache with context support
func (c *LRUCache) GetContext(ctx context.Context, key string) (interface{}, bool) {
	if !c.config.Enabled {
		return nil, false
	}

	start := time.Now()
	defer func() { c.recordGetTime(time.Since(start)) }()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, false
	default:
	}

	c.mu.RLock()
	entry, exists := c.items[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&c.stats.Misses, 1)
		return nil, false
	}

	// Check expiration
	if entry.IsExpired() {
		c.mu.Lock()
		c.removeEntry(key, entry)
		c.mu.Unlock()
		atomic.AddInt64(&c.stats.Misses, 1)
		atomic.AddInt64(&c.stats.Expirations, 1)
		return nil, false
	}

	// Performance optimization: Reduce lock contention by batching LRU updates
	// Only update LastAccess and LRU position if entry is getting stale
	atomic.AddInt64(&entry.AccessCount, 1)
	now := time.Now()

	// Only take exclusive lock if LastAccess is stale (>1 second old) to reduce contention
	if now.Sub(entry.LastAccess) > time.Second {
		c.mu.Lock()
		// Double-check after acquiring lock to avoid race conditions
		if now.Sub(entry.LastAccess) > time.Second {
			entry.LastAccess = now
			// Move to front of LRU list
			c.lruList.MoveToFront(entry.element)
		}
		c.mu.Unlock()
	}

	// Check if entry is negative
	if entry.IsNegative {
		atomic.AddInt64(&c.stats.NegativeHits, 1)
	}

	atomic.AddInt64(&c.stats.Hits, 1)

	c.logger.Debug("cache_hit",
		slog.String("key", key),
		slog.Bool("is_negative", entry.IsNegative),
		slog.Duration("age", time.Since(entry.CreatedAt)))

	return entry.Value, true
}

// Set stores a value in the cache with the specified TTL
func (c *LRUCache) Set(key string, value interface{}, ttl time.Duration) error {
	return c.SetContext(context.Background(), key, value, ttl)
}

// SetContext stores a value in the cache with context support
func (c *LRUCache) SetContext(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if !c.config.Enabled {
		return ErrCacheDisabled
	}

	start := time.Now()
	defer func() { c.recordSetTime(time.Since(start)) }()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if ttl <= 0 {
		ttl = c.config.TTL
	}

	// Estimate entry size
	entrySize := c.estimateEntrySize(key, value)

	// Check memory limits
	currentMemory := atomic.LoadInt64(&c.memoryUsage)
	maxMemoryBytes := int64(c.config.MaxMemoryMB * 1024 * 1024)
	if currentMemory+int64(entrySize) > maxMemoryBytes {
		// Try to make space by evicting LRU entries
		if err := c.evictForSpace(int64(entrySize)); err != nil {
			return err
		}
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		CreatedAt:   now,
		LastAccess:  now,
		ExpiresAt:   now.Add(ttl),
		TTL:         ttl,
		Size:        entrySize,
		AccessCount: 0,
		IsNegative:  false,
		Compressed:  false,
	}

	// Compress large entries if enabled
	if c.config.CompressionEnabled && entrySize > int32(c.config.CompressionThreshold) {
		if compressedValue, err := c.compressValue(value); err == nil {
			entry.Value = compressedValue
			entry.Compressed = true
			entry.Size = c.estimateEntrySize(key, compressedValue)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if entry already exists
	if existingEntry, exists := c.items[key]; exists {
		// Update existing entry
		atomic.AddInt64(&c.memoryUsage, -int64(existingEntry.Size))
		c.lruList.Remove(existingEntry.element)
	}

	// Check size limits
	if len(c.items) >= c.config.MaxSize && c.items[key] == nil {
		// Evict LRU entry
		c.evictLRU()
	}

	// Add to LRU list
	entry.element = c.lruList.PushFront(entry)
	c.items[key] = entry
	atomic.AddInt64(&c.memoryUsage, int64(entry.Size))
	atomic.AddInt64(&c.stats.Sets, 1)

	// Update max entries stat
	currentEntries := int32(len(c.items))
	for {
		maxEntries := atomic.LoadInt32(&c.stats.MaxEntries)
		if currentEntries <= maxEntries || atomic.CompareAndSwapInt32(&c.stats.MaxEntries, maxEntries, currentEntries) {
			break
		}
	}

	c.logger.Debug("cache_set",
		slog.String("key", key),
		slog.Duration("ttl", ttl),
		slog.Int("size", int(entrySize)),
		slog.Bool("compressed", entry.Compressed))

	return nil
}

// SetNegative stores a negative cache entry (for "not found" results)
func (c *LRUCache) SetNegative(key string, ttl time.Duration) error {
	if !c.config.Enabled {
		return ErrCacheDisabled
	}

	if ttl <= 0 {
		ttl = c.config.NegativeCacheTTL
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:         key,
		Value:       nil,
		CreatedAt:   now,
		LastAccess:  now,
		ExpiresAt:   now.Add(ttl),
		TTL:         ttl,
		Size:        c.estimateEntrySize(key, nil),
		AccessCount: 0,
		IsNegative:  true,
		Compressed:  false,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if entry already exists
	if existingEntry, exists := c.items[key]; exists {
		atomic.AddInt64(&c.memoryUsage, -int64(existingEntry.Size))
		c.lruList.Remove(existingEntry.element)
	}

	// Check size limits
	if len(c.items) >= c.config.MaxSize && c.items[key] == nil {
		c.evictLRU()
	}

	entry.element = c.lruList.PushFront(entry)
	c.items[key] = entry
	atomic.AddInt64(&c.memoryUsage, int64(entry.Size))
	atomic.AddInt32(&c.stats.NegativeEntries, 1)

	c.logger.Debug("negative_cache_set",
		slog.String("key", key),
		slog.Duration("ttl", ttl))

	return nil
}

// Delete removes a value from the cache
func (c *LRUCache) Delete(key string) bool {
	if !c.config.Enabled {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.items[key]
	if !exists {
		return false
	}

	c.removeEntry(key, entry)
	atomic.AddInt64(&c.stats.Deletes, 1)

	c.logger.Debug("cache_delete",
		slog.String("key", key))

	return true
}

// Clear removes all entries from the cache
func (c *LRUCache) Clear() {
	if !c.config.Enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entryCount := len(c.items)

	for key, entry := range c.items {
		c.removeEntry(key, entry)
	}

	c.logger.Info("cache_cleared",
		slog.Int("entries_removed", entryCount))
}

// GetWithRefresh retrieves a value, refreshing it if stale
func (c *LRUCache) GetWithRefresh(key string, refreshFunc func() (interface{}, error)) (interface{}, error) {
	if !c.config.Enabled || !c.config.RefreshOnAccess {
		// Fall back to refresh function if cache is disabled
		return refreshFunc()
	}

	// Try to get from cache first
	if value, found := c.Get(key); found {
		// Check if entry is stale and needs refresh
		c.mu.RLock()
		entry := c.items[key]
		isStale := entry != nil && entry.IsStale()
		c.mu.RUnlock()

		if !isStale {
			return value, nil
		}

		// Entry is stale, refresh in background and return current value
		go func() {
			if newValue, err := refreshFunc(); err == nil {
				_ = c.Set(key, newValue, c.config.TTL)
				atomic.AddInt64(&c.stats.RefreshOps, 1)
			}
		}()

		return value, nil
	}

	// Not in cache, fetch and cache
	value, err := refreshFunc()
	if err != nil {
		// Cache negative result
		_ = c.SetNegative(key, c.config.NegativeCacheTTL)
		return nil, err
	}

	_ = c.Set(key, value, c.config.TTL)
	return value, nil
}

// Stats returns current cache statistics
func (c *LRUCache) Stats() CacheStats {
	c.mu.RLock()
	totalEntries := int32(len(c.items))
	var negativeEntries int32
	for _, entry := range c.items {
		if entry.IsNegative {
			negativeEntries++
		}
	}
	c.mu.RUnlock()

	hits := atomic.LoadInt64(&c.stats.Hits)
	misses := atomic.LoadInt64(&c.stats.Misses)
	total := hits + misses

	var hitRatio float64
	if total > 0 {
		hitRatio = float64(hits) / float64(total) * 100
	}

	memoryBytes := atomic.LoadInt64(&c.memoryUsage)
	memoryMB := float64(memoryBytes) / (1024 * 1024)

	c.timingMu.Lock()
	avgGetTime := c.calculateAverageTime(c.getTimes)
	avgSetTime := c.calculateAverageTime(c.setTimes)
	c.timingMu.Unlock()

	return CacheStats{
		Hits:             hits,
		Misses:           misses,
		HitRatio:         hitRatio,
		TotalEntries:     totalEntries,
		MaxEntries:       atomic.LoadInt32(&c.stats.MaxEntries),
		MemoryUsageBytes: memoryBytes,
		MemoryUsageMB:    memoryMB,
		Sets:             atomic.LoadInt64(&c.stats.Sets),
		Deletes:          atomic.LoadInt64(&c.stats.Deletes),
		Evictions:        atomic.LoadInt64(&c.stats.Evictions),
		Expirations:      atomic.LoadInt64(&c.stats.Expirations),
		AvgGetTime:       avgGetTime,
		AvgSetTime:       avgSetTime,
		NegativeHits:     atomic.LoadInt64(&c.stats.NegativeHits),
		NegativeEntries:  negativeEntries,
		RefreshOps:       atomic.LoadInt64(&c.stats.RefreshOps),
		CleanupOps:       atomic.LoadInt64(&c.stats.CleanupOps),
	}
}

// Close shuts down the cache and releases resources
func (c *LRUCache) Close() error {
	if !c.config.Enabled {
		return nil
	}

	if c.stopChan != nil {
		close(c.stopChan)
		c.wg.Wait()
	}

	if c.ticker != nil {
		c.ticker.Stop()
	}

	c.Clear()

	c.logger.Info("cache_closed",
		slog.Int64("total_hits", atomic.LoadInt64(&c.stats.Hits)),
		slog.Int64("total_misses", atomic.LoadInt64(&c.stats.Misses)),
		slog.Float64("final_hit_ratio", c.Stats().HitRatio))

	return nil
}

// Helper methods

// removeEntry removes an entry from both the map and LRU list
func (c *LRUCache) removeEntry(key string, entry *CacheEntry) {
	delete(c.items, key)
	if entry.element != nil {
		c.lruList.Remove(entry.element)
	}
	atomic.AddInt64(&c.memoryUsage, -int64(entry.Size))
	if entry.IsNegative {
		atomic.AddInt32(&c.stats.NegativeEntries, -1)
	}
}

// evictLRU removes the least recently used entry
func (c *LRUCache) evictLRU() {
	if c.lruList.Len() == 0 {
		return
	}

	oldest := c.lruList.Back()
	if oldest != nil {
		entry := oldest.Value.(*CacheEntry)
		c.removeEntry(entry.Key, entry)
		atomic.AddInt64(&c.stats.Evictions, 1)

		c.logger.Debug("cache_eviction",
			slog.String("key", entry.Key),
			slog.Duration("age", time.Since(entry.CreatedAt)))
	}
}

// evictForSpace evicts entries to make room for the specified size
func (c *LRUCache) evictForSpace(neededBytes int64) error {
	maxMemoryBytes := int64(c.config.MaxMemoryMB * 1024 * 1024)
	currentMemory := atomic.LoadInt64(&c.memoryUsage)

	if currentMemory+neededBytes <= maxMemoryBytes {
		return nil // No eviction needed
	}

	bytesToFree := (currentMemory + neededBytes) - maxMemoryBytes
	bytesFreed := int64(0)
	evictions := 0

	// Evict LRU entries until we have enough space
	for bytesFreed < bytesToFree && c.lruList.Len() > 0 {
		oldest := c.lruList.Back()
		if oldest == nil {
			break
		}

		entry := oldest.Value.(*CacheEntry)
		entrySize := int64(entry.Size)
		c.removeEntry(entry.Key, entry)
		bytesFreed += entrySize
		evictions++
		atomic.AddInt64(&c.stats.Evictions, 1)
	}

	if bytesFreed < bytesToFree {
		return ErrCacheFull
	}

	c.logger.Debug("cache_space_eviction",
		slog.Int("evictions", evictions),
		slog.Int64("bytes_freed", bytesFreed))

	return nil
}

// estimateEntrySize calculates approximate memory usage for a cache entry
func (c *LRUCache) estimateEntrySize(key string, value interface{}) int32 {
	size := len(key) + 8 // Key string + basic overhead

	if value == nil {
		return int32(size + 16) // Base entry overhead
	}

	switch v := value.(type) {
	case string:
		size += len(v)
	case []byte:
		size += len(v)
	case *User:
		size += len(v.Object.dn) + len(v.SAMAccountName) + len(v.Description)
		if v.Mail != nil {
			size += len(*v.Mail)
		}
		size += len(v.Groups) * 50 // Estimate 50 chars per DN
	case *Group:
		size += len(v.Object.dn)
		size += len(v.Members) * 50 // Estimate 50 chars per member DN
	case []User:
		for _, u := range v {
			size += len(u.Object.dn) + len(u.SAMAccountName) + len(u.Description)
			if u.Mail != nil {
				size += len(*u.Mail)
			}
			size += len(u.Groups) * 50
		}
	case []Group:
		for _, g := range v {
			size += len(g.Object.dn)
			size += len(g.Members) * 50
		}
	default:
		// For unknown types, use a conservative estimate
		size += 256
	}

	return int32(size + 64) // Add overhead for CacheEntry struct
}

// compressValue compresses a value using gzip (placeholder implementation)
func (c *LRUCache) compressValue(value interface{}) (interface{}, error) {
	// TODO: Implement actual compression if needed
	// For now, return the value unchanged
	return value, nil
}

// recordGetTime records the timing for get operations
func (c *LRUCache) recordGetTime(duration time.Duration) {
	c.timingMu.Lock()
	defer c.timingMu.Unlock()

	if len(c.getTimes) >= 1000 {
		// Keep only the most recent 1000 timings
		copy(c.getTimes, c.getTimes[1:])
		c.getTimes[999] = duration
	} else {
		c.getTimes = append(c.getTimes, duration)
	}
}

// recordSetTime records the timing for set operations
func (c *LRUCache) recordSetTime(duration time.Duration) {
	c.timingMu.Lock()
	defer c.timingMu.Unlock()

	if len(c.setTimes) >= 1000 {
		// Keep only the most recent 1000 timings
		copy(c.setTimes, c.setTimes[1:])
		c.setTimes[999] = duration
	} else {
		c.setTimes = append(c.setTimes, duration)
	}
}

// calculateAverageTime calculates the average from a slice of durations
func (c *LRUCache) calculateAverageTime(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}

	return total / time.Duration(len(times))
}

// startBackgroundTasks starts maintenance routines
func (c *LRUCache) startBackgroundTasks() {
	c.ticker = time.NewTicker(c.config.RefreshInterval)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.ticker.Stop()

		for {
			select {
			case <-c.ticker.C:
				c.performMaintenance()
			case <-c.stopChan:
				return
			}
		}
	}()

	c.logger.Debug("cache_background_tasks_started",
		slog.Duration("refresh_interval", c.config.RefreshInterval))
}

// performMaintenance performs periodic cache maintenance
func (c *LRUCache) performMaintenance() {
	start := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove expired entries
	var expiredKeys []string
	for key, entry := range c.items {
		if entry.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		entry := c.items[key]
		c.removeEntry(key, entry)
		atomic.AddInt64(&c.stats.Expirations, 1)
	}

	// Force GC if memory usage is high
	memoryUsage := atomic.LoadInt64(&c.memoryUsage)
	maxMemoryBytes := int64(c.config.MaxMemoryMB * 1024 * 1024)
	if memoryUsage > maxMemoryBytes*8/10 { // 80% threshold
		runtime.GC()
	}

	atomic.AddInt64(&c.stats.CleanupOps, 1)

	if len(expiredKeys) > 0 {
		c.logger.Debug("cache_maintenance_completed",
			slog.Int("expired_removed", len(expiredKeys)),
			slog.Duration("duration", time.Since(start)),
			slog.Int64("memory_usage_mb", memoryUsage/(1024*1024)))
	}
}

// GenerateCacheKey creates a cache key from multiple components
func GenerateCacheKey(operation string, components ...string) string {
	// Create a hash-based key to avoid key collisions and length issues
	hasher := sha256.New()
	hasher.Write([]byte(operation))
	for _, comp := range components {
		hasher.Write([]byte(":"))
		hasher.Write([]byte(comp))
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Create a human-readable prefix
	prefix := operation
	if len(components) > 0 {
		prefix += ":" + components[0]
	}
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}

	return fmt.Sprintf("%s:%s", prefix, hash[:16])
}
