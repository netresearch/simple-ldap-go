# Migration Guide: Optimized Implementations

## ✅ Migration Completed

As of the latest version, the dual implementations have been successfully merged into unified implementations with feature flags.

## Previous State (Now Resolved)

This library previously had dual implementations for several core components:

### 1. User Operations
- **Standard**: `users.go` (967 lines)
- **Optimized**: `users_optimized.go` (812 lines)
- **Differences**: Optimized version adds caching, batch operations, and performance monitoring

### 2. Group Operations
- **Standard**: `groups.go` (221 lines)
- **Optimized**: `groups_optimized.go` (843 lines)
- **Differences**: Optimized version adds caching, concurrent search, and metrics

### 3. Client Implementation
- **Standard**: `client.go` (733 lines)
- **Modern**: `modern_client.go` (701 lines)
- **Differences**: Modern version uses context-aware patterns and improved error handling

## Why Dual Implementations Exist

The optimized versions were added to provide:
1. **Caching**: LRU cache for frequently accessed objects
2. **Performance Monitoring**: Built-in metrics and alerting
3. **Batch Operations**: Efficient bulk operations
4. **Context Support**: Better cancellation and timeout handling

## ✅ Completed Migration Strategy

The recommended approach has been successfully implemented:

### Unified Implementation with Feature Flags

Optimized features have been merged into unified implementations with feature flags:

```go
type Config struct {
    // Existing fields...

    // Optimization flags (IMPLEMENTED)
    EnableOptimizations bool // Enable all optimizations
    EnableCache         bool // Enable caching separately
    EnableMetrics       bool // Enable performance metrics separately
    EnableBulkOps       bool // Enable bulk operations separately
}
```

**✅ Benefits Achieved**:
- ✅ Single source of truth
- ✅ Reduced maintenance burden
- ✅ Clear upgrade path
- ✅ Backward compatibility maintained

**✅ Implementation Completed**:
1. ✅ Added feature flags to Config
2. ✅ Merged optimized code into unified files (users_extended.go, groups_extended.go)
3. ✅ Added NewWithOptions with enhanced initialization
4. ✅ Removed deprecated optimized files
5. ✅ All tests passing

### Option 2: Complete Migration to Optimized

Replace standard implementations with optimized versions:

```bash
mv users_optimized.go users.go
mv groups_optimized.go groups.go
mv modern_client.go client.go
```

**Benefits**:
- Immediate performance improvements
- Simpler codebase

**Risks**:
- Breaking changes for existing users
- Forced adoption of caching/metrics

## ✅ New Unified Usage

The migration provides both standard and optimized methods:

### Standard Methods (unchanged)
```go
// Standard usage (unchanged)
user, err := client.FindUserByDN(dn)
user, err := client.FindUserByDNContext(ctx, dn)
```

### New WithOptions Methods (optimized)
```go
// Optimized usage with caching and performance monitoring
user, err := client.FindUserByDNWithOptions(ctx, dn, &SearchOptions{
    UseCache: true,
    TTL: 5 * time.Minute,
})

// Groups with options
group, err := client.FindGroupByDNWithOptions(ctx, dn, &SearchOptions{
    UseCache: true,
    TTL: 5 * time.Minute,
})
```

### Backward Compatibility (deprecated but functional)
```go
// These still work but are deprecated - they redirect to WithOptions methods
user, err := client.FindUserByDNOptimized(ctx, dn, &SearchOptions{
    UseCache: true,
    TTL: 5 * time.Minute,
})
```

### Enhanced Client Creation
```go
// NewWithOptions automatically enables optimizations
client, err := ldap.NewWithOptions(config, username, password,
    ldap.WithConnectionPool(&ldap.PoolConfig{MaxConnections: 20}),
    ldap.WithCache(&ldap.CacheConfig{Enabled: true, TTL: 5 * time.Minute}),
)

// Convenience constructors
client, err := ldap.NewHighPerformanceClient(config, username, password)
client, err := ldap.NewCachedClient(config, username, password, 1000, 5*time.Minute)
```

## Recommendation

We recommend **Option 1** (merge with feature flags) because it:
- Maintains backward compatibility
- Allows gradual adoption
- Provides flexibility for different use cases
- Reduces code duplication

## Migration Timeline

1. **Phase 1** (Current): Document dual implementations
2. **Phase 2**: Add feature flags and merge code
3. **Phase 3**: Deprecate optimized files with warnings
4. **Phase 4**: Remove deprecated files (after 2 releases)

## For Contributors

When adding new features:
- Add to the standard implementation only
- Use feature flags for optional optimizations
- Don't create new `*_optimized.go` files
- Follow the patterns in existing merged code