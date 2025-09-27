# Migration Guide: Optimized Implementations

## Current State

This library currently has dual implementations for several core components:

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

## Migration Strategy

### Option 1: Merge Into Single Implementation (Recommended)

Merge optimized features into the standard files with feature flags:

```go
type Config struct {
    // Existing fields...

    // Optimization flags
    EnableCache     bool
    EnableMetrics   bool
    EnableBatching  bool
}
```

**Benefits**:
- Single source of truth
- Reduced maintenance burden
- Clear upgrade path

**Timeline**:
1. Add feature flags to Config
2. Merge optimized code into standard files
3. Deprecate optimized files
4. Remove after transition period

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

## Current Usage

To use optimized implementations:

```go
// Standard usage
user, err := client.FindUserByDN(dn)

// Optimized usage (with caching)
user, err := client.FindUserByDNOptimized(ctx, dn, &SearchOptions{
    UseCache: true,
    CacheTTL: 5 * time.Minute,
})
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