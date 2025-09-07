# Go LDAP Library Modernization Plan

## Current Architecture Analysis

### Codebase Overview
- **Total Size**: ~6,500 lines of Go code
- **Go Version**: Currently using Go 1.23.0 with toolchain 1.25.0
- **Core Files**: 
  - `client.go` (117 lines) - Core LDAP client 
  - `auth.go` (166 lines) - Authentication functions
  - `users.go` (439 lines) - User CRUD operations
  - `groups.go` (103 lines) - Group operations
  - `computers.go` (212 lines) - Computer account operations
  - `utils.go` (65 lines) - Utility functions
  - `uac.go` (313 lines) - User Account Control handling
  - `object.go` (29 lines) - Base LDAP object
- **Test Coverage**: Comprehensive with ~2,400 lines of test code
- **Dependencies**: Uses `github.com/go-ldap/ldap/v3` and `golang.org/x/text`

### Current Limitations

1. **No Context Support**
   - All operations lack `context.Context` parameters
   - No timeout control or cancellation capability
   - No distributed tracing support

2. **Basic Error Handling**
   - Simple error returns without error wrapping
   - Limited error context and debugging information
   - No structured error types for different failure modes

3. **No Structured Logging**
   - No logging framework integration
   - Debugging issues require external tools
   - No operational visibility

4. **Manual Connection Management**
   - Each operation creates and closes connections
   - No connection pooling or reuse
   - Potential connection leaks if defer statements fail

5. **Limited Input Validation**
   - Basic LDAP filter escaping only
   - No comprehensive input sanitization
   - Potential injection vulnerabilities

6. **Performance Limitations**
   - No caching capabilities
   - No bulk operation optimizations
   - Inefficient for high-volume operations

## Modernization Strategy

### Phase 1: Core Infrastructure (Weeks 1-2)

#### 1.1 Context Integration
**Target**: Add context.Context support throughout the API

**Go Features**:
- `context.Context` (Go 1.7+) for cancellation and timeouts
- `context.WithTimeout`, `context.WithCancel` for operation control
- `context.WithValue` for request-scoped data (tracing IDs, etc.)

**Implementation**:
```go
// Before
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (*User, error)

// After - Add context-aware methods
func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (*User, error)

// Maintain backward compatibility with wrapper
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (*User, error) {
    return l.FindUserBySAMAccountNameContext(context.Background(), sAMAccountName)
}
```

**Files to Modify**:
- All files with LDAP operations
- New internal context utilities

#### 1.2 Structured Logging with log/slog
**Target**: Implement comprehensive logging with Go 1.21+ slog

**Go Features**:
- `log/slog` (Go 1.21+) for structured logging
- Contextual logging with request IDs
- Performance-optimized logging levels

**Implementation**:
```go
type LDAP struct {
    config Config
    user     string
    password string
    logger   *slog.Logger  // Add structured logger
}

// Throughout operations
slog.InfoContext(ctx, "LDAP operation started", 
    "operation", "FindUserBySAMAccountName",
    "sAMAccountName", sAMAccountName,
    "baseDN", l.config.BaseDN)
```

#### 1.3 Enhanced Error Handling
**Target**: Implement error wrapping and structured error types

**Go Features**:
- `fmt.Errorf` with `%w` verb (Go 1.13+) for error wrapping
- `errors.Is` and `errors.As` for error inspection
- Custom error types with context

**Implementation**:
```go
// Enhanced error types
type LDAPError struct {
    Op       string    // Operation name
    DN       string    // Distinguished Name if applicable
    Code     int       // LDAP result code
    Err      error     // Underlying error
    Context  map[string]interface{} // Additional context
}

func (e *LDAPError) Error() string {
    return fmt.Sprintf("LDAP %s failed for DN %s: %v", e.Op, e.DN, e.Err)
}

func (e *LDAPError) Unwrap() error { return e.Err }

// Usage
if err != nil {
    return nil, fmt.Errorf("FindUserBySAMAccountName(%s): %w", 
        sAMAccountName, &LDAPError{
            Op: "search",
            DN: l.config.BaseDN,
            Code: ldapErr.ResultCode,
            Err: err,
            Context: map[string]interface{}{
                "filter": filter,
                "attributes": userFields,
            },
        })
}
```

### Phase 2: Connection Management & Performance (Weeks 3-4)

#### 2.1 Connection Pool Implementation
**Target**: Add connection pooling for improved performance and resource management

**Go Features**:
- `sync.Pool` for connection reuse
- Context-aware connection management
- Graceful shutdown with contexts

**Implementation**:
```go
type ConnectionPool struct {
    config    Config
    user      string
    password  string
    pool      sync.Pool
    maxConns  int
    active    int64  // atomic counter
    mu        sync.RWMutex
    closed    bool
    logger    *slog.Logger
}

func (cp *ConnectionPool) Get(ctx context.Context) (*ldap.Conn, error)
func (cp *ConnectionPool) Put(conn *ldap.Conn)
func (cp *ConnectionPool) Close() error
```

#### 2.2 Input Validation & Security
**Target**: Comprehensive input validation and security enhancements

**Go Features**:
- `regexp` package for input validation
- `strings` package for sanitization
- Custom validation types

**Implementation**:
```go
type DNValidator struct {
    maxLength int
    allowedChars *regexp.Regexp
}

func (v *DNValidator) Validate(dn string) error {
    if len(dn) > v.maxLength {
        return fmt.Errorf("DN exceeds maximum length of %d characters", v.maxLength)
    }
    if !v.allowedChars.MatchString(dn) {
        return fmt.Errorf("DN contains invalid characters")
    }
    return nil
}

// Security-focused input sanitization
func sanitizeLDAPFilter(input string) string {
    // Enhanced beyond basic EscapeFilter
    return ldap.EscapeFilter(strings.TrimSpace(input))
}
```

### Phase 3: Advanced Features (Weeks 5-6)

#### 3.1 Optional Caching Layer
**Target**: Add configurable caching for read operations

**Go Features**:
- `sync.Map` for concurrent-safe caching
- `time.Time` for expiration tracking
- Generics (Go 1.18+) for type-safe caching

**Implementation**:
```go
type Cache[T any] struct {
    data   sync.Map
    ttl    time.Duration
    logger *slog.Logger
}

type CacheEntry[T any] struct {
    Value     T
    ExpiresAt time.Time
}

func (c *Cache[T]) Get(key string) (T, bool)
func (c *Cache[T]) Set(key string, value T)
func (c *Cache[T]) Delete(key string)

// Usage
type CachedLDAP struct {
    *LDAP
    userCache  *Cache[*User]
    groupCache *Cache[*Group]
}
```

#### 3.2 Modern Go Patterns & Generics
**Target**: Leverage generics for type-safe operations where beneficial

**Go Features**:
- Type parameters (Go 1.18+) for generic operations
- Type constraints for LDAP objects
- Interface improvements

**Implementation**:
```go
// Generic search interface
type LDAPObject interface {
    DN() string
    CN() string
}

func Search[T LDAPObject](ctx context.Context, l *LDAP, 
    baseDN string, filter string, 
    parser func(*ldap.Entry) (T, error)) ([]T, error) {
    // Generic search implementation
}

// Usage
users, err := Search(ctx, ldapClient, baseDN, userFilter, userFromEntry)
groups, err := Search(ctx, ldapClient, baseDN, groupFilter, groupFromEntry)
```

### Phase 4: API Enhancement & Backward Compatibility (Week 7)

#### 4.1 New Modern API Design
**Target**: Design modern, context-aware API with options pattern

**Implementation**:
```go
// Options pattern for configuration
type ClientOptions struct {
    Logger         *slog.Logger
    ConnectionPool *ConnectionPoolConfig
    Cache          *CacheConfig
    Validator      *ValidationConfig
    Timeout        time.Duration
}

type ClientOption func(*ClientOptions)

func WithLogger(logger *slog.Logger) ClientOption {
    return func(o *ClientOptions) { o.Logger = logger }
}

func WithConnectionPool(config *ConnectionPoolConfig) ClientOption {
    return func(o *ClientOptions) { o.ConnectionPool = config }
}

func WithCache(config *CacheConfig) ClientOption {
    return func(o *ClientOptions) { o.Cache = config }
}

// New constructor
func NewClient(config Config, user, password string, opts ...ClientOption) (*LDAP, error)

// Context-first operations
func (l *LDAP) SearchUsersContext(ctx context.Context, opts *SearchOptions) ([]User, error)
func (l *LDAP) SearchGroupsContext(ctx context.Context, opts *SearchOptions) ([]Group, error)
```

#### 4.2 Backward Compatibility Layer
**Target**: Maintain existing API while providing modern alternatives

**Implementation**:
```go
// Existing methods remain unchanged for backward compatibility
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (*User, error) {
    return l.FindUserBySAMAccountNameContext(context.Background(), sAMAccountName)
}

// New methods added with Context suffix
func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (*User, error) {
    // Modern implementation with context, logging, validation, etc.
}
```

## Dependencies & Technology Stack

### New Dependencies to Add

1. **No additional external dependencies required**
   - All modernization uses standard library features
   - `log/slog` is built into Go 1.21+
   - `context` package is standard library
   - `fmt.Errorf` with `%w` is standard library

2. **Development Dependencies** (optional):
   - `go.opentelemetry.io/otel` for distributed tracing
   - `github.com/prometheus/client_golang` for metrics
   - `github.com/stretchr/testify` (already present) for enhanced testing

### Go Version Requirements

- **Minimum**: Go 1.21+ (for log/slog support)
- **Recommended**: Go 1.22+ (for improved performance and tooling)
- **Target**: Go 1.23+ (current project version)

## Security Enhancements

### 1. Input Validation
```go
type SecurityConfig struct {
    MaxDNLength      int
    MaxFilterLength  int
    AllowedChars     *regexp.Regexp
    BlockedPatterns  []string
}

func (sc *SecurityConfig) ValidateDN(dn string) error
func (sc *SecurityConfig) ValidateFilter(filter string) error
```

### 2. Connection Security
```go
type TLSConfig struct {
    InsecureSkipVerify bool
    ServerName         string
    Certificates       []tls.Certificate
    RootCAs           *x509.CertPool
}

func (l *LDAP) WithTLS(config *TLSConfig) error
```

### 3. Credential Management
```go
type CredentialProvider interface {
    GetCredentials(ctx context.Context) (username, password string, err error)
    RefreshCredentials(ctx context.Context) error
}

func (l *LDAP) WithCredentialProvider(provider CredentialProvider) error
```

## Performance Optimizations

### 1. Connection Pooling
- Reuse connections across operations
- Configurable pool size (default: 10 connections)
- Connection health checks
- Graceful pool shutdown

### 2. Bulk Operations
```go
func (l *LDAP) BulkSearchUsersContext(ctx context.Context, filters []string) ([]User, error)
func (l *LDAP) BulkUpdateUsersContext(ctx context.Context, updates []UserUpdate) error
```

### 3. Streaming Results
```go
func (l *LDAP) StreamUsersContext(ctx context.Context, filter string) (<-chan User, <-chan error)
```

### 4. Optional Caching
- In-memory cache with TTL
- Cache invalidation on write operations
- Configurable cache sizes
- Metrics for cache hit/miss rates

## Migration Strategy

### Breaking Changes (Opt-in)

1. **New Constructor with Options**:
   ```go
   // Old (still supported)
   client, err := ldap.New(config, user, password)
   
   // New (recommended)
   client, err := ldap.NewClient(config, user, password,
       ldap.WithLogger(logger),
       ldap.WithConnectionPool(&ldap.ConnectionPoolConfig{MaxConns: 20}),
       ldap.WithCache(&ldap.CacheConfig{TTL: 5*time.Minute}),
   )
   ```

2. **Context-aware Methods**:
   ```go
   // Old (still supported)
   user, err := client.FindUserBySAMAccountName("jdoe")
   
   // New (recommended)
   ctx := context.WithTimeout(context.Background(), 30*time.Second)
   user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
   ```

### Non-breaking Changes

1. **Enhanced Error Information**: Errors now include more context
2. **Optional Logging**: Logging is opt-in via configuration
3. **Performance Improvements**: Connection pooling and caching are transparent

## Implementation Timeline

### Week 1-2: Foundation
- [ ] Add context.Context support to all operations
- [ ] Implement structured logging with slog
- [ ] Enhanced error handling with wrapping
- [ ] Comprehensive input validation

### Week 3-4: Performance & Security
- [ ] Connection pool implementation
- [ ] Security enhancements (TLS, validation)
- [ ] Performance optimizations
- [ ] Memory usage improvements

### Week 5-6: Advanced Features
- [ ] Optional caching layer
- [ ] Bulk operations support
- [ ] Generic interfaces where beneficial
- [ ] Monitoring and metrics hooks

### Week 7: Integration & Testing
- [ ] Backward compatibility verification
- [ ] Performance benchmarking
- [ ] Documentation updates
- [ ] Migration guides

## Testing Strategy

### Unit Tests
- Maintain 100% of existing test coverage
- Add tests for new context-aware operations
- Test error scenarios with enhanced error types
- Mock connection pool behavior

### Integration Tests
- Test with real LDAP servers (OpenLDAP and Active Directory)
- Performance regression testing
- Connection pool stress testing
- Cache effectiveness testing

### Backward Compatibility Tests
- Ensure all existing APIs continue to work
- Version compatibility matrix testing
- Migration path validation

## Documentation Requirements

### 1. API Documentation
- Context usage examples
- Error handling patterns
- Configuration options
- Performance tuning guide

### 2. Migration Guide
- Step-by-step upgrade process
- Breaking change notifications
- Performance improvement tips
- Best practices for new features

### 3. Security Guide
- Input validation patterns
- TLS configuration examples
- Credential management best practices
- Security hardening checklist

## Success Metrics

### Performance
- 50% reduction in connection establishment overhead (via pooling)
- 30% improvement in high-volume operations (via caching)
- 90% reduction in memory allocations for repeated operations

### Reliability
- Zero connection leaks under normal operation
- Graceful handling of network timeouts and interruptions
- Comprehensive error context for debugging

### Maintainability
- 100% backward compatibility with existing APIs
- Clear upgrade path with deprecation warnings
- Modern Go idioms throughout the codebase

### Security
- Comprehensive input validation preventing injection attacks
- Secure credential handling with provider pattern
- TLS configuration validation and enforcement

This modernization plan transforms the simple-ldap-go library into a production-ready, modern Go library while maintaining full backward compatibility and following current Go best practices.