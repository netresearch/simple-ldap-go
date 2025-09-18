# Project Context: simple-ldap-go

## Overview
**simple-ldap-go** is a comprehensive Go library providing an easy-to-use wrapper around go-ldap/ldap/v3 for LDAP and Active Directory operations. The project has recently undergone a massive modernization, transforming from a basic LDAP wrapper into a feature-rich, production-ready library following modern Go best practices.

## Technical Stack
- **Language**: Go 1.23.0 (toolchain 1.25.0)
- **Core Dependency**: github.com/go-ldap/ldap/v3
- **Testing**: testcontainers-go, stretchr/testify
- **Size**: 57 Go files, 29K+ lines of code
- **Branch**: feature/code-maintenance-overhaul

## Core Modules

### 1. Authentication (`auth.go`)
- Password verification for LDAP/AD users
- Support for DN and SAMAccountName authentication
- Context-aware operations with timeout control
- Enhanced error handling with wrapped errors

### 2. Entity Management
- **Users** (`users.go`, `users_optimized.go`): Full CRUD operations, 12 methods
- **Groups** (`groups.go`, `groups_optimized.go`): Group management, membership operations
- **Computers** (`computers.go`): Active Directory computer account management
- **Objects** (`object.go`): Base LDAP object abstraction

### 3. Infrastructure Components
- **Connection Pool** (`pool.go`): Manages LDAP connections with health checks
- **Cache** (`cache.go`): LRU cache with TTL, negative caching, 849 lines
- **Concurrency** (`concurrency.go`): Worker pools, pipelines, semaphores, 881 lines
- **Performance** (`performance.go`): Monitoring, metrics collection, 594 lines

### 4. Modern Patterns
- **Builders** (`builders.go`): Fluent API for Users, Groups, Computers, Config, Query
- **Options** (`options.go`): Functional options pattern for flexible configuration
- **Generics** (`generics.go`): Type-safe operations, pipelines, 572 lines
- **Interfaces** (`interfaces.go`): SOLID principles with Reader/Writer segregation

### 5. Quality & Security
- **Validation** (`validation.go`): Input sanitization, LDAP injection prevention, 783 lines
- **Security** (`security.go`): Credential management, audit logging, 805 lines
- **Errors** (`errors.go`): Structured error types, context preservation, 691 lines
- **Logging**: Structured logging with slog throughout

## API Surface
- **56 CRUD Operations**: Find, Get, Create, Update, Delete, Check methods
- **34 Constructor Functions**: New* functions for various components
- **79 Structs**: Domain models and internal structures
- **21 Interfaces**: Clean contracts for testability
- **Context Support**: All operations have Context variants (73 uses)

## Architectural Patterns

1. **Context-Aware Design**: Every operation supports context for cancellation/timeout
2. **Interface Segregation**: Separate Reader/Writer interfaces (UserReader, UserWriter, etc.)
3. **Dependency Injection**: Constructor injection for testability
4. **Builder Pattern**: Fluent API for complex object construction
5. **Options Pattern**: Flexible configuration without breaking changes
6. **Error Wrapping**: Context-preserving error chains with errors.Is support
7. **Connection Pooling**: Efficient connection reuse with health monitoring
8. **Caching Strategy**: LRU cache with negative caching and TTL
9. **Concurrent Operations**: Worker pools, pipelines, batch processing
10. **Generic Components**: Type-safe reusable operations

## Test Infrastructure
- **24 Test Files**: Comprehensive test coverage
- **159 Test Functions**: Unit and integration tests
- **8 Example Programs**: Real-world usage demonstrations
- **Testcontainers**: OpenLDAP containers for integration testing
- **Challenge**: Container startup causes 2+ minute test runs

## Recent Changes (feature/code-maintenance-overhaul)
- Fixed go vet issues with defer time.Since patterns
- Resolved pointer dereferencing errors in examples
- Updated test error checking to use errors.Is
- Fixed nil logger panics in context tests
- Updated all dependencies to latest versions
- Applied gofmt across entire codebase
- Created comprehensive maintenance report

## Outstanding Issues
1. **Test Performance**: Container-based tests timeout (need pooling/fixtures)
2. **Builder Validation**: UserBuilder requires FirstName/LastName but tests expect optional
3. **Cache Compression**: TODO placeholder at cache.go:720
4. **Test Coverage**: Unit tests show 6.4% (misleading due to integration test separation)

## Documentation
- README.md: Quick start and basic usage
- MODERNIZATION_PLAN.md: Architecture transformation strategy (527 lines)
- PERFORMANCE_OPTIMIZATION.md: Performance guidelines (491 lines)
- SECURITY.md: Security best practices (657 lines)
- STRUCTURED_LOGGING.md: Logging implementation (497 lines)
- ERROR_HANDLING.md: Error management patterns (369 lines)
- Plus 5 additional architectural docs

## Development Guidelines
1. All new operations must support context
2. Use structured logging with slog
3. Wrap errors with context using fmt.Errorf with %w
4. Follow interface segregation principle
5. Maintain backward compatibility
6. Write both unit and integration tests
7. Use builders for complex objects
8. Apply input validation for security

## Usage Example
```go
// Modern client with all features
client, err := ldap.NewHighPerformanceClient(
    config,
    username,
    password,
)

// Context-aware operation
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
```

## Project Status
The library has successfully completed a comprehensive modernization, transforming from a basic LDAP wrapper into a production-ready, feature-rich library. It now includes enterprise features like connection pooling, caching, performance monitoring, and comprehensive security controls while maintaining backward compatibility and clean API design.

---
*Context loaded: 2025-09-17 | Branch: feature/code-maintenance-overhaul*