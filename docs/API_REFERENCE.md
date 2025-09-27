# simple-ldap-go API Reference

## Table of Contents
- [Client Management](#client-management)
- [Authentication](#authentication)
- [User Operations](#user-operations)
- [Group Operations](#group-operations)
- [Computer Operations](#computer-operations)
- [Builders](#builders)
- [Infrastructure](#infrastructure)
- [Error Types](#error-types)
- [Types and Interfaces](#types-and-interfaces)

---

## Client Management

### Constructor Functions

#### `New`
```go
func New(config Config, user, password string) (*LDAP, error)
```
Creates a standard LDAP client with the provided configuration and credentials.

The LDAP client automatically enables optimizations based on the configuration:
- Connection pooling when `config.PoolSize > 1`
- Caching when `config.EnableCache = true`
- Circuit breaker when `config.Resilience.EnableCircuitBreaker = true`

### Connection Methods

#### `GetConnection`
```go
func (l LDAP) GetConnection() (*ldap.Conn, error)
```
Returns an LDAP connection. The caller is responsible for closing it.

#### `GetConnectionContext`
```go
func (l LDAP) GetConnectionContext(ctx context.Context) (*ldap.Conn, error)
```
Returns an LDAP connection with context support for cancellation and timeout.

#### `WithCredentials`
```go
func (l *LDAP) WithCredentials(dn, password string) (*LDAP, error)
```
Creates a new client instance with different credentials.

---

## Authentication

### Password Verification

#### `CheckPasswordForSAMAccountName`
```go
func (l *LDAP) CheckPasswordForSAMAccountName(sAMAccountName, password string) (*User, error)
```
Verifies a user's password using their SAM account name.

#### `CheckPasswordForSAMAccountNameContext`
```go
func (l *LDAP) CheckPasswordForSAMAccountNameContext(ctx context.Context, sAMAccountName, password string) (*User, error)
```
Context-aware version of password verification by SAM account name.

#### `CheckPasswordForDN`
```go
func (l *LDAP) CheckPasswordForDN(dn, password string) (*User, error)
```
Verifies a user's password using their distinguished name.

#### `CheckPasswordForDNContext`
```go
func (l *LDAP) CheckPasswordForDNContext(ctx context.Context, dn, password string) (*User, error)
```
Context-aware version of password verification by DN.

### Password Management

#### `ChangePasswordForSAMAccountName`
```go
func (l *LDAP) ChangePasswordForSAMAccountName(sAMAccountName, oldPassword, newPassword string) error
```
Changes a user's password. Requires LDAPS for Active Directory.

#### `ChangePasswordForSAMAccountNameContext`
```go
func (l *LDAP) ChangePasswordForSAMAccountNameContext(ctx context.Context, sAMAccountName, oldPassword, newPassword string) error
```
Context-aware password change operation.

---

## User Operations

### Search Operations

#### `FindUserByDN` / `FindUserByDNContext`
```go
func (l *LDAP) FindUserByDN(dn string) (*User, error)
func (l *LDAP) FindUserByDNContext(ctx context.Context, dn string) (*User, error)
```
Finds a user by their distinguished name.

#### `FindUserBySAMAccountName` / `FindUserBySAMAccountNameContext`
```go
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (*User, error)
func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (*User, error)
```
Finds a user by their SAM account name.

#### `FindUserByMail` / `FindUserByMailContext`
```go
func (l *LDAP) FindUserByMail(mail string) (*User, error)
func (l *LDAP) FindUserByMailContext(ctx context.Context, mail string) (*User, error)
```
Finds a user by their email address.

#### `FindUsers` / `FindUsersContext`
```go
func (l *LDAP) FindUsers() ([]User, error)
func (l *LDAP) FindUsersContext(ctx context.Context) ([]User, error)
```
Retrieves all users from the directory.

#### `BulkFindUsersBySAMAccountName`
```go
func (l *LDAP) BulkFindUsersBySAMAccountName(ctx context.Context, samAccountNames []string, options *BulkSearchOptions) (map[string]*User, error)
```
Efficiently finds multiple users in a single operation.

### User Management

#### `CreateUser` / `CreateUserContext`
```go
func (l *LDAP) CreateUser(user FullUser, password string) (string, error)
func (l *LDAP) CreateUserContext(ctx context.Context, user FullUser, password string) (string, error)
```
Creates a new user account. Returns the DN of the created user.

#### `DeleteUser` / `DeleteUserContext`
```go
func (l *LDAP) DeleteUser(dn string) error
func (l *LDAP) DeleteUserContext(ctx context.Context, dn string) error
```
Deletes a user account by DN.

### Group Membership

#### `AddUserToGroup` / `AddUserToGroupContext`
```go
func (l *LDAP) AddUserToGroup(userDN, groupDN string) error
func (l *LDAP) AddUserToGroupContext(ctx context.Context, userDN, groupDN string) error
```
Adds a user to a group.

#### `RemoveUserFromGroup` / `RemoveUserFromGroupContext`
```go
func (l *LDAP) RemoveUserFromGroup(userDN, groupDN string) error
func (l *LDAP) RemoveUserFromGroupContext(ctx context.Context, userDN, groupDN string) error
```
Removes a user from a group.

---

## Group Operations

### Search Operations

#### `FindGroupByDN` / `FindGroupByDNContext`
```go
func (l *LDAP) FindGroupByDN(dn string) (*Group, error)
func (l *LDAP) FindGroupByDNContext(ctx context.Context, dn string) (*Group, error)
```
Finds a group by its distinguished name.

#### `FindGroups` / `FindGroupsContext`
```go
func (l *LDAP) FindGroups() ([]Group, error)
func (l *LDAP) FindGroupsContext(ctx context.Context) ([]Group, error)
```
Retrieves all groups from the directory.
Gets all groups a user belongs to.

---

## Computer Operations

### Search Operations

#### `FindComputerByDN` / `FindComputerByDNContext`
```go
func (l *LDAP) FindComputerByDN(dn string) (*Computer, error)
func (l *LDAP) FindComputerByDNContext(ctx context.Context, dn string) (*Computer, error)
```
Finds a computer by its distinguished name.

#### `FindComputerBySAMAccountName` / `FindComputerBySAMAccountNameContext`
```go
func (l *LDAP) FindComputerBySAMAccountName(sAMAccountName string) (*Computer, error)
func (l *LDAP) FindComputerBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (*Computer, error)
```
Finds a computer by its SAM account name (typically ends with $).

#### `FindComputers` / `FindComputersContext`
```go
func (l *LDAP) FindComputers() ([]Computer, error)
func (l *LDAP) FindComputersContext(ctx context.Context) ([]Computer, error)
```
Retrieves all computers from the directory.

---

## Builders

### UserBuilder

```go
func NewUserBuilder() *UserBuilder
```

Methods:
- `WithCN(cn string) *UserBuilder`
- `WithSAMAccountName(samAccountName string) *UserBuilder`
- `WithMail(email string) *UserBuilder`
- `WithDescription(description string) *UserBuilder`
- `WithEnabled(enabled bool) *UserBuilder`
- `WithGroups(groupDNs []string) *UserBuilder`
- `WithFirstName(firstName string) *UserBuilder`
- `WithLastName(lastName string) *UserBuilder`
- `Build() (*FullUser, error)`
- `MustBuild() *FullUser`

### GroupBuilder

```go
func NewGroupBuilder() *GroupBuilder
```

Methods:
- `WithCN(cn string) *GroupBuilder`
- `WithDescription(description string) *GroupBuilder`
- `WithGroupType(groupType uint32) *GroupBuilder`
- `WithSAMAccountName(samAccountName string) *GroupBuilder`
- `WithMembers(memberDNs []string) *GroupBuilder`
- `Build() (*FullGroup, error)`
- `MustBuild() *FullGroup`

### ComputerBuilder

```go
func NewComputerBuilder() *ComputerBuilder
```

Methods:
- `WithCN(cn string) *ComputerBuilder`
- `WithSAMAccountName(samAccountName string) *ComputerBuilder`
- `WithDescription(description string) *ComputerBuilder`
- `WithEnabled(enabled bool) *ComputerBuilder`
- `WithDNSHostName(dnsHostName string) *ComputerBuilder`
- `WithOperatingSystem(os string) *ComputerBuilder`
- `Build() (*FullComputer, error)`
- `MustBuild() *FullComputer`

### ConfigBuilder

```go
func NewConfigBuilder() *ConfigBuilder
```

Methods:
- `WithServer(server string) *ConfigBuilder`
- `WithBaseDN(baseDN string) *ConfigBuilder`
- `WithActiveDirectory(isAD bool) *ConfigBuilder`
- `WithConnectionPool(poolConfig *PoolConfig) *ConfigBuilder`
- `WithCache(cacheConfig *CacheConfig) *ConfigBuilder`
- `WithPerformanceMonitoring(perfConfig *PerformanceConfig) *ConfigBuilder`
- `Build() (*Config, error)`
- `MustBuild() *Config`

### QueryBuilder

```go
func NewQueryBuilder() *QueryBuilder
```

Methods:
- `WithBaseDN(baseDN string) *QueryBuilder`
- `WithScope(scope int) *QueryBuilder`
- `WithAttributes(attributes ...string) *QueryBuilder`
- `WithSizeLimit(limit int) *QueryBuilder`
- `WithTimeLimit(limit int) *QueryBuilder`
- `FilterByObjectClass(objectClass string) *QueryBuilder`
- `FilterByAttribute(attribute, value string) *QueryBuilder`
- `BuildFilter() (string, error)`

---

## Infrastructure

### Connection Pool

#### `NewConnectionPool`
```go
func NewConnectionPool(config *PoolConfig, ldapConfig Config, user, password string, logger *slog.Logger) (*ConnectionPool, error)
```
Creates a connection pool for efficient connection management.

### Cache

#### `NewLRUCache`
```go
func NewLRUCache(config *CacheConfig, logger *slog.Logger) (*LRUCache, error)
```
Creates an LRU cache with TTL support.

Cache Methods:
- `Get(key string) (interface{}, bool)`
- `GetContext(ctx context.Context, key string) (interface{}, bool)`
- `Set(key string, value interface{}, ttl time.Duration) error`
- `SetContext(ctx context.Context, key string, value interface{}, ttl time.Duration) error`
- `SetNegative(key string, ttl time.Duration) error`
- `Delete(key string) bool`
- `Clear()`
- `GetWithRefresh(key string, refreshFunc func() (interface{}, error)) (interface{}, error)`
- `Stats() CacheStats`
- `Close() error`

### Performance Monitor

#### `NewPerformanceMonitor`
```go
func NewPerformanceMonitor(config *PerformanceConfig, logger *slog.Logger) *PerformanceMonitor
```

Monitor Methods:
- `RecordOperation(ctx context.Context, operation string, duration time.Duration, cacheHit bool, err error, resultCount int)`
- `StartOperation(ctx context.Context, operation string) func(cacheHit bool, err error, resultCount int)`
- `GetStats() PerformanceStats`
- `SetCache(cache Cache)`
- `SetConnectionPool(pool *ConnectionPool)`
- `Close() error`

### Validator

#### `NewValidator`
```go
func NewValidator(config *ValidationConfig) *Validator
```

Validation Methods:
- `ValidateDNSyntax(dn string) *ValidationResult`
- `ValidateFilter(filter string) *ValidationResult`
- `ValidateAttribute(name, value string) *ValidationResult`
- `ValidateCredentials(username, password string) *ValidationResult`

---

## Error Types

### LDAPError
```go
func NewLDAPError(op, server string, err error) *LDAPError
```

Methods:
- `Error() string`
- `Unwrap() error`
- `Is(target error) bool`
- `WithDN(dn string) *LDAPError`
- `WithCode(code int) *LDAPError`
- `WithContext(key string, value interface{}) *LDAPError`

### ValidationError
```go
func NewValidationError(field string, message string) *ValidationError
```

Methods:
- `Error() string`
- `Unwrap() error`
- `WithDetail(field string, value interface{}) *ValidationError`

### MultiError
```go
func NewMultiError(op string) *MultiError
```

Methods:
- `Error() string`
- `Unwrap() error`
- `Is(target error) bool`
- `Add(err error)`
- `HasErrors() bool`
- `ErrorOrNil() error`

### ConfigError
```go
func NewConfigError(field, message string) *ConfigError
```

Methods:
- `Error() string`

### OperationError
```go
func NewOperationError(operation, dn, server string, err error) *OperationError
```

Methods:
- `Error() string`
- `Unwrap() error`
- `IsRetryable() bool`

---

## Types and Interfaces

### Core Types

#### Config
```go
type Config struct {
    Server            string
    BaseDN            string
    IsActiveDirectory bool
    UsersOU           string
    GroupsOU          string
    ComputersOU       string
}
```

#### User
```go
type User struct {
    Object
    SAMAccountName string
    Mail           string
    // Additional fields...
}
```

#### Group
```go
type Group struct {
    Object
    SAMAccountName string
    Description    string
    Members        []string
    // Additional fields...
}
```

#### Computer
```go
type Computer struct {
    Object
    SAMAccountName string
    DNSHostName    string
    OperatingSystem string
    // Additional fields...
}
```

#### FullUser
```go
type FullUser struct {
    CN              string
    SAMAccountName  *string
    FirstName       string
    LastName        string
    Mail            *string
    Description     string
    UserAccountControl uint32
    // Additional fields...
}
```

#### FullGroup
```go
type FullGroup struct {
    CN              string
    SAMAccountName  string
    Description     string
    GroupType       uint32
    Members         []string
    // Additional fields...
}
```

#### FullComputer
```go
type FullComputer struct {
    CN              string
    SAMAccountName  string
    Description     string
    UserAccountControl uint32
    DNSHostName     string
    OperatingSystem string
    // Additional fields...
}
```

### Options Types

#### SearchOptions
```go
type SearchOptions struct {
    Attributes      []string
    SizeLimit       int
    TimeLimit       int
    TypesOnly       bool
    UseCache        bool
    CacheTTL        time.Duration
    PageSize        int
    IncludeDeleted  bool
}
```

#### BulkSearchOptions
```go
type BulkSearchOptions struct {
    SearchOptions
    BatchSize       int
    MaxConcurrency  int
    FailFast        bool
}
```

#### PoolConfig
```go
type PoolConfig struct {
    MaxConnections  int
    MinIdleConnections int
    MaxIdleTime     time.Duration
    MaxLifetime     time.Duration
    HealthCheckInterval time.Duration
}
```

#### CacheConfig
```go
type CacheConfig struct {
    MaxSize         int
    DefaultTTL      time.Duration
    NegativeTTL     time.Duration
    CleanupInterval time.Duration
    EnableNegativeCache bool
}
```

#### PerformanceConfig
```go
type PerformanceConfig struct {
    EnableMetrics   bool
    MetricsInterval time.Duration
    SlowQueryThreshold time.Duration
    EnableTracing   bool
}
```

#### ValidationConfig
```go
type ValidationConfig struct {
    StrictMode      bool
    AllowEmptyDN    bool
    MaxDNLength     int
    MaxFilterLength int
    CustomPatterns  map[string]string
}
```

### Interface Definitions

#### UserReader
```go
type UserReader interface {
    FindUserByDN(dn string) (*User, error)
    FindUserByDNContext(ctx context.Context, dn string) (*User, error)
    FindUserBySAMAccountName(name string) (*User, error)
    FindUserBySAMAccountNameContext(ctx context.Context, name string) (*User, error)
    FindUserByMail(mail string) (*User, error)
    FindUserByMailContext(ctx context.Context, mail string) (*User, error)
}
```

#### UserWriter
```go
type UserWriter interface {
    CreateUser(user FullUser, password string) (string, error)
    CreateUserContext(ctx context.Context, user FullUser, password string) (string, error)
    DeleteUser(dn string) error
    DeleteUserContext(ctx context.Context, dn string) error
    UpdateUserPassword(dn string, newPassword string) error
    UpdateUserPasswordContext(ctx context.Context, dn, newPassword string) error
}
```

#### UserManager
```go
type UserManager interface {
    UserReader
    UserWriter
    GetUserGroups(userDN string) ([]Group, error)
    GetUserGroupsContext(ctx context.Context, userDN string) ([]Group, error)
}
```

#### GroupReader
```go
type GroupReader interface {
    FindGroupByDN(dn string) (*Group, error)
    FindGroupByDNContext(ctx context.Context, dn string) (*Group, error)
    FindGroupByCN(cn string) (*Group, error)
    FindGroupByCNContext(ctx context.Context, cn string) (*Group, error)
}
```

#### GroupWriter
```go
type GroupWriter interface {
    CreateGroup(group FullGroup) (string, error)
    CreateGroupContext(ctx context.Context, group FullGroup) (string, error)
    DeleteGroup(dn string) error
    DeleteGroupContext(ctx context.Context, dn string) error
    AddUserToGroup(userDN, groupDN string) error
    AddUserToGroupContext(ctx context.Context, userDN, groupDN string) error
    RemoveUserFromGroup(userDN, groupDN string) error
    RemoveUserFromGroupContext(ctx context.Context, userDN, groupDN string) error
}
```

#### GroupManager
```go
type GroupManager interface {
    GroupReader
    GroupWriter
    GetGroupMembers(groupDN string) ([]User, error)
    GetGroupMembersContext(ctx context.Context, groupDN string) ([]User, error)
}
```

#### Cache
```go
type Cache interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, ttl time.Duration) error
    Delete(key string) bool
    Clear()
    Stats() CacheStats
}
```

#### LDAPObject
```go
type LDAPObject interface {
    GetDN() string
    GetObjectClass() []string
    GetAttributes() map[string][]string
}
```

---

## Constants and Variables

### User Account Control Flags
```go
const (
    UACAccountDisable         = 0x00000002
    UACPasswordNotRequired    = 0x00000020
    UACPasswordCantChange     = 0x00000040
    UACNormalAccount          = 0x00000200
    UACDontExpirePassword     = 0x00010000
    UACSmartcardRequired      = 0x00040000
    UACPasswordExpired        = 0x00800000
)
```

### SAM Account Types
```go
const (
    SamAccountTypeDomainObject     = 0x00000000
    SamAccountTypeGroupObject      = 0x10000000
    SamAccountTypeNonSecurityGroup = 0x10000001
    SamAccountTypeAliasObject      = 0x20000000
    SamAccountTypeNonSecurityAlias = 0x20000001
    SamAccountTypeUserObject       = 0x30000000
    SamAccountTypeNormalUser       = 0x30000000
    SamAccountTypeMachineAccount   = 0x30000001
    SamAccountTypeTrustAccount     = 0x30000002
)
```

### Error Variables
```go
var (
    ErrUserNotFound     = errors.New("user not found")
    ErrGroupNotFound    = errors.New("group not found")
    ErrComputerNotFound = errors.New("computer not found")
    ErrDNDuplicated     = errors.New("DN is not unique")
    ErrInvalidDN        = errors.New("invalid DN syntax")
    ErrInvalidFilter    = errors.New("invalid LDAP filter")
)
```

---

## Usage Examples

### Basic Authentication
```go
config := ldap.Config{
    Server: "ldaps://ldap.example.com:636",
    BaseDN: "dc=example,dc=com",
}

client, err := ldap.New(config, "admin@example.com", "password")
if err != nil {
    log.Fatal(err)
}

user, err := client.CheckPasswordForSAMAccountName("jdoe", "userpass")
if err != nil {
    log.Printf("Authentication failed: %v", err)
} else {
    log.Printf("Welcome %s!", user.CN())
}
```

### Context with Timeout
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
if err != nil {
    log.Printf("User not found: %v", err)
}
```

### Using Builders
```go
user := ldap.NewUserBuilder().
    WithCN("John Doe").
    WithSAMAccountName("jdoe").
    WithMail("john.doe@example.com").
    WithFirstName("John").
    WithLastName("Doe").
    WithEnabled(true).
    Build()

dn, err := client.CreateUser(*user, "initialPassword123!")
if err != nil {
    log.Printf("Failed to create user: %v", err)
}
```

### Bulk Operations
```go
users := []string{"user1", "user2", "user3", "user4", "user5"}
opts := &ldap.BulkSearchOptions{
    BatchSize:      10,
    MaxConcurrency: 3,
}

results, err := client.BulkFindUsersBySAMAccountName(ctx, users, opts)
if err != nil {
    log.Printf("Bulk search failed: %v", err)
}

for sam, user := range results {
    log.Printf("Found: %s - %s", sam, user.Mail)
}
```

### Error Handling
```go
user, err := client.FindUserByDN(dn)
if err != nil {
    var ldapErr *ldap.LDAPError
    if errors.As(err, &ldapErr) {
        log.Printf("LDAP Error - Operation: %s, Server: %s, Code: %d",
            ldapErr.Operation, ldapErr.Server, ldapErr.Code)
    }

    if errors.Is(err, ldap.ErrUserNotFound) {
        // Handle user not found specifically
    }
}
```

---

*API Reference Version 1.0.0 - Generated 2025-09-17*