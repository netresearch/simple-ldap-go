# Builder Patterns Guide

## 📚 Overview

Simple LDAP Go implements comprehensive builder patterns for fluent, type-safe object construction. This guide covers all available builders, their usage patterns, error handling, and best practices.

## 🏗️ Available Builders

### Builder Types
- **UserBuilder** - Construct user objects with validation
- **GroupBuilder** - Build group objects with member management
- **ComputerBuilder** - Create computer accounts
- **ConfigBuilder** - Fluent configuration setup
- **QueryBuilder** - Construct LDAP queries programmatically

## 📦 UserBuilder

### Purpose
Creates fully-formed user objects with validation and error accumulation.

### Basic Usage
```go
user, err := ldap.NewUserBuilder().
    WithCN("John Doe").
    WithFirstName("John").
    WithLastName("Doe").
    WithEmail("john.doe@example.com").
    WithSAMAccountName("jdoe").
    WithPath("ou=users,dc=example,dc=com").
    Build()

if err != nil {
    // Handle accumulated validation errors
    log.Printf("User creation failed: %v", err)
}
```

### Advanced Features

#### Custom Attributes
```go
user, err := ldap.NewUserBuilder().
    WithCN("Jane Smith").
    WithFirstName("Jane").
    WithLastName("Smith").
    WithEmail("jane@example.com").
    WithAttribute("department", "Engineering").
    WithAttribute("employeeNumber", "12345").
    WithAttribute("telephoneNumber", "+1-555-0100").
    WithMultiValueAttribute("memberOf", []string{
        "cn=developers,ou=groups,dc=example,dc=com",
        "cn=staff,ou=groups,dc=example,dc=com",
    }).
    Build()
```

#### Object Classes Configuration
```go
user, err := ldap.NewUserBuilder().
    WithCN("Service Account").
    WithObjectClasses([]string{
        "top",
        "person",
        "organizationalPerson",
        "inetOrgPerson",
        "posixAccount", // For Unix attributes
    }).
    WithAttribute("uidNumber", "10001").
    WithAttribute("gidNumber", "10001").
    WithAttribute("homeDirectory", "/home/service").
    Build()
```

### Methods Reference

| Method | Description | Validation |
|--------|-------------|------------|
| `WithCN(cn string)` | Set common name | Required, non-empty |
| `WithFirstName(name string)` | Set given name | Optional |
| `WithLastName(name string)` | Set surname | Optional |
| `WithEmail(email string)` | Set email address | Email format validation |
| `WithSAMAccountName(sam string)` | Set SAM account name | AD-specific, length limits |
| `WithPath(path string)` | Set container DN | Valid DN format |
| `WithPassword(password string)` | Set initial password | Policy validation |
| `WithObjectClasses(classes []string)` | Set object classes | Non-empty list |
| `WithAttribute(key, value string)` | Add single attribute | Key validation |
| `WithMultiValueAttribute(key string, values []string)` | Add multi-value attribute | Non-empty values |
| `Build()` | Construct final user | Returns accumulated errors |

### Error Handling
```go
user, err := ldap.NewUserBuilder().
    WithCN(""). // Error: empty CN
    WithEmail("invalid-email"). // Error: invalid format
    Build()

if err != nil {
    // err contains all validation errors
    // Example: "CN cannot be empty; invalid email format"
    for _, e := range err.(ldap.BuilderError).Errors() {
        log.Printf("Validation error: %v", e)
    }
}
```

## 🏗️ GroupBuilder

### Purpose
Constructs group objects with member management capabilities.

### Basic Usage
```go
group, err := ldap.NewGroupBuilder().
    WithCN("Developers").
    WithDescription("Software Development Team").
    WithPath("ou=groups,dc=example,dc=com").
    WithMember("uid=jdoe,ou=users,dc=example,dc=com").
    WithMember("uid=jsmith,ou=users,dc=example,dc=com").
    Build()
```

### Advanced Features

#### Group Types
```go
// Security Group (AD)
securityGroup, err := ldap.NewGroupBuilder().
    WithCN("SecurityAdmins").
    WithGroupType(ldap.SecurityGroup).
    WithSAMAccountName("sec-admins").
    WithAttribute("groupType", "-2147483646"). // Universal Security Group
    Build()

// Distribution Group
distGroup, err := ldap.NewGroupBuilder().
    WithCN("AllStaff").
    WithGroupType(ldap.DistributionGroup).
    WithEmail("all-staff@example.com").
    Build()

// POSIX Group (OpenLDAP)
posixGroup, err := ldap.NewGroupBuilder().
    WithCN("developers").
    WithObjectClasses([]string{"top", "posixGroup"}).
    WithAttribute("gidNumber", "5001").
    Build()
```

#### Nested Groups
```go
parentGroup, err := ldap.NewGroupBuilder().
    WithCN("Engineering").
    WithMember("cn=Backend,ou=groups,dc=example,dc=com").
    WithMember("cn=Frontend,ou=groups,dc=example,dc=com").
    WithMember("cn=DevOps,ou=groups,dc=example,dc=com").
    Build()
```

### Methods Reference

| Method | Description | Notes |
|--------|-------------|-------|
| `WithCN(cn string)` | Set group name | Required |
| `WithDescription(desc string)` | Set description | Optional |
| `WithPath(path string)` | Set container DN | Valid DN required |
| `WithMember(dn string)` | Add member DN | Validates DN format |
| `WithMembers(dns []string)` | Add multiple members | Bulk operation |
| `WithEmail(email string)` | Set group email | Distribution lists |
| `WithSAMAccountName(sam string)` | Set SAM name | AD-specific |
| `WithGroupType(type GroupType)` | Set group type | Security/Distribution |
| `Build()` | Construct group | Returns errors |

## 🏗️ ComputerBuilder

### Purpose
Creates computer account objects for domain-joined machines.

### Basic Usage
```go
computer, err := ldap.NewComputerBuilder().
    WithCN("WORKSTATION-01").
    WithSAMAccountName("WORKSTATION-01$").
    WithPath("ou=computers,dc=example,dc=com").
    WithOperatingSystem("Windows 11 Professional").
    WithServicePrincipalName("HOST/workstation-01.example.com").
    Build()
```

### Advanced Features

#### Server Configuration
```go
server, err := ldap.NewComputerBuilder().
    WithCN("DC-01").
    WithSAMAccountName("DC-01$").
    WithDNSHostName("dc-01.example.com").
    WithOperatingSystem("Windows Server 2022").
    WithOperatingSystemVersion("10.0.20348").
    WithServicePrincipalNames([]string{
        "HOST/dc-01.example.com",
        "HOST/DC-01",
        "ldap/dc-01.example.com",
        "ldap/DC-01",
    }).
    WithAttribute("userAccountControl", "532480"). // Domain Controller
    Build()
```

### Methods Reference

| Method | Description | Requirements |
|--------|-------------|--------------|
| `WithCN(cn string)` | Computer name | Required, uppercase convention |
| `WithSAMAccountName(sam string)` | SAM account | Must end with $ |
| `WithPath(path string)` | Container DN | Valid DN |
| `WithDNSHostName(dns string)` | FQDN | Valid hostname |
| `WithOperatingSystem(os string)` | OS name | Free text |
| `WithOperatingSystemVersion(ver string)` | OS version | Version format |
| `WithServicePrincipalName(spn string)` | Add SPN | Unique in domain |
| `Build()` | Create computer | Validates all fields |

## 🏗️ ConfigBuilder

### Purpose
Fluent configuration of LDAP client settings with validation.

### Basic Usage
```go
config, err := ldap.NewConfigBuilder().
    WithServer("ldap.example.com").
    WithPort(636).
    WithBaseDN("dc=example,dc=com").
    WithTLS(true).
    Build()

if err != nil {
    log.Fatalf("Invalid configuration: %v", err)
}

client, err := ldap.New(*config, "admin", "password")
```

### Advanced Features

#### Connection Pooling
```go
config, err := ldap.NewConfigBuilder().
    WithServer("ldap.example.com").
    WithPort(636).
    WithBaseDN("dc=example,dc=com").
    WithPooling(20, 5). // max: 20, min: 5
    WithPoolHealthCheck(30 * time.Second).
    WithIdleTimeout(5 * time.Minute).
    Build()
```

#### Caching Configuration
```go
config, err := ldap.NewConfigBuilder().
    WithServer("ldap.example.com").
    WithBaseDN("dc=example,dc=com").
    WithCache(10000, 5*time.Minute). // size: 10000, TTL: 5 min
    WithCacheCompression(true).
    Build()
```

#### Security Configuration
```go
config, err := ldap.NewConfigBuilder().
    WithServer("ldaps://secure.example.com").
    WithPort(636).
    WithBaseDN("dc=example,dc=com").
    WithTLSConfig(&tls.Config{
        MinVersion:               tls.VersionTLS12,
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }).
    WithReadOnly(true).
    WithTimeout(10*time.Second, 30*time.Second). // dial, request
    Build()
```

#### Resilience Configuration
```go
config, err := ldap.NewConfigBuilder().
    WithServer("ldap.example.com").
    WithBaseDN("dc=example,dc=com").
    WithCircuitBreaker(5, 1*time.Minute). // failures: 5, timeout: 1 min
    WithRetry(3, 100*time.Millisecond). // attempts: 3, initial delay: 100ms
    WithRateLimit(100). // 100 requests per second
    Build()
```

### Methods Reference

| Method | Description | Validation |
|--------|-------------|------------|
| `WithServer(server string)` | LDAP server | Required, valid hostname/IP |
| `WithPort(port int)` | Server port | 1-65535 |
| `WithBaseDN(dn string)` | Base DN | Valid DN format |
| `WithTLS(enabled bool)` | Enable TLS | - |
| `WithTLSConfig(config *tls.Config)` | Custom TLS | Valid config |
| `WithPooling(max, min int)` | Connection pool | max >= min > 0 |
| `WithCache(size int, ttl time.Duration)` | Enable cache | size > 0 |
| `WithTimeout(dial, request time.Duration)` | Timeouts | > 0 |
| `WithRetry(attempts int, delay time.Duration)` | Retry logic | attempts > 0 |
| `WithCircuitBreaker(failures int, timeout time.Duration)` | Circuit breaker | failures > 0 |
| `WithReadOnly(enabled bool)` | Read-only mode | - |
| `Build()` | Create config | Returns validation errors |

## 🏗️ QueryBuilder

### Purpose
Programmatic construction of LDAP search filters with type safety.

### Basic Usage
```go
query := ldap.NewQueryBuilder().
    WithBaseDN("ou=users,dc=example,dc=com").
    WithScope(ldap.ScopeWholeSubtree).
    Where("objectClass", "inetOrgPerson").
    And("mail", "*@example.com").
    Build()

// Generates: (&(objectClass=inetOrgPerson)(mail=*@example.com))
```

### Advanced Features

#### Complex Filters
```go
// Find active users in engineering or sales
query := ldap.NewQueryBuilder().
    WithBaseDN("ou=users,dc=example,dc=com").
    WithScope(ldap.ScopeWholeSubtree).
    Where("objectClass", "user").
    And("userAccountControl", "512"). // Active accounts
    AndGroup(func(q *ldap.QueryBuilder) {
        q.Or("department", "Engineering").
        Or("department", "Sales")
    }).
    Build()

// Result: (&(objectClass=user)(userAccountControl=512)(|(department=Engineering)(department=Sales)))
```

#### Negation and Wildcards
```go
// Find users without email from specific domains
query := ldap.NewQueryBuilder().
    WithBaseDN("ou=users,dc=example,dc=com").
    Where("objectClass", "inetOrgPerson").
    Not("mail", "*").                    // No email
    OrNot("mail", "*@external.com").     // Or not external
    AndPresent("employeeNumber").        // Has employee number
    Build()

// Result: (&(objectClass=inetOrgPerson)(!(mail=*))(!(mail=*@external.com))(employeeNumber=*))
```

#### Date Range Queries
```go
// Find recently modified users
lastWeek := time.Now().AddDate(0, 0, -7).Format("20060102150405Z")
query := ldap.NewQueryBuilder().
    WithBaseDN("ou=users,dc=example,dc=com").
    Where("objectClass", "user").
    AndGreaterOrEqual("modifyTimestamp", lastWeek).
    Build()

// Result: (&(objectClass=user)(modifyTimestamp>=20240322150405Z))
```

### Methods Reference

| Method | Description | Example |
|--------|-------------|---------|
| `WithBaseDN(dn string)` | Set search base | `"ou=users,dc=example,dc=com"` |
| `WithScope(scope int)` | Search scope | `ldap.ScopeWholeSubtree` |
| `Where(attr, value string)` | Initial condition | `Where("cn", "John*")` |
| `And(attr, value string)` | AND condition | `And("sn", "Doe")` |
| `Or(attr, value string)` | OR condition | `Or("mail", "*@gmail.com")` |
| `Not(attr, value string)` | NOT condition | `Not("userAccountControl", "514")` |
| `AndPresent(attr string)` | Attribute exists | `AndPresent("mail")` |
| `AndAbsent(attr string)` | Attribute missing | `AndAbsent("deletedDate")` |
| `AndGroup(func)` | Grouped AND | Complex nested conditions |
| `OrGroup(func)` | Grouped OR | Alternative conditions |
| `AndGreaterOrEqual(attr, value)` | >= comparison | Date/number ranges |
| `AndLessOrEqual(attr, value)` | <= comparison | Upper bounds |
| `Build()` | Generate filter | Returns LDAP filter string |

## 🎯 Best Practices

### 1. Error Handling
Always check builder errors before using the result:
```go
obj, err := builder.Build()
if err != nil {
    // Handle validation errors
    return nil, fmt.Errorf("builder failed: %w", err)
}
```

### 2. Validation Chain
Builders accumulate errors, allowing complete validation:
```go
user, err := ldap.NewUserBuilder().
    WithCN("").           // Error 1: empty CN
    WithEmail("invalid"). // Error 2: invalid email
    WithPath("bad-dn").   // Error 3: invalid DN
    Build()

// err contains all 3 validation errors
```

### 3. Reusable Builders
Create builder factories for common patterns:
```go
func NewEmployeeBuilder(firstName, lastName, email string) *ldap.UserBuilder {
    return ldap.NewUserBuilder().
        WithFirstName(firstName).
        WithLastName(lastName).
        WithCN(fmt.Sprintf("%s %s", firstName, lastName)).
        WithEmail(email).
        WithPath("ou=employees,dc=company,dc=com").
        WithObjectClasses([]string{
            "top", "person", "organizationalPerson",
            "inetOrgPerson", "employee",
        })
}

// Usage
employee, err := NewEmployeeBuilder("John", "Doe", "john@company.com").
    WithAttribute("department", "Engineering").
    WithAttribute("manager", "cn=Jane Smith,ou=managers,dc=company,dc=com").
    Build()
```

### 4. Configuration Templates
Use builders for environment-specific configs:
```go
func NewProductionConfig() (*ldap.Config, error) {
    return ldap.NewConfigBuilder().
        WithServer("ldap-prod.example.com").
        WithPort(636).
        WithBaseDN("dc=prod,dc=example,dc=com").
        WithTLS(true).
        WithPooling(50, 10).
        WithCache(50000, 10*time.Minute).
        WithCircuitBreaker(10, 2*time.Minute).
        Build()
}

func NewDevelopmentConfig() (*ldap.Config, error) {
    return ldap.NewConfigBuilder().
        WithServer("ldap-dev.example.com").
        WithPort(389).
        WithBaseDN("dc=dev,dc=example,dc=com").
        WithTLS(false).
        WithPooling(5, 1).
        WithCache(1000, 1*time.Minute).
        Build()
}
```

### 5. Query Composition
Build queries dynamically based on conditions:
```go
func BuildUserQuery(filters map[string]string) string {
    qb := ldap.NewQueryBuilder().
        WithBaseDN("ou=users,dc=example,dc=com").
        WithScope(ldap.ScopeWholeSubtree).
        Where("objectClass", "inetOrgPerson")

    for attr, value := range filters {
        if value != "" {
            qb = qb.And(attr, value)
        }
    }

    return qb.Build()
}

// Usage
filters := map[string]string{
    "department": "Sales",
    "location":   "New York",
    "title":      "Manager",
}
query := BuildUserQuery(filters)
// Result: (&(objectClass=inetOrgPerson)(department=Sales)(location=New York)(title=Manager))
```

## 🚨 Common Pitfalls

### 1. Missing Required Fields
```go
// ❌ Bad: Missing required CN
user, err := ldap.NewUserBuilder().
    WithEmail("john@example.com").
    Build()
// Error: CN is required

// ✅ Good: All required fields provided
user, err := ldap.NewUserBuilder().
    WithCN("John Doe").
    WithEmail("john@example.com").
    Build()
```

### 2. Invalid DN Format
```go
// ❌ Bad: Invalid DN format
user, err := ldap.NewUserBuilder().
    WithCN("John Doe").
    WithPath("users").  // Not a valid DN
    Build()

// ✅ Good: Proper DN format
user, err := ldap.NewUserBuilder().
    WithCN("John Doe").
    WithPath("ou=users,dc=example,dc=com").
    Build()
```

### 3. Forgetting Build()
```go
// ❌ Bad: Forgetting to call Build()
user := ldap.NewUserBuilder().
    WithCN("John Doe")
// user is *UserBuilder, not *FullUser

// ✅ Good: Calling Build()
user, err := ldap.NewUserBuilder().
    WithCN("John Doe").
    Build()
// user is *FullUser
```

### 4. Ignoring Validation Errors
```go
// ❌ Bad: Ignoring errors
config, _ := ldap.NewConfigBuilder().
    WithServer("").  // Empty server!
    Build()

// ✅ Good: Handling errors
config, err := ldap.NewConfigBuilder().
    WithServer("").
    Build()
if err != nil {
    log.Fatalf("Configuration invalid: %v", err)
}
```

## 📚 Complete Examples

### Example 1: User Creation Workflow
```go
func CreateUser(client *ldap.LDAP, firstName, lastName, email string) error {
    // Build user object
    user, err := ldap.NewUserBuilder().
        WithFirstName(firstName).
        WithLastName(lastName).
        WithCN(fmt.Sprintf("%s %s", firstName, lastName)).
        WithEmail(email).
        WithSAMAccountName(strings.ToLower(firstName + "." + lastName)).
        WithPath("ou=users,dc=example,dc=com").
        WithObjectClasses([]string{
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "user",
        }).
        WithAttribute("userAccountControl", "512"). // Normal account
        Build()

    if err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }

    // Create in LDAP
    err = client.CreateUser(*user, "TempPassword123!")
    if err != nil {
        return fmt.Errorf("LDAP creation failed: %w", err)
    }

    return nil
}
```

### Example 2: Dynamic Query Building
```go
func SearchUsers(client *ldap.LDAP, criteria SearchCriteria) ([]*ldap.User, error) {
    // Build dynamic query
    qb := ldap.NewQueryBuilder().
        WithBaseDN("ou=users,dc=example,dc=com").
        WithScope(ldap.ScopeWholeSubtree).
        Where("objectClass", "user")

    if criteria.Department != "" {
        qb = qb.And("department", criteria.Department)
    }

    if criteria.Location != "" {
        qb = qb.And("l", criteria.Location)  // l = location attribute
    }

    if criteria.ActiveOnly {
        qb = qb.And("userAccountControl", "512")
    }

    if criteria.HasEmail {
        qb = qb.AndPresent("mail")
    }

    filter := qb.Build()

    // Execute search
    return client.SearchUsers(filter, []string{"*"})
}
```

### Example 3: Configuration Profiles
```go
type Environment string

const (
    Production  Environment = "production"
    Staging     Environment = "staging"
    Development Environment = "development"
)

func GetConfig(env Environment) (*ldap.Config, error) {
    base := ldap.NewConfigBuilder()

    switch env {
    case Production:
        return base.
            WithServer("ldap-prod.example.com").
            WithPort(636).
            WithBaseDN("dc=prod,dc=example,dc=com").
            WithTLS(true).
            WithPooling(100, 20).
            WithCache(100000, 15*time.Minute).
            WithCircuitBreaker(10, 5*time.Minute).
            WithTimeout(5*time.Second, 30*time.Second).
            Build()

    case Staging:
        return base.
            WithServer("ldap-staging.example.com").
            WithPort(636).
            WithBaseDN("dc=staging,dc=example,dc=com").
            WithTLS(true).
            WithPooling(20, 5).
            WithCache(10000, 5*time.Minute).
            Build()

    case Development:
        return base.
            WithServer("localhost").
            WithPort(389).
            WithBaseDN("dc=dev,dc=example,dc=com").
            WithTLS(false).
            WithPooling(5, 1).
            WithCache(1000, 1*time.Minute).
            Build()

    default:
        return nil, fmt.Errorf("unknown environment: %s", env)
    }
}
```

## 📊 Performance Considerations

### 1. Builder Allocation
Builders allocate minimal memory until Build() is called:
```go
// Efficient: Single allocation
user, err := ldap.NewUserBuilder().
    WithCN("John").
    WithEmail("john@example.com").
    Build()  // Single allocation here
```

### 2. Validation Cost
Validation occurs at Build() time, not during construction:
```go
// All validations run once at Build()
builder := ldap.NewUserBuilder()
for _, attr := range attributes {
    builder.WithAttribute(attr.Key, attr.Value)
}
user, err := builder.Build()  // Validation happens here
```

### 3. Query Performance
QueryBuilder generates optimized LDAP filters:
```go
// Generates efficient filter
query := ldap.NewQueryBuilder().
    Where("objectClass", "user").
    And("department", "Sales").
    And("location", "NYC").
    Build()
// Result: (&(objectClass=user)(department=Sales)(location=NYC))
// Optimized for LDAP server indexing
```

## 🔗 Related Documentation

- [API Reference](API_REFERENCE.md#builders-api) - Complete builder API documentation
- [Architecture Guide](ARCHITECTURE.md#builder-pattern) - Builder pattern implementation details
- [Examples](../examples/basic-usage/) - Runnable builder examples
- [Performance Guide](PERFORMANCE_TUNING.md#builders) - Builder performance optimization

---

*Last Updated: 2025-09-29*
*Version: 1.2.0*
*Component: Builder Patterns*