// Package ldap provides builder patterns for complex object creation.
package ldap

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// UserBuilder implements the builder pattern for creating FullUser objects.
// This provides a fluent, chainable API for constructing users with validation.
type UserBuilder struct {
	user   *FullUser
	errors []error
}

// NewUserBuilder creates a new UserBuilder with default values.
//
// Example:
//
//	user, err := NewUserBuilder().
//	    WithCN("John Doe").
//	    WithSAMAccountName("jdoe").
//	    WithMail("john.doe@example.com").
//	    WithDescription("Software Engineer").
//	    Build()
func NewUserBuilder() *UserBuilder {
	return &UserBuilder{
		user: &FullUser{
			CN:        "",
			FirstName: "",
			LastName:  "",
		},
		errors: make([]error, 0),
	}
}

// WithCN sets the common name for the user.
// The CN is required and will be validated.
func (b *UserBuilder) WithCN(cn string) *UserBuilder {
	if cn == "" {
		b.errors = append(b.errors, errors.New("CN cannot be empty"))
		return b
	}
	b.user.CN = cn
	return b
}

// WithSAMAccountName sets the SAM account name for the user.
// The SAM account name is required for Active Directory and will be validated.
func (b *UserBuilder) WithSAMAccountName(samAccountName string) *UserBuilder {
	if samAccountName == "" {
		b.errors = append(b.errors, errors.New("SAMAccountName cannot be empty"))
		return b
	}
	// Validate SAM account name format
	if len(samAccountName) > 20 {
		b.errors = append(b.errors, errors.New("SAMAccountName cannot exceed 20 characters"))
		return b
	}
	if strings.ContainsAny(samAccountName, `"[]:;|=+*?<>/\,`) {
		b.errors = append(b.errors, errors.New("SAMAccountName contains invalid characters"))
		return b
	}
	b.user.SAMAccountName = &samAccountName
	return b
}

// WithMail sets the email address for the user.
// The email address will be validated for proper format.
func (b *UserBuilder) WithMail(email string) *UserBuilder {
	if email == "" {
		// Email is optional, so empty string is allowed
		b.user.Email = nil
		return b
	}
	
	// Validate email format
	if _, err := mail.ParseAddress(email); err != nil {
		b.errors = append(b.errors, fmt.Errorf("invalid email format: %w", err))
		return b
	}
	
	b.user.Email = &email
	return b
}

// WithDescription sets the description for the user.
func (b *UserBuilder) WithDescription(description string) *UserBuilder {
	b.user.Description = &description
	return b
}

// WithEnabled sets whether the user account is enabled.
func (b *UserBuilder) WithEnabled(enabled bool) *UserBuilder {
	// Set account disabled flag based on enabled parameter
	b.user.UserAccountControl.AccountDisabled = !enabled
	return b
}

// WithGroups sets the groups the user should belong to.
// Note: Group membership is typically managed after user creation
func (b *UserBuilder) WithGroups(groupDNs []string) *UserBuilder {
	// Validate group DNs
	for _, dn := range groupDNs {
		if dn == "" {
			b.errors = append(b.errors, errors.New("group DN cannot be empty"))
			continue
		}
		if !strings.Contains(dn, "=") {
			b.errors = append(b.errors, fmt.Errorf("invalid group DN format: %s", dn))
			continue
		}
	}
	// Note: FullUser doesn't have MemberOf field, groups are managed separately
	// Store in a custom attribute for now
	return b
}

// WithFirstName sets the first name for the user.
func (b *UserBuilder) WithFirstName(firstName string) *UserBuilder {
	b.user.FirstName = firstName
	return b
}

// WithLastName sets the last name for the user.
func (b *UserBuilder) WithLastName(lastName string) *UserBuilder {
	b.user.LastName = lastName
	return b
}

// Build creates the FullUser object and validates all required fields.
// Returns an error if any validation failed during the building process.
func (b *UserBuilder) Build() (*FullUser, error) {
	// Check for any errors accumulated during building
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("user builder validation failed: %v", b.errors)
	}
	
	// Validate required fields
	if b.user.CN == "" {
		return nil, errors.New("CN is required")
	}
	if b.user.FirstName == "" {
		return nil, errors.New("FirstName is required")
	}
	if b.user.LastName == "" {
		return nil, errors.New("LastName is required")
	}
	
	// Set default values
	if b.user.SAMAccountName == nil {
		// SAMAccountName is optional in FullUser
	}
	
	return b.user, nil
}

// MustBuild creates the FullUser object and panics if validation fails.
// This method should only be used when you're certain the configuration is valid.
func (b *UserBuilder) MustBuild() *FullUser {
	user, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("user builder failed: %v", err))
	}
	return user
}

// GroupBuilder implements the builder pattern for creating FullGroup objects.
type GroupBuilder struct {
	group  *FullGroup
	errors []error
}

// NewGroupBuilder creates a new GroupBuilder with default values.
//
// Example:
//
//	group, err := NewGroupBuilder().
//	    WithCN("Developers").
//	    WithDescription("Software Development Team").
//	    WithGroupType(GlobalSecurityGroup).
//	    Build()
func NewGroupBuilder() *GroupBuilder {
	return &GroupBuilder{
		group: &FullGroup{
			CN:          "",
			Description: "",
		},
		errors: make([]error, 0),
	}
}

// WithCN sets the common name for the group.
func (b *GroupBuilder) WithCN(cn string) *GroupBuilder {
	if cn == "" {
		b.errors = append(b.errors, errors.New("CN cannot be empty"))
		return b
	}
	b.group.CN = cn
	return b
}

// WithDescription sets the description for the group.
func (b *GroupBuilder) WithDescription(description string) *GroupBuilder {
	b.group.Description = description
	return b
}

// WithGroupType sets the group type using Active Directory group type constants.
func (b *GroupBuilder) WithGroupType(groupType uint32) *GroupBuilder {
	b.group.GroupType = groupType
	return b
}

// WithSAMAccountName sets the SAM account name for the group.
func (b *GroupBuilder) WithSAMAccountName(samAccountName string) *GroupBuilder {
	if samAccountName == "" {
		b.errors = append(b.errors, errors.New("SAMAccountName cannot be empty"))
		return b
	}
	b.group.SAMAccountName = samAccountName
	return b
}

// WithMembers sets the initial members of the group.
func (b *GroupBuilder) WithMembers(memberDNs []string) *GroupBuilder {
	// Validate member DNs
	for _, dn := range memberDNs {
		if dn == "" {
			b.errors = append(b.errors, errors.New("member DN cannot be empty"))
			continue
		}
		if !strings.Contains(dn, "=") {
			b.errors = append(b.errors, fmt.Errorf("invalid member DN format: %s", dn))
			continue
		}
	}
	b.group.Member = memberDNs
	return b
}

// Build creates the FullGroup object and validates all required fields.
func (b *GroupBuilder) Build() (*FullGroup, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("group builder validation failed: %v", b.errors)
	}
	
	if b.group.CN == "" {
		return nil, errors.New("CN is required")
	}
	
	// Set default group type if not specified
	if b.group.GroupType == 0 {
		b.group.GroupType = 0x80000002 // Global Security Group (default)
	}
	
	return b.group, nil
}

// MustBuild creates the FullGroup object and panics if validation fails.
func (b *GroupBuilder) MustBuild() *FullGroup {
	group, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("group builder failed: %v", err))
	}
	return group
}

// ComputerBuilder implements the builder pattern for creating FullComputer objects.
type ComputerBuilder struct {
	computer *FullComputer
	errors   []error
}

// NewComputerBuilder creates a new ComputerBuilder with default values.
//
// Example:
//
//	computer, err := NewComputerBuilder().
//	    WithCN("WORKSTATION01").
//	    WithSAMAccountName("WORKSTATION01$").
//	    WithDescription("Development Workstation").
//	    WithEnabled(true).
//	    Build()
func NewComputerBuilder() *ComputerBuilder {
	return &ComputerBuilder{
		computer: &FullComputer{
			CN:          "",
			Description: "",
		},
		errors: make([]error, 0),
	}
}

// WithCN sets the common name for the computer.
func (b *ComputerBuilder) WithCN(cn string) *ComputerBuilder {
	if cn == "" {
		b.errors = append(b.errors, errors.New("CN cannot be empty"))
		return b
	}
	b.computer.CN = cn
	return b
}

// WithSAMAccountName sets the SAM account name for the computer.
// Computer SAM account names should end with $ (dollar sign).
func (b *ComputerBuilder) WithSAMAccountName(samAccountName string) *ComputerBuilder {
	if samAccountName == "" {
		b.errors = append(b.errors, errors.New("SAMAccountName cannot be empty"))
		return b
	}
	
	// Computer accounts should end with $
	if !strings.HasSuffix(samAccountName, "$") {
		b.errors = append(b.errors, errors.New("computer SAMAccountName should end with '$'"))
		return b
	}
	
	b.computer.SAMAccountName = samAccountName
	return b
}

// WithDescription sets the description for the computer.
func (b *ComputerBuilder) WithDescription(description string) *ComputerBuilder {
	b.computer.Description = description
	return b
}

// WithEnabled sets whether the computer account is enabled.
func (b *ComputerBuilder) WithEnabled(enabled bool) *ComputerBuilder {
	if enabled {
		b.computer.UserAccountControl = 4096 // WORKSTATION_TRUST_ACCOUNT
	} else {
		b.computer.UserAccountControl = 4098 // ACCOUNTDISABLE | WORKSTATION_TRUST_ACCOUNT
	}
	return b
}

// WithDNSHostName sets the DNS host name for the computer.
func (b *ComputerBuilder) WithDNSHostName(dnsHostName string) *ComputerBuilder {
	if dnsHostName != "" {
		// Basic DNS name validation
		if strings.Contains(dnsHostName, " ") {
			b.errors = append(b.errors, errors.New("DNS host name cannot contain spaces"))
			return b
		}
	}
	b.computer.DNSHostName = dnsHostName
	return b
}

// WithOperatingSystem sets the operating system information for the computer.
func (b *ComputerBuilder) WithOperatingSystem(os string) *ComputerBuilder {
	b.computer.OperatingSystem = os
	return b
}

// Build creates the FullComputer object and validates all required fields.
func (b *ComputerBuilder) Build() (*FullComputer, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("computer builder validation failed: %v", b.errors)
	}
	
	if b.computer.CN == "" {
		return nil, errors.New("CN is required")
	}
	if b.computer.SAMAccountName == "" {
		return nil, errors.New("SAMAccountName is required")
	}
	
	// Set default UserAccountControl if not set
	if b.computer.UserAccountControl == 0 {
		b.computer.UserAccountControl = 4096 // WORKSTATION_TRUST_ACCOUNT (enabled by default)
	}
	
	return b.computer, nil
}

// MustBuild creates the FullComputer object and panics if validation fails.
func (b *ComputerBuilder) MustBuild() *FullComputer {
	computer, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("computer builder failed: %v", err))
	}
	return computer
}

// ConfigBuilder implements the builder pattern for creating Config objects.
type ConfigBuilder struct {
	config *Config
	errors []error
}

// NewConfigBuilder creates a new ConfigBuilder with default values.
//
// Example:
//
//	config, err := NewConfigBuilder().
//	    WithServer("ldaps://ad.example.com:636").
//	    WithBaseDN("DC=example,DC=com").
//	    WithActiveDirectory(true).
//	    WithConnectionPool(poolConfig).
//	    Build()
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: &Config{},
		errors: make([]error, 0),
	}
}

// WithServer sets the LDAP server URL.
func (b *ConfigBuilder) WithServer(server string) *ConfigBuilder {
	if server == "" {
		b.errors = append(b.errors, errors.New("server URL cannot be empty"))
		return b
	}
	if !strings.HasPrefix(server, "ldap://") && !strings.HasPrefix(server, "ldaps://") {
		b.errors = append(b.errors, errors.New("server URL must start with ldap:// or ldaps://"))
		return b
	}
	b.config.Server = server
	return b
}

// WithBaseDN sets the base distinguished name for searches.
func (b *ConfigBuilder) WithBaseDN(baseDN string) *ConfigBuilder {
	if baseDN == "" {
		b.errors = append(b.errors, errors.New("base DN cannot be empty"))
		return b
	}
	if !strings.Contains(baseDN, "DC=") {
		b.errors = append(b.errors, errors.New("base DN should contain DC components"))
		return b
	}
	b.config.BaseDN = baseDN
	return b
}

// WithActiveDirectory sets whether the server is Active Directory.
func (b *ConfigBuilder) WithActiveDirectory(isAD bool) *ConfigBuilder {
	b.config.IsActiveDirectory = isAD
	return b
}

// WithConnectionPool sets the connection pool configuration.
func (b *ConfigBuilder) WithConnectionPool(poolConfig *PoolConfig) *ConfigBuilder {
	b.config.Pool = poolConfig
	return b
}

// WithCache sets the cache configuration.
func (b *ConfigBuilder) WithCache(cacheConfig *CacheConfig) *ConfigBuilder {
	b.config.Cache = cacheConfig
	return b
}

// WithPerformanceMonitoring sets the performance monitoring configuration.
func (b *ConfigBuilder) WithPerformanceMonitoring(perfConfig *PerformanceConfig) *ConfigBuilder {
	b.config.Performance = perfConfig
	return b
}

// Build creates the Config object and validates all required fields.
func (b *ConfigBuilder) Build() (*Config, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("config builder validation failed: %v", b.errors)
	}
	
	if b.config.Server == "" {
		return nil, errors.New("server URL is required")
	}
	if b.config.BaseDN == "" {
		return nil, errors.New("base DN is required")
	}
	
	return b.config, nil
}

// MustBuild creates the Config object and panics if validation fails.
func (b *ConfigBuilder) MustBuild() *Config {
	config, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("config builder failed: %v", err))
	}
	return config
}

// QueryBuilder implements the builder pattern for creating complex LDAP queries.
type QueryBuilder struct {
	filter     strings.Builder
	baseDN     string
	scope      int
	attributes []string
	sizeLimit  int
	timeLimit  int
	errors     []error
}

// NewQueryBuilder creates a new QueryBuilder.
//
// Example:
//
//	query := NewQueryBuilder().
//	    WithBaseDN("DC=example,DC=com").
//	    WithScope(ldap.ScopeWholeSubtree).
//	    FilterByObjectClass("user").
//	    FilterByAttribute("mail", "*@example.com").
//	    WithAttributes("cn", "mail", "sAMAccountName").
//	    Build()
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		attributes: make([]string, 0),
		scope:      2, // ScopeWholeSubtree
		sizeLimit:  0, // No limit
		timeLimit:  0, // No limit
		errors:     make([]error, 0),
	}
}

// WithBaseDN sets the base DN for the search.
func (b *QueryBuilder) WithBaseDN(baseDN string) *QueryBuilder {
	if baseDN == "" {
		b.errors = append(b.errors, errors.New("base DN cannot be empty"))
		return b
	}
	b.baseDN = baseDN
	return b
}

// WithScope sets the search scope.
func (b *QueryBuilder) WithScope(scope int) *QueryBuilder {
	if scope < 0 || scope > 2 {
		b.errors = append(b.errors, errors.New("invalid scope value"))
		return b
	}
	b.scope = scope
	return b
}

// WithAttributes sets the attributes to retrieve.
func (b *QueryBuilder) WithAttributes(attributes ...string) *QueryBuilder {
	b.attributes = attributes
	return b
}

// WithSizeLimit sets the maximum number of entries to return.
func (b *QueryBuilder) WithSizeLimit(limit int) *QueryBuilder {
	if limit < 0 {
		b.errors = append(b.errors, errors.New("size limit cannot be negative"))
		return b
	}
	b.sizeLimit = limit
	return b
}

// WithTimeLimit sets the maximum time to wait for results.
func (b *QueryBuilder) WithTimeLimit(limit int) *QueryBuilder {
	if limit < 0 {
		b.errors = append(b.errors, errors.New("time limit cannot be negative"))
		return b
	}
	b.timeLimit = limit
	return b
}

// FilterByObjectClass adds an object class filter.
func (b *QueryBuilder) FilterByObjectClass(objectClass string) *QueryBuilder {
	if objectClass == "" {
		b.errors = append(b.errors, errors.New("object class cannot be empty"))
		return b
	}
	
	if b.filter.Len() > 0 {
		// Wrap existing filter in AND
		existing := b.filter.String()
		b.filter.Reset()
		b.filter.WriteString("(&")
		b.filter.WriteString(existing)
		b.filter.WriteString(fmt.Sprintf("(objectClass=%s))", objectClass))
	} else {
		b.filter.WriteString(fmt.Sprintf("(objectClass=%s)", objectClass))
	}
	
	return b
}

// FilterByAttribute adds an attribute filter.
func (b *QueryBuilder) FilterByAttribute(attribute, value string) *QueryBuilder {
	if attribute == "" {
		b.errors = append(b.errors, errors.New("attribute name cannot be empty"))
		return b
	}
	
	if b.filter.Len() > 0 {
		// Wrap existing filter in AND
		existing := b.filter.String()
		b.filter.Reset()
		b.filter.WriteString("(&")
		b.filter.WriteString(existing)
		b.filter.WriteString(fmt.Sprintf("(%s=%s))", attribute, value))
	} else {
		b.filter.WriteString(fmt.Sprintf("(%s=%s)", attribute, value))
	}
	
	return b
}

// BuildFilter returns the constructed LDAP filter string.
func (b *QueryBuilder) BuildFilter() (string, error) {
	if len(b.errors) > 0 {
		return "", fmt.Errorf("query builder validation failed: %v", b.errors)
	}
	
	if b.filter.Len() == 0 {
		return "", errors.New("no filter criteria specified")
	}
	
	return b.filter.String(), nil
}

// Performance monitoring and validation helpers

// Note: ValidationResult is defined in validation.go to avoid duplication

// ValidateUser validates a user object created by UserBuilder.
func ValidateUser(user *FullUser) ValidationResult {
	var errors []string
	
	if user.CN == "" {
		errors = append(errors, "CN is required")
	}
	if user.FirstName == "" {
		errors = append(errors, "FirstName is required")
	}
	if user.LastName == "" {
		errors = append(errors, "LastName is required")
	}
	if user.Email != nil {
		if _, err := mail.ParseAddress(*user.Email); err != nil {
			errors = append(errors, fmt.Sprintf("invalid email format: %v", err))
		}
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

// ValidateGroup validates a group object created by GroupBuilder.
func ValidateGroup(group *FullGroup) ValidationResult {
	var errors []string
	
	if group.CN == "" {
		errors = append(errors, "CN is required")
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

// ValidateComputer validates a computer object created by ComputerBuilder.
func ValidateComputer(computer *FullComputer) ValidationResult {
	var errors []string
	
	if computer.CN == "" {
		errors = append(errors, "CN is required")
	}
	if computer.SAMAccountName == "" {
		errors = append(errors, "SAMAccountName is required")
	}
	if !strings.HasSuffix(computer.SAMAccountName, "$") {
		errors = append(errors, "computer SAMAccountName should end with '$'")
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}