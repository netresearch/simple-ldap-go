// Minimal configuration functions to avoid circular import issues in v2.0.0
// Advanced configuration options are temporarily disabled

package ldap

import ()

// Option represents a functional option for configuring an LDAP client.
type Option func(*LDAP)

// WithConnectionPoolDisabled is a placeholder for the connection pool configuration.
// NOTE: Advanced pool configuration temporarily disabled in v2.0.0 due to circular imports
func WithConnectionPoolDisabled() Option {
	return func(l *LDAP) {
		// Pool configuration disabled
	}
}

// WithCacheDisabled is a placeholder for cache configuration.
// NOTE: Advanced cache configuration temporarily disabled in v2.0.0 due to circular imports
func WithCacheDisabled() Option {
	return func(l *LDAP) {
		// Cache configuration disabled
	}
}

// WithPerformanceMonitoringDisabled is a placeholder for performance monitoring.
// NOTE: Performance monitoring temporarily disabled in v2.0.0 due to circular imports
func WithPerformanceMonitoringDisabled() Option {
	return func(l *LDAP) {
		// Performance monitoring disabled
	}
}

// Minimal stats types to avoid breaking existing API
type PerformanceStats struct {
	Message string `json:"message"`
}

type CacheStats struct {
	Message         string `json:"message"`
	AvgSetTime      int64  `json:"avg_set_time"`
	Sets            int64  `json:"sets"`
	Deletes         int64  `json:"deletes"`
	Evictions       int64  `json:"evictions"`
	Expirations     int64  `json:"expirations"`
	NegativeHits    int64  `json:"negative_hits"`
	NegativeEntries int64  `json:"negative_entries"`
	RefreshOps      int64  `json:"refresh_ops"`
	CleanupOps      int64  `json:"cleanup_ops"`
}

// BulkSearchOptions contains options for bulk search operations
type BulkSearchOptions struct {
	BatchSize       int
	MaxConcurrency  int
	UseCache        bool
	ContinueOnError bool
	RetryAttempts   int
}

// Common errors temporarily placed in main package for v2.0.0
var ()

// maskSensitiveData masks sensitive information for logging
// Temporarily placed in main package for v2.0.0
func maskSensitiveData(data string) string {
	if len(data) <= 4 {
		return "***"
	}
	return data[:2] + "***" + data[len(data)-2:]
}

// Object represents an LDAP object (minimal for v2.0.0)
type Object struct {
	// The distinguished name
	dn string
	// The common name
	cn string
	// The attributes
	attributes map[string][]string
}

// DN returns the distinguished name
func (o Object) DN() string {
	return o.dn
}

// CN returns the common name
func (o Object) CN() string {
	return o.cn
}

// GetAttributeValues returns the values for an attribute
func (o Object) GetAttributeValues(name string) []string {
	if o.attributes == nil {
		return nil
	}
	return o.attributes[name]
}

// SearchOptions provides configuration for optimized search operations
// Temporarily placed in main package for v2.0.0
type SearchOptions struct {
	UseCache         bool
	CacheKey         string
	UseNegativeCache bool
	MaxResults       int
	AttributeFilter  []string
}

// DefaultSearchOptions returns SearchOptions with sensible defaults
func DefaultSearchOptions() *SearchOptions {
	return &SearchOptions{
		UseCache:         true,
		UseNegativeCache: true,
		MaxResults:       1000,
	}
}
