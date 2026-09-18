package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// New used to set Config.EnableOptimizations itself, before validation and
// before any option ran, which made the cache and the metrics conditions always
// true — `EnableCache: false` could not turn caching off, and neither could
// `EnableOptimizations: false` (#243). The flags are opt-in now, as
// EnableBulkOps always was.

func TestNewLeavesTheOptimizationFlagsAsTheCallerSetThem(t *testing.T) {
	// SkipConnectionCheck keeps New from dialling; the flag is written at the
	// top of New, before the check, so this reaches the defect.
	client, err := New(Config{
		Server:              "ldap://test.example.invalid:389",
		BaseDN:              "dc=example,dc=com",
		SkipConnectionCheck: true,
	}, "admin", "pass")
	require.NoError(t, err)

	assert.False(t, client.config.EnableOptimizations,
		"New set EnableOptimizations behind the caller's back")
	assert.False(t, client.config.EnableCache)
	assert.False(t, client.config.EnableMetrics)
	assert.False(t, client.config.EnableBulkOps)
}

func TestNewKeepsAnExplicitlyEnabledFlag(t *testing.T) {
	client, err := New(Config{
		Server:              "ldap://test.example.invalid:389",
		BaseDN:              "dc=example,dc=com",
		EnableOptimizations: true,
		SkipConnectionCheck: true,
	}, "admin", "pass")
	require.NoError(t, err)

	assert.True(t, client.config.EnableOptimizations)
}
