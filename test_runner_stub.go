//go:build !integration
// +build !integration

package ldap

import (
	"os"
	"testing"
	"sync"
)

// Stub variables for non-integration builds
var (
	sharedContainer *SharedTestContainer
	containerMu     sync.Mutex
)

// SharedTestContainer is a stub for non-integration builds
type SharedTestContainer struct {
	refCount int
	mu       sync.Mutex
}

// cleanup is a stub method
func (stc *SharedTestContainer) cleanup(t *testing.T) {
	// No-op stub
}

// TestMain is a stub that just runs the tests normally
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}