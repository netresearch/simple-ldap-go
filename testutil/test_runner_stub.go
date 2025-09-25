//go:build !integration
// +build !integration

package testutil

import (
	"os"
	"testing"
	"sync"
)

// Stub variables for non-integration builds
var (
	sharedContainer *SharedTestContainer //nolint:unused
	containerMu     sync.Mutex          //nolint:unused
)

// SharedTestContainer is a stub for non-integration builds
type SharedTestContainer struct {
	refCount int        //nolint:unused
	mu       sync.Mutex //nolint:unused
}

// cleanup is a stub method
func (stc *SharedTestContainer) cleanup(t *testing.T) { //nolint:unused
	// No-op stub
}

// TestMain is a stub that just runs the tests normally
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}