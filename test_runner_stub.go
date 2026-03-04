//go:build !integration
// +build !integration

package ldap

import (
	"os"
	"testing"
)

// TestMain is a stub that just runs the tests normally
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
