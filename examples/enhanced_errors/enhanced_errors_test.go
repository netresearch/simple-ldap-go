//go:build !integration

package main

import "testing"

// TestMain_Smoke exercises main() so that the example source file contributes
// to statement coverage. The demo's LDAP calls fail against an unreachable
// address and main() reports them rather than exiting, so what this covers is
// the example's error handling.
func TestMain_Smoke(t *testing.T) {
	main()
}
