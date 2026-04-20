//go:build !integration

package main

import "testing"

// TestMain_Smoke exercises main() so that the example source file contributes
// to statement coverage. All LDAP operations short-circuit against example
// servers.
func TestMain_Smoke(t *testing.T) {
	main()
}
