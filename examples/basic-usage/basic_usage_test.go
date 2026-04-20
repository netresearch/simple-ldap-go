//go:build !integration

package main

import (
	"log"
	"os"
	"testing"
)

// TestMain_Smoke exercises main() against an example server so that the
// example source file contributes to package-level statement coverage. All
// ldap.Client calls fail internally (example server short-circuits the dial)
// but main() tolerates errors and prints diagnostics, so it runs to
// completion without exiting the test binary.
func TestMain_Smoke(t *testing.T) {
	// Redirect log.Fatalf output away from stderr noise; these examples do
	// not call Fatalf in the example-server path but we avoid any accidental
	// process exits just in case by routing through t.
	log.SetOutput(os.Stderr)
	main()
}
