//go:build !integration

package main

import "testing"

// TestMain_Smoke exercises main() against the example servers configured in
// the demo so that the example source file contributes to statement coverage.
func TestMain_Smoke(t *testing.T) {
	main()
}
