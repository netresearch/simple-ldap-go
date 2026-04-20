//go:build !integration

package main

import "testing"

// TestMain_Smoke exercises main() against example servers. It intentionally
// runs the slow-path because the demo sleeps to illustrate cancellation
// behavior; it still stays well under the default test timeout.
func TestMain_Smoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping example smoke in -short mode (sleeps ~5s)")
	}
	main()
}
