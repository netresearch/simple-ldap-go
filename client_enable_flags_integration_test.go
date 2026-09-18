//go:build integration
// +build integration

package ldap

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Removing the forced EnableOptimizations is a silent change: nothing fails, the
// cache is simply absent. One INFO record is what makes it noticeable to an
// operator upgrading across it. It is gated on a real server, like every other
// initialization log in client.go, so it needs the container.

func TestNewLogsThatCachingIsOffWhenNoFlagIsSet(t *testing.T) {
	// The change is silent by construction: nothing fails, the cache is simply
	// absent. One log line at INFO is what makes it noticeable to an operator
	// upgrading across it.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tc := SetupTestContainer(t)
	defer tc.Close(t)

	config := tc.Config
	config.Logger = logger

	client, err := New(config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	assert.Nil(t, client.cache, "a cache was built although no flag asked for one")

	var found map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "optimizations_disabled" {
			found = record
		}
	}

	require.NotNil(t, found, "no optimizations_disabled record; operators get no signal at all")
	assert.Equal(t, "INFO", found["level"])
	assert.Contains(t, found["hint"], "EnableCache")
}

func TestNewDoesNotLogTheHintWhenAFlagIsSet(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tc := SetupTestContainer(t)
	defer tc.Close(t)

	config := tc.Config
	config.EnableCache = true
	config.Logger = logger

	client, err := New(config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	assert.NotNil(t, client.cache, "EnableCache was set but no cache was built")

	assert.NotContains(t, buf.String(), "optimizations_disabled",
		"the hint fired although the caller enabled caching")
}
