package ldap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Config.Port is deprecated because nothing reads it. A doc comment saying so
// is a claim; this pins it. Both cases dial port 1 — the one in Server —
// whatever Port says, and the dial error names the port it actually used.
func TestConfigPortIsNotRead(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"Port unset", 0},
		{"Port set to something else entirely", 636},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(Config{
				// Port 1 refuses immediately and involves no resolver.
				Server:              "ldap://127.0.0.1:1",
				Port:                tt.port,
				BaseDN:              "dc=example,dc=com",
				SkipConnectionCheck: true,
			}, "user", "pass")
			require.NoError(t, err)

			conn, err := client.GetConnectionContext(context.Background())
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "127.0.0.1:1",
				"the port comes from Server; Config.Port changes nothing")
		})
	}
}
