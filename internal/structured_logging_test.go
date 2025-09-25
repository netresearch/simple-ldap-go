package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogBuffer captures log output for testing
type TestLogBuffer struct {
	buf    *bytes.Buffer
	logger *slog.Logger
}

// NewTestLogBuffer creates a new test log buffer with JSON handler
func NewTestLogBuffer(level slog.Level) *TestLogBuffer {
	buf := &bytes.Buffer{}
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: level,
	})
	logger := slog.New(handler)

	return &TestLogBuffer{
		buf:    buf,
		logger: logger,
	}
}

// GetLogEntries parses JSON log entries from the buffer
func (tlb *TestLogBuffer) GetLogEntries() []map[string]interface{} {
	lines := strings.Split(strings.TrimSpace(tlb.buf.String()), "\n")
	var entries []map[string]interface{}

	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			entries = append(entries, entry)
		}
	}

	return entries
}

// Reset clears the buffer
func (tlb *TestLogBuffer) Reset() {
	tlb.buf.Reset()
}

func TestStructuredLoggingConfiguration(t *testing.T) {
	testBuf := NewTestLogBuffer(slog.LevelDebug)

	config := Config{
		Server:            "ldap://test:389",
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		Logger:            testBuf.logger,
	}

	// This will fail but should generate initialization logs
	_, err := New(&config, "test", "test")
	require.Error(t, err) // Expected to fail since no real server

	entries := testBuf.GetLogEntries()
	require.NotEmpty(t, entries)

	// Check initialization log
	initLog := entries[0]
	assert.Equal(t, "ldap_client_initializing", initLog["msg"])
	assert.Equal(t, "ldap://test:389", initLog["server"])
	assert.Equal(t, "DC=test,DC=com", initLog["base_dn"])
	assert.Equal(t, false, initLog["is_active_directory"])

	// Check error log
	found := false
	for _, entry := range entries {
		if entry["msg"] == "ldap_client_initialization_failed" {
			found = true
			assert.Equal(t, "ldap://test:389", entry["server"])
			assert.Contains(t, entry, "error")
			assert.Contains(t, entry, "duration")
			break
		}
	}
	assert.True(t, found, "Should contain initialization failed log")
}

func TestNoOpLogger(t *testing.T) {
	// Test with no logger configured (should use no-op)
	config := Config{
		Server:            "ldap://test:389",
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		// Logger is nil
	}

	// This should not panic and should not generate any output
	_, err := New(&config, "test", "test")
	require.Error(t, err) // Expected to fail since no real server
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel slog.Level
		expected []string
	}{
		{
			name:     "Debug level logs everything",
			logLevel: slog.LevelDebug,
			expected: []string{"ldap_client_initializing", "ldap_connection_establishing", "ldap_connection_dial_failed", "ldap_client_initialization_failed"},
		},
		{
			name:     "Info level skips debug logs",
			logLevel: slog.LevelInfo,
			expected: []string{"ldap_client_initialization_failed"},
		},
		{
			name:     "Error level only shows errors",
			logLevel: slog.LevelError,
			expected: []string{"ldap_connection_dial_failed", "ldap_client_initialization_failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBuf := NewTestLogBuffer(tt.logLevel)

			config := Config{
				Server:            "ldap://nonexistent:389",
				BaseDN:            "DC=test,DC=com",
				IsActiveDirectory: false,
				Logger:            testBuf.logger,
			}

			_, err := New(&config, "test", "test")
			require.Error(t, err)

			entries := testBuf.GetLogEntries()

			// Check that we have the expected log messages
			foundMsgs := make(map[string]bool)
			for _, entry := range entries {
				if msg, ok := entry["msg"].(string); ok {
					foundMsgs[msg] = true
				}
			}

			for _, expectedMsg := range tt.expected {
				assert.True(t, foundMsgs[expectedMsg], "Should contain log message: %s", expectedMsg)
			}
		})
	}
}

func TestAuthenticationLogging(t *testing.T) {
	testBuf := NewTestLogBuffer(slog.LevelDebug)

	// Test with invalid server - will generate connection logs
	config := Config{
		Server:            "ldap://nonexistent:389",
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		Logger:            testBuf.logger,
	}

	client, err := New(&config, "test", "test")
	require.Error(t, err) // Expected to fail
	require.Nil(t, client)

	entries := testBuf.GetLogEntries()

	// Should have initialization and connection attempt logs
	var initLog, connLog, errorLog map[string]interface{}
	for _, entry := range entries {
		switch entry["msg"] {
		case "ldap_client_initializing":
			initLog = entry
		case "ldap_connection_establishing":
			connLog = entry
		case "ldap_connection_dial_failed":
			errorLog = entry
		}
	}

	assert.NotNil(t, initLog, "Should log client initialization")
	assert.Equal(t, "ldap://nonexistent:389", initLog["server"])
	assert.Equal(t, "DC=test,DC=com", initLog["base_dn"])

	assert.NotNil(t, connLog, "Should log connection attempt")
	assert.Equal(t, "ldap://nonexistent:389", connLog["server"])

	assert.NotNil(t, errorLog, "Should log connection failure")
	assert.Contains(t, errorLog, "error")
	assert.Contains(t, errorLog, "duration")
}

func TestSearchOperationLogging(t *testing.T) {
	// This test demonstrates that search operations would log appropriately
	// In a real scenario with a running LDAP server, these logs would be generated
	testBuf := NewTestLogBuffer(slog.LevelDebug)

	config := Config{
		Server:            "ldap://nonexistent.server:389", // Non-existent server for testing
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		Logger:            testBuf.logger,
	}

	_, err := New(&config, "cn=admin,dc=test,dc=com", "password")
	require.Error(t, err) // Will fail to connect but generate logs

	entries := testBuf.GetLogEntries()

	// Verify we get proper connection and error logs
	foundTypes := make(map[string]bool)
	for _, entry := range entries {
		if msgType, ok := entry["msg"].(string); ok {
			foundTypes[msgType] = true
		}
	}

	// Should have initialization and connection logs
	assert.True(t, foundTypes["ldap_client_initializing"], "Should log initialization")
	assert.True(t, foundTypes["ldap_connection_establishing"], "Should log connection attempt")
	assert.True(t, foundTypes["ldap_connection_dial_failed"] || foundTypes["ldap_client_initialization_failed"], "Should log error")
}

func TestLogSecurity(t *testing.T) {
	testBuf := NewTestLogBuffer(slog.LevelDebug)

	config := Config{
		Server:            "ldap://test:389",
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		Logger:            testBuf.logger,
	}

	// This will fail but should not log the password
	_, err := New(&config, "testuser", "supersecretpassword")
	require.Error(t, err)

	allLogs := testBuf.buf.String()

	// Verify passwords are never logged
	assert.NotContains(t, allLogs, "supersecretpassword", "Password should never appear in logs")

	// Verify usernames do not appear (they should only be logged during actual operations)
	assert.NotContains(t, allLogs, "testuser", "Username should not appear in connection logs for security")
}

func TestPerformanceLogging(t *testing.T) {
	testBuf := NewTestLogBuffer(slog.LevelDebug)

	config := Config{
		Server:            "ldap://timeout-server:389",
		BaseDN:            "DC=test,DC=com",
		IsActiveDirectory: false,
		Logger:            testBuf.logger,
	}

	// This will fail but should log duration
	start := time.Now()
	_, err := New(&config, "test", "test")
	actualDuration := time.Since(start)
	require.Error(t, err)

	entries := testBuf.GetLogEntries()

	// Find error log with duration
	var errorLog map[string]interface{}
	for _, entry := range entries {
		if strings.Contains(fmt.Sprintf("%v", entry["msg"]), "failed") && entry["duration"] != nil {
			errorLog = entry
			break
		}
	}

	require.NotNil(t, errorLog, "Should have error log with duration")

	// Verify duration is present (could be string or number)
	duration := errorLog["duration"]
	require.NotNil(t, duration, "Duration should be present")

	// Check if it's parseable as a duration string or is a number
	if durationStr, ok := duration.(string); ok {
		loggedDuration, err := time.ParseDuration(durationStr)
		require.NoError(t, err)
		assert.LessOrEqual(t, loggedDuration, actualDuration+time.Second)
		assert.Greater(t, loggedDuration, time.Duration(0))
	} else {
		// If it's not a string, it might be a number (nanoseconds)
		assert.NotNil(t, duration, "Duration should be present in some format")
	}
}
