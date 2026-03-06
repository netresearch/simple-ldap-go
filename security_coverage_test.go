//go:build !integration

package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- SecureCredential coverage ----------

func TestSecureCredential_ZeroizeCredentials(t *testing.T) {
	cred, err := NewSecureCredentialSimple("admin", "password123")
	require.NoError(t, err)

	err = cred.ZeroizeCredentials()
	require.NoError(t, err)

	// After zeroize, internal slices should be nil
	assert.Nil(t, cred.username)
	assert.Nil(t, cred.password)
}

func TestSecureCredential_Clone_Expired(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", -1*time.Second)
	_, err := cred.Clone()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestSecureCredential_Clone_Valid(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", 5*time.Minute)
	cloned, err := cred.Clone()
	require.NoError(t, err)

	u, p := cloned.GetCredentials()
	assert.Equal(t, "user", u)
	assert.Equal(t, "pass", p)
}

func TestSecureCredential_GetCredentials_Expired(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", -1*time.Second)
	u, p := cred.GetCredentials()
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)
}

func TestSecureCredential_IsExpired_ByFlag(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", 5*time.Minute)
	assert.False(t, cred.IsExpired())
	cred.Zeroize()
	assert.True(t, cred.IsExpired())
}

func TestSecureCredential_IsExpired_ByTime(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", -1*time.Second)
	assert.True(t, cred.IsExpired())
}

func TestNewSecureCredential_NilProvider(t *testing.T) {
	_, err := NewSecureCredential(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewSecureCredential_InvalidCredentials(t *testing.T) {
	provider := &DefaultCredentialProvider{username: "", password: "pass"}
	_, err := NewSecureCredential(provider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestDefaultCredentialProvider_ValidateCredentials(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{"valid", "admin", "pass", false},
		{"empty username", "", "pass", true},
		{"empty password", "admin", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DefaultCredentialProvider{username: tt.user, password: tt.pass}
			err := p.ValidateCredentials()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultCredentialProvider_ZeroizeCredentials(t *testing.T) {
	p := &DefaultCredentialProvider{username: "admin", password: "secret"}
	err := p.ZeroizeCredentials()
	assert.NoError(t, err)
	// After zeroize, strings should be zeroed out
	assert.NotEqual(t, "admin", p.username)
	assert.NotEqual(t, "secret", p.password)
}

func TestDefaultCredentialProvider_ZeroizeEmpty(t *testing.T) {
	p := &DefaultCredentialProvider{username: "", password: ""}
	err := p.ZeroizeCredentials()
	assert.NoError(t, err)
}

// ---------- RateLimiter coverage ----------

func TestRateLimiter_RecordSuccess(t *testing.T) {
	rl := NewRateLimiter(nil, nil)
	defer rl.Close()

	rl.CheckLimit("user1")
	rl.CheckLimit("user1")
	rl.RecordSuccess("user1")

	// After success, attempts should be reset
	rl.mutex.RLock()
	entry := rl.entries["user1"]
	assert.Equal(t, 0, entry.Attempts)
	rl.mutex.RUnlock()
}

func TestRateLimiter_RecordSuccess_NonExistent(t *testing.T) {
	rl := NewRateLimiter(nil, nil)
	defer rl.Close()
	// Should not panic for non-existent user
	rl.RecordSuccess("nonexistent")
}

func TestRateLimiter_RecordFailure(t *testing.T) {
	rl := NewRateLimiter(nil, nil)
	defer rl.Close()

	rl.RecordFailure("user1")
	rl.RecordFailure("user1")

	metrics := rl.GetMetrics()
	assert.Equal(t, int64(2), metrics.FailedAuth)
}

func TestRateLimiter_GetMetrics(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     3,
		Window:          time.Minute,
		LockoutDuration: time.Minute,
		CleanupInterval: time.Hour,
		MaxEntries:      1000,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	// Generate some activity
	rl.CheckLimit("user1")
	rl.CheckLimit("user1")
	rl.RecordSuccess("user1")
	rl.RecordFailure("user2")

	metrics := rl.GetMetrics()
	assert.Equal(t, int64(2), metrics.TotalAttempts)
	assert.Equal(t, int64(1), metrics.SuccessfulAuth)
	assert.Equal(t, int64(1), metrics.FailedAuth)
	assert.Greater(t, metrics.AverageAttempts, float64(0))
}

func TestRateLimiter_GetMetrics_ZeroAttempts(t *testing.T) {
	rl := NewRateLimiter(nil, nil)
	defer rl.Close()

	metrics := rl.GetMetrics()
	assert.Equal(t, float64(0), metrics.AverageAttempts)
}

func TestRateLimiter_GetMetrics_ActiveLockouts(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     2,
		Window:          time.Minute,
		LockoutDuration: time.Hour,
		CleanupInterval: time.Hour,
		MaxEntries:      1000,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	// Exceed limit for user1
	rl.CheckLimit("user1")
	rl.CheckLimit("user1")
	rl.CheckLimit("user1") // This triggers lockout

	metrics := rl.GetMetrics()
	assert.Equal(t, int64(1), metrics.ActiveLockouts)
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(nil, nil)
	defer rl.Close()

	rl.CheckLimit("user1")
	rl.CheckLimit("user2")
	rl.RecordFailure("user1")

	rl.Reset()

	rl.mutex.RLock()
	assert.Empty(t, rl.entries)
	rl.mutex.RUnlock()

	metrics := rl.GetMetrics()
	assert.Equal(t, int64(0), metrics.TotalAttempts)
	assert.Equal(t, int64(0), metrics.FailedAuth)
}

func TestRateLimiter_CheckLimit_WindowExpired(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     3,
		Window:          1 * time.Millisecond,
		LockoutDuration: time.Minute,
		CleanupInterval: time.Hour,
		MaxEntries:      1000,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	rl.CheckLimit("user1")
	rl.CheckLimit("user1")

	// Wait for window to expire
	time.Sleep(5 * time.Millisecond)

	// Should be allowed again (window expired, attempts reset)
	assert.True(t, rl.CheckLimit("user1"))
}

func TestRateLimiter_CheckLimit_Lockout(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     2,
		Window:          time.Minute,
		LockoutDuration: time.Minute,
		CleanupInterval: time.Hour,
		MaxEntries:      1000,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	assert.True(t, rl.CheckLimit("user1"))
	assert.True(t, rl.CheckLimit("user1"))
	assert.False(t, rl.CheckLimit("user1")) // Exceeds, locked out

	// Subsequent attempts should be blocked by lockout check
	assert.False(t, rl.CheckLimit("user1"))
}

// ---------- PasswordValidator coverage ----------

func TestDefaultPasswordValidator(t *testing.T) {
	pv := DefaultPasswordValidator()
	assert.Equal(t, 8, pv.MinLength)
	assert.True(t, pv.RequireUppercase)
	assert.True(t, pv.RequireLowercase)
	assert.True(t, pv.RequireNumbers)
	assert.True(t, pv.RequireSymbols)
	assert.NotEmpty(t, pv.ForbiddenWords)
}

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	pv := DefaultPasswordValidator()

	tests := []struct {
		name    string
		pass    string
		wantErr bool
		errMsg  string
	}{
		{"valid", "Str0ng!Pass", false, ""},
		{"too short", "Ab1!", true, "at least"},
		{"no uppercase", "strong1!pass", true, "uppercase"},
		{"no lowercase", "STRONG1!PASS", true, "lowercase"},
		{"no number", "StrongPass!", true, "number"},
		{"no symbol", "StrongPass1", true, "symbol"},
		{"forbidden word", "Password1!x", true, "forbidden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pv.ValidatePassword(tt.pass)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordValidator_CustomConfig(t *testing.T) {
	pv := &PasswordValidator{
		MinLength:        4,
		RequireUppercase: false,
		RequireLowercase: true,
		RequireNumbers:   false,
		RequireSymbols:   false,
		ForbiddenWords:   []string{},
	}

	// Should pass with just lowercase
	assert.NoError(t, pv.ValidatePassword("abcdefgh"))
}

// ---------- containsUppercase/containsLowercase/containsNumber/containsSymbol ----------

func TestContainsHelpers(t *testing.T) {
	assert.True(t, containsUppercase("Hello"))
	assert.False(t, containsUppercase("hello"))
	assert.True(t, containsLowercase("Hello"))
	assert.False(t, containsLowercase("HELLO"))
	assert.True(t, containsNumber("abc1"))
	assert.False(t, containsNumber("abc"))
	assert.True(t, containsSymbol("abc!"))
	assert.False(t, containsSymbol("abc"))
}

// ---------- generateSecureToken ----------

func TestGenerateSecureToken(t *testing.T) {
	token, err := generateSecureToken(32)
	assert.NoError(t, err)
	assert.Len(t, token, 32)

	// Tokens should be unique
	token2, _ := generateSecureToken(32)
	assert.NotEqual(t, token, token2)

	// Invalid length
	_, err = generateSecureToken(0)
	assert.Error(t, err)

	_, err = generateSecureToken(-1)
	assert.Error(t, err)
}

// ---------- SecurityContext ----------

func TestNewSecurityContext(t *testing.T) {
	sc := NewSecurityContext()
	assert.NotEmpty(t, sc.RequestID)
	assert.True(t, sc.AuditEnabled)
}

func TestSecurityContext_AddToContext(t *testing.T) {
	sc := NewSecurityContext()
	sc.ClientIP = "192.168.1.1"
	sc.UserAgent = "test-agent"
	sc.SessionID = "sess-123"

	ctx := sc.AddToContext(context.Background())

	assert.Equal(t, sc, ctx.Value(ContextKeySecurityCtx))
	assert.Equal(t, "192.168.1.1", ctx.Value(ContextKeyClientIP))
	assert.Equal(t, "test-agent", ctx.Value(ContextKeyUserAgent))
	assert.Equal(t, sc.RequestID, ctx.Value(ContextKeyRequestID))
	assert.Equal(t, "sess-123", ctx.Value(ContextKeySessionID))
}

func TestGetSecurityContext_Exists(t *testing.T) {
	sc := NewSecurityContext()
	sc.AuthenticatedUser = "admin"
	ctx := sc.AddToContext(context.Background())

	retrieved := GetSecurityContext(ctx)
	assert.Equal(t, "admin", retrieved.AuthenticatedUser)
}

func TestGetSecurityContext_NotExists(t *testing.T) {
	ctx := context.Background()
	sc := GetSecurityContext(ctx)
	// Should return a new SecurityContext
	assert.NotNil(t, sc)
	assert.NotEmpty(t, sc.RequestID)
}

// ---------- DefaultSecurityConfig ----------

func TestDefaultSecurityConfig(t *testing.T) {
	cfg := DefaultSecurityConfig()
	assert.True(t, cfg.RequireSecureConnection)
	assert.False(t, cfg.DisableTLSVerification)
	assert.Equal(t, 30*time.Second, cfg.ConnectionTimeout)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 256, cfg.MaxPasswordLength)
	assert.True(t, cfg.RequireStrongPasswords)
	assert.True(t, cfg.EnableAuditLogging)
}

// ---------- ValidateTLSConfig coverage ----------

func TestValidateTLSConfig_NilConfig(t *testing.T) {
	err := ValidateTLSConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestValidateTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	err := ValidateTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "InsecureSkipVerify")
}

func TestValidateTLSConfig_NoSecureCiphers(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	err := ValidateTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secure cipher")
}

func TestValidateTLSConfig_SecureCiphers(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
	err := ValidateTLSConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateTLSConfig_NoCiphersSpecified(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	err := ValidateTLSConfig(cfg)
	assert.NoError(t, err)
}

// ---------- CreateSecureTLSConfig coverage ----------

func TestCreateSecureTLSConfig_NilConfig(t *testing.T) {
	cfg := CreateSecureTLSConfig(nil)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.NotEmpty(t, cfg.CipherSuites)
	assert.False(t, cfg.InsecureSkipVerify)
}

func TestCreateSecureTLSConfig_CustomConfig(t *testing.T) {
	input := &TLSConfig{
		MinVersion: tls.VersionTLS13,
		ServerName: "ldap.corp.com",
	}
	cfg := CreateSecureTLSConfig(input)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Equal(t, "ldap.corp.com", cfg.ServerName)
	// CipherSuites should be set to defaults since input didn't have any
	assert.NotEmpty(t, cfg.CipherSuites)
}

func TestCreateSecureTLSConfig_ZeroMinVersion(t *testing.T) {
	input := &TLSConfig{}
	cfg := CreateSecureTLSConfig(input)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// ---------- ValidateIPWhitelist coverage ----------

func TestValidateIPWhitelist_SingleIP(t *testing.T) {
	networks, err := ValidateIPWhitelist([]string{"192.168.1.1"})
	require.NoError(t, err)
	assert.Len(t, networks, 1)
}

func TestValidateIPWhitelist_IPv6(t *testing.T) {
	networks, err := ValidateIPWhitelist([]string{"::1"})
	require.NoError(t, err)
	assert.Len(t, networks, 1)
}

func TestValidateIPWhitelist_InvalidEntry(t *testing.T) {
	_, err := ValidateIPWhitelist([]string{"not-an-ip"})
	assert.Error(t, err)
}

func TestValidateIPWhitelist_Empty(t *testing.T) {
	networks, err := ValidateIPWhitelist([]string{})
	require.NoError(t, err)
	assert.Empty(t, networks)
}

// ---------- maskSensitiveData ----------

func TestMaskSensitiveData(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"test.com domain not masked", "ldaps://test.com", "ldaps://test.com"},
		{"example.com not masked", "user@example.com", "user@example.com"},
		{"CN=test not masked", "CN=test,DC=com", "CN=test,DC=com"},
		{"TestOperation not masked", "TestOperation failed", "TestOperation failed"},
		{"short string masked", "abc", "***"},
		{"4 char string masked", "abcd", "***"},
		{"5 char string masked", "abcde", "a***e"},
		{"longer string masked", "sensitive_data", "se**********ta"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSensitiveData(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// ---------- ValidateSAMAccountName edge cases ----------

func TestValidateSAMAccountName_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		sam     string
		wantErr bool
		errMsg  string
	}{
		{"starts with period", ".admin", true, "period"},
		{"ends with period", "admin.", true, "period"},
		{"backslash", "admin\\test", true, "invalid character"},
		{"double quote", `admin"test`, true, "invalid character"},
		{"forward slash", "admin/test", true, "invalid character"},
		{"brackets", "admin[0]", true, "invalid character"},
		{"colon", "admin:test", true, "invalid character"},
		{"semicolon", "admin;test", true, "invalid character"},
		{"pipe", "admin|test", true, "invalid character"},
		{"equals", "admin=test", true, "invalid character"},
		{"comma", "admin,test", true, "invalid character"},
		{"question mark", "admin?test", true, "invalid character"},
		{"less than", "admin<test", true, "invalid character"},
		{"greater than", "admin>test", true, "invalid character"},
		{"asterisk", "admin*test", true, "invalid character"},
		{"valid hyphen", "admin-test", false, ""},
		{"valid two chars", "ab", false, ""},
		{"exactly max length", "abcdefghijklmnopqrst", false, ""}, // 20 chars
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSAMAccountName(tt.sam)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------- ValidatePassword edge cases ----------

func TestValidatePassword_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		pass    string
		wantErr bool
		errMsg  string
	}{
		{"empty", "", true, "empty"},
		{"too long", string(make([]byte, 129)), true, "too long"},
		{"no special char", "SecurePass1", true, "special"},
		{"no digit", "SecurePass!", true, "digit"},
		{"no uppercase", "securepass1!", true, "uppercase"},
		{"no lowercase", "SECUREPASS1!", true, "lowercase"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.pass)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------- ValidateServerURL edge cases ----------

func TestValidateServerURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"ldap with port 1", "ldap://host:1", false},
		{"ldap with port 65535", "ldap://host:65535", false},
		{"port 0", "ldap://host:0", true},
		{"port 65536", "ldap://host:65536", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServerURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------- ValidateLDAPFilter edge cases ----------

func TestValidateLDAPFilter_MaxNesting(t *testing.T) {
	// Build filter with nesting depth > 20
	filter := ""
	for i := 0; i < 25; i++ {
		filter += "(&"
	}
	filter += "(cn=test)"
	for i := 0; i < 25; i++ {
		filter += ")"
	}
	_, err := ValidateLDAPFilter(filter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "complex")
}

// ---------- RateLimiter cleanup ----------

func TestRateLimiter_Cleanup(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     5,
		Window:          1 * time.Millisecond,
		LockoutDuration: 1 * time.Millisecond,
		CleanupInterval: time.Hour, // won't auto-trigger
		MaxEntries:      1000,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	rl.CheckLimit("old-user")
	time.Sleep(5 * time.Millisecond)

	rl.cleanup()

	rl.mutex.RLock()
	_, exists := rl.entries["old-user"]
	rl.mutex.RUnlock()
	assert.False(t, exists, "old entry should be cleaned up")
}

func TestRateLimiter_Cleanup_MaxEntries(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     5,
		Window:          time.Hour,
		LockoutDuration: time.Hour,
		CleanupInterval: time.Hour,
		MaxEntries:      2,
	}
	rl := NewRateLimiter(config, nil)
	defer rl.Close()

	// Add more than MaxEntries
	rl.CheckLimit("user1")
	time.Sleep(time.Millisecond)
	rl.CheckLimit("user2")
	time.Sleep(time.Millisecond)
	rl.CheckLimit("user3")
	time.Sleep(time.Millisecond)
	rl.CheckLimit("user4")

	rl.cleanup()

	rl.mutex.RLock()
	count := len(rl.entries)
	rl.mutex.RUnlock()
	assert.LessOrEqual(t, count, 2, "should trim to MaxEntries")
}

// ---------- ValidateEmail edge case ----------

func TestValidateEmail_EdgeCases(t *testing.T) {
	err := ValidateEmail("")
	assert.Error(t, err)

	err = ValidateEmail("valid@example.com")
	assert.NoError(t, err)
}

// ---------- Zeroize with nil provider ----------

func TestSecureCredential_Zeroize_NilProvider(t *testing.T) {
	cred := &SecureCredential{
		username: []byte("user"),
		password: []byte("pass"),
		provider: nil,
	}
	// Should not panic
	cred.Zeroize()
	assert.True(t, cred.expired)
}

// ---------- SecureCredential concurrent access ----------

func TestSecureCredential_ConcurrentAccess(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", 5*time.Minute)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			cred.GetCredentials()
			cred.IsExpired()
		}
	}()

	for i := 0; i < 100; i++ {
		cred.GetCredentials()
		cred.IsExpired()
	}
	<-done
}

// ---------- ContextKey types ----------

func TestContextKeys(t *testing.T) {
	assert.Equal(t, ContextKey("client_ip"), ContextKeyClientIP)
	assert.Equal(t, ContextKey("user_agent"), ContextKeyUserAgent)
	assert.Equal(t, ContextKey("request_id"), ContextKeyRequestID)
	assert.Equal(t, ContextKey("session_id"), ContextKeySessionID)
	assert.Equal(t, ContextKey("security_context"), ContextKeySecurityCtx)
}

// ---------- Clone expired by Zeroize ----------

func TestSecureCredential_Clone_Zeroized(t *testing.T) {
	cred := NewSecureCredentialWithTimeout("user", "pass", 5*time.Minute)
	cred.Zeroize()
	_, err := cred.Clone()
	assert.Error(t, err)
}

// ---------- LDAPError thread safety ----------

func TestLDAPError_WithContext_ThreadSafe(t *testing.T) {
	err := NewLDAPError("Op", "srv", errors.New("fail"))
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = err.WithContext("key1", "val1")
		}
	}()

	for i := 0; i < 100; i++ {
		_ = err.WithContext("key2", "val2")
	}
	<-done

	ctx := GetErrorContext(err)
	assert.NotNil(t, ctx)
}
