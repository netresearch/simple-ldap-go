//go:build !integration

package ldap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewUserBuilder tests the UserBuilder constructor
func TestNewUserBuilder(t *testing.T) {
	t.Run("creates builder with defaults", func(t *testing.T) {
		builder := NewUserBuilder()
		assert.NotNil(t, builder)
		assert.NotNil(t, builder.user)
		assert.Empty(t, builder.errors)
		assert.Equal(t, "", builder.user.CN)
		assert.Equal(t, "", builder.user.FirstName)
		assert.Equal(t, "", builder.user.LastName)
	})
}

// TestUserBuilderWithCN tests the WithCN method
func TestUserBuilderWithCN(t *testing.T) {
	t.Run("sets valid CN", func(t *testing.T) {
		builder := NewUserBuilder().WithCN("John Doe")
		_, err := builder.Build()
		require.Error(t, err) // Still needs SAMAccountName
		assert.Equal(t, "John Doe", builder.user.CN)
	})

	t.Run("rejects empty CN", func(t *testing.T) {
		builder := NewUserBuilder().WithCN("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "CN cannot be empty")
	})

	t.Run("CN is required for build", func(t *testing.T) {
		builder := NewUserBuilder().WithSAMAccountName("jdoe")
		user, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CN is required")
		assert.Nil(t, user)
	})
}

// TestUserBuilderWithSAMAccountName tests the WithSAMAccountName method
func TestUserBuilderWithSAMAccountName(t *testing.T) {
	t.Run("sets valid SAMAccountName", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.NotNil(t, user.SAMAccountName)
		assert.Equal(t, "jdoe", *user.SAMAccountName)
	})

	t.Run("rejects empty SAMAccountName", func(t *testing.T) {
		builder := NewUserBuilder().WithSAMAccountName("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "SAMAccountName cannot be empty")
	})

	t.Run("rejects SAMAccountName over 20 characters", func(t *testing.T) {
		builder := NewUserBuilder().WithSAMAccountName("thisusernameiswaytoolong")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "cannot exceed 20 characters")
	})

	t.Run("rejects SAMAccountName with invalid characters", func(t *testing.T) {
		invalidChars := []string{"[", "]", ":", ";", "|", "=", "+", "*", "?", "<", ">", "/", "\\", ","}
		for _, char := range invalidChars {
			builder := NewUserBuilder().WithSAMAccountName("user" + char + "name")
			assert.Greater(t, len(builder.errors), 0)
			assert.Contains(t, builder.errors[len(builder.errors)-1].Error(), "invalid characters")
		}
	})

	t.Run("SAMAccountName is required for build", func(t *testing.T) {
		builder := NewUserBuilder().WithCN("John Doe")
		user, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SAMAccountName is required")
		assert.Nil(t, user)
	})
}

// TestUserBuilderWithMail tests the WithMail method
func TestUserBuilderWithMail(t *testing.T) {
	t.Run("sets valid email", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithMail("john.doe@example.com")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.NotNil(t, user.Email)
		assert.Equal(t, "john.doe@example.com", *user.Email)
	})

	t.Run("allows empty email", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithMail("")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.Nil(t, user.Email)
	})

	t.Run("rejects invalid email format", func(t *testing.T) {
		invalidEmails := []string{
			"notanemail",
			"@example.com",
			"user@",
			"user@.com",
		}
		for _, email := range invalidEmails {
			builder := NewUserBuilder().WithMail(email)
			if assert.Greater(t, len(builder.errors), 0, "Email '%s' should generate error", email) {
				assert.Contains(t, builder.errors[0].Error(), "invalid email format")
			}
		}
	})
}

// TestUserBuilderWithDescription tests the WithDescription method
func TestUserBuilderWithDescription(t *testing.T) {
	t.Run("sets description", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithDescription("Software Engineer")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.NotNil(t, user.Description)
		assert.Equal(t, "Software Engineer", *user.Description)
	})

	t.Run("allows empty description", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithDescription("")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.NotNil(t, user.Description)
		assert.Equal(t, "", *user.Description)
	})
}

// TestUserBuilderWithEnabled tests the WithEnabled method
func TestUserBuilderWithEnabled(t *testing.T) {
	t.Run("sets enabled to true", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithEnabled(true)
		user, err := builder.Build()
		require.NoError(t, err)
		assert.False(t, user.UserAccountControl.AccountDisabled)
	})

	t.Run("sets enabled to false", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithEnabled(false)
		user, err := builder.Build()
		require.NoError(t, err)
		assert.True(t, user.UserAccountControl.AccountDisabled)
	})
}

// TestUserBuilderWithGroups tests the WithGroups method
func TestUserBuilderWithGroups(t *testing.T) {
	t.Run("validates group DNs", func(t *testing.T) {
		builder := NewUserBuilder().WithGroups([]string{
			"cn=admins,ou=groups,dc=example,dc=com",
			"cn=users,ou=groups,dc=example,dc=com",
		})
		// Groups are validated but not stored in FullUser (managed separately)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty group DN", func(t *testing.T) {
		builder := NewUserBuilder().WithGroups([]string{""})
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "group DN cannot be empty")
	})

	t.Run("rejects invalid group DN format", func(t *testing.T) {
		builder := NewUserBuilder().WithGroups([]string{"notadn"})
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "invalid group DN format")
	})
}

// TestUserBuilderWithNames tests WithFirstName and WithLastName methods
func TestUserBuilderWithNames(t *testing.T) {
	t.Run("sets first and last name", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithFirstName("John").
			WithLastName("Doe")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.Equal(t, "John", user.FirstName)
		assert.Equal(t, "Doe", user.LastName)
	})

	t.Run("allows empty names", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithFirstName("").
			WithLastName("")
		user, err := builder.Build()
		require.NoError(t, err)
		assert.Equal(t, "", user.FirstName)
		assert.Equal(t, "", user.LastName)
	})
}

// TestUserBuilderBuild tests the Build method
func TestUserBuilderBuild(t *testing.T) {
	t.Run("successful build with all fields", func(t *testing.T) {
		user, err := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			WithMail("john.doe@example.com").
			WithDescription("Software Engineer").
			WithEnabled(true).
			WithFirstName("John").
			WithLastName("Doe").
			Build()

		require.NoError(t, err)
		assert.Equal(t, "John Doe", user.CN)
		assert.Equal(t, "jdoe", *user.SAMAccountName)
		assert.Equal(t, "john.doe@example.com", *user.Email)
		assert.Equal(t, "Software Engineer", *user.Description)
		assert.False(t, user.UserAccountControl.AccountDisabled)
		assert.Equal(t, "John", user.FirstName)
		assert.Equal(t, "Doe", user.LastName)
	})

	t.Run("fails with accumulated errors", func(t *testing.T) {
		user, err := NewUserBuilder().
			WithCN("").                                     // Error: empty CN
			WithSAMAccountName("thisusernameiswaytoolong"). // Error: too long
			WithMail("notanemail").                         // Error: invalid format
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user builder validation failed")
		assert.Nil(t, user)
	})

	t.Run("minimal valid user", func(t *testing.T) {
		user, err := NewUserBuilder().
			WithCN("Minimal User").
			WithSAMAccountName("minimal").
			Build()

		require.NoError(t, err)
		assert.Equal(t, "Minimal User", user.CN)
		assert.Equal(t, "minimal", *user.SAMAccountName)
		assert.Nil(t, user.Email)
		assert.Nil(t, user.Description)
	})
}

// TestUserBuilderMustBuild tests the MustBuild method
func TestUserBuilderMustBuild(t *testing.T) {
	t.Run("returns user on valid build", func(t *testing.T) {
		user := NewUserBuilder().
			WithCN("John Doe").
			WithSAMAccountName("jdoe").
			MustBuild()

		assert.NotNil(t, user)
		assert.Equal(t, "John Doe", user.CN)
		assert.Equal(t, "jdoe", *user.SAMAccountName)
	})

	t.Run("panics on invalid build", func(t *testing.T) {
		assert.Panics(t, func() {
			NewUserBuilder().
				WithCN("").
				WithSAMAccountName("").
				MustBuild()
		})
	})
}

// TestNewGroupBuilder tests the GroupBuilder constructor
func TestNewGroupBuilder(t *testing.T) {
	t.Run("creates builder with defaults", func(t *testing.T) {
		builder := NewGroupBuilder()
		assert.NotNil(t, builder)
		assert.NotNil(t, builder.group)
		assert.Empty(t, builder.errors)
		assert.Equal(t, "", builder.group.CN)
		assert.Equal(t, "", builder.group.Description)
	})
}

// TestGroupBuilderWithCN tests the WithCN method for groups
func TestGroupBuilderWithCN(t *testing.T) {
	t.Run("sets valid CN", func(t *testing.T) {
		builder := NewGroupBuilder().WithCN("Developers")
		assert.Equal(t, "Developers", builder.group.CN)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty CN", func(t *testing.T) {
		builder := NewGroupBuilder().WithCN("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "CN cannot be empty")
	})
}

// TestChainedBuilding tests fluent interface chaining
func TestChainedBuilding(t *testing.T) {
	t.Run("user builder method chaining", func(t *testing.T) {
		user, err := NewUserBuilder().
			WithCN("Alice Smith").
			WithSAMAccountName("asmith").
			WithMail("alice.smith@example.com").
			WithDescription("Team Lead").
			WithFirstName("Alice").
			WithLastName("Smith").
			WithEnabled(true).
			WithGroups([]string{"cn=leads,ou=groups,dc=example,dc=com"}).
			Build()

		require.NoError(t, err)
		assert.Equal(t, "Alice Smith", user.CN)
		assert.Equal(t, "asmith", *user.SAMAccountName)
		assert.Equal(t, "alice.smith@example.com", *user.Email)
	})

	t.Run("builder returns self for chaining", func(t *testing.T) {
		builder := NewUserBuilder()
		assert.Equal(t, builder, builder.WithCN("Test"))
		assert.Equal(t, builder, builder.WithSAMAccountName("test"))
		assert.Equal(t, builder, builder.WithMail("test@example.com"))
		assert.Equal(t, builder, builder.WithDescription("Test"))
		assert.Equal(t, builder, builder.WithEnabled(true))
		assert.Equal(t, builder, builder.WithFirstName("Test"))
		assert.Equal(t, builder, builder.WithLastName("User"))
		assert.Equal(t, builder, builder.WithGroups([]string{}))
	})
}

// TestBuilderErrorAccumulation tests that errors accumulate properly
func TestBuilderErrorAccumulation(t *testing.T) {
	t.Run("accumulates multiple errors", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("").                     // Error 1
			WithSAMAccountName("").         // Error 2
			WithMail("invalid").            // Error 3
			WithGroups([]string{"", "bad"}) // Error 4 & 5

		assert.Len(t, builder.errors, 5)
	})

	t.Run("all errors reported in build", func(t *testing.T) {
		builder := NewUserBuilder().
			WithCN("").
			WithSAMAccountName("user@name") // Invalid chars

		user, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
		assert.Nil(t, user)
	})
}

// BenchmarkUserBuilder benchmarks user building
func BenchmarkUserBuilder(b *testing.B) {
	b.Run("minimal user", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = NewUserBuilder().
				WithCN("John Doe").
				WithSAMAccountName("jdoe").
				Build()
		}
	})

	b.Run("full user", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = NewUserBuilder().
				WithCN("John Doe").
				WithSAMAccountName("jdoe").
				WithMail("john.doe@example.com").
				WithDescription("Software Engineer").
				WithFirstName("John").
				WithLastName("Doe").
				WithEnabled(true).
				Build()
		}
	})
}

// TestBuilderThreadSafety tests that builders are not thread-safe (by design)
func TestBuilderThreadSafety(t *testing.T) {
	t.Run("separate builders don't interfere", func(t *testing.T) {
		builder1 := NewUserBuilder().WithCN("User1")
		builder2 := NewUserBuilder().WithCN("User2")

		assert.Equal(t, "User1", builder1.user.CN)
		assert.Equal(t, "User2", builder2.user.CN)
	})
}

// TestBuilderValidationRules tests specific validation rules
func TestBuilderValidationRules(t *testing.T) {
	t.Run("SAMAccountName validation", func(t *testing.T) {
		testCases := []struct {
			name        string
			samAccount  string
			shouldError bool
			errorMsg    string
		}{
			{"valid", "jdoe", false, ""},
			{"valid with numbers", "jdoe123", false, ""},
			{"max length", strings.Repeat("a", 20), false, ""},
			{"too long", strings.Repeat("a", 21), true, "exceed 20 characters"},
			{"with quote", `john"doe`, true, "invalid characters"},
			{"with bracket", "john[doe]", true, "invalid characters"},
			{"with colon", "john:doe", true, "invalid characters"},
			{"with semicolon", "john;doe", true, "invalid characters"},
			{"with pipe", "john|doe", true, "invalid characters"},
			{"with equals", "john=doe", true, "invalid characters"},
			{"with plus", "john+doe", true, "invalid characters"},
			{"with asterisk", "john*doe", true, "invalid characters"},
			{"with question", "john?doe", true, "invalid characters"},
			{"with less than", "john<doe", true, "invalid characters"},
			{"with greater than", "john>doe", true, "invalid characters"},
			{"with slash", "john/doe", true, "invalid characters"},
			{"with backslash", `john\doe`, true, "invalid characters"},
			{"with comma", "john,doe", true, "invalid characters"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				builder := NewUserBuilder().WithSAMAccountName(tc.samAccount)
				if tc.shouldError {
					if assert.Greater(t, len(builder.errors), 0, "SAMAccountName '%s' should error", tc.samAccount) {
						if tc.errorMsg != "" {
							assert.Contains(t, builder.errors[0].Error(), tc.errorMsg)
						}
					}
				} else {
					assert.Empty(t, builder.errors)
				}
			})
		}
	})

	t.Run("email validation", func(t *testing.T) {
		testCases := []struct {
			name        string
			email       string
			shouldError bool
		}{
			{"valid", "user@example.com", false},
			{"valid with subdomain", "user@mail.example.com", false},
			{"valid with plus", "user+tag@example.com", false},
			{"valid with dots", "first.last@example.com", false},
			{"empty allowed", "", false},
			{"missing @", "userexample.com", true},
			{"missing domain", "user@", true},
			{"missing user", "@example.com", true},
			{"no dot", "userexample@com", false}, // Go mail.ParseAddress accepts this
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				builder := NewUserBuilder().WithMail(tc.email)
				if tc.shouldError {
					assert.Greater(t, len(builder.errors), 0, "Email '%s' should be invalid", tc.email)
				} else {
					assert.Empty(t, builder.errors, "Email '%s' should be valid", tc.email)
				}
			})
		}
	})
}

// TestBuilderDefaultValues tests default values in builders
func TestBuilderDefaultValues(t *testing.T) {
	t.Run("user defaults", func(t *testing.T) {
		builder := NewUserBuilder()
		assert.Equal(t, "", builder.user.CN)
		assert.Equal(t, "", builder.user.FirstName)
		assert.Equal(t, "", builder.user.LastName)
		assert.Nil(t, builder.user.SAMAccountName)
		assert.Nil(t, builder.user.Email)
		assert.Nil(t, builder.user.Description)
		assert.False(t, builder.user.UserAccountControl.AccountDisabled) // Enabled by default
	})

	t.Run("group defaults", func(t *testing.T) {
		builder := NewGroupBuilder()
		assert.Equal(t, "", builder.group.CN)
		assert.Equal(t, "", builder.group.Description)
	})
}

// TestBuilderErrorMessages tests error message quality
func TestBuilderErrorMessages(t *testing.T) {
	t.Run("descriptive error messages", func(t *testing.T) {
		tests := []struct {
			name     string
			builder  *UserBuilder
			expected string
		}{
			{
				"empty CN",
				NewUserBuilder().WithCN(""),
				"CN cannot be empty",
			},
			{
				"empty SAMAccountName",
				NewUserBuilder().WithSAMAccountName(""),
				"SAMAccountName cannot be empty",
			},
			{
				"long SAMAccountName",
				NewUserBuilder().WithSAMAccountName(strings.Repeat("a", 21)),
				"cannot exceed 20 characters",
			},
			{
				"invalid email",
				NewUserBuilder().WithMail("not-an-email"),
				"invalid email format",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if assert.Greater(t, len(test.builder.errors), 0) {
					found := false
					for _, err := range test.builder.errors {
						if strings.Contains(err.Error(), test.expected) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message containing '%s' not found", test.expected)
				}
			})
		}
	})
}
