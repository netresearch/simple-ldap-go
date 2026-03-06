//go:build !integration

package ldap

import (
	"strings"
	"testing"
	"time"

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
func TestQueryBuilderFilterInjection(t *testing.T) {
	t.Run("ObjectClass filter escapes special characters", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByObjectClass("user)(|(cn=*))").
			BuildFilter()
		assert.NoError(t, err)
		assert.NotContains(t, filter, ")(|(cn=*")
		assert.Contains(t, filter, "\\29") // escaped ')'
	})

	t.Run("Attribute filter escapes special characters", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("cn", "admin)(|(objectClass=*))").
			BuildFilter()
		assert.NoError(t, err)
		assert.NotContains(t, filter, ")(|(objectClass=*")
		assert.Contains(t, filter, "\\29") // escaped ')'
	})

	t.Run("null byte injection is escaped", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("cn", "admin\x00injected").
			BuildFilter()
		assert.NoError(t, err)
		assert.NotContains(t, filter, "\x00")
		assert.Contains(t, filter, "\\00")
	})

	t.Run("asterisk wildcard injection is escaped", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("cn", "*").
			BuildFilter()
		assert.NoError(t, err)
		assert.NotContains(t, filter, "(cn=*)")
		assert.Contains(t, filter, "\\2a") // escaped '*'
	})

	t.Run("combined filters escape properly", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByObjectClass("user").
			FilterByAttribute("cn", "test(value)").
			BuildFilter()
		assert.NoError(t, err)
		assert.Contains(t, filter, "(objectClass=user)")
		assert.Contains(t, filter, "\\28") // escaped '('
		assert.Contains(t, filter, "\\29") // escaped ')'
	})
}

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

// ---------------------------------------------------------------------------
// GroupBuilder tests
// ---------------------------------------------------------------------------

// TestGroupBuilderWithDescription tests the WithDescription method for groups
func TestGroupBuilderWithDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{"sets description", "Software Development Team"},
		{"allows empty description", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewGroupBuilder().WithDescription(tc.description)
			assert.Equal(t, tc.description, builder.group.Description)
			assert.Empty(t, builder.errors)
		})
	}
}

// TestGroupBuilderWithGroupType tests the WithGroupType method
func TestGroupBuilderWithGroupType(t *testing.T) {
	tests := []struct {
		name      string
		groupType uint32
	}{
		{"global security group", 0x80000002},
		{"domain local security group", 0x80000004},
		{"universal security group", 0x80000008},
		{"zero value", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewGroupBuilder().WithGroupType(tc.groupType)
			assert.Equal(t, tc.groupType, builder.group.GroupType)
			assert.Empty(t, builder.errors)
		})
	}
}

// TestGroupBuilderWithSAMAccountName tests the WithSAMAccountName method for groups
func TestGroupBuilderWithSAMAccountName(t *testing.T) {
	t.Run("sets valid SAMAccountName", func(t *testing.T) {
		builder := NewGroupBuilder().WithSAMAccountName("Developers")
		assert.Equal(t, "Developers", builder.group.SAMAccountName)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty SAMAccountName", func(t *testing.T) {
		builder := NewGroupBuilder().WithSAMAccountName("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "SAMAccountName cannot be empty")
	})
}

// TestGroupBuilderWithMembers tests the WithMembers method
func TestGroupBuilderWithMembers(t *testing.T) {
	t.Run("sets valid members", func(t *testing.T) {
		members := []string{
			"cn=jdoe,ou=users,dc=example,dc=com",
			"cn=asmith,ou=users,dc=example,dc=com",
		}
		builder := NewGroupBuilder().WithMembers(members)
		assert.Equal(t, members, builder.group.Member)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty member DN", func(t *testing.T) {
		builder := NewGroupBuilder().WithMembers([]string{""})
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "member DN cannot be empty")
	})

	t.Run("rejects invalid member DN format", func(t *testing.T) {
		builder := NewGroupBuilder().WithMembers([]string{"notadn"})
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "invalid member DN format")
	})

	t.Run("accumulates multiple member errors", func(t *testing.T) {
		builder := NewGroupBuilder().WithMembers([]string{"", "bad", "cn=ok,dc=com"})
		assert.Len(t, builder.errors, 2)
	})
}

// TestGroupBuilderBuild tests the Build method for groups
func TestGroupBuilderBuild(t *testing.T) {
	t.Run("successful build with all fields", func(t *testing.T) {
		group, err := NewGroupBuilder().
			WithCN("Developers").
			WithDescription("Dev Team").
			WithGroupType(0x80000002).
			WithSAMAccountName("Developers").
			WithMembers([]string{"cn=jdoe,ou=users,dc=example,dc=com"}).
			Build()

		require.NoError(t, err)
		assert.Equal(t, "Developers", group.CN)
		assert.Equal(t, "Dev Team", group.Description)
		assert.Equal(t, uint32(0x80000002), group.GroupType)
		assert.Equal(t, "Developers", group.SAMAccountName)
		assert.Len(t, group.Member, 1)
	})

	t.Run("sets default group type when not specified", func(t *testing.T) {
		group, err := NewGroupBuilder().
			WithCN("TestGroup").
			Build()

		require.NoError(t, err)
		assert.Equal(t, uint32(0x80000002), group.GroupType)
	})

	t.Run("fails when CN is missing", func(t *testing.T) {
		group, err := NewGroupBuilder().Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CN is required")
		assert.Nil(t, group)
	})

	t.Run("fails with accumulated errors", func(t *testing.T) {
		group, err := NewGroupBuilder().
			WithCN("").
			WithSAMAccountName("").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group builder validation failed")
		assert.Nil(t, group)
	})
}

// TestGroupBuilderMustBuild tests the MustBuild method for groups
func TestGroupBuilderMustBuild(t *testing.T) {
	t.Run("returns group on valid build", func(t *testing.T) {
		group := NewGroupBuilder().
			WithCN("Developers").
			MustBuild()

		assert.NotNil(t, group)
		assert.Equal(t, "Developers", group.CN)
	})

	t.Run("panics on invalid build", func(t *testing.T) {
		assert.Panics(t, func() {
			NewGroupBuilder().
				WithCN("").
				MustBuild()
		})
	})
}

// ---------------------------------------------------------------------------
// ComputerBuilder tests
// ---------------------------------------------------------------------------

// TestNewComputerBuilder tests the ComputerBuilder constructor
func TestNewComputerBuilder(t *testing.T) {
	t.Run("creates builder with defaults", func(t *testing.T) {
		builder := NewComputerBuilder()
		assert.NotNil(t, builder)
		assert.NotNil(t, builder.computer)
		assert.Empty(t, builder.errors)
		assert.Equal(t, "", builder.computer.CN)
		assert.Equal(t, "", builder.computer.Description)
	})
}

// TestComputerBuilderWithCN tests the WithCN method for computers
func TestComputerBuilderWithCN(t *testing.T) {
	t.Run("sets valid CN", func(t *testing.T) {
		builder := NewComputerBuilder().WithCN("WORKSTATION01")
		assert.Equal(t, "WORKSTATION01", builder.computer.CN)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty CN", func(t *testing.T) {
		builder := NewComputerBuilder().WithCN("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "CN cannot be empty")
	})
}

// TestComputerBuilderWithSAMAccountName tests the WithSAMAccountName method for computers
func TestComputerBuilderWithSAMAccountName(t *testing.T) {
	t.Run("sets valid SAMAccountName with dollar suffix", func(t *testing.T) {
		builder := NewComputerBuilder().WithSAMAccountName("WORKSTATION01$")
		assert.Equal(t, "WORKSTATION01$", builder.computer.SAMAccountName)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty SAMAccountName", func(t *testing.T) {
		builder := NewComputerBuilder().WithSAMAccountName("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "SAMAccountName cannot be empty")
	})

	t.Run("rejects SAMAccountName without dollar suffix", func(t *testing.T) {
		builder := NewComputerBuilder().WithSAMAccountName("WORKSTATION01")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "should end with '$'")
	})
}

// TestComputerBuilderWithDescription tests the WithDescription method for computers
func TestComputerBuilderWithDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{"sets description", "Development Workstation"},
		{"allows empty description", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewComputerBuilder().WithDescription(tc.description)
			assert.Equal(t, tc.description, builder.computer.Description)
			assert.Empty(t, builder.errors)
		})
	}
}

// TestComputerBuilderWithEnabled tests the WithEnabled method for computers
func TestComputerBuilderWithEnabled(t *testing.T) {
	t.Run("sets enabled to true", func(t *testing.T) {
		builder := NewComputerBuilder().WithEnabled(true)
		assert.Equal(t, uint32(4096), builder.computer.UserAccountControl)
	})

	t.Run("sets enabled to false", func(t *testing.T) {
		builder := NewComputerBuilder().WithEnabled(false)
		assert.Equal(t, uint32(4098), builder.computer.UserAccountControl)
	})
}

// TestComputerBuilderWithDNSHostName tests the WithDNSHostName method
func TestComputerBuilderWithDNSHostName(t *testing.T) {
	t.Run("sets valid DNS host name", func(t *testing.T) {
		builder := NewComputerBuilder().WithDNSHostName("ws01.example.com")
		assert.Equal(t, "ws01.example.com", builder.computer.DNSHostName)
		assert.Empty(t, builder.errors)
	})

	t.Run("allows empty DNS host name", func(t *testing.T) {
		builder := NewComputerBuilder().WithDNSHostName("")
		assert.Equal(t, "", builder.computer.DNSHostName)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects DNS host name with spaces", func(t *testing.T) {
		builder := NewComputerBuilder().WithDNSHostName("ws 01.example.com")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "cannot contain spaces")
	})
}

// TestComputerBuilderWithOperatingSystem tests the WithOperatingSystem method
func TestComputerBuilderWithOperatingSystem(t *testing.T) {
	tests := []struct {
		name string
		os   string
	}{
		{"sets operating system", "Windows Server 2022"},
		{"allows empty OS", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewComputerBuilder().WithOperatingSystem(tc.os)
			assert.Equal(t, tc.os, builder.computer.OperatingSystem)
			assert.Empty(t, builder.errors)
		})
	}
}

// TestComputerBuilderBuild tests the Build method for computers
func TestComputerBuilderBuild(t *testing.T) {
	t.Run("successful build with all fields", func(t *testing.T) {
		computer, err := NewComputerBuilder().
			WithCN("WORKSTATION01").
			WithSAMAccountName("WORKSTATION01$").
			WithDescription("Dev Workstation").
			WithEnabled(true).
			WithDNSHostName("ws01.example.com").
			WithOperatingSystem("Windows 11").
			Build()

		require.NoError(t, err)
		assert.Equal(t, "WORKSTATION01", computer.CN)
		assert.Equal(t, "WORKSTATION01$", computer.SAMAccountName)
		assert.Equal(t, "Dev Workstation", computer.Description)
		assert.Equal(t, uint32(4096), computer.UserAccountControl)
		assert.Equal(t, "ws01.example.com", computer.DNSHostName)
		assert.Equal(t, "Windows 11", computer.OperatingSystem)
	})

	t.Run("sets default UserAccountControl when not set", func(t *testing.T) {
		computer, err := NewComputerBuilder().
			WithCN("WORKSTATION01").
			WithSAMAccountName("WORKSTATION01$").
			Build()

		require.NoError(t, err)
		assert.Equal(t, uint32(4096), computer.UserAccountControl)
	})

	t.Run("fails when CN is missing", func(t *testing.T) {
		computer, err := NewComputerBuilder().
			WithSAMAccountName("WS01$").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CN is required")
		assert.Nil(t, computer)
	})

	t.Run("fails when SAMAccountName is missing", func(t *testing.T) {
		computer, err := NewComputerBuilder().
			WithCN("WORKSTATION01").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SAMAccountName is required")
		assert.Nil(t, computer)
	})

	t.Run("fails with accumulated errors", func(t *testing.T) {
		computer, err := NewComputerBuilder().
			WithCN("").
			WithSAMAccountName("").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "computer builder validation failed")
		assert.Nil(t, computer)
	})
}

// TestComputerBuilderMustBuild tests the MustBuild method for computers
func TestComputerBuilderMustBuild(t *testing.T) {
	t.Run("returns computer on valid build", func(t *testing.T) {
		computer := NewComputerBuilder().
			WithCN("WORKSTATION01").
			WithSAMAccountName("WORKSTATION01$").
			MustBuild()

		assert.NotNil(t, computer)
		assert.Equal(t, "WORKSTATION01", computer.CN)
		assert.Equal(t, "WORKSTATION01$", computer.SAMAccountName)
	})

	t.Run("panics on invalid build", func(t *testing.T) {
		assert.Panics(t, func() {
			NewComputerBuilder().
				WithCN("").
				WithSAMAccountName("").
				MustBuild()
		})
	})
}

// ---------------------------------------------------------------------------
// ConfigBuilder tests
// ---------------------------------------------------------------------------

// TestNewConfigBuilder tests the ConfigBuilder constructor
func TestNewConfigBuilder(t *testing.T) {
	t.Run("creates builder with defaults", func(t *testing.T) {
		builder := NewConfigBuilder()
		assert.NotNil(t, builder)
		assert.NotNil(t, builder.config)
		assert.Empty(t, builder.errors)
		assert.Equal(t, "", builder.config.Server)
		assert.Equal(t, "", builder.config.BaseDN)
		assert.False(t, builder.config.IsActiveDirectory)
	})
}

// TestConfigBuilderWithServer tests the WithServer method
func TestConfigBuilderWithServer(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		shouldError bool
		errorMsg    string
	}{
		{"valid ldap URL", "ldap://ad.example.com:389", false, ""},
		{"valid ldaps URL", "ldaps://ad.example.com:636", false, ""},
		{"rejects empty server", "", true, "server URL cannot be empty"},
		{"rejects invalid scheme", "http://ad.example.com", true, "must start with ldap:// or ldaps://"},
		{"rejects bare hostname", "ad.example.com", true, "must start with ldap:// or ldaps://"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewConfigBuilder().WithServer(tc.server)
			if tc.shouldError {
				require.Len(t, builder.errors, 1)
				assert.Contains(t, builder.errors[0].Error(), tc.errorMsg)
			} else {
				assert.Empty(t, builder.errors)
				assert.Equal(t, tc.server, builder.config.Server)
			}
		})
	}
}

// TestConfigBuilderWithBaseDN tests the WithBaseDN method
func TestConfigBuilderWithBaseDN(t *testing.T) {
	tests := []struct {
		name        string
		baseDN      string
		shouldError bool
		errorMsg    string
	}{
		{"valid base DN", "DC=example,DC=com", false, ""},
		{"rejects empty base DN", "", true, "base DN cannot be empty"},
		{"rejects base DN without DC", "ou=users,o=example", true, "should contain DC components"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewConfigBuilder().WithBaseDN(tc.baseDN)
			if tc.shouldError {
				require.Len(t, builder.errors, 1)
				assert.Contains(t, builder.errors[0].Error(), tc.errorMsg)
			} else {
				assert.Empty(t, builder.errors)
				assert.Equal(t, tc.baseDN, builder.config.BaseDN)
			}
		})
	}
}

// TestConfigBuilderWithActiveDirectory tests the WithActiveDirectory method
func TestConfigBuilderWithActiveDirectory(t *testing.T) {
	t.Run("sets Active Directory to true", func(t *testing.T) {
		builder := NewConfigBuilder().WithActiveDirectory(true)
		assert.True(t, builder.config.IsActiveDirectory)
	})

	t.Run("sets Active Directory to false", func(t *testing.T) {
		builder := NewConfigBuilder().WithActiveDirectory(false)
		assert.False(t, builder.config.IsActiveDirectory)
	})
}

// TestConfigBuilderWithConnectionPool tests the WithConnectionPool method
func TestConfigBuilderWithConnectionPool(t *testing.T) {
	t.Run("sets pool config", func(t *testing.T) {
		poolCfg := &PoolConfig{MaxConnections: 10}
		builder := NewConfigBuilder().WithConnectionPool(poolCfg)
		assert.Equal(t, poolCfg, builder.config.Pool)
	})

	t.Run("allows nil pool config", func(t *testing.T) {
		builder := NewConfigBuilder().WithConnectionPool(nil)
		assert.Nil(t, builder.config.Pool)
	})
}

// TestConfigBuilderWithCache tests the WithCache method
func TestConfigBuilderWithCache(t *testing.T) {
	t.Run("sets cache config", func(t *testing.T) {
		cacheCfg := &CacheConfig{Enabled: true, TTL: 5 * time.Minute}
		builder := NewConfigBuilder().WithCache(cacheCfg)
		assert.Equal(t, cacheCfg, builder.config.Cache)
	})

	t.Run("allows nil cache config", func(t *testing.T) {
		builder := NewConfigBuilder().WithCache(nil)
		assert.Nil(t, builder.config.Cache)
	})
}

// TestConfigBuilderWithPerformanceMonitoring tests the WithPerformanceMonitoring method
func TestConfigBuilderWithPerformanceMonitoring(t *testing.T) {
	t.Run("sets performance config", func(t *testing.T) {
		perfCfg := &PerformanceConfig{Enabled: true}
		builder := NewConfigBuilder().WithPerformanceMonitoring(perfCfg)
		assert.Equal(t, perfCfg, builder.config.Performance)
	})

	t.Run("allows nil performance config", func(t *testing.T) {
		builder := NewConfigBuilder().WithPerformanceMonitoring(nil)
		assert.Nil(t, builder.config.Performance)
	})
}

// TestConfigBuilderBuild tests the Build method for configs
func TestConfigBuilderBuild(t *testing.T) {
	t.Run("successful build with all fields", func(t *testing.T) {
		poolCfg := &PoolConfig{MaxConnections: 10}
		cacheCfg := &CacheConfig{Enabled: true}
		perfCfg := &PerformanceConfig{Enabled: true}

		config, err := NewConfigBuilder().
			WithServer("ldaps://ad.example.com:636").
			WithBaseDN("DC=example,DC=com").
			WithActiveDirectory(true).
			WithConnectionPool(poolCfg).
			WithCache(cacheCfg).
			WithPerformanceMonitoring(perfCfg).
			Build()

		require.NoError(t, err)
		assert.Equal(t, "ldaps://ad.example.com:636", config.Server)
		assert.Equal(t, "DC=example,DC=com", config.BaseDN)
		assert.True(t, config.IsActiveDirectory)
		assert.Equal(t, poolCfg, config.Pool)
		assert.Equal(t, cacheCfg, config.Cache)
		assert.Equal(t, perfCfg, config.Performance)
	})

	t.Run("minimal valid config", func(t *testing.T) {
		config, err := NewConfigBuilder().
			WithServer("ldap://localhost:389").
			WithBaseDN("DC=test,DC=local").
			Build()

		require.NoError(t, err)
		assert.Equal(t, "ldap://localhost:389", config.Server)
		assert.Equal(t, "DC=test,DC=local", config.BaseDN)
	})

	t.Run("fails when server is missing", func(t *testing.T) {
		config, err := NewConfigBuilder().
			WithBaseDN("DC=example,DC=com").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server URL is required")
		assert.Nil(t, config)
	})

	t.Run("fails when base DN is missing", func(t *testing.T) {
		config, err := NewConfigBuilder().
			WithServer("ldap://localhost:389").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "base DN is required")
		assert.Nil(t, config)
	})

	t.Run("fails with accumulated errors", func(t *testing.T) {
		config, err := NewConfigBuilder().
			WithServer("").
			WithBaseDN("").
			Build()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config builder validation failed")
		assert.Nil(t, config)
	})
}

// TestConfigBuilderMustBuild tests the MustBuild method for configs
func TestConfigBuilderMustBuild(t *testing.T) {
	t.Run("returns config on valid build", func(t *testing.T) {
		config := NewConfigBuilder().
			WithServer("ldaps://ad.example.com:636").
			WithBaseDN("DC=example,DC=com").
			MustBuild()

		assert.NotNil(t, config)
		assert.Equal(t, "ldaps://ad.example.com:636", config.Server)
	})

	t.Run("panics on invalid build", func(t *testing.T) {
		assert.Panics(t, func() {
			NewConfigBuilder().
				WithServer("").
				MustBuild()
		})
	})
}

// ---------------------------------------------------------------------------
// QueryBuilder tests
// ---------------------------------------------------------------------------

// TestNewQueryBuilder tests the QueryBuilder constructor
func TestNewQueryBuilder(t *testing.T) {
	t.Run("creates builder with defaults", func(t *testing.T) {
		builder := NewQueryBuilder()
		assert.NotNil(t, builder)
		assert.Empty(t, builder.errors)
		assert.Empty(t, builder.attributes)
		assert.Equal(t, 2, builder.scope)
		assert.Equal(t, 0, builder.sizeLimit)
		assert.Equal(t, 0, builder.timeLimit)
		assert.Equal(t, "", builder.baseDN)
	})
}

// TestQueryBuilderWithBaseDN tests the WithBaseDN method
func TestQueryBuilderWithBaseDN(t *testing.T) {
	t.Run("sets valid base DN", func(t *testing.T) {
		builder := NewQueryBuilder().WithBaseDN("DC=example,DC=com")
		assert.Equal(t, "DC=example,DC=com", builder.baseDN)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects empty base DN", func(t *testing.T) {
		builder := NewQueryBuilder().WithBaseDN("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "base DN cannot be empty")
	})
}

// TestQueryBuilderWithScope tests the WithScope method
func TestQueryBuilderWithScope(t *testing.T) {
	tests := []struct {
		name        string
		scope       int
		shouldError bool
	}{
		{"base scope (0)", 0, false},
		{"single level scope (1)", 1, false},
		{"whole subtree scope (2)", 2, false},
		{"negative scope", -1, true},
		{"out of range scope", 3, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewQueryBuilder().WithScope(tc.scope)
			if tc.shouldError {
				assert.Len(t, builder.errors, 1)
				assert.Contains(t, builder.errors[0].Error(), "invalid scope value")
			} else {
				assert.Empty(t, builder.errors)
				assert.Equal(t, tc.scope, builder.scope)
			}
		})
	}
}

// TestQueryBuilderWithAttributes tests the WithAttributes method
func TestQueryBuilderWithAttributes(t *testing.T) {
	t.Run("sets attributes", func(t *testing.T) {
		builder := NewQueryBuilder().WithAttributes("cn", "mail", "sAMAccountName")
		assert.Equal(t, []string{"cn", "mail", "sAMAccountName"}, builder.attributes)
	})

	t.Run("sets empty attributes", func(t *testing.T) {
		builder := NewQueryBuilder().WithAttributes()
		assert.Empty(t, builder.attributes)
	})
}

// TestQueryBuilderWithSizeLimit tests the WithSizeLimit method
func TestQueryBuilderWithSizeLimit(t *testing.T) {
	t.Run("sets valid size limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithSizeLimit(100)
		assert.Equal(t, 100, builder.sizeLimit)
		assert.Empty(t, builder.errors)
	})

	t.Run("allows zero size limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithSizeLimit(0)
		assert.Equal(t, 0, builder.sizeLimit)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects negative size limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithSizeLimit(-1)
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "size limit cannot be negative")
	})
}

// TestQueryBuilderWithTimeLimit tests the WithTimeLimit method
func TestQueryBuilderWithTimeLimit(t *testing.T) {
	t.Run("sets valid time limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithTimeLimit(30)
		assert.Equal(t, 30, builder.timeLimit)
		assert.Empty(t, builder.errors)
	})

	t.Run("allows zero time limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithTimeLimit(0)
		assert.Equal(t, 0, builder.timeLimit)
		assert.Empty(t, builder.errors)
	})

	t.Run("rejects negative time limit", func(t *testing.T) {
		builder := NewQueryBuilder().WithTimeLimit(-1)
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "time limit cannot be negative")
	})
}

// TestQueryBuilderFilterByObjectClass tests the FilterByObjectClass method
func TestQueryBuilderFilterByObjectClass(t *testing.T) {
	t.Run("sets single object class filter", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByObjectClass("user").
			BuildFilter()
		require.NoError(t, err)
		assert.Equal(t, "(objectClass=user)", filter)
	})

	t.Run("combines multiple object class filters with AND", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByObjectClass("user").
			FilterByObjectClass("person").
			BuildFilter()
		require.NoError(t, err)
		assert.Contains(t, filter, "(&")
		assert.Contains(t, filter, "(objectClass=user)")
		assert.Contains(t, filter, "(objectClass=person)")
	})

	t.Run("rejects empty object class", func(t *testing.T) {
		builder := NewQueryBuilder().FilterByObjectClass("")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "object class cannot be empty")
	})
}

// TestQueryBuilderFilterByAttribute tests the FilterByAttribute method
func TestQueryBuilderFilterByAttribute(t *testing.T) {
	t.Run("sets single attribute filter", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("cn", "John Doe").
			BuildFilter()
		require.NoError(t, err)
		assert.Equal(t, "(cn=John Doe)", filter)
	})

	t.Run("combines attribute with object class", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByObjectClass("user").
			FilterByAttribute("cn", "John Doe").
			BuildFilter()
		require.NoError(t, err)
		assert.Contains(t, filter, "(&")
		assert.Contains(t, filter, "(objectClass=user)")
		assert.Contains(t, filter, "(cn=John Doe)")
	})

	t.Run("rejects empty attribute name", func(t *testing.T) {
		builder := NewQueryBuilder().FilterByAttribute("", "value")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "attribute name cannot be empty")
	})

	t.Run("rejects invalid attribute name", func(t *testing.T) {
		builder := NewQueryBuilder().FilterByAttribute("bad attr!", "value")
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "invalid attribute name")
	})

	t.Run("accepts OID format attribute name", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("1.2.840.113556.1.4.221", "value").
			BuildFilter()
		require.NoError(t, err)
		assert.Contains(t, filter, "1.2.840.113556.1.4.221=value")
	})

	t.Run("accepts attribute with hyphens and dots", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("sAMAccount-Name.test", "jdoe").
			BuildFilter()
		require.NoError(t, err)
		assert.Contains(t, filter, "sAMAccount-Name.test=jdoe")
	})

	t.Run("combines multiple attribute filters with AND", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			FilterByAttribute("cn", "John").
			FilterByAttribute("mail", "john@example.com").
			BuildFilter()
		require.NoError(t, err)
		assert.Contains(t, filter, "(&")
		assert.Contains(t, filter, "(cn=John)")
		assert.Contains(t, filter, "(mail=john@example.com)")
	})
}

// TestQueryBuilderBuildFilter tests the BuildFilter method
func TestQueryBuilderBuildFilter(t *testing.T) {
	t.Run("fails with no filter criteria", func(t *testing.T) {
		filter, err := NewQueryBuilder().BuildFilter()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no filter criteria specified")
		assert.Equal(t, "", filter)
	})

	t.Run("fails with accumulated errors", func(t *testing.T) {
		filter, err := NewQueryBuilder().
			WithBaseDN("").
			WithScope(-1).
			FilterByObjectClass("user").
			BuildFilter()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query builder validation failed")
		assert.Equal(t, "", filter)
	})
}

// ---------------------------------------------------------------------------
// Validate functions tests
// ---------------------------------------------------------------------------

// TestValidateUser tests the ValidateUser function
func TestValidateUser(t *testing.T) {
	t.Run("valid user with all fields", func(t *testing.T) {
		email := "john@example.com"
		user := &FullUser{
			CN:        "John Doe",
			FirstName: "John",
			LastName:  "Doe",
			Email:     &email,
		}
		result := ValidateUser(user)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("invalid user missing CN", func(t *testing.T) {
		user := &FullUser{
			CN:        "",
			FirstName: "John",
			LastName:  "Doe",
		}
		result := ValidateUser(user)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "CN is required")
	})

	t.Run("invalid user missing FirstName", func(t *testing.T) {
		user := &FullUser{
			CN:        "John Doe",
			FirstName: "",
			LastName:  "Doe",
		}
		result := ValidateUser(user)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "FirstName is required")
	})

	t.Run("invalid user missing LastName", func(t *testing.T) {
		user := &FullUser{
			CN:        "John Doe",
			FirstName: "John",
			LastName:  "",
		}
		result := ValidateUser(user)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "LastName is required")
	})

	t.Run("invalid user with bad email", func(t *testing.T) {
		badEmail := "not-an-email"
		user := &FullUser{
			CN:        "John Doe",
			FirstName: "John",
			LastName:  "Doe",
			Email:     &badEmail,
		}
		result := ValidateUser(user)
		assert.False(t, result.Valid)
		found := false
		for _, e := range result.Errors {
			if strings.Contains(e, "invalid email format") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected 'invalid email format' in errors")
	})

	t.Run("valid user with nil email", func(t *testing.T) {
		user := &FullUser{
			CN:        "John Doe",
			FirstName: "John",
			LastName:  "Doe",
			Email:     nil,
		}
		result := ValidateUser(user)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("accumulates all errors", func(t *testing.T) {
		badEmail := "invalid"
		user := &FullUser{
			CN:        "",
			FirstName: "",
			LastName:  "",
			Email:     &badEmail,
		}
		result := ValidateUser(user)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 4)
	})
}

// TestValidateGroup tests the ValidateGroup function
func TestValidateGroup(t *testing.T) {
	t.Run("valid group", func(t *testing.T) {
		group := &FullGroup{CN: "Developers"}
		result := ValidateGroup(group)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("invalid group missing CN", func(t *testing.T) {
		group := &FullGroup{CN: ""}
		result := ValidateGroup(group)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "CN is required")
	})
}

// TestValidateComputer tests the ValidateComputer function
func TestValidateComputer(t *testing.T) {
	t.Run("valid computer", func(t *testing.T) {
		computer := &FullComputer{
			CN:             "WORKSTATION01",
			SAMAccountName: "WORKSTATION01$",
		}
		result := ValidateComputer(computer)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("invalid computer missing CN", func(t *testing.T) {
		computer := &FullComputer{
			CN:             "",
			SAMAccountName: "WS01$",
		}
		result := ValidateComputer(computer)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "CN is required")
	})

	t.Run("invalid computer missing SAMAccountName", func(t *testing.T) {
		computer := &FullComputer{
			CN:             "WORKSTATION01",
			SAMAccountName: "",
		}
		result := ValidateComputer(computer)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "SAMAccountName is required")
	})

	t.Run("invalid computer SAMAccountName without dollar", func(t *testing.T) {
		computer := &FullComputer{
			CN:             "WORKSTATION01",
			SAMAccountName: "WS01",
		}
		result := ValidateComputer(computer)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "computer SAMAccountName should end with '$'")
	})

	t.Run("accumulates all errors", func(t *testing.T) {
		computer := &FullComputer{
			CN:             "",
			SAMAccountName: "",
		}
		result := ValidateComputer(computer)
		assert.False(t, result.Valid)
		// CN required, SAMAccountName required, and SAMAccountName missing $
		assert.GreaterOrEqual(t, len(result.Errors), 2)
	})
}

// TestValidateComputerSAMAccountName tests the ValidateComputerSAMAccountName function
func TestValidateComputerSAMAccountName(t *testing.T) {
	tests := []struct {
		name           string
		samAccountName string
		expected       bool
	}{
		{"valid uppercase with dollar", "WORKSTATION01$", true},
		{"missing dollar suffix", "WORKSTATION01", false},
		{"lowercase invalid", "workstation01$", false},
		{"double dollar invalid", "WORKSTATION01$$", false},
		{"empty string", "", false},
		{"only dollar", "$", false},
		{"mixed case invalid", "Workstation01$", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateComputerSAMAccountName(tc.samAccountName)
			assert.Equal(t, tc.expected, result)
		})
	}
}
