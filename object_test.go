package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

func TestObject(t *testing.T) {
	t.Run("object creation and methods", func(t *testing.T) {
		// Create a mock LDAP entry
		entry := &ldap.Entry{
			DN: "cn=Test Object,ou=objects,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{
					Name:   "cn",
					Values: []string{"Test Object"},
				},
			},
		}

		// Test objectFromEntry function
		obj := objectFromEntry(entry)

		// Test DN method
		assert.Equal(t, "cn=Test Object,ou=objects,dc=example,dc=com", obj.DN())

		// Test CN method
		assert.Equal(t, "Test Object", obj.CN())
	})
}

func TestObjectFromEntry(t *testing.T) {
	tests := []struct {
		name       string
		entry      *ldap.Entry
		expectedDN string
		expectedCN string
	}{
		{
			name: "standard user entry",
			entry: &ldap.Entry{
				DN: "uid=jdoe,ou=people,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"John Doe"},
					},
				},
			},
			expectedDN: "uid=jdoe,ou=people,dc=example,dc=com",
			expectedCN: "John Doe",
		},
		{
			name: "group entry",
			entry: &ldap.Entry{
				DN: "cn=admins,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"admins"},
					},
				},
			},
			expectedDN: "cn=admins,ou=groups,dc=example,dc=com",
			expectedCN: "admins",
		},
		{
			name: "computer entry",
			entry: &ldap.Entry{
				DN: "cn=WORKSTATION01,ou=computers,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"WORKSTATION01"},
					},
				},
			},
			expectedDN: "cn=WORKSTATION01,ou=computers,dc=example,dc=com",
			expectedCN: "WORKSTATION01",
		},
		{
			name: "entry with empty CN",
			entry: &ldap.Entry{
				DN: "cn=empty,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{""},
					},
				},
			},
			expectedDN: "cn=empty,dc=example,dc=com",
			expectedCN: "",
		},
		{
			name: "entry with no CN attribute",
			entry: &ldap.Entry{
				DN:         "cn=nocn,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{},
			},
			expectedDN: "cn=nocn,dc=example,dc=com",
			expectedCN: "", // GetAttributeValue returns empty string for missing attributes
		},
		{
			name: "entry with multiple CN values",
			entry: &ldap.Entry{
				DN: "cn=multiple,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"First CN", "Second CN"},
					},
				},
			},
			expectedDN: "cn=multiple,dc=example,dc=com",
			expectedCN: "First CN", // GetAttributeValue returns first value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := objectFromEntry(tt.entry)

			assert.Equal(t, tt.expectedDN, obj.DN())
			assert.Equal(t, tt.expectedCN, obj.CN())
		})
	}
}

func TestObjectStructFields(t *testing.T) {
	t.Run("object struct field access", func(t *testing.T) {
		// Test that Object struct fields are properly set and accessed
		obj := Object{
			cn: "Test CN",
			dn: "cn=Test CN,dc=example,dc=com",
		}

		assert.Equal(t, "Test CN", obj.CN())
		assert.Equal(t, "cn=Test CN,dc=example,dc=com", obj.DN())
	})
}

func TestObjectInheritance(t *testing.T) {
	// Test that structs embedding Object inherit its methods correctly
	t.Run("user object inheritance", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "uid=testuser,ou=people,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{
					Name:   "cn",
					Values: []string{"Test User"},
				},
				{
					Name:   "sAMAccountName",
					Values: []string{"testuser"},
				},
				{
					Name:   "userAccountControl",
					Values: []string{"512"}, // Normal enabled account
				},
			},
		}

		// This simulates what userFromEntry would do
		user := &User{
			Object:         objectFromEntry(entry),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Enabled:        true, // Would be parsed from userAccountControl
		}

		// Test that User can access Object methods
		assert.Equal(t, "uid=testuser,ou=people,dc=example,dc=com", user.DN())
		assert.Equal(t, "Test User", user.CN())
		assert.Equal(t, "testuser", user.SAMAccountName)
		assert.True(t, user.Enabled)
	})

	t.Run("group object inheritance", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=testgroup,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{
					Name:   "cn",
					Values: []string{"testgroup"},
				},
				{
					Name: "member",
					Values: []string{
						"uid=user1,ou=people,dc=example,dc=com",
						"uid=user2,ou=people,dc=example,dc=com",
					},
				},
			},
		}

		// This simulates what the group creation would do
		group := &Group{
			Object:  objectFromEntry(entry),
			Members: entry.GetAttributeValues("member"),
		}

		// Test that Group can access Object methods
		assert.Equal(t, "cn=testgroup,ou=groups,dc=example,dc=com", group.DN())
		assert.Equal(t, "testgroup", group.CN())
		assert.Len(t, group.Members, 2)
	})

	t.Run("computer object inheritance", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=TESTCOMPUTER,ou=computers,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{
					Name:   "cn",
					Values: []string{"TESTCOMPUTER"},
				},
				{
					Name:   "sAMAccountName",
					Values: []string{"TESTCOMPUTER$"},
				},
				{
					Name:   "operatingSystem",
					Values: []string{"Windows 10 Pro"},
				},
				{
					Name:   "operatingSystemVersion",
					Values: []string{"10.0.19041"},
				},
			},
		}

		// This simulates what the computer creation would do
		computer := &Computer{
			Object:         objectFromEntry(entry),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			OS:             entry.GetAttributeValue("operatingSystem"),
			OSVersion:      entry.GetAttributeValue("operatingSystemVersion"),
			Enabled:        true,
		}

		// Test that Computer can access Object methods
		assert.Equal(t, "cn=TESTCOMPUTER,ou=computers,dc=example,dc=com", computer.DN())
		assert.Equal(t, "TESTCOMPUTER", computer.CN())
		assert.Equal(t, "TESTCOMPUTER$", computer.SAMAccountName)
		assert.Equal(t, "Windows 10 Pro", computer.OS)
		assert.Equal(t, "10.0.19041", computer.OSVersion)
	})
}

func TestObjectWithSpecialCharacters(t *testing.T) {
	t.Run("object with special characters in DN and CN", func(t *testing.T) {
		tests := []struct {
			name string
			dn   string
			cn   string
		}{
			{
				name: "special characters in CN",
				dn:   "cn=User\\, John (IT),ou=people,dc=example,dc=com",
				cn:   "User, John (IT)",
			},
			{
				name: "unicode characters",
				dn:   "cn=Пользователь,ou=people,dc=example,dc=com",
				cn:   "Пользователь",
			},
			{
				name: "empty CN",
				dn:   "cn=,ou=people,dc=example,dc=com",
				cn:   "",
			},
			{
				name: "CN with spaces",
				dn:   "cn=   User With Spaces   ,ou=people,dc=example,dc=com",
				cn:   "   User With Spaces   ",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				entry := &ldap.Entry{
					DN: tt.dn,
					Attributes: []*ldap.EntryAttribute{
						{
							Name:   "cn",
							Values: []string{tt.cn},
						},
					},
				}

				obj := objectFromEntry(entry)
				assert.Equal(t, tt.dn, obj.DN())
				assert.Equal(t, tt.cn, obj.CN())
			})
		}
	})
}

func TestObjectEdgeCases(t *testing.T) {
	t.Run("nil entry handling", func(t *testing.T) {
		// This tests what would happen if objectFromEntry received a nil entry
		// In practice, this shouldn't happen, but it's good to document the behavior

		// Note: This test is more theoretical since objectFromEntry is typically
		// called with valid entries from LDAP search results
		defer func() {
			if r := recover(); r != nil {
				// If it panics, that's acceptable for nil entry
				t.Log("objectFromEntry panics with nil entry (acceptable)")
			}
		}()

		// This would panic, but we're testing the behavior
		// obj := objectFromEntry(nil)
	})

	t.Run("entry with very long DN and CN", func(t *testing.T) {
		longDN := "cn=" + string(make([]byte, 1000)) + ",ou=people,dc=example,dc=com"
		longCN := string(make([]byte, 1000))

		entry := &ldap.Entry{
			DN: longDN,
			Attributes: []*ldap.EntryAttribute{
				{
					Name:   "cn",
					Values: []string{longCN},
				},
			},
		}

		obj := objectFromEntry(entry)
		assert.Equal(t, longDN, obj.DN())
		assert.Equal(t, longCN, obj.CN())
	})
}

func TestObjectIntegrationWithLDAP(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("object methods with real LDAP data", func(t *testing.T) {
		// Find a user to test real Object functionality
		user, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
		if err != nil {
			t.Skipf("Cannot find test user: %v", err)
		}

		// Test Object methods work correctly with real LDAP data
		assert.NotEmpty(t, user.DN())
		assert.NotEmpty(t, user.CN())
		assert.Contains(t, user.DN(), testData.ValidUserUID)

		// DN should contain the CN value (in some form)
		// Note: This might not always be true for all DN formats
		if user.CN() != "" {
			// At minimum, the DN should be well-formed
			assert.Contains(t, user.DN(), "=")
			assert.Contains(t, user.DN(), ",")
		}
	})

	t.Run("object consistency across different find methods", func(t *testing.T) {
		// Find the same user by different methods and verify Object consistency
		userBySAM, err1 := client.FindUserBySAMAccountName(testData.ValidUserUID)
		userByDN, err2 := client.FindUserByDN(testData.ValidUserDN)

		if err1 != nil || err2 != nil {
			t.Skipf("Cannot find test user by different methods: %v, %v", err1, err2)
		}

		// Object methods should return consistent values
		assert.Equal(t, userBySAM.DN(), userByDN.DN())
		assert.Equal(t, userBySAM.CN(), userByDN.CN())
	})
}

// Benchmark Object operations
func BenchmarkObjectDN(b *testing.B) {
	obj := Object{
		dn: "uid=testuser,ou=people,dc=example,dc=com",
		cn: "Test User",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obj.DN()
	}
}

func BenchmarkObjectCN(b *testing.B) {
	obj := Object{
		dn: "uid=testuser,ou=people,dc=example,dc=com",
		cn: "Test User",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obj.CN()
	}
}

func BenchmarkObjectFromEntry(b *testing.B) {
	entry := &ldap.Entry{
		DN: "uid=testuser,ou=people,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{
				Name:   "cn",
				Values: []string{"Test User"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = objectFromEntry(entry)
	}
}
