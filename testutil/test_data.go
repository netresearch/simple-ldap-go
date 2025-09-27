package testutil

// SetupTestUsersAndGroups creates standard test data for mock LDAP connections
func SetupTestUsersAndGroups(mock *MockLDAPConn) {
	// Clear existing data
	mock.Users = make(map[string]*MockUser)
	mock.Groups = make(map[string]*MockGroup)

	// Add test users
	mock.AddUser(&MockUser{
		DN:             "cn=admin,ou=users,dc=example,dc=com",
		CN:             "admin",
		SAMAccountName: "admin",
		Mail:           "admin@example.com",
		Description:    "Administrator",
		Password:       "admin123",
		Enabled:        true,
		Groups:         []string{"cn=admins,ou=groups,dc=example,dc=com"},
	})

	mock.AddUser(&MockUser{
		DN:             "cn=user1,ou=users,dc=example,dc=com",
		CN:             "user1",
		SAMAccountName: "user1",
		Mail:           "user1@example.com",
		Description:    "Test User 1",
		Password:       "password1",
		Enabled:        true,
		Groups:         []string{"cn=users,ou=groups,dc=example,dc=com"},
	})

	mock.AddUser(&MockUser{
		DN:             "cn=disabled,ou=users,dc=example,dc=com",
		CN:             "disabled",
		SAMAccountName: "disabled",
		Mail:           "disabled@example.com",
		Description:    "Disabled User",
		Password:       "disabled123",
		Enabled:        false,
		Groups:         []string{},
	})
}
