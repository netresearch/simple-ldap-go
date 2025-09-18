package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGroupByDNIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name          string
		dn            string
		expectError   bool
		expectedError error
	}{
		{
			name:        "valid group DN",
			dn:          testData.ValidGroupDN,
			expectError: false,
		},
		{
			name:          "nonexistent group DN",
			dn:            "cn=nonexistent,ou=groups,dc=example,dc=org",
			expectError:   true,
			expectedError: ErrGroupNotFound,
		},
		{
			name:        "malformed DN",
			dn:          "invalid-dn-format",
			expectError: true,
		},
		{
			name:        "empty DN",
			dn:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, err := client.FindGroupByDN(tt.dn)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, group)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, group)
				assert.Equal(t, testData.ValidGroupCN, group.CN())
				assert.Equal(t, testData.ValidGroupDN, group.DN())
			}
		})
	}
}

func TestFindGroupsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	groups, err := client.FindGroups()
	require.NoError(t, err)
	require.NotNil(t, groups)

	// We should have at least 3 test groups created in the test setup
	assert.GreaterOrEqual(t, len(groups), 3)

	// Verify group properties
	for _, group := range groups {
		assert.NotEmpty(t, group.CN())
		assert.NotEmpty(t, group.DN())
		// Groups should have members (may be empty for some groups)
		assert.NotNil(t, group.Members)
	}
}

func TestGroupSearchAndValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("find group by DN and validate structure", func(t *testing.T) {
		group, err := client.FindGroupByDN(testData.ValidGroupDN)
		require.NoError(t, err)
		require.NotNil(t, group)

		// Verify basic properties
		assert.Equal(t, testData.ValidGroupCN, group.CN())
		assert.Equal(t, testData.ValidGroupDN, group.DN())

		// Group should have at least one member (admin user was added as a placeholder)
		assert.NotEmpty(t, group.Members)
		t.Logf("Group %s has %d members: %v", group.CN(), len(group.Members), group.Members)
	})

	t.Run("verify group membership", func(t *testing.T) {
		// Find the admins group
		group, err := client.FindGroupByDN(testData.ValidGroupDN)
		require.NoError(t, err)
		require.NotNil(t, group)

		// The group should contain valid member DNs
		for _, member := range group.Members {
			assert.NotEmpty(t, member)
			// Member should be a valid DN format (contains equals and comma)
			assert.Contains(t, member, "=")
			assert.Contains(t, member, ",")
		}
	})
}
