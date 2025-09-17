package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindComputerBySAMAccountNameIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name           string
		samAccountName string
		expectError    bool
		expectedError  error
	}{
		{
			name:           "valid computer name",
			samAccountName: testData.ValidComputerCN, // Use CN for OpenLDAP compatibility
			expectError:    false,
		},
		{
			name:           "nonexistent computer",
			samAccountName: "NONEXISTENT01",
			expectError:    true,
			expectedError:  ErrComputerNotFound,
		},
		{
			name:           "empty computer name",
			samAccountName: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			computer, err := client.FindComputerBySAMAccountName(tt.samAccountName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, computer)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, computer)
				assert.Equal(t, tt.samAccountName, computer.SAMAccountName)
				assert.True(t, computer.Enabled) // OpenLDAP devices are typically enabled
			}
		})
	}
}

func TestFindComputersIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	computers, err := client.FindComputers()
	require.NoError(t, err)
	require.NotNil(t, computers)

	// We should have at least 2 test computers created in the test setup
	assert.GreaterOrEqual(t, len(computers), 2)

	// Verify computer properties
	for _, computer := range computers {
		assert.NotEmpty(t, computer.CN())
		assert.NotEmpty(t, computer.DN())
		assert.NotEmpty(t, computer.SAMAccountName)
		assert.True(t, computer.Enabled) // OpenLDAP devices are typically enabled
	}
}

func TestComputerOperationsIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("find computer by DN and verify properties", func(t *testing.T) {
		computer, err := client.FindComputerByDN(testData.ValidComputerDN)
		require.NoError(t, err)
		require.NotNil(t, computer)

		assert.Equal(t, testData.ValidComputerCN, computer.CN())
		assert.Equal(t, testData.ValidComputerDN, computer.DN())
		assert.Equal(t, testData.ValidComputerCN, computer.SAMAccountName)
		assert.True(t, computer.Enabled)
	})

	t.Run("find computer by SAM account name", func(t *testing.T) {
		computer, err := client.FindComputerBySAMAccountName(testData.ValidComputerCN)
		require.NoError(t, err)
		require.NotNil(t, computer)

		assert.Equal(t, testData.ValidComputerCN, computer.CN())
		assert.Equal(t, testData.ValidComputerDN, computer.DN())
		assert.Equal(t, testData.ValidComputerCN, computer.SAMAccountName)
	})
}
