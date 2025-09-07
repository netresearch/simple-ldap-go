package ldap

import (
	"fmt"
	"strconv"
	"time"
)

// parseObjectEnabled determines if an LDAP object is enabled based on userAccountControl attribute.
// This function checks the ACCOUNTDISABLE flag (0x2) in the userAccountControl bitmask.
//
// Parameters:
//   - userAccountControl: String representation of the userAccountControl attribute value
//
// Returns:
//   - bool: true if the account is enabled (ACCOUNTDISABLE flag is not set), false if disabled
//   - error: Any error parsing the userAccountControl value
//
// Reference: https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
func parseObjectEnabled(userAccountControl string) (bool, error) {
	raw, err := strconv.ParseInt(userAccountControl, 10, 32)
	if err != nil {
		return false, err
	}

	// https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
	// 2 (0x2) - ACCOUNTDISABLE
	// The user account is disabled.
	if raw&2 != 0 {
		return false, nil
	}

	return true, nil
}

// convertAccountExpires converts a Go time.Time to Active Directory accountExpires format.
// Active Directory stores account expiration as the number of 100-nanosecond intervals
// since January 1, 1601 UTC (Windows FILETIME format).
//
// Parameters:
//   - target: The expiration time, or nil for accounts that never expire
//
// Returns:
//   - string: The accountExpires value formatted for Active Directory
//
// Special values:
//   - nil target returns 0x7FFFFFFFFFFFFFFF (account never expires)
//   - Otherwise returns the calculated 100-nanosecond intervals since 1601-01-01
//
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/acdfe32c-ce53-4073-b9b4-40d1130038dc
func convertAccountExpires(target *time.Time) string {
	if target == nil {
		return fmt.Sprintf("%d", accountExpiresNever)
	}

	remaining := target.Sub(accountExpiresBase)

	/*
	   This value represents the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	   A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires.
	*/
	ns := remaining.Nanoseconds() / 100

	return fmt.Sprintf("%d", ns)
}
