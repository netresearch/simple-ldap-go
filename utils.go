package ldap

import (
	"fmt"
	"strconv"
	"time"
)

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

// convertAccountExpires converts the time.Time to the accountExpires value.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/acdfe32c-ce53-4073-b9b4-40d1130038dc
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
