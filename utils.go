package ldap

import (
	"strconv"
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
