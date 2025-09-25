package ldap

import (
	"fmt"
)

// Error helper functions to improve consistency and efficiency
// These reduce repetitive error construction patterns across the codebase

// connectionError creates a standardized connection error
func connectionError(operation, context string, err error) error {
	return fmt.Errorf("failed to get connection for %s %s: %w", operation, context, err)
}

// authenticationError creates a standardized authentication error
func authenticationError(operation, identifier string, err error) error {
	ldapErr, ok := err.(*LDAPError)
	if !ok {
		ldapErr = &LDAPError{
			Op:  operation,
			Err: err,
		}
	}
	return fmt.Errorf("authentication failed for %s: %w", identifier, ldapErr)
}
