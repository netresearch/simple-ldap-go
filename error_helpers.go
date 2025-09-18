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

// searchError creates a standardized search operation error
func searchError(operation, identifier, server string, err error) error {
	return fmt.Errorf("%s search failed for %s: %w", operation, identifier, WrapLDAPError(operation, server, err))
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

// notFoundError creates a standardized not-found error
func notFoundError(objectType, identifier string, baseErr error) error {
	return fmt.Errorf("%s not found: %s: %w", objectType, identifier, baseErr)
}

// operationCancelledError creates a standardized cancellation error
func operationCancelledError(operation, identifier, server string, err error) error {
	return fmt.Errorf("%s cancelled for %s: %w", operation, identifier, WrapLDAPError(operation, server, err))
}

// validationError creates a standardized validation error
func validationError(field, value, reason string) error {
	return fmt.Errorf("validation failed for %s '%s': %s", field, value, reason)
}

// configurationError creates a standardized configuration error
func configurationError(component, issue string, err error) error {
	if err != nil {
		return fmt.Errorf("configuration error in %s: %s: %w", component, issue, err)
	}
	return fmt.Errorf("configuration error in %s: %s", component, issue)
}

// resourceExhaustionError creates a standardized resource exhaustion error
func resourceExhaustionError(resource string, current, max int64, suggestion string) error {
	return NewResourceExhaustionError(resource, current, max, suggestion, true)
}