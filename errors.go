package ldap

import "errors"

// Common LDAP error definitions

// ErrUserNotFound is returned when a user search operation finds no matching entries.
var ErrUserNotFound = errors.New("user not found")

// ErrGroupNotFound is returned when a group search operation finds no matching entries.
var ErrGroupNotFound = errors.New("group not found")

// ErrComputerNotFound is returned when a computer search operation finds no matching entries.
var ErrComputerNotFound = errors.New("computer not found")

// ErrDNDuplicated is returned when multiple entries share the same DN (data integrity issue).
var ErrDNDuplicated = errors.New("DN is not unique")

// ErrSAMAccountNameDuplicated is returned when multiple users have the same sAMAccountName.
var ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")

// ErrMailDuplicated is returned when multiple users have the same email address.
var ErrMailDuplicated = errors.New("mail is not unique")
