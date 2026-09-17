package ldap

import (
	"context"
	"errors"
	"fmt"
)

var ErrUnlockRequiresActiveDirectory = errors.New(
	"account unlock is only supported for Active Directory",
)

// UnlockUser clears the Active Directory account lockout state for the
// user identified by distinguished name.
//
// Unlocking an Active Directory account consists of setting the
// lockoutTime attribute to 0. The operation is idempotent: calling it
// for an account that is not currently locked leaves the account
// unlocked.
//
// AD only. OpenLDAP has no portable equivalent of the lockoutTime
// attribute.
//
// The bound account must have permission to write lockoutTime on the
// target user object.
func (l *LDAP) UnlockUser(dn string) error {
	return l.UnlockUserContext(context.Background(), dn)
}

// unlockAttributes returns the attribute update required to unlock
// an Active Directory user account.
func unlockAttributes() map[string][]string {
	return map[string][]string{
		"lockoutTime": {"0"},
	}
}

// UnlockUserContext is the context-aware variant of UnlockUser.
func (l *LDAP) UnlockUserContext(ctx context.Context, dn string) error {
	if !l.config.IsActiveDirectory {
		return ErrUnlockRequiresActiveDirectory
	}

	return l.ModifyUserContext(ctx, dn, unlockAttributes())
}

// UnlockUserForSAMAccountName clears the Active Directory account
// lockout state for the user identified by sAMAccountName.
//
// It resolves the account to its distinguished name and then performs
// the same operation as UnlockUser.
//
// AD only. The bound account must have permission to write lockoutTime
// on the target user object.
func (l *LDAP) UnlockUserForSAMAccountName(sAMAccountName string) error {
	return l.UnlockUserForSAMAccountNameContext(context.Background(), sAMAccountName)
}

// UnlockUserForSAMAccountNameContext is the context-aware variant of
// UnlockUserForSAMAccountName.
func (l *LDAP) UnlockUserForSAMAccountNameContext(ctx context.Context, sAMAccountName string) error {
	if !l.config.IsActiveDirectory {
		return ErrUnlockRequiresActiveDirectory
	}

	if err := l.validateAccountIdentifier(sAMAccountName); err != nil {
		return err
	}

	user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
	if err != nil {
		return fmt.Errorf("failed to find user %s for account unlock: %w", sAMAccountName, err)
	}

	return l.UnlockUserContext(ctx, user.DN())
}
