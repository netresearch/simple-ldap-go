package ldap

// Disable / Enable helpers for Active Directory user and computer
// accounts. Both operate on the `userAccountControl` attribute, which
// AD exposes as a uint32 bitmask. The ACCOUNTDISABLE flag is bit 0x2.
//
// Strategy: read-modify-write. We can't just issue a Modify with the
// literal "514" because the entry may already have other flags set
// (WORKSTATION_TRUST_ACCOUNT, NoPasswordExpiration, etc.) and blindly
// overwriting would clear them. A single search + bit manipulation +
// single ModifyUser round-trip is cheap and preserves the rest of
// the bitmask.
//
// Semantics:
//   - DisableUser/DisableComputer SET the ACCOUNTDISABLE bit. If the
//     bit is already set, the write is still issued (idempotent),
//     which is harmless.
//   - EnableUser/EnableComputer CLEAR the bit. Same idempotency note.
//   - All four only make sense on AD. OpenLDAP inetOrgPerson and
//     groupOfNames have no portable disable mechanism. Callers that
//     mix directory kinds should gate on Config.IsActiveDirectory.
//
// Concurrency: read-modify-write IS NOT atomic. Two concurrent
// Disable+Enable races can drop one of the writes' effects on other
// UAC flags. For the specific ACCOUNTDISABLE bit, the worst case is
// that the final state reflects whichever write committed last,
// which is the same race you'd have with any non-compare-and-swap
// LDAP modification. Callers needing strict ordering should
// serialise their admin calls.

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

// ACCOUNTDISABLE is the userAccountControl bit that AD uses to mark
// a user or computer account as disabled (ADS_UF_ACCOUNTDISABLE).
// Exposed so callers who want to build custom UAC writes can refer to
// it without magic numbers.
const ACCOUNTDISABLE uint32 = 0x2

// DisableUser sets the ACCOUNTDISABLE flag (0x2) on the user's
// userAccountControl attribute, preserving all other UAC bits. Uses
// context.Background(); see DisableUserContext for timeout control.
//
// AD only. On OpenLDAP this will fail because inetOrgPerson does not
// define userAccountControl.
func (l *LDAP) DisableUser(dn string) error {
	return l.DisableUserContext(context.Background(), dn)
}

// DisableUserContext is the context-aware variant of DisableUser.
func (l *LDAP) DisableUserContext(ctx context.Context, dn string) error {
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, true)
}

// EnableUser clears the ACCOUNTDISABLE flag (0x2) on the user's
// userAccountControl attribute, preserving all other UAC bits. Uses
// context.Background(); see EnableUserContext for timeout control.
//
// AD only (see DisableUser).
func (l *LDAP) EnableUser(dn string) error {
	return l.EnableUserContext(context.Background(), dn)
}

// EnableUserContext is the context-aware variant of EnableUser.
func (l *LDAP) EnableUserContext(ctx context.Context, dn string) error {
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, false)
}

// DisableComputer mirrors DisableUser for computer accounts. AD
// stores computer UAC on the same attribute with the same
// ACCOUNTDISABLE semantics (plus WORKSTATION_TRUST_ACCOUNT=0x1000
// which the existing bits preserve because we read-modify-write).
func (l *LDAP) DisableComputer(dn string) error {
	return l.DisableComputerContext(context.Background(), dn)
}

// DisableComputerContext is the context-aware variant of DisableComputer.
func (l *LDAP) DisableComputerContext(ctx context.Context, dn string) error {
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, true)
}

// EnableComputer clears ACCOUNTDISABLE on a computer account,
// preserving all other UAC bits.
func (l *LDAP) EnableComputer(dn string) error {
	return l.EnableComputerContext(context.Background(), dn)
}

// EnableComputerContext is the context-aware variant of EnableComputer.
func (l *LDAP) EnableComputerContext(ctx context.Context, dn string) error {
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, false)
}

// updateUACBit is the shared read-modify-write body for all four
// Disable*/Enable* methods. `set=true` ORs `bit` into the current
// userAccountControl, `set=false` clears it. Preserves every other
// UAC flag by reading the attribute first.
//
// Error shape matches the rest of the simple-ldap-go API: returns
// ErrUserNotFound (or a generic ldap.Error for computers, since we
// don't search by kind), and connection/permission errors wrapped
// via WrapLDAPError.
func (l *LDAP) updateUACBit(ctx context.Context, dn string, bit uint32, set bool) error {
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return connectionError("modify", "uac", err)
	}
	defer func() { _ = l.ReleaseConnection(conn) }()

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"userAccountControl"},
		nil,
	)

	sr, err := conn.SearchWithPaging(searchReq, 1)
	if err != nil {
		return WrapLDAPError("SearchUAC", l.config.Server, err)
	}

	if len(sr.Entries) == 0 {
		return fmt.Errorf("%w: %s", ErrUserNotFound, dn)
	}

	raw := sr.Entries[0].GetAttributeValue("userAccountControl")
	if raw == "" {
		// No userAccountControl on the entry — only AD has this
		// attribute. Return a clear error so OpenLDAP callers get a
		// useful message instead of a silent no-op.
		return fmt.Errorf("userAccountControl attribute missing on %s (not an Active Directory entry?)", dn)
	}

	current64, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return fmt.Errorf("parse userAccountControl %q on %s: %w", raw, dn, err)
	}

	current := uint32(current64)
	var next uint32
	if set {
		next = current | bit
	} else {
		next = current &^ bit
	}

	if next == current {
		// Already in the desired state — nothing to do. Writing the
		// same value is harmless but we skip the round-trip.
		return nil
	}

	return l.ModifyUserContext(ctx, dn, map[string][]string{
		"userAccountControl": {strconv.FormatUint(uint64(next), 10)},
	})
}
