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
//     bit is already set, the call is a no-op — no Modify is sent —
//     so callers that retry or invoke optimistically incur a single
//     round-trip search and nothing else.
//   - EnableUser/EnableComputer CLEAR the bit. Same no-op behaviour
//     when the bit is already clear.
//   - All four only make sense on AD. OpenLDAP inetOrgPerson and
//     groupOfNames have no portable disable mechanism. Callers that
//     mix directory kinds should gate on Config.IsActiveDirectory.
//   - Missing-DN errors surface as ErrUserNotFound (DisableUser /
//     EnableUser) or ErrComputerNotFound (DisableComputer /
//     EnableComputer), regardless of whether AD returns
//     LDAPResultNoSuchObject on the search or an empty result set.
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
	"errors"
	"fmt"
	"log/slog"
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
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, true, ErrUserNotFound)
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
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, false, ErrUserNotFound)
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
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, true, ErrComputerNotFound)
}

// EnableComputer clears ACCOUNTDISABLE on a computer account,
// preserving all other UAC bits.
func (l *LDAP) EnableComputer(dn string) error {
	return l.EnableComputerContext(context.Background(), dn)
}

// EnableComputerContext is the context-aware variant of EnableComputer.
func (l *LDAP) EnableComputerContext(ctx context.Context, dn string) error {
	return l.updateUACBit(ctx, dn, ACCOUNTDISABLE, false, ErrComputerNotFound)
}

// updateUACBit is the shared read-modify-write body for all four
// Disable*/Enable* methods. `set=true` ORs `bit` into the current
// userAccountControl, `set=false` clears it. Preserves every other
// UAC flag by reading the attribute first. notFoundErr is the
// sentinel returned when AD reports the DN is missing (so users
// surface ErrUserNotFound and computers surface ErrComputerNotFound).
//
// Connection and permission errors are wrapped via WrapLDAPError.
//
// Implementation note: the read-modify steps are split into two pure
// helpers (classifyUACSearchResult and applyUACBitToEntry) so the
// error-mapping and bit-arithmetic branches are exercisable from
// unit tests without an LDAP server. updateUACBit itself only
// orchestrates conn → search → classify → apply → modify and is
// covered by the offline-server connection-error test in disable_test.go.
func (l *LDAP) updateUACBit(ctx context.Context, dn string, bit uint32, set bool, notFoundErr error) error {
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return connectionError("modify", "uac", err)
	}
	defer func() {
		l.logConnectionReleaseError("updateUACBit", l.ReleaseConnection(conn))
	}()

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"userAccountControl"},
		nil,
	)

	// Single base-object lookup — Search rather than SearchWithPaging
	// because there is at most one entry by definition (ScopeBaseObject
	// + SizeLimit=1) and paging adds an unnecessary control round-trip.
	sr, searchErr := conn.Search(searchReq)
	entry, mapErr := classifyUACSearchResult(sr, searchErr, dn, notFoundErr, l.config.Server)
	if mapErr != nil {
		return mapErr
	}

	_, next, changed, applyErr := applyUACBitToEntry(entry, bit, set)
	if applyErr != nil {
		return applyErr
	}
	if !changed {
		// Already in the desired state — nothing to do. Writing the
		// same value is harmless but we skip the round-trip.
		return nil
	}

	return l.ModifyUserContext(ctx, dn, map[string][]string{
		"userAccountControl": {strconv.FormatUint(uint64(next), 10)},
	})
}

// logConnectionReleaseError emits a debug log line when releasing a
// connection back to the pool fails. Extracted so the (rare but
// non-trivial) defer path can be unit-tested without an LDAP server.
// A nil err is the success path and is silent.
func (l *LDAP) logConnectionReleaseError(operation string, err error) {
	if err == nil {
		return
	}
	l.logger.Debug("connection_close_error",
		slog.String("operation", operation),
		slog.String("error", err.Error()))
}

// classifyUACSearchResult maps a base-object search result + error
// into either the single matching entry or a typed error. Pure
// function used by updateUACBit so the LDAPResultNoSuchObject /
// empty-result-set / wrap branches are unit-testable.
//
// Returns:
//   - the matching entry on success (sr.Entries[0])
//   - notFoundErr (wrapped with dn) when the search reported
//     LDAPResultNoSuchObject *or* when the result set is empty
//   - a WrapLDAPError("SearchUAC", server, ...) for any other search error
//
// server is passed through to WrapLDAPError; in production this is
// l.config.Server.
func classifyUACSearchResult(sr *ldap.SearchResult, searchErr error, dn string, notFoundErr error, server string) (*ldap.Entry, error) {
	if searchErr != nil {
		// AD typically reports a missing DN as LDAPResultNoSuchObject
		// on the search itself rather than an empty result set. Map
		// that to the caller-supplied sentinel so the error shape
		// matches the rest of the API (FindUserByDN, FindComputerByDN).
		var ldapErr *ldap.Error
		if errors.As(searchErr, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return nil, fmt.Errorf("%w: %s", notFoundErr, dn)
		}
		return nil, WrapLDAPError("SearchUAC", server, searchErr)
	}
	if sr == nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s", notFoundErr, dn)
	}
	return sr.Entries[0], nil
}

// applyUACBitToEntry computes the new userAccountControl value for a
// single LDAP entry. Pure function — no I/O. Returns:
//
//   - current: the parsed current UAC value
//   - next:    current with bit set or cleared per `set`
//   - changed: true iff next != current (caller can short-circuit
//     the Modify when this is false)
//   - err:     non-nil when the entry has no userAccountControl
//     attribute (not AD), or when the attribute value can't be parsed
//     as uint32. Both shapes match what updateUACBit returned before
//     extraction.
//
// The dn is taken from entry.DN for error messages; entry.DN is
// always populated by go-ldap on a base-object search.
func applyUACBitToEntry(entry *ldap.Entry, bit uint32, set bool) (current, next uint32, changed bool, err error) {
	raw := entry.GetAttributeValue("userAccountControl")
	if raw == "" {
		// No userAccountControl on the entry — only AD has this
		// attribute. Return a clear error so OpenLDAP callers get a
		// useful message instead of a silent no-op.
		return 0, 0, false, fmt.Errorf("userAccountControl attribute missing on %s (not an Active Directory entry?)", entry.DN)
	}
	current64, parseErr := strconv.ParseUint(raw, 10, 32)
	if parseErr != nil {
		return 0, 0, false, fmt.Errorf("parse userAccountControl %q on %s: %w", raw, entry.DN, parseErr)
	}
	current = uint32(current64)
	if set {
		next = current | bit
	} else {
		next = current &^ bit
	}
	return current, next, next != current, nil
}
