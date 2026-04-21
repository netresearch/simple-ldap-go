package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrComputerNotFound is returned when a computer search operation finds no matching entries.
var ErrComputerNotFound = errors.New("computer not found")

// computerFields is the shared attribute list every internal Computer
// search requests. Servers silently ignore attribute names they don't
// know, so a single list works for both AD and OpenLDAP / RFC-4524.
var computerFields = []string{
	"memberOf", "cn", "sAMAccountName", "userAccountControl",
	"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
	"description", "dNSHostName", "lastLogonTimestamp",
	"managedBy", "whenCreated", "whenChanged",
}

// Computer represents an LDAP computer object with common attributes.
type Computer struct {
	Object
	// SAMAccountName is the Security Account Manager account name for the computer (typically ends with $).
	SAMAccountName string
	// Enabled indicates whether the computer account is enabled (not disabled by userAccountControl).
	Enabled bool
	// Description contains the computer's description or notes.
	Description string
	// DNSHostName is the fully qualified DNS hostname of the computer.
	DNSHostName string
	// OS contains the operating system name from the operatingSystem attribute.
	OS string
	// OSVersion contains the operating system version from the operatingSystemVersion attribute.
	OSVersion string
	// ServicePack contains the service pack information from operatingSystemServicePack.
	ServicePack string
	// LastLogon contains the timestamp of the last logon (from lastLogonTimestamp, replicated).
	LastLogon int64
	// ManagedByDN is the distinguished name of the user/group that owns
	// this computer (from `managedBy`), or "" when unset.
	ManagedByDN string
	// WhenCreated is the Unix-seconds timestamp at which the entry was
	// created (from `whenCreated`, parsed via parseGeneralizedTime).
	// 0 when the attribute is absent (OpenLDAP / RFC-4524 entries).
	WhenCreated int64
	// WhenChanged is the Unix-seconds timestamp of the most recent
	// modification. 0 when absent.
	WhenChanged int64
	// Groups contains a list of distinguished names (DNs) of groups the computer belongs to.
	Groups []string
}

// computerFromEntry maps an LDAP entry to a Computer, handling the
// AD vs OpenLDAP enablement+account-name split. Returns a non-nil
// error only when AD's userAccountControl is present but malformed;
// OpenLDAP entries never produce an error. Callers can choose to
// propagate the error (FindComputerByDN) or skip the entry
// (FindComputers).
func computerFromEntry(entry *ldap.Entry) (Computer, error) {
	var (
		enabled        bool
		samAccountName string
	)

	if uac := entry.GetAttributeValue("userAccountControl"); uac != "" {
		var err error
		enabled, err = parseObjectEnabled(uac)
		if err != nil {
			return Computer{}, err
		}

		samAccountName = entry.GetAttributeValue("sAMAccountName")
	} else {
		// OpenLDAP / RFC-4524 device entries: no userAccountControl —
		// default to enabled and use cn as the account name.
		enabled = true
		samAccountName = entry.GetAttributeValue("cn")
	}

	return Computer{
		Object:         objectFromEntry(entry),
		SAMAccountName: samAccountName,
		Enabled:        enabled,
		Description:    entry.GetAttributeValue("description"),
		DNSHostName:    entry.GetAttributeValue("dNSHostName"),
		OS:             entry.GetAttributeValue("operatingSystem"),
		OSVersion:      entry.GetAttributeValue("operatingSystemVersion"),
		ServicePack:    entry.GetAttributeValue("operatingSystemServicePack"),
		LastLogon:      parseLastLogonTimestamp(entry.GetAttributeValue("lastLogonTimestamp")),
		ManagedByDN:    entry.GetAttributeValue("managedBy"),
		WhenCreated:    parseGeneralizedTime(entry.GetAttributeValue("whenCreated")),
		WhenChanged:    parseGeneralizedTime(entry.GetAttributeValue("whenChanged")),
		Groups:         entry.GetAttributeValues("memberOf"),
	}, nil
}

// FullComputer represents a complete LDAP computer object for creation and modification operations.
type FullComputer struct {
	// CN is the common name of the computer (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (required, typically ends with $).
	SAMAccountName string
	// Description provides additional information about the computer (optional).
	Description string
	// UserAccountControl defines the account control flags for the computer account.
	UserAccountControl uint32
	// DNSHostName is the fully qualified domain name of the computer (optional).
	DNSHostName string
	// OperatingSystem contains the operating system name (optional).
	OperatingSystem string
	// OperatingSystemVersion contains the operating system version (optional).
	OperatingSystemVersion string
	// OperatingSystemServicePack contains the service pack information (optional).
	OperatingSystemServicePack string
	// MemberOf contains a list of distinguished names (DNs) of groups the computer belongs to.
	MemberOf []string
	// OtherAttributes contains additional LDAP attributes not covered by the above fields.
	OtherAttributes map[string][]string
}

// FindComputerByDN retrieves a computer by its distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the computer (e.g., "CN=COMPUTER01,CN=Computers,DC=example,DC=com")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
func (l *LDAP) FindComputerByDN(dn string) (computer *Computer, err error) {
	return l.FindComputerByDNContext(context.Background(), dn)
}

// FindComputerByDNContext retrieves a computer by its distinguished name with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the computer (e.g., "CN=COMPUTER01,CN=Computers,DC=example,DC=com")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     context cancellation error, or any LDAP operation error
func (l *LDAP) FindComputerByDNContext(ctx context.Context, dn string) (computer *Computer, err error) {
	start := time.Now()
	l.logger.Debug("computer_search_by_dn_started",
		slog.String("operation", "FindComputerByDN"),
		slog.String("dn", dn))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for computer DN search: %w", err)
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindComputerByDN"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("computer_search_cancelled",
			slog.String("operation", "FindComputerByDN"),
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("computer search cancelled for DN %s: %w", dn, WrapLDAPError("FindComputerByDN", l.config.Server, ctx.Err()))
	default:
	}

	filter := "(|(objectClass=computer)(objectClass=device))"
	l.logger.Debug("computer_search_executing",
		slog.String("filter", filter),
		slog.String("dn", dn))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   computerFields,
	})
	if err != nil {
		// If LDAP error indicates object not found, return ErrComputerNotFound
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			l.logger.Debug("computer_not_found_by_dn",
				slog.String("operation", "FindComputerByDN"),
				slog.String("dn", dn),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("computer not found by DN %s: %w", dn, ErrComputerNotFound)
		}
		l.logger.Error("computer_search_by_dn_failed",
			slog.String("operation", "FindComputerByDN"),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("computer search failed for DN %s: %w", dn, WrapLDAPError("FindComputerByDN", l.config.Server, err))
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("computer_not_found_by_dn",
			slog.String("operation", "FindComputerByDN"),
			slog.String("dn", dn),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrComputerNotFound
	}

	if len(r.Entries) > 1 {
		l.logger.Error("computer_dn_duplicated",
			slog.String("operation", "FindComputerByDN"),
			slog.String("dn", dn),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrDNDuplicated
	}

	cm, err := computerFromEntry(r.Entries[0])
	if err != nil {
		l.logger.Error("computer_uac_parsing_failed",
			slog.String("dn", dn),
			slog.String("error", err.Error()))

		return nil, err
	}

	computer = &cm

	l.logger.Debug("computer_found_by_dn",
		slog.String("operation", "FindComputerByDN"),
		slog.String("dn", dn),
		slog.String("sam_account_name", computer.SAMAccountName),
		slog.String("os", computer.OS),
		slog.Bool("enabled", computer.Enabled),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindComputerBySAMAccountName retrieves a computer by its Security Account Manager account name.
//
// Parameters:
//   - sAMAccountName: The SAM account name of the computer (e.g., "COMPUTER01$")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple computers have the same sAMAccountName,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computer sAMAccountNames typically end with a dollar sign ($).
func (l *LDAP) FindComputerBySAMAccountName(sAMAccountName string) (computer *Computer, err error) {
	return l.FindComputerBySAMAccountNameContext(context.Background(), sAMAccountName)
}

// FindComputerBySAMAccountNameContext retrieves a computer by its Security Account Manager account name with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - sAMAccountName: The SAM account name of the computer (e.g., "COMPUTER01$")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple computers have the same sAMAccountName,
//     context cancellation error, or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computer sAMAccountNames typically end with a dollar sign ($).
func (l *LDAP) FindComputerBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (computer *Computer, err error) {
	if err := ValidateSAMAccountName(sAMAccountName); err != nil {
		return nil, fmt.Errorf("invalid sAMAccountName: %w", err)
	}

	start := time.Now()
	l.logger.Debug("computer_search_by_sam_account_started",
		slog.String("operation", "FindComputerBySAMAccountName"),
		slog.String("sam_account_name", sAMAccountName))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindComputerBySAMAccountName"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("computer_search_cancelled",
			slog.String("operation", "FindComputerBySAMAccountName"),
			slog.String("sam_account_name", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return nil, ctx.Err()
	default:
	}

	filter := fmt.Sprintf("(&(|(objectClass=computer)(objectClass=device))(|(sAMAccountName=%s)(cn=%s)))", ldap.EscapeFilter(sAMAccountName), ldap.EscapeFilter(sAMAccountName))
	l.logger.Debug("computer_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   computerFields,
	})
	if err != nil {
		l.logger.Error("computer_search_by_sam_account_failed",
			slog.String("operation", "FindComputerBySAMAccountName"),
			slog.String("sam_account_name", sAMAccountName),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("computer_not_found_by_sam_account",
			slog.String("operation", "FindComputerBySAMAccountName"),
			slog.String("sam_account_name", sAMAccountName),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrComputerNotFound
	}

	if len(r.Entries) > 1 {
		l.logger.Error("computer_sam_account_duplicated",
			slog.String("operation", "FindComputerBySAMAccountName"),
			slog.String("sam_account_name", sAMAccountName),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrSAMAccountNameDuplicated
	}

	cm, err := computerFromEntry(r.Entries[0])
	if err != nil {
		l.logger.Error("computer_uac_parsing_failed",
			slog.String("sam_account_name", sAMAccountName),
			slog.String("error", err.Error()))

		return nil, err
	}

	computer = &cm

	l.logger.Debug("computer_found_by_sam_account",
		slog.String("operation", "FindComputerBySAMAccountName"),
		slog.String("sam_account_name", sAMAccountName),
		slog.String("dn", computer.DN()),
		slog.String("os", computer.OS),
		slog.Bool("enabled", computer.Enabled),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindComputers retrieves all computer objects from the directory.
//
// Returns:
//   - []Computer: A slice of all computer objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computers that cannot be parsed (due to missing required attributes) are skipped.
func (l *LDAP) FindComputers() (computers []Computer, err error) {
	return l.FindComputersContext(context.Background())
}

// FindComputersContext retrieves all computer objects from the directory with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//
// Returns:
//   - []Computer: A slice of all computer objects found in the directory
//   - error: Any LDAP operation error or context cancellation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computers that cannot be parsed (due to missing required attributes) are skipped.
func (l *LDAP) FindComputersContext(ctx context.Context) (computers []Computer, err error) {
	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "FindComputers", "N/A", "start"); err != nil {
		return nil, ctx.Err()
	}

	start := time.Now()
	l.logger.Debug("computer_list_search_started",
		slog.String("operation", "FindComputers"))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindComputers"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("computer_list_search_cancelled",
			slog.String("error", ctx.Err().Error()))
		return nil, ctx.Err()
	default:
	}

	filter := "(|(objectClass=computer)(objectClass=device))"
	l.logger.Debug("computer_list_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   computerFields,
	})
	if err != nil {
		l.logger.Error("computer_list_search_failed",
			slog.String("operation", "FindComputers"),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	processed := 0
	skipped := 0

	for _, entry := range r.Entries {
		// Check for context cancellation during processing
		select {
		case <-ctx.Done():
			l.logger.Debug("computer_list_processing_cancelled",
				slog.Int("processed", processed),
				slog.String("error", ctx.Err().Error()))
			return nil, ctx.Err()
		default:
		}

		computer, cerr := computerFromEntry(entry)
		if cerr != nil {
			l.logger.Debug("computer_entry_skipped_uac_parsing",
				slog.String("dn", entry.DN),
				slog.String("error", cerr.Error()))

			skipped++

			continue
		}

		computers = append(computers, computer)
		processed++
	}

	l.logger.Info("computer_list_search_completed",
		slog.String("operation", "FindComputers"),
		slog.Int("total_found", len(r.Entries)),
		slog.Int("processed", processed),
		slog.Int("skipped", skipped),
		slog.Duration("duration", time.Since(start)))

	return
}
