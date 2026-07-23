# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Self-service password change now binds as the user on non-AD directories.** v1.12.1 stopped `ChangePasswordForSAMAccountName` writing `unicodePwd` to OpenLDAP, but it still issued the RFC 3062 Password Modify on the *pooled* connection — bound as the caller's service account. RFC 3062 authorises a self-service change from the bind identity, so a directory refuses to verify `oldPasswd` for a caller that cannot write the target entry; slapd answers `LDAP Result Code 53 "Unwilling To Perform": unwilling to verify old password`. Any deployment binding a read-only service account (the normal arrangement) therefore still could not change a password. The non-AD path now opens a dedicated connection bound as the user with their current password, which is the flow RFC 3062 describes and which makes the bind itself the proof of the old password. The administrative reset path is unchanged: it legitimately uses the service-account connection with no old password.
- A wrong current password now fails at the bind rather than at the modify, so the returned error names an authentication failure instead of a server-side refusal.

### Changed

- `createDirectConnection` delegates to a new internal `dialAndBind`, so a connection can be opened under a specific identity. The user-bound connection is deliberately unpooled — binding a pooled connection as an end user would leak that identity to the next caller that borrowed it.

### Added

- The integration harness now provisions a read-only service account (`ReadOnlyDN`/`ReadOnlyPassword`) with a directory-wide read grant. Tests asserting a write must not bind as `cn=admin`: the superuser can write every entry and so masks any defect that depends on the caller's privileges. The v1.12.1 self-service test did exactly that — it passed while real deployments failed. The rewritten test binds as the read-only account and fails against v1.12.1.

---

## [v1.12.1] - 2026-07-23

### Fixed

- **Password writes no longer assume Active Directory.** `ChangePasswordForSAMAccountName` and `ResetPasswordForSAMAccountName` (and their `*Context` variants) wrote the Microsoft-specific `unicodePwd` attribute unconditionally, with no branch on `Config.IsActiveDirectory`. OpenLDAP and other non-AD directories have no such attribute and rejected every write with `LDAP Result Code 17 "Undefined Attribute Type"`, so no password could be changed or reset on them at all — the failure was total, on the first attempt, with no configuration that avoided it. Both paths now branch: Active Directory keeps the `unicodePwd` write (DELETE+ADD for a self-service change, REPLACE for an administrative reset), and every other directory uses the RFC 3062 Password Modify extended operation, which also lets the server apply its configured hashing scheme instead of storing whatever the client sends. The AD-only UTF-16LE encoding is no longer applied on the non-AD path, where it would corrupt the password.
- `CreateUser` already gated AD-only attributes on `IsActiveDirectory` for exactly this failure mode; the password paths had never received the same treatment.

### Added

- Integration coverage for password writes against a real OpenLDAP container (`auth_openldap_integration_test.go`). It binds with the new password after each write rather than only asserting the call returned no error — the previous mock-only coverage could not distinguish "the server accepted the request" from "the password actually changed", which is why the `unicodePwd` defect went unnoticed.
- Warning log `password_write_over_cleartext_connection` when a non-AD password write goes over an unencrypted `ldap://` connection. The RFC 3062 request carries the new password in the clear, and since these writes previously always failed, this is the first release in which such a deployment can work at all. Active Directory is still refused outright (`ErrActiveDirectoryMustBeLDAPS`); non-AD only warns, because plain `ldap://` behind an already-encrypted transport is a legitimate setup and failing would break working deployments.

---

## [v1.12.0] - 2026-04-22

### Added

- **`(*LDAP).DisableUser(dn)` / `EnableUser(dn)` and their `*Context` variants.**
  Flip the `ACCOUNTDISABLE` bit (0x2) on AD `userAccountControl`, preserving every other flag via a read-modify-write. Idempotent — a second disable on an already-disabled account is a no-op, not an error.
- **`(*LDAP).DisableComputer(dn)` / `EnableComputer(dn)` and their `*Context` variants.** Same mechanism as user, same idempotency. Preserves `WORKSTATION_TRUST_ACCOUNT` and any other UAC flags on the entry.
- **`ACCOUNTDISABLE` exported constant** (`uint32 = 0x2`) for callers who want to compose their own UAC writes.
- **`User.AdminCount bool`** — mapped from the `adminCount` AD attribute; `true` when AD has flagged the user as privileged via `adminSDHolder` (members of Domain Admins / Enterprise Admins / Administrators / Account Operators / Backup Operators, etc.). `false` on OpenLDAP entries which never set this attribute. The field is sticky: AD does not clear it when a user leaves a protected group, so `AdminCount=true` means "is OR was privileged", not a perfect real-time check. Documented inline on the struct field.
- `adminCount` added to the internal `userFields` attribute list fetched by every user search.

### Notes

- Disable/Enable require Active Directory. OpenLDAP `inetOrgPerson` has no portable disable attribute; calls return a clear error ("userAccountControl attribute missing on … (not an Active Directory entry?)") instead of a silent no-op.
- Disable/Enable are NOT atomic across concurrent callers — the read-modify-write window is visible to parallel UAC writes on the same DN. The ACCOUNTDISABLE-bit case converges to whichever write commits last; callers needing strict ordering should serialise their admin operations.

---

## [v1.11.0] - 2026-04-22

### Added

Extend every entity struct with the attributes admin UIs typically surface, plus AD-specific audit timestamps. New fields default to zero values when the directory doesn't return them, so existing consumers are unaffected.

- **`User`** gets 11 new fields + three parser helpers ([#160](https://github.com/netresearch/simple-ldap-go/pull/160)):
  - Identity: `GivenName`, `Surname`, `DisplayName`, `Title`, `Department`, `Company`
  - Contact: `ManagerDN`, `TelephoneNumber`, `Mobile`, `Office`
  - Security posture: `AccountExpires` (0 unset / -1 never / Unix seconds), `PwdLastSet`, `MustChangePassword` (true when AD's `pwdLastSet` is 0), `LockoutTime`
  - Audit: `WhenCreated`, `WhenChanged`
  - Helpers: `parseAccountExpires`, `parseGeneralizedTime`, `parseFileTimeSeconds`
- **`Group`** gets `GroupType` (uint32 bitmask), `ManagedByDN`, `WhenCreated`, `WhenChanged`, plus classification helpers `IsSecurity()`, `IsDistribution()`, `Scope()` (`"builtin"` / `"global"` / `"domain-local"` / `"universal"` / `"app-basic"` / `"app-query"` / `""` when unknown) ([#161](https://github.com/netresearch/simple-ldap-go/pull/161)).
- **`Computer`** gets `ManagedByDN`, `WhenCreated`, `WhenChanged` ([#162](https://github.com/netresearch/simple-ldap-go/pull/162)).

### Changed

- Each entity now has a single `userFields` / `groupFields` / `computerFields` attribute list shared by every internal search call, and a `userFromEntry` / `groupFromEntry` / `computerFromEntry` mapping helper. Inline attribute lists and inline struct constructions are gone.

### Fixed

- `CreateUser` maps `sAMAccountName` → `uid` on non-AD directories so OpenLDAP-backed flows no longer fail ([#155](https://github.com/netresearch/simple-ldap-go/pull/155)).
- `CreateUser` honours `WithLogger` for init log lines and is safe to call against OpenLDAP.
- Bulk user operations close the worker pool before ranging over results, removing a race that could surface as a data race or hang ([#146](https://github.com/netresearch/simple-ldap-go/pull/146)).
- Integration test suite brought back to green and re-enabled on CI ([#151](https://github.com/netresearch/simple-ldap-go/pull/151)).

### Tests

- `users_from_entry_test.go`, `groups_from_entry_test.go`, `computers_from_entry_test.go` — focused coverage for the new mapping helpers (AD full-entry, OpenLDAP fallback, malformed UAC / groupType).
- `utils_extra_test.go` — covers `parseAccountExpires`, `parseFileTimeSeconds`, `parseGeneralizedTime`.
- Overall coverage raised from 58.6 % to 77.3 % ([#142](https://github.com/netresearch/simple-ldap-go/pull/142)).

### CI

- Sync with `netresearch/.github` templates/go-lib (#141, #143, #145, #150, #152, #158).
- Migrate reusable workflow references + absorb optimized-tests into `go-check` / `tests.yml` (#131).
- Dependabot ecosystem cleanup: drop npm, docker, devcontainers (#159).

---

## [v1.10.0] - 2026-04-16

### Fixed

- Pass `sAMAccountName` to `NewSecureCredentialSimple` in `ChangePasswordForSAMAccountNameContext` — was passing empty string, causing all password changes to fail ([#129](https://github.com/netresearch/simple-ldap-go/pull/129))
- Add `ValidateSAMAccountName` to all sAMAccountName entrypoints consistently (`CheckPassword`, `ChangePassword`, `ResetPassword`, `FindUser`, `FindComputer`) — prevents LDAP injection and catches malformed input early

### Changed

- Isolate testcontainers dependency from consumers ([#110](https://github.com/netresearch/simple-ldap-go/pull/110))

### Dependencies

- Update `go-ldap/ldap/v3` to v3.4.13 ([#107](https://github.com/netresearch/simple-ldap-go/pull/107))
- Update `golang.org/x/text` to v0.36.0 ([#127](https://github.com/netresearch/simple-ldap-go/pull/127))
- Update `testcontainers-go` to v0.42.0 ([#128](https://github.com/netresearch/simple-ldap-go/pull/128))
- Tidy `go.mod`, remove stale indirect dependencies

### CI

- Add `create-release.yml` workflow using org reusable `golib-create-release.yml`

---

## [v1.9.0] - 2026-03-06

### Fixed

- Guard against `time.NewTicker(0)` panic when `PerformanceConfig` has zero intervals
- Pass DN as identifier in `CheckPasswordForDNContext` instead of empty string
- `EnableOptimizations` now correctly enables cache/metrics via `cacheEnabled()` helper
- Return connections to pool instead of destroying them
- Prevent LDAP filter and attribute injection in `QueryBuilder`
- Fix error handling and unwrap chains in security module
- Resolve security issues in credentials and rate limiter

### Added

- Comprehensive unit tests achieving full statement coverage across all packages ([#95](https://github.com/netresearch/simple-ldap-go/pull/95))
- Integration tests with OpenLDAP testcontainers
- Codecov integration with unit/integration flags
- Full CI pipeline: unit tests, integration tests, CodeQL, gosec, govulncheck, trivy, gitleaks, license compliance, actionlint ([#88](https://github.com/netresearch/simple-ldap-go/pull/88))
- Added CONTRIBUTING.md with contribution guidelines
- Added CHANGELOG.md

---

## [v1.8.0] - 2025-12-28

### Added

- `LastLogon` field to User struct exposing the `lastLogonTimestamp` LDAP attribute
- Helper function to convert Windows FILETIME to Unix timestamp (shared with Computer struct)

---

## [v1.7.0] - 2025-12-28

### Added

- **Group struct enhancements**:
  - `Description` field for group description/notes
  - `MemberOf` field for parent group memberships (nested groups)
- **Computer struct enhancements**:
  - `Description` field for computer description/notes
  - `DNSHostName` field for fully qualified DNS hostname
  - `ServicePack` field for OS service pack information
  - `LastLogon` field (Unix timestamp from lastLogonTimestamp)
- `parseLastLogonTimestamp()` helper for converting AD FILETIME to Unix timestamp

---

## [v1.6.0] - 2025-10-06

### Added

- `ResetPasswordForSAMAccountName` for admin password reset operations ([#52](https://github.com/netresearch/simple-ldap-go/pull/52))

---

## [v1.5.5] - 2025-10-03

### Fixed

- Connection leaks in pool management
- Added self-healing pool functionality ([#51](https://github.com/netresearch/simple-ldap-go/pull/51))

---

## [v1.5.4] - 2025-10-02

### Fixed

- Complete pool connection lifecycle fix for authentication methods ([#50](https://github.com/netresearch/simple-ldap-go/pull/50))

---

## Earlier Releases

For releases prior to v1.5.4, see the [GitHub Releases](https://github.com/netresearch/simple-ldap-go/releases) page.
