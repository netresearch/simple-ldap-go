# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
