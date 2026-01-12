# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added CONTRIBUTING.md with contribution guidelines
- Added CHANGELOG.md (this file)

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
