# Simple LDAP Go - Project Overview

## Purpose
Simple LDAP Go is a Go package that provides a simple API wrapper around the go-ldap/ldap/v3 library. It was extracted from netresearch/raybeam and focuses on simplifying LDAP operations, particularly for Active Directory environments.

## Tech Stack
- **Language**: Go 1.23.0+ (toolchain go1.25.0)
- **Main Dependency**: github.com/go-ldap/ldap/v3 v3.4.11
- **Text Processing**: golang.org/x/text v0.28.0
- **Additional Dependencies**: 
  - Azure/go-ntlmssp (for NTLM authentication)
  - go-asn1-ber/asn1-ber (for ASN.1 BER encoding)
  - google/uuid (for UUID generation)
  - golang.org/x/crypto (for cryptographic operations)

## License
MIT License

## Key Features
- LDAP client with Active Directory support
- User authentication and password management
- User, group, and computer object management
- Support for both LDAP and LDAPS connections
- Built-in error handling for common LDAP scenarios