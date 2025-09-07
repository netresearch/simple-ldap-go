# Simple LDAP Go - Style and Conventions

## Code Style
- **Formatting**: Uses default `gofmt` formatting rules (as stated in README.md)
- **Package**: All code in single `ldap` package
- **Naming Conventions**: 
  - Structs: PascalCase (Config, LDAP, User, Group, Computer)
  - Methods: PascalCase with receiver notation (e.g., `(*LDAP).FindUserByDN`)
  - Variables: camelCase
  - Constants: PascalCase with descriptive prefixes (e.g., `ErrUserNotFound`)
  - Private functions: camelCase (e.g., `userFromEntry`, `parseObjectEnabled`)

## Error Handling
- Custom error variables for common scenarios (e.g., `ErrUserNotFound`, `ErrDNDuplicated`)
- Standard Go error handling patterns
- Descriptive error messages

## Documentation
- Minimal inline comments
- External documentation via README.md
- Function names are self-documenting

## Import Organization
- Standard library imports first
- Third-party imports second
- Local imports last (if any)

## Method Organization
- Receiver methods grouped by type
- Logical grouping by functionality (auth, user ops, group ops, etc.)