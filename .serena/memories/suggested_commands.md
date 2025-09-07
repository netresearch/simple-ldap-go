# Simple LDAP Go - Suggested Commands

## Development Commands

### Testing
```bash
# Run all tests (requires LDAP server environment variables)
go test -v ./...

# Required environment variables for testing:
# LDAP_SERVER, LDAP_BASE_DN, LDAP_READ_USER, LDAP_READ_PASSWORD
```

### Code Formatting
```bash
# Format all Go code using gofmt
go fmt ./...
# or
gofmt -w .
```

### Code Quality
```bash
# Run Go vet for static analysis
go vet ./...

# Check for race conditions (if applicable)
go test -race ./...
```

### Building
```bash
# Build the package (library - no executable)
go build ./...

# Validate module dependencies
go mod verify
go mod tidy
```

### Documentation
```bash
# Generate and view documentation
go doc ./...
go doc -all ./...
```

## System Commands (Linux)
- `ls` - list files
- `cd` - change directory
- `grep` - search text patterns
- `find` - find files
- `git` - version control

## Git Workflow
The project uses Conventional Commits for commit messages.

## Notes
- Tests are disabled in CI due to LDAP server dependency requirements
- The project is a library package, not an executable
- Primary focus is on LDAP/Active Directory integration