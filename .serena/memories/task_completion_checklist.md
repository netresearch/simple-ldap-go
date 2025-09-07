# Simple LDAP Go - Task Completion Checklist

## When a task is completed, ensure:

### Code Quality
1. **Format code**: Run `go fmt ./...` to ensure consistent formatting
2. **Static analysis**: Run `go vet ./...` to catch potential issues
3. **Dependencies**: Run `go mod tidy` to clean up module dependencies

### Testing
1. **Run tests**: `go test -v ./...` (requires LDAP environment setup)
2. **Consider race conditions**: `go test -race ./...` if relevant
3. **Validate test coverage** for new functionality

### Documentation
1. **Update README.md** if public API changes
2. **Add inline comments** for complex logic only
3. **Follow Conventional Commits** for commit messages

### Git Workflow
1. **Commit with conventional commits format**
2. **Create meaningful commit messages**
3. **Consider PR requirements** if contributing

### Environment Considerations
- Remember that tests require LDAP server environment variables
- CI is disabled due to LDAP server dependency
- This is a library package, not an executable

### Specific to LDAP Operations
- Test against actual LDAP/AD server when possible
- Validate security implications for authentication changes
- Ensure backward compatibility with existing API consumers