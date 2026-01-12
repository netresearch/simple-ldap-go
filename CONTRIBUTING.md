# Contributing to simple-ldap-go

Thank you for your interest in contributing! This document provides guidelines for contributing to this Go LDAP client library.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of background, experience level, gender identity, sexual orientation, disability, personal appearance, race, ethnicity, age, religion, or nationality.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discrimination, or intimidation
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an issue or contacting the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

---

## Getting Started

### Prerequisites

- **Go** 1.25 or higher
- **Docker** (for integration tests with OpenLDAP)
- **Git** for version control

### Initial Setup

1. **Fork and clone the repository**:

   ```bash
   git clone https://github.com/YOUR-USERNAME/simple-ldap-go.git
   cd simple-ldap-go
   ```

2. **Download dependencies**:

   ```bash
   go mod download
   ```

3. **Run tests**:

   ```bash
   make test-unit
   ```

4. **Run integration tests** (requires Docker):

   ```bash
   make test-integration
   ```

---

## Development Workflow

### Branching Strategy

We use a feature branch workflow:

1. **Create a feature branch** from `main`:

   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with descriptive commits:

   ```bash
   git add .
   git commit -m "feat: add connection pooling support"
   ```

3. **Push to your fork**:

   ```bash
   git push -u origin feature/your-feature-name
   ```

4. **Open a Pull Request** against `main`

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements

**Examples**:

```bash
feat(client): add connection pooling support
fix(users): correct DN escaping for special characters
docs(readme): update installation instructions
test(groups): add concurrent access tests
refactor(cache): extract cache interface
perf(search): optimize paged search iteration
```

---

## Code Standards

### Go Code

**Style Guide**:

- Use `gofmt` for formatting (automatic)
- Follow [Effective Go](https://go.dev/doc/effective_go) principles
- Keep functions focused (single responsibility)
- Use descriptive names (avoid abbreviations)

**GoDoc Comments**:

```go
// Client provides a high-level interface for LDAP operations.
// It wraps the underlying LDAP connection with additional features
// like connection pooling, automatic reconnection, and caching.
type Client struct {
    // ...
}

// FindUserByEmail searches for a user by their email address.
// Returns ErrNotFound if no user matches the given email.
func (c *Client) FindUserByEmail(ctx context.Context, email string) (*User, error) {
    // Implementation
}
```

**Error Handling**:

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to bind to LDAP: %w", err)
}

// Bad: Return raw errors
if err != nil {
    return err
}
```

**Context Usage**:

```go
// Good: Accept context for cancellation
func (c *Client) Search(ctx context.Context, filter string) ([]*Entry, error)

// Bad: No context support
func (c *Client) Search(filter string) ([]*Entry, error)
```

### Package Structure

- Keep packages focused on single responsibility
- Export only what consumers need
- Add package documentation in `doc.go`
- Use internal packages for implementation details

---

## Testing Requirements

### Test Types

- **Unit Tests**: Fast tests without external dependencies
- **Integration Tests**: Tests requiring Docker (OpenLDAP container)
- **Benchmark Tests**: Performance measurements
- **Example Tests**: Executable documentation

### Running Tests

```bash
# Fast unit tests
make test-fast

# All unit tests
make test-unit

# Integration tests (requires Docker)
make test-integration

# All tests
make test-all

# With coverage
make test-coverage

# Race detection
make test-race

# Benchmarks
make test-benchmark-fast
```

### Writing Tests

**Table-Driven Tests**:

```go
func TestParseFilter(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *Filter
        wantErr bool
    }{
        {"simple equality", "(cn=test)", &Filter{...}, false},
        {"invalid syntax", "(cn=)", nil, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseFilter(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseFilter() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ParseFilter() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

**Integration Tests** (use testcontainers):

```go
func TestClient_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test in short mode")
    }

    ctx := context.Background()
    container, err := openldap.Run(ctx, "bitnami/openldap:latest")
    require.NoError(t, err)
    defer container.Terminate(ctx)

    // Test with real LDAP server
}
```

### Test Coverage Goals

- Maintain overall coverage above 70%
- Critical paths (authentication, search) should have >90% coverage
- New features must include tests

---

## Pull Request Process

### Before Submitting

1. **Run quality checks**:

   ```bash
   make qa
   ```

2. **Run tests**:

   ```bash
   make test-all
   ```

3. **Update documentation** if needed:
   - API changes: Update GoDoc comments
   - New features: Update README.md
   - Breaking changes: Note in PR description

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass (`make test-all`)
- [ ] Test coverage maintained or improved
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow Conventional Commits format
- [ ] No breaking changes (or documented if necessary)

### Review Process

1. **Automated checks** run on PR (CI/CD)
2. **Code review** by maintainers
3. **Address feedback** and push updates
4. **Approval and merge** by maintainers

---

## Community

### Getting Help

- **Documentation**: Check [README.md](README.md) and [docs/](docs/) directory
- **Issues**: Search [existing issues](https://github.com/netresearch/simple-ldap-go/issues)
- **Examples**: See [examples/](examples/) directory

### Reporting Bugs

When reporting bugs, include:

- **Environment**: OS, Go version
- **Steps to reproduce**: Clear, step-by-step instructions
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs/Errors**: Relevant error messages

### Suggesting Features

For feature requests:

- **Use case**: Describe the problem you're solving
- **Proposed solution**: How would you implement it?
- **Alternatives**: What other approaches did you consider?
- **Compatibility**: Any impact on existing API?

### Security Issues

**Do not open public issues for security vulnerabilities.**

Report security issues privately:

- See [SECURITY.md](SECURITY.md) for reporting process
- Use GitHub Security Advisories for responsible disclosure

---

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

**Thank you for contributing!** Your efforts help make this library better for everyone.
