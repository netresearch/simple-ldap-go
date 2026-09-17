<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2026-09-17 -->

# AGENTS.md — Examples

## Overview
Example applications demonstrating library usage patterns for authentication, user management, performance optimization, context handling, and error patterns. Each subdirectory holds one program; the file is named after the example (`authentication/authentication.go`, `performance/performance_example.go`), not `main.go`.

## Setup & environment
- Install: `go mod download`
- Run example: `go run ./examples/<name>`
- Env: examples read LDAP_SERVER, LDAP_BASE_DN and credentials from the environment; none is required to compile

## Build & tests (prefer file-scoped)
- Typecheck one example: `go build -v ./examples/<name>`
- Format a file: `gofmt -w examples/<name>/<file>.go`
- Run example: `go run ./examples/<name>`
- Test them: every example has a `_test.go` beside it; `go test ./examples/...`

## Code style & conventions
- Examples should be self-contained and runnable
- Use clear variable names that explain the concept
- Include comments explaining non-obvious patterns
- Error handling should demonstrate best practices
- Keep examples focused on a single concept

## Security & safety
- Never include real credentials in examples
- Use placeholder values like "ldap.example.com"
- Document required permissions clearly
- Examples should fail gracefully without real LDAP server

## PR/commit checklist
- Examples must compile without errors
- Add the example to `examples/README.md`
- Test example with both real and mock LDAP servers if possible
- Ensure examples follow library best practices

## Good vs. bad examples
- Good: `authentication/authentication.go` (clear flow, error handling)
- Good: `context-usage/context_usage.go` (proper context propagation)
- Pattern to follow: Simple, focused, well-commented demonstrations

## When stuck
- Check the main library documentation in ../docs/
- Review similar examples in sibling directories
- Ensure you have the latest library version