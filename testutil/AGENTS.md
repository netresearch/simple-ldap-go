<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

# AGENTS.md — Test Utilities

## Overview
Testing utilities for LDAP integration tests using testcontainers. Provides OpenLDAP container management, test data fixtures, and helper functions. Main entry point is `container.go`.

## Setup & environment
- Install: `go mod download`
- Docker required: Ensure Docker daemon is running
- Test: `go test -tags=integration ./...`

## Build & tests (prefer file-scoped)
- Typecheck a file: `go build -v testutil/<file.go>`
- Format a file: `gofmt -w testutil/<file.go>`
- Run integration tests: `go test -tags=integration -timeout=60s ./...`
- Clean containers: `make docker-clean`

## Code style & conventions
- Use testcontainers for container lifecycle management
- Provide cleanup functions with proper defer statements
- Log container output for debugging failed tests
- Use meaningful test data that exercises edge cases
- Keep test fixtures minimal but representative

## Security & safety
- Clean up containers after tests (use defer and t.Cleanup)
- Don't expose container ports publicly
- Use test-specific credentials only
- Containers should be labeled with org.testcontainers=true
- Never use production LDAP servers for tests

## PR/commit checklist
- Ensure containers are properly cleaned up
- Test both startup and teardown scenarios
- Verify tests work in CI environment
- Check Docker resource usage is reasonable
- Update test data if schema changes

## Good vs. bad examples
- Good: `container.go` (proper lifecycle management)
- Good: Test cleanup patterns with defer statements
- Bad: Leaving orphaned containers after test failures

## When stuck
- Check Docker logs: `docker logs <container-id>`
- Verify Docker is running: `docker info`
- Clean up stuck containers: `make docker-clean`
- Review testcontainers-go documentation