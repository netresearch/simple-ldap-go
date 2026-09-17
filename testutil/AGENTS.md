<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2026-09-17 -->

# AGENTS.md — Test Utilities

## Overview
In-memory test doubles for the LDAP connection, used by unit tests. `mock_ldap.go` holds `MockLDAPConn`, a hand-written mock with per-method function hooks (`BindFunc`, `SearchFunc`, `ModifyFunc`, …), recorded calls (`BindCalls`, `SearchCalls`, …) and an in-memory directory of `MockUser` and `MockGroup`. `test_data.go` fills that directory through `SetupTestUsersAndGroups`.

No containers live here. The OpenLDAP testcontainer belongs to the root package (`test_setup_test.go`, `SetupTestContainer`), and integration tests run there, not in `testutil`.

## Setup & environment
- Install: `go mod download`
- No Docker needed for this package
- Test: `go test ./testutil/...`

## Build & tests (prefer file-scoped)
- Typecheck a file: `go build -v testutil/<file.go>`
- Format a file: `gofmt -w testutil/<file.go>`
- Run this package's tests: `go test ./testutil/...`
- Run everything fast: `make test-fast`

## Code style & conventions
- Keep the mock deterministic: no timers, no network, no filesystem
- A new behaviour gets a `…Func` hook so a test can override one method without reimplementing the rest
- Record calls rather than asserting inside the mock; the test decides what is correct
- Guard shared state with the existing mutex - tests run in parallel
- Keep fixtures in `test_data.go` minimal but representative of real directory entries

## Security & safety
- Test-only credentials, and they are visible in the source on purpose
- Never point a test at a production directory
- Do not add a code path that reaches the network from this package

## PR/commit checklist
- `go test ./testutil/...` passes
- New mock behaviour is covered in `mock_ldap_test.go`
- Fixtures updated when the entry shape a test depends on changes
- No container or Docker dependency introduced here

## Good vs. bad examples
- Good: `mock_ldap.go` (hooks plus recorded calls, no assertions inside the mock)
- Good: `test_data.go` (one place that knows the fixture directory)
- Bad: a mock that returns fixed values with no way to override them
- Bad: assertions inside the mock, which force every test to want the same thing

## When stuck
- Read `mock_ldap_test.go` first: it exercises every hook
- For container-backed tests, look at `test_setup_test.go` in the root package instead
- `make docker-clean` removes containers left by the integration tier
