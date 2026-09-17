# Simple LDAP Go - Code Structure

## File Organization

One package, `ldap`, flat at the repository root: 30 non-test Go files and 74
`_test.go` files beside them.

### Entry points and directory operations
- **client.go**: `Config`, `LDAP`, `New` and the pre-baked constructors
  (`NewBasicClient`, `NewPooledClient`, `NewCachedClient`,
  `NewHighPerformanceClient`, `NewSecureClient`, `NewReadOnlyClient`)
- **auth.go**: password checking and changing, rate limiting, lockout handling
- **users.go**, **groups.go**, **computers.go**: the three object families
- **object.go**: the embedded `Object` that carries the DN and CN
- **shared_search.go**: the search path all three families go through
- **iterators.go**: `SearchIter`, `SearchPagedIter`, `GroupMembersIter`
- **password_expiry.go**, **unlock.go**, **disable.go**: account state

### Infrastructure
- **pool.go**: `ConnectionPool`, health checks, leak detection and self-healing
- **cache.go**, **cache_generic.go**, **cache_indexed.go**: the LRU cache and
  its key tracking
- **resilience.go**: `CircuitBreaker`
- **performance.go**, **concurrency.go**: metrics, worker pools, bulk operations
- **options.go**: the `Option` functions passed to `New`
- **errors.go**, **error_helpers.go**: sentinels, `LDAPError`, wrapping
- **security.go**: input validation and `maskSensitiveData`
- **builders.go**, **generics.go**, **interfaces.go**, **validation.go**
- **uac.go**, **sam_account_type.go**: Active Directory bit constants

### Supporting directories
- **testutil/**: in-memory `MockLDAPConn` and fixtures for unit tests. No
  containers: the OpenLDAP testcontainer lives in `test_setup_test.go` in the
  root package
- **examples/**: eight runnable programs, each with a test beside it
- **docs/**: 13 guides plus `DOCUMENTATION_INDEX.md`, gated by
  `scripts/check-docs-api.py`
- **scripts/**: repository tooling, including that gate

### CI
12 active workflows under `.github/workflows/`, `ci.yml` being the main one: build,
unit and integration tests, lint, a 79% coverage gate and the `docs-api` job.
`test.yml.disabled` is a leftover from before CI ran the suite; it is inert.

## Package Structure
All code is in the `ldap` package, providing a cohesive API surface.
