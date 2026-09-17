<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2026-09-17 -->

# AGENTS.md (root)

This file explains repo-wide conventions and where to find scoped rules.
**Precedence:** the **closest `AGENTS.md`** to the files you're changing wins. Root holds global defaults only.

## Global rules
- Keep diffs small; add tests for new code paths
- Ask first before: adding heavy deps, running full e2e suites, or repo-wide rewrites
- Never commit secrets or sensitive data to the repository
- Follow Go 1.26 conventions and idioms. Go 1.26 and 1.27 are both supported: `go.mod`'s `go` directive is the binding floor, so no language feature newer than it may be used.
- Keep total coverage at or above the `coverage-threshold` in `.github/workflows/ci.yml`. CI enforces it on the non-integration run; integration coverage is reported to Codecov separately and is not part of that gate.

## Minimal pre-commit checks
- Typecheck (all packages): `go build -v ./...`
- Lint/format (file scope): `gofmt -w <file.go>` and `~/go/bin/golangci-lint run ./...`
- Unit tests (fast): `go test -v -race -short -timeout=10s ./...`
- Both supported Go releases: `make test-compat` (mirrors the `go-compat` CI job)

## Index of scoped AGENTS.md
- `./examples/AGENTS.md` — Example applications and usage patterns
- `./testutil/AGENTS.md` — Testing utilities and container management
- `./docs/AGENTS.md` — Documentation and guides

## Codebase gotchas
- **Identifier-derived rate-limit/cache keys are folded.** uid/sAMAccountName matching is case-insensitive, so keys go through `normalizeIdentifierKey` (lowercase). DN-derived keys additionally need `ldap.ParseDN` canonicalization (`normalizeDNKey`) — LDAP DN equality ignores case **and** insignificant whitespace, so a plain `strings.ToLower` leaves `CN=x, DC=y` and `CN=x,DC=y` on separate counters.
- **`RateLimiter.CheckLimit` increments the attempt counter itself; `RecordFailure` only records a metric.** A code path that calls `CheckLimit` but not `RecordFailure` (e.g. the not-found branch of `CheckPasswordForDN`) is still rate-limited — do not conclude otherwise from the absence of `RecordFailure`.
- **Identifier validation is per directory type.** `validateAccountIdentifier` applies the strict sAMAccountName rules only when `IsActiveDirectory`; otherwise `ValidateUID` (relaxed uid rules). The `UserBuilder`/`Validator` surfaces differ by intent — the builder is permissive (creation path), the standalone `Validator` stays strict (advisory threat gate).
- **A Go version check needs `GOTOOLCHAIN=local` on every command.** `go.mod` carries a `toolchain` line above the `go` directive, so an older toolchain silently upgrades itself and reports the newer version. Without the pin, a "1.26" run is a 1.27 run wearing a label.
- **`*ldap.Conn` is a concrete type with no injection seam.** `GetConnection` dials for real, and `LDAP`'s fields are unexported, so unit tests can only reach the pre-dial portion of an operation (validation, cache hits, context cancellation, early returns). Everything past the dial is covered by the integration tier (`-tags=integration`, OpenLDAP testcontainer), not by unit tests. Do not add a seam to production code to move a coverage number.
- **Docs are checked against the API for call shape and member names.** `scripts/check-docs-api.py` (CI job `docs-api`) verifies that every `l.`/`client.`/`ldapClient.` call in `docs/*.md` and `README.md` names a real `*LDAP` method with an acceptable argument count, and that every `user.`/`group.`/`computer.` reference names a real member of `User`/`Group`/`Computer` — called if it is a method, not called if it is a field. It does not type-check arguments or compile the snippets, so a wrong *type* still slips through. Run it after renaming or re-signing anything on those types.

## When instructions conflict
- The nearest `AGENTS.md` wins. Explicit user prompts override files.
- For Go-specific patterns, defer to language idioms and standard library conventions