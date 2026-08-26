<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

# AGENTS.md (root)

This file explains repo-wide conventions and where to find scoped rules.
**Precedence:** the **closest `AGENTS.md`** to the files you're changing wins. Root holds global defaults only.

## Global rules
- Keep diffs small; add tests for new code paths
- Ask first before: adding heavy deps, running full e2e suites, or repo-wide rewrites
- Never commit secrets or sensitive data to the repository
- Follow Go 1.26 conventions and idioms
- Maintain minimum test coverage of 40%

## Minimal pre-commit checks
- Typecheck (all packages): `go build -v ./...`
- Lint/format (file scope): `gofmt -w <file.go>` and `~/go/bin/golangci-lint run ./...`
- Unit tests (fast): `go test -v -race -short -timeout=10s ./...`

## Index of scoped AGENTS.md
- `./examples/AGENTS.md` — Example applications and usage patterns
- `./testutil/AGENTS.md` — Testing utilities and container management
- `./docs/AGENTS.md` — Documentation and guides

## Codebase gotchas
- **Identifier-derived rate-limit/cache keys are folded.** uid/sAMAccountName matching is case-insensitive, so keys go through `normalizeIdentifierKey` (lowercase). DN-derived keys additionally need `ldap.ParseDN` canonicalization (`normalizeDNKey`) — LDAP DN equality ignores case **and** insignificant whitespace, so a plain `strings.ToLower` leaves `CN=x, DC=y` and `CN=x,DC=y` on separate counters.
- **`RateLimiter.CheckLimit` increments the attempt counter itself; `RecordFailure` only records a metric.** A code path that calls `CheckLimit` but not `RecordFailure` (e.g. the not-found branch of `CheckPasswordForDN`) is still rate-limited — do not conclude otherwise from the absence of `RecordFailure`.
- **Identifier validation is per directory type.** `validateAccountIdentifier` applies the strict sAMAccountName rules only when `IsActiveDirectory`; otherwise `ValidateUID` (relaxed uid rules). The `UserBuilder`/`Validator` surfaces differ by intent — the builder is permissive (creation path), the standalone `Validator` stays strict (advisory threat gate).

## When instructions conflict
- The nearest `AGENTS.md` wins. Explicit user prompts override files.
- For Go-specific patterns, defer to language idioms and standard library conventions