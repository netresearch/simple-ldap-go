# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BEHAVIOUR: the hostname no longer decides whether a client is real.** `New` matched `Config.Server` against a substring list — `localhost`, `example.`, `test.com`, `enterprise.com`, `server.com`, `.server` and nine more — and for a match it skipped the cache, the connection pool, the performance monitor and the connection check, and returned a client without ever dialling. `GetPerformanceStats` returned fabricated figures for those names (`IdleConnections: 5`, `TotalConnections: 5`, `PoolHits: 1`, `PoolMisses: 1`), `GetConnection` returned a stub error instead of connecting, and `FindUsers` returned **150 invented users**. All of it is gone ([#246](https://github.com/netresearch/simple-ldap-go/issues/246)).

  `ldap://localhost:389` is the address of every locally running OpenLDAP, every port-forwarded directory and every docker-compose service reached from the host. A client pointed at one got no cache, no pool, no metrics, no verification that the server was reachable, and a user list that was not from the directory — with no log record saying so.

  **What to check before upgrading:** if you construct a client against a name containing any of those substrings, `New` now dials it and returns an error when it cannot connect, where it previously returned a working-looking client. That is the intended behaviour, and the failure is the one that was being hidden. If you need a client without that round trip — in tests, or for lazy initialization — set the new `Config.SkipConnectionCheck`. It gates the dial and nothing else: the cache, the pool and the monitor follow their own flags, and pool warm-up follows `Pool.MinConnections`.

  Two consequences worth naming. `FindUsers` against such a name now performs a real search, so code that was reading the 150 invented users gets the directory's answer or an error. And the cache, pool and metrics now actually initialize for those names — the guide's own `ldaps://ldap.example.com:636` example configures a cache that is finally built, which it never was.

- **BEHAVIOUR: the optimization flags are honoured, so a client that asks for nothing gets nothing.** `New` set `Config.EnableOptimizations = true` at its top, before validation and before any option ran. The cache and the performance monitor are built when their own flag *or* `EnableOptimizations` is set, so both were on for every client whatever the caller wrote — `EnableCache: false` could not turn caching off, and neither could `EnableOptimizations: false`. Every client against a real server allocated a 1000-entry, 64 MB cache and started three background loops ([#243](https://github.com/netresearch/simple-ldap-go/issues/243)).

  The line arrived in `e7becee` (2025-09-27), the same commit that added the four flags "for fine-grained control over performance features" — it contradicted its own purpose, and `DefaultCacheConfig()` has said `Enabled: false // Disabled by default for backwards compatibility` throughout.

  **What to check before upgrading:** if you construct a client without setting `EnableCache`, `EnableMetrics` or `EnableOptimizations`, you have been running with a cache and metrics you did not ask for, and after this change you will not be. Nothing fails and nothing warns at compile time — the directory simply sees more traffic. Set the flag you want. For one release, `New` logs `optimizations_disabled` at INFO when none of the three is set, naming the flags.

  `EnableBulkOps` is unaffected: it was always read on its own and always opt-in.

### Fixed

- **`GetPoolStats` reported no connections for every real server.** `PerformanceMetrics` declares ten flat pool fields — `PoolHits`, `PoolMisses`, `TotalConnections`, `ConnectionsCreated`, `ConnectionsClosed`, `ActiveConnections`, `IdleConnections`, `HealthChecksPassed`, `HealthChecksFailed` and `ConnectionPoolRatio` — and none of them was ever assigned outside the example-server mock branch. `PerformanceMonitor.GetStats` filled the nested `PoolStats` from the pool and left the ten at zero, and they are serialized, so any JSON a caller exposed read as "zero connections" rather than "not reported". A readiness probe built on `GetPoolStats().TotalConnections > 0` — [netresearch/ldap-manager](https://github.com/netresearch/ldap-manager)'s is — could therefore never become ready, and answered 503 permanently ([#247](https://github.com/netresearch/simple-ldap-go/issues/247)).

  All ten now carry the pool's own snapshot. `ConnectionPoolRatio` is active connections over `PoolConfig.MaxConnections`, in `[0,1]`, and `0` when no ceiling is known. `ConnectionPoolStats.MaxConnections` and `MinConnections` are filled from the pool's configuration instead of the zero they carried with a "would need config" comment; its `TotalRequests`, `AvgWaitTime`, `MaxWaitTime`, `FailedConnections` and `TimeoutsCount` stay zero, because the pool keeps no such counters.

  `GetPoolStats` also reads the pool directly when no performance monitor exists. `Config.Pool` is honoured on its own and does not imply `EnableMetrics`, so a pool-without-metrics client — an ordinary configuration, and the more likely one after the flag change above — used to get zeros from the empty-stats branch.

  `ConnectionPoolRatio` saturates at `1`: the pool's capacity check reads `len(p.connections)` under a read lock it releases before appending, so two callers racing at capacity-1 can both pass it and the active count can briefly exceed `MaxConnections`. The raw counts are reported as they are; only the ratio is clamped, so it cannot leave the range its documentation promises.

  A pool that is not configured still reports zeros, and `PoolStats` stays `nil` there, so "no pool" remains distinguishable from "a pool with nothing in it".

  **For readiness probes:** `TotalConnections > 0` holds only while the pool keeps connections. The idle-cleanup loop stops closing at `MinConnections`, so with `MinConnections: 0` an idle pool drains to zero and the predicate goes false again on a perfectly healthy client. `DefaultPoolConfig()` sets `MinConnections: 2`; a caller who overrides it to `0` should test `PoolStats != nil` instead.

- **`New` never released the connection it opens to test the server.** The initialization check called `GetConnection()` and discarded the result. With a pool that connection stayed checked out for the life of the client: one slot of `MaxConnections` was permanently gone and `ActiveConnections` never fell back to zero. Without a pool the socket was left open. It is released now — which is also what makes `ConnectionPoolRatio` read as `0` on an idle client rather than as one connection's worth of utilisation.


- **`New` ignored `Config.Cache`.** The cache was built from `DefaultCacheConfig()` and the supplied configuration was read in exactly one place, `users.go`, for `TTL` alone — so `MaxSize`, `MaxMemoryMB`, `NegativeCacheTTL`, `RefreshInterval`, `RefreshOnAccess`, `CompressionEnabled` and `CompressionThreshold` had no effect whatever the caller set, with no error and no log line saying so. A client asking for `MaxSize: 100000` ran at the default 1000. It also took `NewCachedClient`'s `maxSize` argument with it — that constructor wraps `maxSize` and `ttl` in a `CacheConfig` and passes it through `WithCache`, and only the `ttl` half survived, because `getCacheTTL` in `users.go` reads it back. `NewHighPerformanceClient` lost its cache sizing the same way ([#240](https://github.com/netresearch/simple-ldap-go/issues/240)).

  Callers who have been setting these fields will see the cache they configured: memory use follows `MaxSize` and `MaxMemoryMB` rather than the 1000-entry, 64 MB default.

### Changed

- `New` no longer writes into the configuration structs it is handed. It enabled monitoring on the caller's `PerformanceConfig`, and `NewConnectionPool` fills its defaults into whatever `PoolConfig` it receives, so a caller who set only `MaxConnections` found the remaining fields filled in behind their back. Both are copied now, as `Config.Cache` is.

---

## [v1.17.0] - 2026-09-17

### Added

- `UnlockUser`, `UnlockUserContext`, `UnlockUserForSAMAccountName`, and `UnlockUserForSAMAccountNameContext`: Active Directory account unlock support by setting the user's `lockoutTime` attribute to `0`. The operation is explicit and separate from password reset, so existing password-reset callers do not acquire an additional `lockoutTime` write-permission requirement.
- `go-compat` CI job and `make test-compat`: the library is now built, vetted and unit-tested under every supported Go release (1.26 and 1.27) with `GOTOOLCHAIN=local`, so the `go 1.26.0` minimum in `go.mod` is enforced rather than merely declared. The shared `go-check` workflow derives its Go version from the `toolchain` line alone, so Go 1.26 had no gate.
- `scripts/check-docs-api.py` and the `docs-api` CI job: every `l.`/`client.`/`ldapClient.` call in `docs/*.md` and `README.md` is checked against `go doc` for both a real method name and an argument count the signature accepts. The guides are prose, not compiled, so nothing noticed when they drifted; two calls with the wrong arity survived the previous pass, which only checked that the method existed.
- `scripts/check-docs-api.py` now also checks package-qualified calls and configuration literals: an exported name after the `ldap.` prefix must exist, and every `Field:` key inside a literal of a struct type this package exports must be a field that type has. The call checks could not see a struct literal at all, which is how `PoolConfig` came to be documented with `MinIdleConnections` and `MaxLifetime` — neither of which exists in any branch — while the `docs-api` job stayed green. Checked references go from 286 to 787.
- `scripts/check-docs-api.py` also checks result-object members: every `user.`/`group.`/`computer.` reference in the guides must name a real member of `User`/`Group`/`Computer`, called if it is a method and not called if it is a field. That closed 37 further defects — 11 members that do not exist (`user.IsLocked()`, `user.Email` where the field is `Mail *string`), 26 method values used as if they were strings (`"user:" + user.DN`), and one field invoked as a method.

### Fixed

- **Codecov reported 19.36% and had stopped recomputing.** Go coverage profiles name files by import path, so every entry arrived as `github.com/netresearch/simple-ldap-go/users.go`. No `fixes:` stripped that prefix, so the `ignore:` list never fired — 2140 lines of `examples/` sat in the project total at 0% — and Codecov could not map a report entry to a file in the repository. Totals were byte-identical (`lines=10452 hits=2024`) on commits 32 apart, and files covered only by unit tests (`validation.go`, `concurrency.go`, `cache_generic.go`) showed 0% while the numbers tracked the integration upload alone. The prefix is now stripped, and the per-flag `paths` filters — which listed `**/*.go` and could not match a prefixed entry either — are removed. The `patch` status stays informational so the fix does not arm an uncalibrated 100% gate on a library near 78%.
- **`Close` is now idempotent.** `LRUCache.Close` and `PerformanceMonitor.Close` closed a channel behind nothing but a nil check, so a second call panicked with `close of closed channel` and took the process down. `defer client.Close()` beside an explicit shutdown `Close()` is an ordinary pattern, and `LDAP.Close` fans out to both, so any client built with caching or performance monitoring enabled was exposed. Both now guard with `sync.Once`, whose `Do` returns only after the teardown has finished, so a concurrent second caller waits rather than returning mid-shutdown. (`ConnectionPool.Close` has had a `closed` flag all along; a plain flag fixes the panic but not the early return, which is why it was not copied.)

### Changed

- Documentation corrected against the package as it is. The connection pool (`PoolConfig`, `PoolStats`, and the absence of `Resize`, `WarmUp`, `MonitorHealth` and `ResetUnhealthy`), `ConfigBuilder`'s eight real methods, the error sentinels, the circuit breaker, bulk results, `PerformanceMetrics`, and what the library actually logs — the JSON examples showed `"username": "jdoe"` in clear where the calls emit `username_masked`, `dn_masked` and `client_ip_masked`, and the guide promised a no-op logger where a nil `Logger` falls back to `slog.Default()`. `README.md` no longer tells contributors that the test suite needs a live LDAP server and four environment variables, two of which appear in no Go file.
- `docs/DOCUMENTATION_INDEX.md` is the documentation index; `docs/README.md` is a short entry point into it. The two had each named the other its successor. The index held all 34 broken relative links in the repository — it was written for the repository root and moved into `docs/` without adjusting the paths — along with rows for a method family (`*Optimized`) that exists nowhere and thirteen source links whose line anchors had all moved.
- Dependencies: all indirect modules updated across the graph. The direct requirements (`go-ldap/ldap/v3` v3.4.14, `golang.org/x/text` v0.42.0, `stretchr/testify` v1.12.1, `testcontainers-go` v0.44.0) were already at their latest releases and are unchanged.
- `Makefile`: the unused `GO_VERSION` variable is replaced by `GO_VERSIONS`, which `test-compat` consumes.

### Removed

- Nine documents that had one commit each from September 2025 and were never revised: `KNOWLEDGE_BASE.md` (25 of its 125 checkable claims false, two of four Go samples not compiling), `docs/CONNECTION_POOLING.md` (nine identifiers that exist in no branch), `docs/TEST_OPTIMIZATION_GUIDE.md` (documenting four files that had been deleted), `docs/CONTEXT_SUPPORT.md` (teaching `err == context.DeadlineExceeded`, which never matches because the library wraps context errors into its own sentinels), and five reports about finished one-time activities. Nothing was moved out of them: every section had a maintained owner elsewhere.
- `.trivyignore`: both premises behind it are gone — no workflow in this repository or in the shared `netresearch/.github` set runs Trivy, and the `github.com/docker/docker` module the two suppressed CVEs belong to is no longer in the module graph (testcontainers-go now depends on `moby/moby/api` and `moby/moby/client`).

---

## [v1.16.0] - 2026-08-26

### Fixed

- **`CheckPasswordForDN` no longer leaks DN existence through timing.** The DN path returned early on a failed lookup with no bind attempt, so an attacker could distinguish existing from non-existing DNs by latency — the constant-time dummy bind that `CheckPasswordForSAMAccountName` has had all along was missing here, and the #217 service rebind had widened the gap by one round-trip on the existent path only. The not-found case now performs the same escaped dummy bind plus the service rebind, and the probe is recorded in the rate limiter's failure metric, as on the sAMAccountName path ([#219](https://github.com/netresearch/simple-ldap-go/issues/219)).

### Dependencies

- All Go dependencies updated across the module graph (indirect-only version moves) ([#218](https://github.com/netresearch/simple-ldap-go/pull/218)).

---

## [v1.15.0] - 2026-08-26

### Added

- `ValidateUID(uid string) error` and `MaxUIDLength` (255): the relaxed identifier validation for non-Active-Directory servers — non-empty, at most 255 bytes, valid UTF-8, no control (Cc) or format (Cf) characters, no leading or trailing whitespace of any kind ([#211](https://github.com/netresearch/simple-ldap-go/pull/211)).

### Fixed

- **OpenLDAP users with uids longer than 20 characters are no longer rejected.** `CheckPasswordForSAMAccountName`, `ChangePasswordForSAMAccountName`, `ResetPasswordForSAMAccountName`, `FindUserBySAMAccountName` and `CreateUser` validated every identifier with Active Directory's sAMAccountName rules (20-character limit, no leading digit, character blacklist) before any query ran, so such users could not be resolved and could never change or reset their password ([netresearch/ldap-selfservice-password-changer#666](https://github.com/netresearch/ldap-selfservice-password-changer/issues/666)). Validation is now chosen per `IsActiveDirectory`: the strict rules stay for AD, `ValidateUID` applies otherwise. Filter values were already escaped at query time, so the relaxation does not affect filter construction. `FindComputerBySAMAccountName` (machine-account lookup) remains strict by design; the `UserBuilder.WithSAMAccountName` builder was later relaxed to the same `ValidateUID` rules ([#214](https://github.com/netresearch/simple-ldap-go/issues/214), [#217](https://github.com/netresearch/simple-ldap-go/pull/217)) ([#211](https://github.com/netresearch/simple-ldap-go/pull/211)).
- **The timing-mitigation dummy bind now escapes the identifier before building its DN.** `CheckPasswordForSAMAccountName`'s not-found path interpolates the identifier into a bind DN; with the relaxed uid validation admitting DN metacharacters (`,` `=` `+` `\` `"`), the value is now passed through `ldap.EscapeDN` so it cannot alter the DN structure. Defense in depth — the fixed `CN=nonexistent-` prefix already prevented binding to a real entry ([#211](https://github.com/netresearch/simple-ldap-go/pull/211)).
- **Pooled connections are no longer left bound as the verified user.** `CheckPasswordForSAMAccountName` and `CheckPasswordForDN` verify a password by binding a borrowed connection as the end user; when pooling is enabled the connection was returned to the pool still bound as that user, so the next borrower ran under the user's identity. The service-account bind is now restored before release (`rebindPooledConnToService`) ([#213](https://github.com/netresearch/simple-ldap-go/issues/213), [#217](https://github.com/netresearch/simple-ldap-go/pull/217)).
- **`maskSensitiveData` no longer leaks or garbles identifiers.** It dropped the carve-out that returned inputs containing `test.com`/`example.com`/`CN=test,`/`TestOperation` in cleartext (reachable now that `@`/`.` are valid in non-AD uids), and it masks by rune rather than byte so multibyte identifiers are not split into invalid UTF-8 ([#215](https://github.com/netresearch/simple-ldap-go/issues/215), [#217](https://github.com/netresearch/simple-ldap-go/pull/217)).
- **Rate-limit and cache keys are normalized.** The authentication rate limiter and user cache keyed on the raw identifier, but uid/sAMAccountName/DN matching is case-insensitive, so case (and, for DNs, whitespace) variants of one account received independent lockout counters — letting an attacker reset the per-account counter by rotating case. Keys are now folded (`normalizeIdentifierKey`; DNs canonicalized via `ldap.ParseDN`) ([#216](https://github.com/netresearch/simple-ldap-go/issues/216), [#217](https://github.com/netresearch/simple-ldap-go/pull/217)).

### Changed

- On non-Active-Directory servers the five identifier-accepting entry points now return `invalid uid: …` where they previously returned `invalid sAMAccountName: …`, reflecting the relaxed validation. Callers that string-match the old message on non-AD directories must adjust ([#211](https://github.com/netresearch/simple-ldap-go/pull/211)).
- **BREAKING**: the `go` directive moved from 1.25.0 to 1.26.0 — consumers must build with Go 1.26 or later (Go release policy: two most recent releases, now 1.26 + 1.27). The toolchain directive moved to go1.27.0. The fourteen `errors.As` call sites now use the type-safe `errors.AsType[T]` from Go 1.26, and `go fix` modernizers were applied across the codebase.

---

## [v1.14.0] - 2026-07-28

### Added

- `NewObject(cn, dn string) Object` ([#191](https://github.com/netresearch/simple-ldap-go/issues/191)). `Object.cn` and `Object.dn` were written only by `objectFromEntry`, so a consumer could not build a `User`, `Group` or `Computer` fixture with a DN through the public API — both downstream repos did it with reflection plus an `unsafe` write, which gosec flags as G103. A constructor rather than setters keeps the fields read-only after construction: an Object still cannot be edited to disagree with what the directory returned.

### Fixed

- **Cache size accounting no longer wraps.** Entry counts and byte sizes are computed as `int` and stored as `int32`; the conversion was unchecked, so a value past `MaxInt32` became negative and corrupted the memory accounting that drives eviction. Conversions now saturate at the `int32` bounds instead ([#190](https://github.com/netresearch/simple-ldap-go/pull/190)). Reaching that size takes a cache far larger than any realistic directory, so this is a latent defect rather than one anyone is likely to have hit.

### CI

- gosec became a blocking check in the shared workflow. The four `context.WithCancel` findings in `concurrency.go` are false positives — `WorkerPool`, `Pipeline`, `FanOut` and `BatchProcessor` each store the cancel function and invoke it from `Close()`, where a `defer cancel()` in the constructor would cancel immediately — and are annotated with that reason rather than suppressed blindly ([#190](https://github.com/netresearch/simple-ldap-go/pull/190)).
- The Go toolchain directive moved to 1.26.5, clearing four standard-library advisories reported by govulncheck ([#190](https://github.com/netresearch/simple-ldap-go/pull/190), [#192](https://github.com/netresearch/simple-ldap-go/pull/192)). The `go` directive stays at 1.25.0, so consumers are not forced onto a newer language version.

---

## [v1.13.0] - 2026-07-23

### Added

- **Password-expiry reporting for Active Directory and OpenLDAP** ([#186](https://github.com/netresearch/simple-ldap-go/pull/186)). `PasswordExpiryFor(ctx, user)` returns a directory-independent answer to when a password expires, and `UsersWithExpiringPasswords(ctx, within)` returns the enabled users whose password expires inside a window, oldest deadline first. The result distinguishes four states — `expires` (with the moment), `never-expires`, `must-change`, `unknown` — rather than a bare timestamp, because they are not interchangeable: a caller that treats `unknown` as expiring would act on every account the directory happens to be quiet about.
  - Active Directory resolves from the constructed `msDS-UserPasswordExpiryTimeComputed`, which folds in the domain policy and any Password Settings Object server-side, so no privileged read of the Password Settings Container is needed. New `User` fields `PasswordExpiresAt`, `PwdChangedAt`, `PasswordPolicyDN` expose the underlying attributes.
  - OpenLDAP resolves from the ppolicy operational `pwdChangedTime` plus the governing policy's `pwdMaxAge`, taken from the entry's `pwdPolicySubentry` or the new `Config.PasswordPolicyDN`. `pwdMaxAge` is memoised per policy DN, so a directory scan costs one policy read per distinct policy rather than one per user.
  - OpenLDAP has no `userAccountControl`, so every OpenLDAP user reads as enabled; a caller that must exclude deactivated OpenLDAP accounts has to do so by its own criterion.

### Fixed

- `FindUserByDNContext` requested a shorter attribute list than the other user searches, so it silently returned a `User` with `pwdLastSet`, `accountExpires`, `lockoutTime` and `whenCreated` zeroed — the same type meaning different things depending on which finder produced it. It now uses the shared `userFields` like every other user search.

### CI

- The codecov unit flag is declared as `unittests` to match what `go-check.yml` uploads under ([#187](https://github.com/netresearch/simple-ldap-go/pull/187)); the previous `unit` name left real unit coverage attributed to an undeclared flag while a stale one carried forward.

---

## [v1.12.2] - 2026-07-23

### Fixed

- **Self-service password change now binds as the user on non-AD directories.** v1.12.1 stopped `ChangePasswordForSAMAccountName` writing `unicodePwd` to OpenLDAP, but it still issued the RFC 3062 Password Modify on the *pooled* connection — bound as the caller's service account. RFC 3062 authorises a self-service change from the bind identity, so a directory refuses to verify `oldPasswd` for a caller that cannot write the target entry; slapd answers `LDAP Result Code 53 "Unwilling To Perform": unwilling to verify old password`. Any deployment binding a read-only service account (the normal arrangement) therefore still could not change a password. The non-AD path now opens a dedicated connection bound as the user with their current password, which is the flow RFC 3062 describes and which makes the bind itself the proof of the old password. The administrative reset path is unchanged: it legitimately uses the service-account connection with no old password.
- A wrong current password now fails at the bind rather than at the modify, so the returned error names an authentication failure instead of a server-side refusal.

### Changed

- `createDirectConnection` delegates to a new internal `dialAndBind`, so a connection can be opened under a specific identity. The user-bound connection is deliberately unpooled — binding a pooled connection as an end user would leak that identity to the next caller that borrowed it.

### Added

- The integration harness now provisions a read-only service account (`ReadOnlyDN`/`ReadOnlyPassword`) with a directory-wide read grant. Tests asserting a write must not bind as `cn=admin`: the superuser can write every entry and so masks any defect that depends on the caller's privileges. The v1.12.1 self-service test did exactly that — it passed while real deployments failed. The rewritten test binds as the read-only account and fails against v1.12.1.

---

## [v1.12.1] - 2026-07-23

### Fixed

- **Password writes no longer assume Active Directory.** `ChangePasswordForSAMAccountName` and `ResetPasswordForSAMAccountName` (and their `*Context` variants) wrote the Microsoft-specific `unicodePwd` attribute unconditionally, with no branch on `Config.IsActiveDirectory`. OpenLDAP and other non-AD directories have no such attribute and rejected every write with `LDAP Result Code 17 "Undefined Attribute Type"`, so no password could be changed or reset on them at all — the failure was total, on the first attempt, with no configuration that avoided it. Both paths now branch: Active Directory keeps the `unicodePwd` write (DELETE+ADD for a self-service change, REPLACE for an administrative reset), and every other directory uses the RFC 3062 Password Modify extended operation, which also lets the server apply its configured hashing scheme instead of storing whatever the client sends. The AD-only UTF-16LE encoding is no longer applied on the non-AD path, where it would corrupt the password.
- `CreateUser` already gated AD-only attributes on `IsActiveDirectory` for exactly this failure mode; the password paths had never received the same treatment.

### Added

- Integration coverage for password writes against a real OpenLDAP container (`auth_openldap_integration_test.go`). It binds with the new password after each write rather than only asserting the call returned no error — the previous mock-only coverage could not distinguish "the server accepted the request" from "the password actually changed", which is why the `unicodePwd` defect went unnoticed.
- Warning log `password_write_over_cleartext_connection` when a non-AD password write goes over an unencrypted `ldap://` connection. The RFC 3062 request carries the new password in the clear, and since these writes previously always failed, this is the first release in which such a deployment can work at all. Active Directory is still refused outright (`ErrActiveDirectoryMustBeLDAPS`); non-AD only warns, because plain `ldap://` behind an already-encrypted transport is a legitimate setup and failing would break working deployments.

---

## [v1.12.0] - 2026-04-22

### Added

- **`(*LDAP).DisableUser(dn)` / `EnableUser(dn)` and their `*Context` variants.**
  Flip the `ACCOUNTDISABLE` bit (0x2) on AD `userAccountControl`, preserving every other flag via a read-modify-write. Idempotent — a second disable on an already-disabled account is a no-op, not an error.
- **`(*LDAP).DisableComputer(dn)` / `EnableComputer(dn)` and their `*Context` variants.** Same mechanism as user, same idempotency. Preserves `WORKSTATION_TRUST_ACCOUNT` and any other UAC flags on the entry.
- **`ACCOUNTDISABLE` exported constant** (`uint32 = 0x2`) for callers who want to compose their own UAC writes.
- **`User.AdminCount bool`** — mapped from the `adminCount` AD attribute; `true` when AD has flagged the user as privileged via `adminSDHolder` (members of Domain Admins / Enterprise Admins / Administrators / Account Operators / Backup Operators, etc.). `false` on OpenLDAP entries which never set this attribute. The field is sticky: AD does not clear it when a user leaves a protected group, so `AdminCount=true` means "is OR was privileged", not a perfect real-time check. Documented inline on the struct field.
- `adminCount` added to the internal `userFields` attribute list fetched by every user search.

### Notes

- Disable/Enable require Active Directory. OpenLDAP `inetOrgPerson` has no portable disable attribute; calls return a clear error ("userAccountControl attribute missing on … (not an Active Directory entry?)") instead of a silent no-op.
- Disable/Enable are NOT atomic across concurrent callers — the read-modify-write window is visible to parallel UAC writes on the same DN. The ACCOUNTDISABLE-bit case converges to whichever write commits last; callers needing strict ordering should serialise their admin operations.

---

## [v1.11.0] - 2026-04-22

### Added

Extend every entity struct with the attributes admin UIs typically surface, plus AD-specific audit timestamps. New fields default to zero values when the directory doesn't return them, so existing consumers are unaffected.

- **`User`** gets 11 new fields + three parser helpers ([#160](https://github.com/netresearch/simple-ldap-go/pull/160)):
  - Identity: `GivenName`, `Surname`, `DisplayName`, `Title`, `Department`, `Company`
  - Contact: `ManagerDN`, `TelephoneNumber`, `Mobile`, `Office`
  - Security posture: `AccountExpires` (0 unset / -1 never / Unix seconds), `PwdLastSet`, `MustChangePassword` (true when AD's `pwdLastSet` is 0), `LockoutTime`
  - Audit: `WhenCreated`, `WhenChanged`
  - Helpers: `parseAccountExpires`, `parseGeneralizedTime`, `parseFileTimeSeconds`
- **`Group`** gets `GroupType` (uint32 bitmask), `ManagedByDN`, `WhenCreated`, `WhenChanged`, plus classification helpers `IsSecurity()`, `IsDistribution()`, `Scope()` (`"builtin"` / `"global"` / `"domain-local"` / `"universal"` / `"app-basic"` / `"app-query"` / `""` when unknown) ([#161](https://github.com/netresearch/simple-ldap-go/pull/161)).
- **`Computer`** gets `ManagedByDN`, `WhenCreated`, `WhenChanged` ([#162](https://github.com/netresearch/simple-ldap-go/pull/162)).

### Changed

- Each entity now has a single `userFields` / `groupFields` / `computerFields` attribute list shared by every internal search call, and a `userFromEntry` / `groupFromEntry` / `computerFromEntry` mapping helper. Inline attribute lists and inline struct constructions are gone.

### Fixed

- `CreateUser` maps `sAMAccountName` → `uid` on non-AD directories so OpenLDAP-backed flows no longer fail ([#155](https://github.com/netresearch/simple-ldap-go/pull/155)).
- `CreateUser` honours `WithLogger` for init log lines and is safe to call against OpenLDAP.
- Bulk user operations close the worker pool before ranging over results, removing a race that could surface as a data race or hang ([#146](https://github.com/netresearch/simple-ldap-go/pull/146)).
- Integration test suite brought back to green and re-enabled on CI ([#151](https://github.com/netresearch/simple-ldap-go/pull/151)).

### Tests

- `users_from_entry_test.go`, `groups_from_entry_test.go`, `computers_from_entry_test.go` — focused coverage for the new mapping helpers (AD full-entry, OpenLDAP fallback, malformed UAC / groupType).
- `utils_extra_test.go` — covers `parseAccountExpires`, `parseFileTimeSeconds`, `parseGeneralizedTime`.
- Overall coverage raised from 58.6 % to 77.3 % ([#142](https://github.com/netresearch/simple-ldap-go/pull/142)).

### CI

- Sync with `netresearch/.github` templates/go-lib (#141, #143, #145, #150, #152, #158).
- Migrate reusable workflow references + absorb optimized-tests into `go-check` / `tests.yml` (#131).
- Dependabot ecosystem cleanup: drop npm, docker, devcontainers (#159).

---

## [v1.10.0] - 2026-04-16

### Fixed

- Pass `sAMAccountName` to `NewSecureCredentialSimple` in `ChangePasswordForSAMAccountNameContext` — was passing empty string, causing all password changes to fail ([#129](https://github.com/netresearch/simple-ldap-go/pull/129))
- Add `ValidateSAMAccountName` to all sAMAccountName entrypoints consistently (`CheckPassword`, `ChangePassword`, `ResetPassword`, `FindUser`, `FindComputer`) — prevents LDAP injection and catches malformed input early

### Changed

- Isolate testcontainers dependency from consumers ([#110](https://github.com/netresearch/simple-ldap-go/pull/110))

### Dependencies

- Update `go-ldap/ldap/v3` to v3.4.13 ([#107](https://github.com/netresearch/simple-ldap-go/pull/107))
- Update `golang.org/x/text` to v0.36.0 ([#127](https://github.com/netresearch/simple-ldap-go/pull/127))
- Update `testcontainers-go` to v0.42.0 ([#128](https://github.com/netresearch/simple-ldap-go/pull/128))
- Tidy `go.mod`, remove stale indirect dependencies

### CI

- Add `create-release.yml` workflow using org reusable `golib-create-release.yml`

---

## [v1.9.0] - 2026-03-06

### Fixed

- Guard against `time.NewTicker(0)` panic when `PerformanceConfig` has zero intervals
- Pass DN as identifier in `CheckPasswordForDNContext` instead of empty string
- `EnableOptimizations` now correctly enables cache/metrics via `cacheEnabled()` helper
- Return connections to pool instead of destroying them
- Prevent LDAP filter and attribute injection in `QueryBuilder`
- Fix error handling and unwrap chains in security module
- Resolve security issues in credentials and rate limiter

### Added

- Comprehensive unit tests achieving full statement coverage across all packages ([#95](https://github.com/netresearch/simple-ldap-go/pull/95))
- Integration tests with OpenLDAP testcontainers
- Codecov integration with unit/integration flags
- Full CI pipeline: unit tests, integration tests, CodeQL, gosec, govulncheck, trivy, gitleaks, license compliance, actionlint ([#88](https://github.com/netresearch/simple-ldap-go/pull/88))
- Added CONTRIBUTING.md with contribution guidelines
- Added CHANGELOG.md

---

## [v1.8.0] - 2025-12-28

### Added

- `LastLogon` field to User struct exposing the `lastLogonTimestamp` LDAP attribute
- Helper function to convert Windows FILETIME to Unix timestamp (shared with Computer struct)

---

## [v1.7.0] - 2025-12-28

### Added

- **Group struct enhancements**:
  - `Description` field for group description/notes
  - `MemberOf` field for parent group memberships (nested groups)
- **Computer struct enhancements**:
  - `Description` field for computer description/notes
  - `DNSHostName` field for fully qualified DNS hostname
  - `ServicePack` field for OS service pack information
  - `LastLogon` field (Unix timestamp from lastLogonTimestamp)
- `parseLastLogonTimestamp()` helper for converting AD FILETIME to Unix timestamp

---

## [v1.6.0] - 2025-10-06

### Added

- `ResetPasswordForSAMAccountName` for admin password reset operations ([#52](https://github.com/netresearch/simple-ldap-go/pull/52))

---

## [v1.5.5] - 2025-10-03

### Fixed

- Connection leaks in pool management
- Added self-healing pool functionality ([#51](https://github.com/netresearch/simple-ldap-go/pull/51))

---

## [v1.5.4] - 2025-10-02

### Fixed

- Complete pool connection lifecycle fix for authentication methods ([#50](https://github.com/netresearch/simple-ldap-go/pull/50))

---

## Earlier Releases

For releases prior to v1.5.4, see the [GitHub Releases](https://github.com/netresearch/simple-ldap-go/releases) page.
