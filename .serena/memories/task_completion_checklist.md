# Simple LDAP Go - Task Completion Checklist

## Before calling a task done

### Code quality
1. `make fmt` and `make vet`
2. `make lint` (golangci-lint, configured in `.golangci.yml`)
3. `make mod-tidy`
4. Or all four at once: `make qa`

### Testing
1. `make test-fast` while editing, `make test-unit` before committing
2. `make test-integration` when the change touches connection, pool or search
   behaviour (needs Docker)
3. `make test-coverage` — CI fails below 79%, so new code needs tests, not a
   lowered threshold
4. `make test-race` for anything touching the pool, the cache or a goroutine
5. `make test-compat` when the change could be Go-version sensitive

### Documentation
1. Update the guide that covers what changed; `docs/AGENTS.md` says which
2. `python3 scripts/check-docs-api.py` must exit 0 — CI runs it as `docs-api`,
   and it now checks struct literal fields and package-level calls too
3. Update `README.md` when the public API changes
4. Never cite a source line number in a document; the file name is enough

### Git workflow
1. Conventional Commits
2. Signed and signed off: `git commit -S --signoff`
3. Say in the commit what was measured, not what is expected to work

### Environment
- No LDAP server needed: unit tests run alone, integration tests start an
  OpenLDAP container via testcontainers
- CI is live: 13 workflows under `.github/workflows/`
- This is a library package, not an executable

### Specific to LDAP operations
- Check both directory flavours where behaviour differs: Active Directory and
  OpenLDAP disagree on password expiry, lockout and `adminCount`
- Validate security implications for anything touching authentication
- Keep backward compatibility with existing API consumers
