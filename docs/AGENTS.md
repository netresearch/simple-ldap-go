<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2026-09-17 -->

# AGENTS.md — Documentation

## Overview
Comprehensive documentation for the Simple LDAP Go library including API references, architecture guides, implementation patterns, and troubleshooting. Start with `DOCUMENTATION_INDEX.md` for navigation.

## Setup & environment
- View locally: Open markdown files in any editor
- Generate godoc: `go doc -all > API.txt`
- Serve godoc: `godoc -http=:6060` then visit http://localhost:6060

## Build & tests (prefer file-scoped)
- **Run the doc gate before pushing: `python3 scripts/check-docs-api.py --verbose`.** CI runs it as the job `docs-api`. It checks every `l.`/`client.`/`ldapClient.` call and every `user.`/`group.`/`computer.` member in `docs/*.md` and `README.md` against the real package, plus package-qualified calls (an exported name after the `ldap.` prefix) and the field names inside `ldap.Config{…}`, `ldap.PoolConfig{…}` and the other config literals.
- What the gate does not check: struct shapes written out in full, method signatures, argument types, and whether a snippet compiles. Those are still on the author.
- Check links: every relative link must resolve; CI has no link checker
- Update index: keep `DOCUMENTATION_INDEX.md` current
- Generate coverage: `go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out`

## Code style & conventions
- Use clear headings and consistent formatting
- Include runnable code examples in markdown
- Keep line length under 120 characters for readability
- Use tables for API method listings
- Cite a source file when it settles a question, but **never with a line number**: line numbers go stale silently, and this directory has already been repaired once for exactly that
- Cross-reference related documentation

## Security & safety
- Never include real credentials in examples
- Document security considerations clearly
- Highlight authentication requirements
- Note permission levels needed for operations
- Include security best practices sections

## PR/commit checklist
- `python3 scripts/check-docs-api.py` exits 0
- Update relevant documentation for code changes
- Every name in an example exists: check it with `go doc <Name>` rather than copying from another document
- Update `DOCUMENTATION_INDEX.md` and `README.md` (this directory's) if adding or removing a guide
- Check all cross-references still resolve

## Good vs. bad examples
- Good: `API_REFERENCE.md` (comprehensive, well-structured)
- Good: `BUILDER_PATTERNS_GUIDE.md` (extensive examples)
- Good: `CACHING_GUIDE.md` (performance data included)
- Pattern: Include both conceptual explanation and code

## When stuck
- Check existing similar documentation
- Review Go documentation conventions
- Ensure consistency with library patterns
- Validate examples actually work