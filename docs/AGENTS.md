<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

# AGENTS.md — Documentation

## Overview
Comprehensive documentation for the Simple LDAP Go library including API references, architecture guides, implementation patterns, and troubleshooting. Start with `DOCUMENTATION_INDEX.md` for navigation.

## Setup & environment
- View locally: Open markdown files in any editor
- Generate godoc: `go doc -all > API.txt`
- Serve godoc: `godoc -http=:6060` then visit http://localhost:6060

## Build & tests (prefer file-scoped)
- Validate markdown: Use any markdown linter
- Check links: Ensure all internal links resolve
- Update index: Keep `DOCUMENTATION_INDEX.md` current
- Generate coverage: `go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out`

## Code style & conventions
- Use clear headings and consistent formatting
- Include runnable code examples in markdown
- Keep line length under 120 characters for readability
- Use tables for API method listings
- Include "Last Updated" dates in guides
- Cross-reference related documentation

## Security & safety
- Never include real credentials in examples
- Document security considerations clearly
- Highlight authentication requirements
- Note permission levels needed for operations
- Include security best practices sections

## PR/commit checklist
- Update relevant documentation for code changes
- Ensure code examples compile and run
- Update DOCUMENTATION_INDEX.md if adding new docs
- Check all cross-references still work
- Update "Last Updated" dates

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