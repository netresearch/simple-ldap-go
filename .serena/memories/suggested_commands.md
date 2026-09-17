# Simple LDAP Go - Suggested Commands

Everything below is a Makefile target; `make help` lists them all.

## Testing

No LDAP server and no environment variables are needed. Unit tests run on their
own; the integration tier starts an OpenLDAP container through testcontainers.

```bash
make test-fast          # unit tests, no Docker, the one to run while editing
make test-unit          # all unit tests
make test-integration   # requires Docker
make test-all           # unit + integration
make test-coverage      # coverage report; CI enforces 79%
make test-race          # race detector
make test-compat        # build and unit-test on every supported Go release
make docker-clean       # remove containers left behind by a failed run
```

`LDAP_SERVER`, `LDAP_BASE_DN` and `LDAP_BIND_DN` are optional and read only by
the pool benchmarks (`benchmark_pool_test.go`), which skip without them.

## Quality

```bash
make qa                 # build, vet, lint, fmt, mod-tidy
make lint               # golangci-lint
make fmt                # gofmt
python3 scripts/check-docs-api.py   # CI job docs-api: docs against the real API
```

## Building

```bash
make build
go mod verify && go mod tidy
```

## Documentation

```bash
go doc -all .           # the package surface; the source of truth for the guides
```

## Notes

- CI runs the full suite: 13 workflows under `.github/workflows/`, with a 79%
  coverage gate in `ci.yml`.
- The project is a library package, not an executable.
- Conventional Commits, signed (`git commit -S --signoff`).
