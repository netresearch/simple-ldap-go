# Simple LDAP Go Documentation

Start at the [Documentation Index](DOCUMENTATION_INDEX.md): it carries the full
API tables and links every guide below. This page is the short way in.

## Guides

| Guide | Read it when |
|-------|--------------|
| [API Reference](API_REFERENCE.md) | Looking up a method, type or configuration field |
| [Architecture](ARCHITECTURE.md) | Understanding how the pieces fit, and why |
| [Authentication Guide](AUTHENTICATION_GUIDE.md) | Implementing sign-in, password changes, account state |
| [Builder Patterns](BUILDER_PATTERNS_GUIDE.md) | Constructing configuration, users, groups or computers |
| [Caching Guide](CACHING_GUIDE.md) | Configuring the cache, or explaining a stale read |
| [Error Handling](ERROR_HANDLING.md) | Deciding what to retry, what to surface, what to log |
| [Iterator Patterns](ITERATOR_PATTERNS_GUIDE.md) | Streaming large result sets without loading them |
| [Performance Configuration](PERFORMANCE_CONFIGURATION_GUIDE.md) | Setting up pooling, metrics and monitoring |
| [Performance Tuning](PERFORMANCE_TUNING.md) | Chasing a measured latency or throughput problem |
| [Resilience](RESILIENCE.md) | Surviving a directory that is slow or unavailable |
| [Security Guide](SECURITY_GUIDE.md) | Hardening an integration, or answering an audit |
| [Structured Logging](STRUCTURED_LOGGING.md) | Knowing what the library writes to your logs |
| [Troubleshooting](TROUBLESHOOTING.md) | Something is not working |

## Elsewhere

- [README](../README.md) - installation, quick start, configuration
- [CONTRIBUTING](../CONTRIBUTING.md) - how to build, test and submit changes
- [SECURITY](../SECURITY.md) - reporting a vulnerability, security practices
- [examples/](../examples/) - runnable programs per topic

## Documentation Standards

- Code examples are Go, and name real API. `scripts/check-docs-api.py` (CI job
  `docs-api`) checks the call shapes in this directory and in the root README
  against the package; run it before opening a pull request.
- Cite a source file when it settles a question, without a line number - line
  numbers go stale silently and this directory has been through that once.
- Note security and performance implications where they apply.
- Add a new guide to the table above and to
  [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md).
