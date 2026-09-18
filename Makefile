# Simple LDAP Go - Optimized Test Makefile

.PHONY: test test-fast test-unit test-integration test-all test-parallel test-benchmark clean help test-compat

# Supported Go releases. Mirrors the go-compat matrix in .github/workflows/ci.yml;
# the oldest entry must match the `go` directive in go.mod. Consumed by test-compat.
GO_VERSIONS := 1.26 1.27
TIMEOUT_UNIT := 10s
TIMEOUT_ALL := 300s
# Every tagged pass reads this: test-integration, test-integration-parallel,
# test-all's second pass and test-ci's local branch. Each starts one OpenLDAP
# container per integration test function — 664s locally, 628s in CI — and
# 1200s leaves room for a cold image pull, where a timeout reads as a hang
# rather than as a budget. TIMEOUT_ALL stays at 300s: the targets reading it
# start no containers, and tripling their hang budget to suit this one would
# turn a five-minute wait for a deadlock into a fifteen-minute one.
TIMEOUT_ALL_INTEGRATION := 1200s
PARALLEL := 4

# Test patterns
UNIT_PATTERN := -run="^Test.*[^(Integration|Benchmark)]$$"
BENCHMARK_PATTERN := -run="Benchmark"

# Build flags
BUILD_FLAGS := -v
TEST_FLAGS := -v -race

help: ## Show this help message
	@echo "Simple LDAP Go - Test Execution"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

test-fast: ## Run only fast unit tests (no containers)
	@echo "Running fast unit tests..."
	go test $(TEST_FLAGS) -short -timeout=$(TIMEOUT_UNIT) -parallel=$(PARALLEL) -coverprofile=coverage-unit.out ./...

test-unit: ## Run all unit tests
	@echo "Running unit tests..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_UNIT) -parallel=$(PARALLEL) $(UNIT_PATTERN) ./...

# The build tag is the selector. Pairing it with -run="Test.*Integration" as
# this target used to also drop 14 of the 42 integration test functions, whose
# names do not contain "Integration" — TestBulkOperations, TestCacheInvalidation,
# TestNewBuildsTheCacheFromTheSuppliedConfig and eleven more. The tagged build also
# carries the test files that declare no build constraint — 101 tests, about
# ten seconds — which is the cost of selecting by tag.
test-integration: ## Run integration tests (requires Docker)
	@echo "Running integration tests..."
	@echo "⚠️  Warning: This will start Docker containers and may take several minutes"
	go test $(TEST_FLAGS) -tags=integration -timeout=$(TIMEOUT_ALL_INTEGRATION) ./...

test-integration-parallel: ## Run integration tests with optimized parallelization
	@echo "Running optimized integration tests..."
	@echo "⚠️  One OpenLDAP container per integration test function; this takes several minutes"
	go test $(TEST_FLAGS) -tags=integration -timeout=$(TIMEOUT_ALL_INTEGRATION) -parallel=2 -coverprofile=coverage-integration.out ./...

# Two passes, because no single invocation covers everything. Without the tag
# the integration tier is not compiled at all — which is what this target used
# to do while its help text promised both tiers. With the tag the example
# packages drop out instead: every examples/*_test.go is `//go:build
# !integration`. So: untagged for the unit tier and the examples, tagged for
# the unit tier and the integration tier.
test-all: ## Run all tests (unit + integration; requires Docker)
	@echo "Running all tests (unit + integration)..."
	@echo "⚠️  Warning: This will start Docker containers and may take several minutes"
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -parallel=$(PARALLEL) ./...
	go test $(TEST_FLAGS) -tags=integration -timeout=$(TIMEOUT_ALL_INTEGRATION) -parallel=2 ./...

test-parallel: ## Run tests with maximum parallelization
	@echo "Running tests with optimized parallelization..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -parallel=8 ./...

test-benchmark-ci: ## Fast benchmarks for CI (no Docker required, 60s max)
	@echo "Running CI-optimized benchmark tests..."
	go test -bench=. -benchmem -short -benchtime=100ms -timeout=60s -run="^Benchmark" ./...

test-benchmark-fast: ## Quick benchmarks for development (30s max)
	@echo "Running fast benchmark tests..."
	go test -bench=. -benchmem -short -benchtime=10ms -timeout=30s -run="^Benchmark" ./...

test-benchmark-full: ## Full benchmarks with Docker containers (300s max)
	@echo "Running full benchmark tests (requires Docker)..."
	go test -bench=. -benchmem -timeout=$(TIMEOUT_ALL) -run="^Benchmark" ./...

test-benchmark: test-benchmark-ci ## Default to CI-optimized benchmarks

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-compat: ## Build and unit-test under every supported Go release (mirrors CI go-compat)
	@for v in $(GO_VERSIONS); do \
		bin=""; \
		for c in $$(ls -d $$HOME/sdk/go$$v.* 2>/dev/null | sort -V | tail -1)/bin/go $$(command -v go); do \
			[ -x "$$c" ] || continue; \
			case "$$(GOTOOLCHAIN=local $$c version 2>/dev/null)" in *"go$$v."*) bin=$$c; break;; esac; \
		done; \
		if [ -z "$$bin" ]; then \
			echo "❌ Go $$v toolchain not found. Install it with: go install golang.org/dl/go$$v.0@latest && go$$v.0 download"; \
			exit 1; \
		fi; \
		echo "==> $$(GOTOOLCHAIN=local $$bin version)"; \
		GOTOOLCHAIN=local $$bin build ./... || exit 1; \
		GOTOOLCHAIN=local $$bin vet ./... || exit 1; \
		GOTOOLCHAIN=local $$bin test -short -race -timeout=$(TIMEOUT_ALL) ./... || exit 1; \
	done
	@echo "✅ All supported Go releases pass"

test-race: ## Run tests with race detection
	@echo "Running tests with race detection..."
	go test -race -timeout=$(TIMEOUT_ALL) ./...

# Performance testing targets

test-performance: ## Run performance-focused test suite
	@echo "Running performance test suite..."
	@echo "1. Unit tests (parallel)..."
	@$(MAKE) test-unit
	@echo "2. Integration tests (optimized)..."
	@$(MAKE) test-integration-parallel
	@echo "3. Benchmarks..."
	@$(MAKE) test-benchmark

test-ci: ## Run tests optimized for CI environment
	@echo "Running CI-optimized test suite..."
	go test $(TEST_FLAGS) -short -timeout=60s -parallel=4 ./...
	@if [ "$$CI" != "true" ]; then \
		echo "Running integration tests..."; \
		go test $(TEST_FLAGS) -tags=integration -timeout=$(TIMEOUT_ALL_INTEGRATION) -parallel=2 ./...; \
	fi

# Development targets

test-watch: ## Run tests in watch mode (requires entr)
	@echo "Starting test watcher..."
	@echo "⚠️  Requires 'entr' tool: brew install entr"
	find . -name "*.go" | entr -c make test-fast

test-debug: ## Run tests with debug output
	@echo "Running tests with debug output..."
	go test -v -timeout=$(TIMEOUT_ALL) -parallel=1 ./...

test-verbose: ## Run tests with maximum verbosity
	@echo "Running tests with verbose output..."
	go test -v -x -timeout=$(TIMEOUT_ALL) ./...

# Container management

docker-check: ## Check if Docker is available
	@if ! command -v docker &> /dev/null; then \
		echo "❌ Docker not found. Integration tests will be skipped."; \
		exit 1; \
	fi
	@if ! docker info &> /dev/null; then \
		echo "❌ Docker daemon not running. Integration tests will be skipped."; \
		exit 1; \
	fi
	@echo "✅ Docker is available"

docker-clean: ## Clean up test containers
	@echo "Cleaning up test containers..."
	docker ps -a --filter "label=org.testcontainers=true" -q | xargs -r docker rm -f
	docker images --filter "dangling=true" -q | xargs -r docker rmi

# Build targets

build: ## Build the library
	@echo "Building simple-ldap-go..."
	go build $(BUILD_FLAGS) ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

lint: ## Run golangci-lint (requires golangci-lint)
	@echo "Running golangci-lint..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...

mod-tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	go mod tidy

# Quality assurance targets

qa: build vet lint fmt mod-tidy ## Run quality assurance checks

qa-full: qa test-all ## Run full quality assurance including all tests (requires Docker)

# Clean up

clean: ## Clean up build artifacts and test files
	@echo "Cleaning up..."
	go clean -testcache
	rm -f coverage.out coverage-unit.out coverage-integration.out coverage.html
	@$(MAKE) docker-clean

# Time-based test targets

test-quick: ## Quick test run (< 30 seconds)
	@echo "Running quick tests..."
	go test -short -timeout=30s -parallel=8 ./...

test-medium: ## Unit tier plus the full integration tier (requires Docker, ~12 minutes)
	@echo "Running medium test suite..."
	@$(MAKE) test-fast
	@$(MAKE) test-integration-parallel

test-comprehensive: ## Comprehensive test run, unit + integration (requires Docker, ~15 minutes)
	@echo "Running comprehensive test suite..."
	@$(MAKE) qa
	@$(MAKE) test-all
	@$(MAKE) test-coverage

# Default target
.DEFAULT_GOAL := test-fast

# Help target should be first for better UX
help: ## Show this help message