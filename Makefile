# Simple LDAP Go - Optimized Test Makefile

.PHONY: test test-fast test-unit test-integration test-all test-parallel test-benchmark clean help

# Default Go settings
GO_VERSION := 1.23
TIMEOUT_UNIT := 10s
TIMEOUT_INTEGRATION := 60s
TIMEOUT_ALL := 300s
PARALLEL := 4

# Test patterns
UNIT_PATTERN := -run="^Test.*[^(Integration|Benchmark)]$$"
INTEGRATION_PATTERN := -run="Test.*Integration"
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
	go test $(TEST_FLAGS) -short -timeout=$(TIMEOUT_UNIT) -parallel=$(PARALLEL) ./...

test-unit: ## Run all unit tests
	@echo "Running unit tests..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_UNIT) -parallel=$(PARALLEL) $(UNIT_PATTERN) ./...

test-integration: ## Run integration tests (requires Docker)
	@echo "Running integration tests..."
	@echo "⚠️  Warning: This will start Docker containers and may take 1-2 minutes"
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_INTEGRATION) $(INTEGRATION_PATTERN) ./...

test-integration-parallel: ## Run integration tests with optimized parallelization
	@echo "Running optimized integration tests..."
	@echo "⚠️  Using shared containers for faster execution"
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_INTEGRATION) -parallel=2 $(INTEGRATION_PATTERN) ./...

test-all: ## Run all tests (unit + integration)
	@echo "Running all tests..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -parallel=$(PARALLEL) ./...

test-parallel: ## Run tests with maximum parallelization
	@echo "Running tests with optimized parallelization..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -parallel=8 ./...

test-benchmark: ## Run benchmark tests
	@echo "Running benchmark tests..."
	go test -bench=. -benchmem -short -timeout=$(TIMEOUT_ALL) $(BENCHMARK_PATTERN) ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	go test $(TEST_FLAGS) -timeout=$(TIMEOUT_ALL) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

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
		go test $(TEST_FLAGS) -timeout=120s -parallel=2 $(INTEGRATION_PATTERN) ./...; \
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

qa-full: qa test-all ## Run full quality assurance including all tests

# Clean up

clean: ## Clean up build artifacts and test files
	@echo "Cleaning up..."
	go clean -testcache
	rm -f coverage.out coverage.html
	@$(MAKE) docker-clean

# Time-based test targets

test-quick: ## Quick test run (< 30 seconds)
	@echo "Running quick tests..."
	go test -short -timeout=30s -parallel=8 ./...

test-medium: ## Medium test run (< 2 minutes)
	@echo "Running medium test suite..."
	@$(MAKE) test-fast
	@$(MAKE) test-integration-parallel

test-comprehensive: ## Comprehensive test run (< 5 minutes)
	@echo "Running comprehensive test suite..."
	@$(MAKE) qa
	@$(MAKE) test-all
	@$(MAKE) test-coverage

# Default target
.DEFAULT_GOAL := test-fast

# Help target should be first for better UX
help: ## Show this help message