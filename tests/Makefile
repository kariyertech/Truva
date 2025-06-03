# Makefile for Truva Test Suite

.PHONY: help test test-unit test-integration test-e2e test-all coverage lint clean setup

# Default target
help:
	@echo "Truva Test Suite"
	@echo "================="
	@echo "Available targets:"
	@echo "  test-unit        Run unit tests"
	@echo "  test-integration Run integration tests"
	@echo "  test-e2e         Run end-to-end tests"
	@echo "  test-all         Run all tests"
	@echo "  coverage         Generate coverage report"
	@echo "  lint             Run linting"
	@echo "  clean            Clean test artifacts"
	@echo "  setup            Setup test environment"
	@echo "  help             Show this help message"

# Test targets
test-unit:
	@echo "Running unit tests..."
	./scripts/run_tests.sh --unit

test-integration:
	@echo "Running integration tests..."
	./scripts/run_tests.sh --integration

test-e2e:
	@echo "Running end-to-end tests..."
	./scripts/run_tests.sh --e2e

test-all:
	@echo "Running all tests..."
	./scripts/run_tests.sh

test: test-all

# Coverage target
coverage:
	@echo "Generating coverage report..."
	./scripts/run_tests.sh --coverage

# Linting target
lint:
	@echo "Running linting..."
	./scripts/run_tests.sh --lint

# Clean target
clean:
	@echo "Cleaning test artifacts..."
	./scripts/run_tests.sh --cleanup
	rm -rf test-results/
	find . -name "*.test" -delete
	find . -name "*.out" -delete

# Setup target
setup:
	@echo "Setting up test environment..."
	go mod download
	go mod verify
	@echo "Test environment setup complete"

# Quick test (unit tests only)
quick:
	@echo "Running quick tests (unit only)..."
	go test -short ./...

# Verbose test output
test-verbose:
	@echo "Running tests with verbose output..."
	go test -v ./tests/...

# Test with race detection
test-race:
	@echo "Running tests with race detection..."
	go test -race ./tests/...

# Benchmark tests
bench:
	@echo "Running benchmark tests..."
	go test -bench=. ./tests/...

# Test specific package
test-pkg:
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make test-pkg PKG=<package_path>"; \
		exit 1; \
	fi
	@echo "Testing package: $(PKG)"
	go test -v $(PKG)

# Install test dependencies
install-deps:
	@echo "Installing test dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/stretchr/testify@latest
	@echo "Test dependencies installed"

# Check test files
check-tests:
	@echo "Checking test files..."
	@find . -name "*_test.go" -type f | wc -l | xargs echo "Total test files:"
	@find ./tests -name "*.go" -type f | wc -l | xargs echo "Integration/E2E test files:"

# Run tests in Docker (if Dockerfile exists)
test-docker:
	@if [ -f "../Dockerfile" ]; then \
		echo "Running tests in Docker..."; \
		docker build -t truva-test -f ../Dockerfile ..; \
		docker run --rm truva-test make test; \
	else \
		echo "Dockerfile not found, skipping Docker tests"; \
	fi

# Watch tests (requires entr or similar)
test-watch:
	@if command -v entr >/dev/null 2>&1; then \
		echo "Watching for changes and running tests..."; \
		find . -name "*.go" | entr -c make test-unit; \
	else \
		echo "entr not found. Install with: brew install entr (macOS) or apt-get install entr (Ubuntu)"; \
	fi