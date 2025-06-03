#!/bin/bash

# Test runner script for Truva integration and e2e tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="10m"
COVERAGE_FILE="coverage.out"
COVERAGE_HTML="coverage.html"
TEST_RESULTS_DIR="test-results"

echo -e "${GREEN}Starting Truva Test Suite${NC}"
echo "=============================="

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Function to run tests with coverage
run_tests() {
    local test_type="$1"
    local test_path="$2"
    local output_file="$TEST_RESULTS_DIR/${test_type}_results.txt"
    
    echo -e "${YELLOW}Running $test_type tests...${NC}"
    
    if go test -v -timeout="$TEST_TIMEOUT" -coverprofile="${TEST_RESULTS_DIR}/${test_type}_coverage.out" "$test_path" 2>&1 | tee "$output_file"; then
        echo -e "${GREEN}✓ $test_type tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_type tests failed${NC}"
        return 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed${NC}"
        exit 1
    fi
    
    # Check if required Go modules are available
    if ! go mod verify; then
        echo -e "${RED}Error: Go modules verification failed${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
}

# Function to generate coverage report
generate_coverage() {
    echo -e "${YELLOW}Generating coverage report...${NC}"
    
    # Combine coverage files
    echo "mode: set" > "$TEST_RESULTS_DIR/$COVERAGE_FILE"
    
    for coverage_file in "$TEST_RESULTS_DIR"/*_coverage.out; do
        if [ -f "$coverage_file" ]; then
            tail -n +2 "$coverage_file" >> "$TEST_RESULTS_DIR/$COVERAGE_FILE"
        fi
    done
    
    # Generate HTML coverage report
    if [ -f "$TEST_RESULTS_DIR/$COVERAGE_FILE" ]; then
        go tool cover -html="$TEST_RESULTS_DIR/$COVERAGE_FILE" -o="$TEST_RESULTS_DIR/$COVERAGE_HTML"
        echo -e "${GREEN}✓ Coverage report generated: $TEST_RESULTS_DIR/$COVERAGE_HTML${NC}"
        
        # Show coverage percentage
        coverage_percent=$(go tool cover -func="$TEST_RESULTS_DIR/$COVERAGE_FILE" | grep total | awk '{print $3}')
        echo -e "${GREEN}Total coverage: $coverage_percent${NC}"
    fi
}

# Function to run linting
run_linting() {
    echo -e "${YELLOW}Running linting...${NC}"
    
    # Check if golangci-lint is available
    if command -v golangci-lint &> /dev/null; then
        if golangci-lint run ./tests/...; then
            echo -e "${GREEN}✓ Linting passed${NC}"
        else
            echo -e "${RED}✗ Linting failed${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}Warning: golangci-lint not found, skipping linting${NC}"
    fi
}

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Remove temporary files
    find . -name "*.test" -delete 2>/dev/null || true
    find . -name "*.out" -delete 2>/dev/null || true
    
    echo -e "${GREEN}✓ Cleanup completed${NC}"
}

# Main execution
main() {
    local exit_code=0
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --unit)
                RUN_UNIT=true
                shift
                ;;
            --integration)
                RUN_INTEGRATION=true
                shift
                ;;
            --e2e)
                RUN_E2E=true
                shift
                ;;
            --coverage)
                GENERATE_COVERAGE=true
                shift
                ;;
            --lint)
                RUN_LINT=true
                shift
                ;;
            --cleanup)
                cleanup
                exit 0
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --unit         Run unit tests"
                echo "  --integration  Run integration tests"
                echo "  --e2e          Run end-to-end tests"
                echo "  --coverage     Generate coverage report"
                echo "  --lint         Run linting"
                echo "  --cleanup      Clean up test artifacts"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                exit 1
                ;;
        esac
    done
    
    # If no specific tests specified, run all
    if [ -z "$RUN_UNIT" ] && [ -z "$RUN_INTEGRATION" ] && [ -z "$RUN_E2E" ]; then
        RUN_UNIT=true
        RUN_INTEGRATION=true
        RUN_E2E=true
        GENERATE_COVERAGE=true
        RUN_LINT=true
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Run linting if requested
    if [ "$RUN_LINT" = true ]; then
        run_linting || exit_code=1
    fi
    
    # Run unit tests if requested
    if [ "$RUN_UNIT" = true ]; then
        run_tests "unit" "./pkg/..." || exit_code=1
    fi
    
    # Run integration tests if requested
    if [ "$RUN_INTEGRATION" = true ]; then
        run_tests "integration" "./tests/integration/..." || exit_code=1
    fi
    
    # Run e2e tests if requested
    if [ "$RUN_E2E" = true ]; then
        run_tests "e2e" "./tests/e2e/..." || exit_code=1
    fi
    
    # Generate coverage report if requested
    if [ "$GENERATE_COVERAGE" = true ]; then
        generate_coverage
    fi
    
    # Summary
    echo ""
    echo "=============================="
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}All tests completed successfully!${NC}"
    else
        echo -e "${RED}Some tests failed. Check the results above.${NC}"
    fi
    
    echo -e "${YELLOW}Test results available in: $TEST_RESULTS_DIR/${NC}"
    
    exit $exit_code
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function with all arguments
main "$@"