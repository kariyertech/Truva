# Security Testing Makefile
# This Makefile provides targets for running various security tests

.PHONY: all sast dast dependency-scan penetration-test security-report clean help

# Default target
all: sast dast dependency-scan penetration-test security-report

# Variables
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
REPORT_DIR := reports
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

# Create reports directory
$(REPORT_DIR):
	@mkdir -p $(REPORT_DIR)

# Static Application Security Testing (SAST)
sast: $(REPORT_DIR)
	@echo "Running SAST tests..."
	@go test -v ./... -run TestSAST -timeout 10m > $(REPORT_DIR)/sast_$(TIMESTAMP).log 2>&1 || true
	@echo "SAST tests completed. Report: $(REPORT_DIR)/sast_$(TIMESTAMP).log"

# Dynamic Application Security Testing (DAST)
dast: $(REPORT_DIR)
	@echo "Running DAST tests..."
	@go test -v ./... -run TestDAST -timeout 15m > $(REPORT_DIR)/dast_$(TIMESTAMP).log 2>&1 || true
	@echo "DAST tests completed. Report: $(REPORT_DIR)/dast_$(TIMESTAMP).log"

# Dependency Scanning
dependency-scan: $(REPORT_DIR)
	@echo "Running dependency scan..."
	@go test -v ./... -run TestDependencyScanning -timeout 10m > $(REPORT_DIR)/dependency_$(TIMESTAMP).log 2>&1 || true
	@echo "Dependency scan completed. Report: $(REPORT_DIR)/dependency_$(TIMESTAMP).log"

# Penetration Testing
penetration-test: $(REPORT_DIR)
	@echo "Running penetration tests..."
	@go test -v ./... -run TestPenetrationTesting -timeout 20m > $(REPORT_DIR)/pentest_$(TIMESTAMP).log 2>&1 || true
	@echo "Penetration tests completed. Report: $(REPORT_DIR)/pentest_$(TIMESTAMP).log"

# Install security tools
install-tools:
	@echo "Installing security tools..."
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@go install github.com/sonatypecommunity/nancy@latest
	@echo "Security tools installed"

# Run gosec SAST tool
gosec: $(REPORT_DIR)
	@echo "Running gosec SAST analysis..."
	@gosec -fmt json -out $(REPORT_DIR)/gosec_$(TIMESTAMP).json ./... || true
	@gosec -fmt text -out $(REPORT_DIR)/gosec_$(TIMESTAMP).txt ./... || true
	@echo "Gosec analysis completed. Reports: $(REPORT_DIR)/gosec_$(TIMESTAMP).*"

# Run govulncheck
govulncheck: $(REPORT_DIR)
	@echo "Running govulncheck..."
	@govulncheck -json ./... > $(REPORT_DIR)/govulncheck_$(TIMESTAMP).json 2>&1 || true
	@govulncheck ./... > $(REPORT_DIR)/govulncheck_$(TIMESTAMP).txt 2>&1 || true
	@echo "Govulncheck completed. Reports: $(REPORT_DIR)/govulncheck_$(TIMESTAMP).*"

# Check for known vulnerabilities in dependencies
nancy: $(REPORT_DIR)
	@echo "Running nancy dependency check..."
	@go list -json -deps ./... | nancy sleuth > $(REPORT_DIR)/nancy_$(TIMESTAMP).txt 2>&1 || true
	@echo "Nancy check completed. Report: $(REPORT_DIR)/nancy_$(TIMESTAMP).txt"

# Generate comprehensive security report
security-report: $(REPORT_DIR)
	@echo "Generating comprehensive security report..."
	@echo "Security Test Report - $(TIMESTAMP)" > $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt
	@echo "=========================================" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt
	@echo "" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt
	@echo "Test Results:" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt
	@echo "-------------" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt
	@for file in $(REPORT_DIR)/*_$(TIMESTAMP).log; do \
		if [ -f "$$file" ]; then \
			echo "$$file:" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt; \
			tail -n 20 "$$file" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt; \
			echo "" >> $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt; \
		fi; \
	done
	@echo "Security report generated: $(REPORT_DIR)/security_summary_$(TIMESTAMP).txt"

# Run quick security check
quick-check:
	@echo "Running quick security check..."
	@go test -v -run TestSAST -timeout 5m
	@echo "Quick security check completed"

# Run full security suite with external tools
full-security: install-tools gosec govulncheck nancy all security-report
	@echo "Full security testing completed"

# Lint security test files
lint:
	@echo "Linting security test files..."
	@gofmt -l $(GO_FILES)
	@go vet ./...
	@echo "Linting completed"

# Build security tests
build:
	@echo "Building security tests..."
	@go build -v ./...
	@echo "Build completed"

# Clean up reports and artifacts
clean:
	@echo "Cleaning up reports and artifacts..."
	@rm -rf $(REPORT_DIR)
	@go clean -testcache
	@echo "Cleanup completed"

# Run tests with coverage
coverage: $(REPORT_DIR)
	@echo "Running security tests with coverage..."
	@go test -v -coverprofile=$(REPORT_DIR)/coverage_$(TIMESTAMP).out ./...
	@go tool cover -html=$(REPORT_DIR)/coverage_$(TIMESTAMP).out -o $(REPORT_DIR)/coverage_$(TIMESTAMP).html
	@echo "Coverage report generated: $(REPORT_DIR)/coverage_$(TIMESTAMP).html"

# Validate test files
validate:
	@echo "Validating security test files..."
	@go test -v -run=^$$ ./... # Compile tests without running
	@echo "Validation completed"

# Run CI/CD security pipeline
ci: lint validate build quick-check
	@echo "CI security pipeline completed"

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Run all security tests"
	@echo "  sast             - Run Static Application Security Testing"
	@echo "  dast             - Run Dynamic Application Security Testing"
	@echo "  dependency-scan  - Run dependency vulnerability scanning"
	@echo "  penetration-test - Run penetration testing"
	@echo "  install-tools    - Install required security tools"
	@echo "  gosec            - Run gosec SAST tool"
	@echo "  govulncheck      - Run Go vulnerability checker"
	@echo "  nancy            - Run nancy dependency checker"
	@echo "  security-report  - Generate comprehensive security report"
	@echo "  quick-check      - Run quick security validation"
	@echo "  full-security    - Run complete security testing suite"
	@echo "  lint             - Lint security test files"
	@echo "  build            - Build security tests"
	@echo "  coverage         - Run tests with coverage analysis"
	@echo "  validate         - Validate test files compilation"
	@echo "  ci               - Run CI/CD security pipeline"
	@echo "  clean            - Clean up reports and artifacts"
	@echo "  help             - Show this help message"