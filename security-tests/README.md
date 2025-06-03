# Security Testing Suite

This directory contains comprehensive security testing tools and scripts for the Truva Kubernetes monitoring application.

## Overview

The security testing suite includes:

- **SAST (Static Application Security Testing)**: Code analysis for security vulnerabilities
- **DAST (Dynamic Application Security Testing)**: Runtime security testing
- **Dependency Scanning**: Vulnerability assessment of third-party dependencies
- **Penetration Testing**: Comprehensive security assessment

## Test Files

### `sast_test.go`
Static Application Security Testing that analyzes source code for:
- SQL injection vulnerabilities
- Cross-site scripting (XSS) patterns
- Command injection risks
- Hardcoded secrets and credentials
- Insecure cryptographic practices
- Path traversal vulnerabilities
- Unsafe file operations
- Input validation issues

### `dast_test.go`
Dynamic Application Security Testing that performs runtime testing for:
- SQL injection attacks
- XSS vulnerabilities
- Command injection
- Path traversal attacks
- Authentication bypass
- LDAP injection
- XXE (XML External Entity) attacks
- CSRF vulnerabilities
- Rate limiting effectiveness
- SSL/TLS configuration

### `dependency_scan_test.go`
Dependency vulnerability scanning that checks:
- Go module vulnerabilities using `govulncheck`
- Dockerfile base image vulnerabilities
- Outdated dependencies
- Known CVEs in dependencies
- License compliance issues

### `penetration_test.go`
Comprehensive penetration testing including:
- Authentication and authorization testing
- Session management vulnerabilities
- Privilege escalation attempts
- Business logic flaws
- Infrastructure security assessment
- Information disclosure testing

## Prerequisites

### Required Tools

```bash
# Install Go vulnerability checker
go install golang.org/x/vuln/cmd/govulncheck@latest

# Install gosec for static analysis
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Install nancy for dependency checking
go install github.com/sonatypecommunity/nancy@latest
```

### System Requirements

- Go 1.19 or later
- Running instance of Truva application (for DAST and penetration tests)
- Internet connection (for vulnerability database updates)

## Usage

### Quick Start

```bash
# Run all security tests
make all

# Run specific test types
make sast
make dast
make dependency-scan
make penetration-test
```

### Individual Test Execution

```bash
# Run SAST tests
go test -v -run TestSAST

# Run DAST tests (requires running application)
go test -v -run TestDAST

# Run dependency scanning
go test -v -run TestDependencyScanning

# Run penetration tests (requires running application)
go test -v -run TestPenetrationTesting
```

### Using External Tools

```bash
# Install security tools
make install-tools

# Run gosec static analysis
make gosec

# Run Go vulnerability check
make govulncheck

# Run nancy dependency check
make nancy

# Run complete security suite
make full-security
```

## Configuration

### Environment Variables

```bash
# Set target application URL for DAST/penetration tests
export TRUVA_TEST_URL="http://localhost:8080"

# Set test timeout
export SECURITY_TEST_TIMEOUT="30m"

# Enable verbose logging
export SECURITY_TEST_VERBOSE="true"
```

### Test Configuration

Modify test parameters in the respective test files:

```go
// In dast_test.go
baseURL := "http://localhost:8080" // Change target URL
timeout := 30 * time.Second        // Adjust timeout

// In penetration_test.go
baseURL := "http://localhost:8080" // Change target URL
concurrentRequests := 10           // Adjust load testing
```

## Reports and Output

### Report Generation

```bash
# Generate comprehensive security report
make security-report

# Run tests with coverage
make coverage
```

### Report Locations

Reports are generated in the `reports/` directory:

- `sast_YYYYMMDD_HHMMSS.log` - SAST test results
- `dast_YYYYMMDD_HHMMSS.log` - DAST test results
- `dependency_YYYYMMDD_HHMMSS.log` - Dependency scan results
- `pentest_YYYYMMDD_HHMMSS.log` - Penetration test results
- `gosec_YYYYMMDD_HHMMSS.json` - Gosec analysis (JSON)
- `govulncheck_YYYYMMDD_HHMMSS.json` - Vulnerability check (JSON)
- `security_summary_YYYYMMDD_HHMMSS.txt` - Comprehensive summary

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.19
    
    - name: Install security tools
      run: |
        cd security-tests
        make install-tools
    
    - name: Run security tests
      run: |
        cd security-tests
        make ci
    
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: security-tests/reports/
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Testing') {
            steps {
                dir('security-tests') {
                    sh 'make install-tools'
                    sh 'make ci'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-tests/reports/**/*', fingerprint: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-tests/reports',
                        reportFiles: '*.html',
                        reportName: 'Security Test Report'
                    ])
                }
            }
        }
    }
}
```

## Security Test Categories

### High Priority Tests

1. **Authentication Bypass** - Tests for authentication vulnerabilities
2. **SQL Injection** - Database injection attack testing
3. **Command Injection** - OS command injection testing
4. **Privilege Escalation** - Authorization bypass testing

### Medium Priority Tests

1. **XSS (Cross-Site Scripting)** - Client-side injection testing
2. **Session Management** - Session security testing
3. **Rate Limiting** - DoS protection testing
4. **Security Headers** - HTTP security header validation

### Low Priority Tests

1. **Information Disclosure** - Sensitive data exposure testing
2. **SSL/TLS Configuration** - Cryptographic configuration testing
3. **Dependency Vulnerabilities** - Third-party security assessment

## Troubleshooting

### Common Issues

1. **Application Not Running**
   ```
   Error: Server not running at http://localhost:8080
   Solution: Start the Truva application before running DAST/penetration tests
   ```

2. **Tool Installation Failures**
   ```
   Error: go install failed
   Solution: Ensure Go is properly installed and GOPATH is set
   ```

3. **Permission Denied**
   ```
   Error: Permission denied accessing reports directory
   Solution: Ensure write permissions for the reports directory
   ```

### Debug Mode

```bash
# Enable verbose output
go test -v -run TestSAST -args -verbose

# Run with race detection
go test -race -v ./...

# Run with memory profiling
go test -memprofile=mem.prof -v ./...
```

## Best Practices

1. **Regular Testing**: Run security tests on every commit
2. **Baseline Establishment**: Establish security baselines and track improvements
3. **False Positive Management**: Review and document false positives
4. **Continuous Monitoring**: Integrate with monitoring and alerting systems
5. **Documentation**: Keep security test documentation up to date

## Contributing

When adding new security tests:

1. Follow the existing test structure and naming conventions
2. Add comprehensive documentation and comments
3. Include both positive and negative test cases
4. Update this README with new test descriptions
5. Ensure tests are deterministic and repeatable

## Security Considerations

- **Test Environment**: Run security tests only in designated test environments
- **Credentials**: Never use production credentials in security tests
- **Data Protection**: Ensure test data doesn't contain sensitive information
- **Network Isolation**: Isolate security testing from production networks

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Go Security Checker](https://github.com/securecodewarrior/gosec)
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)