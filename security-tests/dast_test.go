package security_tests

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// DASTScanner performs dynamic application security testing
type DASTScanner struct {
	BaseURL   string
	Client    *http.Client
	Vulns     []Vulnerability
	TestCases []SecurityTestCase
}

// Vulnerability represents a security vulnerability found during DAST
type Vulnerability struct {
	URL         string
	Method      string
	Type        string
	Severity    string
	Description string
	Payload     string
	Response    string
	Evidence    string
}

// SecurityTestCase represents a security test case
type SecurityTestCase struct {
	Name        string
	Description string
	Method      string
	Path        string
	Headers     map[string]string
	Payload     string
	Expected    TestExpectation
}

// TestExpectation defines what to expect from a security test
type TestExpectation struct {
	StatusCode       int
	ShouldBlock      bool
	ShouldContain    []string
	ShouldNotContain []string
}

// NewDASTScanner creates a new DAST scanner
func NewDASTScanner(baseURL string) *DASTScanner {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing purposes
			},
		},
	}

	return &DASTScanner{
		BaseURL:   baseURL,
		Client:    client,
		Vulns:     make([]Vulnerability, 0),
		TestCases: getSecurityTestCases(),
	}
}

// getSecurityTestCases returns predefined security test cases
func getSecurityTestCases() []SecurityTestCase {
	return []SecurityTestCase{
		// SQL Injection Tests
		{
			Name:        "SQL Injection - Basic",
			Description: "Test for basic SQL injection vulnerability",
			Method:      "GET",
			Path:        "/api/pods?name=' OR '1'='1",
			Expected: TestExpectation{
				ShouldBlock:      true,
				ShouldNotContain: []string{"syntax error", "mysql", "postgresql"},
			},
		},
		// XSS Tests
		{
			Name:        "XSS - Reflected",
			Description: "Test for reflected XSS vulnerability",
			Method:      "GET",
			Path:        "/api/search?q=<script>alert('xss')</script>",
			Expected: TestExpectation{
				ShouldBlock:      true,
				ShouldNotContain: []string{"<script>", "alert"},
			},
		},
		// Command Injection Tests
		{
			Name:        "Command Injection",
			Description: "Test for command injection vulnerability",
			Method:      "POST",
			Path:        "/api/exec",
			Headers:     map[string]string{"Content-Type": "application/json"},
			Payload:     `{"command": "ls; cat /etc/passwd"}`,
			Expected: TestExpectation{
				ShouldBlock:      true,
				ShouldNotContain: []string{"root:", "/bin/bash"},
			},
		},
		// Path Traversal Tests
		{
			Name:        "Path Traversal",
			Description: "Test for path traversal vulnerability",
			Method:      "GET",
			Path:        "/api/files?path=../../../etc/passwd",
			Expected: TestExpectation{
				ShouldBlock:      true,
				ShouldNotContain: []string{"root:", "/bin/bash"},
			},
		},
		// Authentication Bypass Tests
		{
			Name:        "Authentication Bypass - SQL",
			Description: "Test for authentication bypass using SQL injection",
			Method:      "POST",
			Path:        "/api/login",
			Headers:     map[string]string{"Content-Type": "application/json"},
			Payload:     `{"username": "admin' OR '1'='1", "password": "anything"}`,
			Expected: TestExpectation{
				ShouldBlock: true,
				StatusCode:  401,
			},
		},
		// LDAP Injection Tests
		{
			Name:        "LDAP Injection",
			Description: "Test for LDAP injection vulnerability",
			Method:      "GET",
			Path:        "/api/users?filter=*)(uid=*))(|(uid=*",
			Expected: TestExpectation{
				ShouldBlock: true,
			},
		},
		// XXE Tests
		{
			Name:        "XXE Attack",
			Description: "Test for XML External Entity vulnerability",
			Method:      "POST",
			Path:        "/api/xml",
			Headers:     map[string]string{"Content-Type": "application/xml"},
			Payload:     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			Expected: TestExpectation{
				ShouldBlock:      true,
				ShouldNotContain: []string{"root:", "/bin/bash"},
			},
		},
		// CSRF Tests
		{
			Name:        "CSRF Attack",
			Description: "Test for Cross-Site Request Forgery vulnerability",
			Method:      "POST",
			Path:        "/api/admin/delete",
			Headers:     map[string]string{"Origin": "http://evil.com"},
			Payload:     `{"id": "123"}`,
			Expected: TestExpectation{
				ShouldBlock: true,
				StatusCode:  403,
			},
		},
		// Rate Limiting Tests
		{
			Name:        "Rate Limiting Bypass",
			Description: "Test rate limiting implementation",
			Method:      "GET",
			Path:        "/api/health",
			Headers:     map[string]string{"X-Forwarded-For": "1.2.3.4"},
			Expected: TestExpectation{
				StatusCode: 429, // Should be rate limited after many requests
			},
		},
	}
}

// RunSecurityTests runs all security test cases
func (d *DASTScanner) RunSecurityTests() error {
	for _, testCase := range d.TestCases {
		if err := d.runTestCase(testCase); err != nil {
			return fmt.Errorf("failed to run test case %s: %w", testCase.Name, err)
		}
	}
	return nil
}

// runTestCase runs a single security test case
func (d *DASTScanner) runTestCase(testCase SecurityTestCase) error {
	url := d.BaseURL + testCase.Path

	var body io.Reader
	if testCase.Payload != "" {
		body = strings.NewReader(testCase.Payload)
	}

	req, err := http.NewRequest(testCase.Method, url, body)
	if err != nil {
		return err
	}

	// Set headers
	for key, value := range testCase.Headers {
		req.Header.Set(key, value)
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Analyze response for vulnerabilities
	d.analyzeResponse(testCase, resp, string(respBody))

	return nil
}

// analyzeResponse analyzes the HTTP response for security vulnerabilities
func (d *DASTScanner) analyzeResponse(testCase SecurityTestCase, resp *http.Response, body string) {
	vuln := Vulnerability{
		URL:    resp.Request.URL.String(),
		Method: resp.Request.Method,
		Type:   testCase.Name,
	}

	// Check status code expectations
	if testCase.Expected.StatusCode != 0 && resp.StatusCode != testCase.Expected.StatusCode {
		vuln.Severity = "MEDIUM"
		vuln.Description = fmt.Sprintf("Expected status code %d, got %d", testCase.Expected.StatusCode, resp.StatusCode)
		vuln.Response = body
		d.Vulns = append(d.Vulns, vuln)
	}

	// Check for content that should not be present
	for _, content := range testCase.Expected.ShouldNotContain {
		if strings.Contains(body, content) {
			vuln.Severity = "HIGH"
			vuln.Description = fmt.Sprintf("Response contains sensitive content: %s", content)
			vuln.Evidence = content
			vuln.Response = body
			d.Vulns = append(d.Vulns, vuln)
		}
	}

	// Check for content that should be present
	for _, content := range testCase.Expected.ShouldContain {
		if !strings.Contains(body, content) {
			vuln.Severity = "MEDIUM"
			vuln.Description = fmt.Sprintf("Response missing expected content: %s", content)
			vuln.Response = body
			d.Vulns = append(d.Vulns, vuln)
		}
	}

	// Check security headers
	d.checkSecurityHeaders(resp)
}

// checkSecurityHeaders checks for missing security headers
func (d *DASTScanner) checkSecurityHeaders(resp *http.Response) {
	requiredHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "",
		"Content-Security-Policy":   "",
	}

	for header, expectedValue := range requiredHeaders {
		actualValue := resp.Header.Get(header)
		if actualValue == "" {
			vuln := Vulnerability{
				URL:         resp.Request.URL.String(),
				Method:      resp.Request.Method,
				Type:        "Missing Security Header",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Missing security header: %s", header),
			}
			d.Vulns = append(d.Vulns, vuln)
		} else if expectedValue != "" && actualValue != expectedValue {
			vuln := Vulnerability{
				URL:         resp.Request.URL.String(),
				Method:      resp.Request.Method,
				Type:        "Incorrect Security Header",
				Severity:    "LOW",
				Description: fmt.Sprintf("Incorrect value for header %s: expected %s, got %s", header, expectedValue, actualValue),
			}
			d.Vulns = append(d.Vulns, vuln)
		}
	}
}

// TestRateLimiting tests rate limiting implementation
func (d *DASTScanner) TestRateLimiting() error {
	url := d.BaseURL + "/api/health"
	var rateLimitHit bool

	// Send multiple requests rapidly
	for i := 0; i < 100; i++ {
		resp, err := d.Client.Get(url)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == 429 {
			rateLimitHit = true
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if !rateLimitHit {
		vuln := Vulnerability{
			URL:         url,
			Method:      "GET",
			Type:        "Rate Limiting Bypass",
			Severity:    "MEDIUM",
			Description: "Rate limiting not properly implemented",
		}
		d.Vulns = append(d.Vulns, vuln)
	}

	return nil
}

// TestSSLConfiguration tests SSL/TLS configuration
func (d *DASTScanner) TestSSLConfiguration() error {
	if !strings.HasPrefix(d.BaseURL, "https://") {
		vuln := Vulnerability{
			URL:         d.BaseURL,
			Type:        "Insecure Protocol",
			Severity:    "HIGH",
			Description: "Application not using HTTPS",
		}
		d.Vulns = append(d.Vulns, vuln)
		return nil
	}

	// Test with secure client
	secureClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	resp, err := secureClient.Get(d.BaseURL + "/api/health")
	if err != nil {
		vuln := Vulnerability{
			URL:         d.BaseURL,
			Type:        "SSL Configuration Issue",
			Severity:    "HIGH",
			Description: fmt.Sprintf("SSL/TLS configuration error: %v", err),
		}
		d.Vulns = append(d.Vulns, vuln)
	}
	if resp != nil {
		resp.Body.Close()
	}

	return nil
}

// GenerateReport generates a DAST security report
func (d *DASTScanner) GenerateReport() string {
	var report strings.Builder

	report.WriteString("DAST Security Scan Report\n")
	report.WriteString("=========================\n\n")

	// Summary
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vuln := range d.Vulns {
		switch vuln.Severity {
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n", len(d.Vulns)))
	report.WriteString(fmt.Sprintf("High Severity: %d\n", highCount))
	report.WriteString(fmt.Sprintf("Medium Severity: %d\n", mediumCount))
	report.WriteString(fmt.Sprintf("Low Severity: %d\n\n", lowCount))

	// Detailed vulnerabilities
	report.WriteString("Detailed Vulnerabilities:\n")
	report.WriteString("========================\n\n")

	for _, vuln := range d.Vulns {
		report.WriteString(fmt.Sprintf("[%s] %s\n", vuln.Severity, vuln.Type))
		report.WriteString(fmt.Sprintf("URL: %s %s\n", vuln.Method, vuln.URL))
		report.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))
		if vuln.Evidence != "" {
			report.WriteString(fmt.Sprintf("Evidence: %s\n", vuln.Evidence))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// Test functions
func TestDASTScanner(t *testing.T) {
	// This test requires a running instance of the application
	baseURL := "http://localhost:8080" // Adjust as needed

	// Check if server is running
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/api/health")
	if err != nil {
		t.Skipf("Server not running at %s, skipping DAST tests: %v", baseURL, err)
	}
	resp.Body.Close()

	scanner := NewDASTScanner(baseURL)

	// Run security tests
	err = scanner.RunSecurityTests()
	if err != nil {
		t.Fatalf("Failed to run security tests: %v", err)
	}

	// Test rate limiting
	err = scanner.TestRateLimiting()
	if err != nil {
		t.Fatalf("Failed to test rate limiting: %v", err)
	}

	// Test SSL configuration
	err = scanner.TestSSLConfiguration()
	if err != nil {
		t.Fatalf("Failed to test SSL configuration: %v", err)
	}

	// Generate and print report
	report := scanner.GenerateReport()
	t.Logf("DAST Security Report:\n%s", report)

	// Fail test if high severity vulnerabilities found
	highSeverityCount := 0
	for _, vuln := range scanner.Vulns {
		if vuln.Severity == "HIGH" {
			highSeverityCount++
		}
	}

	if highSeverityCount > 0 {
		t.Errorf("Found %d high severity vulnerabilities", highSeverityCount)
	}
}

func TestWebSocketSecurity(t *testing.T) {
	// Test WebSocket security
	baseURL := "ws://localhost:8080" // Adjust as needed

	// Test WebSocket connection limits
	// Test WebSocket message validation
	// Test WebSocket authentication

	t.Logf("WebSocket security tests would be implemented here for %s", baseURL)
}
