package security_tests

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// PenetrationTester performs penetration testing
type PenetrationTester struct {
	BaseURL    string
	Client     *http.Client
	Findings   []PenTestFinding
	TestSuites []PenTestSuite
}

// PenTestFinding represents a penetration testing finding
type PenTestFinding struct {
	TestName    string
	Severity    string
	Category    string
	Description string
	Evidence    string
	Impact      string
	Remediation string
	CVSS        float64
	URL         string
	Method      string
	Payload     string
	Response    string
}

// PenTestSuite represents a suite of penetration tests
type PenTestSuite struct {
	Name        string
	Description string
	Tests       []PenTest
}

// PenTest represents a single penetration test
type PenTest struct {
	Name        string
	Description string
	Category    string
	Severity    string
	Execute     func(*PenetrationTester) error
}

// NewPenetrationTester creates a new penetration tester
func NewPenetrationTester(baseURL string) *PenetrationTester {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}

	return &PenetrationTester{
		BaseURL:    baseURL,
		Client:     client,
		Findings:   make([]PenTestFinding, 0),
		TestSuites: getPenetrationTestSuites(),
	}
}

// getPenetrationTestSuites returns predefined penetration test suites
func getPenetrationTestSuites() []PenTestSuite {
	return []PenTestSuite{
		{
			Name:        "Authentication & Authorization",
			Description: "Tests for authentication and authorization vulnerabilities",
			Tests: []PenTest{
				{
					Name:        "Authentication Bypass",
					Description: "Test for authentication bypass vulnerabilities",
					Category:    "Authentication",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testAuthenticationBypass,
				},
				{
					Name:        "Session Management",
					Description: "Test session management vulnerabilities",
					Category:    "Session",
					Severity:    "MEDIUM",
					Execute:     (*PenetrationTester).testSessionManagement,
				},
				{
					Name:        "Privilege Escalation",
					Description: "Test for privilege escalation vulnerabilities",
					Category:    "Authorization",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testPrivilegeEscalation,
				},
			},
		},
		{
			Name:        "Input Validation",
			Description: "Tests for input validation vulnerabilities",
			Tests: []PenTest{
				{
					Name:        "SQL Injection",
					Description: "Test for SQL injection vulnerabilities",
					Category:    "Injection",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testSQLInjection,
				},
				{
					Name:        "NoSQL Injection",
					Description: "Test for NoSQL injection vulnerabilities",
					Category:    "Injection",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testNoSQLInjection,
				},
				{
					Name:        "Command Injection",
					Description: "Test for command injection vulnerabilities",
					Category:    "Injection",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testCommandInjection,
				},
				{
					Name:        "XSS Testing",
					Description: "Test for Cross-Site Scripting vulnerabilities",
					Category:    "XSS",
					Severity:    "MEDIUM",
					Execute:     (*PenetrationTester).testXSS,
				},
			},
		},
		{
			Name:        "Business Logic",
			Description: "Tests for business logic vulnerabilities",
			Tests: []PenTest{
				{
					Name:        "Rate Limiting Bypass",
					Description: "Test rate limiting bypass techniques",
					Category:    "Business Logic",
					Severity:    "MEDIUM",
					Execute:     (*PenetrationTester).testRateLimitingBypass,
				},
				{
					Name:        "Race Conditions",
					Description: "Test for race condition vulnerabilities",
					Category:    "Business Logic",
					Severity:    "MEDIUM",
					Execute:     (*PenetrationTester).testRaceConditions,
				},
			},
		},
		{
			Name:        "Infrastructure",
			Description: "Tests for infrastructure vulnerabilities",
			Tests: []PenTest{
				{
					Name:        "SSL/TLS Configuration",
					Description: "Test SSL/TLS configuration",
					Category:    "Cryptography",
					Severity:    "HIGH",
					Execute:     (*PenetrationTester).testSSLTLSConfiguration,
				},
				{
					Name:        "HTTP Security Headers",
					Description: "Test HTTP security headers",
					Category:    "Configuration",
					Severity:    "MEDIUM",
					Execute:     (*PenetrationTester).testSecurityHeaders,
				},
				{
					Name:        "Information Disclosure",
					Description: "Test for information disclosure",
					Category:    "Information Disclosure",
					Severity:    "LOW",
					Execute:     (*PenetrationTester).testInformationDisclosure,
				},
			},
		},
	}
}

// RunAllTests runs all penetration tests
func (pt *PenetrationTester) RunAllTests() error {
	for _, suite := range pt.TestSuites {
		for _, test := range suite.Tests {
			if err := test.Execute(pt); err != nil {
				return fmt.Errorf("test %s failed: %w", test.Name, err)
			}
		}
	}
	return nil
}

// testAuthenticationBypass tests for authentication bypass vulnerabilities
func (pt *PenetrationTester) testAuthenticationBypass() error {
	payloads := []string{
		"admin' OR '1'='1",
		"admin' OR '1'='1' --",
		"admin' OR '1'='1' /*",
		"' OR 1=1 --",
		"admin'/**/OR/**/1=1/**/--",
		"admin' UNION SELECT 1,1,1 --",
	}

	for _, payload := range payloads {
		loginData := map[string]string{
			"username": payload,
			"password": "anything",
		}

		jsonData, _ := json.Marshal(loginData)
		resp, err := pt.Client.Post(pt.BaseURL+"/api/login", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		// Check if authentication was bypassed
		if resp.StatusCode == 200 || strings.Contains(string(body), "token") {
			pt.addFinding(PenTestFinding{
				TestName:    "Authentication Bypass",
				Severity:    "HIGH",
				Category:    "Authentication",
				Description: "Authentication bypass vulnerability detected",
				Evidence:    fmt.Sprintf("Payload: %s, Status: %d", payload, resp.StatusCode),
				Impact:      "Unauthorized access to the application",
				Remediation: "Implement proper input validation and parameterized queries",
				CVSS:        9.1,
				URL:         pt.BaseURL + "/api/login",
				Method:      "POST",
				Payload:     payload,
				Response:    string(body),
			})
		}
	}

	return nil
}

// testSessionManagement tests session management vulnerabilities
func (pt *PenetrationTester) testSessionManagement() error {
	// Test session fixation
	resp, err := pt.Client.Get(pt.BaseURL + "/api/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for secure session cookies
	for _, cookie := range resp.Cookies() {
		if !cookie.Secure && strings.HasPrefix(pt.BaseURL, "https://") {
			pt.addFinding(PenTestFinding{
				TestName:    "Insecure Session Cookie",
				Severity:    "MEDIUM",
				Category:    "Session Management",
				Description: "Session cookie not marked as secure",
				Evidence:    fmt.Sprintf("Cookie: %s", cookie.Name),
				Impact:      "Session hijacking over insecure connections",
				Remediation: "Set Secure flag on session cookies",
				CVSS:        5.4,
			})
		}

		if !cookie.HttpOnly {
			pt.addFinding(PenTestFinding{
				TestName:    "Session Cookie Accessible via JavaScript",
				Severity:    "MEDIUM",
				Category:    "Session Management",
				Description: "Session cookie not marked as HttpOnly",
				Evidence:    fmt.Sprintf("Cookie: %s", cookie.Name),
				Impact:      "XSS attacks can steal session cookies",
				Remediation: "Set HttpOnly flag on session cookies",
				CVSS:        5.4,
			})
		}
	}

	return nil
}

// testPrivilegeEscalation tests for privilege escalation vulnerabilities
func (pt *PenetrationTester) testPrivilegeEscalation() error {
	// Test IDOR (Insecure Direct Object References)
	userIDs := []string{"1", "2", "admin", "../admin", "../../admin"}

	for _, userID := range userIDs {
		resp, err := pt.Client.Get(pt.BaseURL + "/api/users/" + userID)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		// Check if unauthorized data is accessible
		if resp.StatusCode == 200 && (strings.Contains(string(body), "admin") || strings.Contains(string(body), "password")) {
			pt.addFinding(PenTestFinding{
				TestName:    "Insecure Direct Object Reference",
				Severity:    "HIGH",
				Category:    "Authorization",
				Description: "IDOR vulnerability allows access to unauthorized data",
				Evidence:    fmt.Sprintf("User ID: %s, Status: %d", userID, resp.StatusCode),
				Impact:      "Unauthorized access to sensitive user data",
				Remediation: "Implement proper authorization checks",
				CVSS:        8.1,
				URL:         pt.BaseURL + "/api/users/" + userID,
				Method:      "GET",
				Response:    string(body),
			})
		}
	}

	return nil
}

// testSQLInjection tests for SQL injection vulnerabilities
func (pt *PenetrationTester) testSQLInjection() error {
	payloads := []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"'; DROP TABLE users; --",
		"' UNION SELECT 1,2,3 --",
		"' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
	}

	endpoints := []string{
		"/api/pods?name=%s",
		"/api/search?q=%s",
		"/api/users?filter=%s",
	}

	for _, endpoint := range endpoints {
		for _, payload := range payloads {
			url := pt.BaseURL + fmt.Sprintf(endpoint, url.QueryEscape(payload))
			resp, err := pt.Client.Get(url)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Check for SQL error messages
			sqlErrors := []string{
				"mysql", "postgresql", "sqlite", "oracle",
				"syntax error", "ORA-", "MySQL", "PostgreSQL",
				"database error", "SQL syntax",
			}

			for _, sqlError := range sqlErrors {
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(sqlError)) {
					pt.addFinding(PenTestFinding{
						TestName:    "SQL Injection",
						Severity:    "HIGH",
						Category:    "Injection",
						Description: "SQL injection vulnerability detected",
						Evidence:    fmt.Sprintf("SQL Error: %s", sqlError),
						Impact:      "Database compromise, data theft",
						Remediation: "Use parameterized queries and input validation",
						CVSS:        9.8,
						URL:         url,
						Method:      "GET",
						Payload:     payload,
						Response:    bodyStr,
					})
				}
			}
		}
	}

	return nil
}

// testNoSQLInjection tests for NoSQL injection vulnerabilities
func (pt *PenetrationTester) testNoSQLInjection() error {
	payloads := []string{
		"{\"$ne\": null}",
		"{\"$gt\": \"\"}",
		"{\"$regex\": \".*\"}",
		"{\"$where\": \"this.username == this.password\"}",
	}

	for _, payload := range payloads {
		data := map[string]interface{}{
			"username": payload,
			"password": "anything",
		}

		jsonData, _ := json.Marshal(data)
		resp, err := pt.Client.Post(pt.BaseURL+"/api/login", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		// Check for successful authentication or NoSQL errors
		if resp.StatusCode == 200 || strings.Contains(string(body), "token") {
			pt.addFinding(PenTestFinding{
				TestName:    "NoSQL Injection",
				Severity:    "HIGH",
				Category:    "Injection",
				Description: "NoSQL injection vulnerability detected",
				Evidence:    fmt.Sprintf("Payload: %s, Status: %d", payload, resp.StatusCode),
				Impact:      "Database bypass, unauthorized access",
				Remediation: "Validate and sanitize NoSQL queries",
				CVSS:        9.1,
				URL:         pt.BaseURL + "/api/login",
				Method:      "POST",
				Payload:     payload,
				Response:    string(body),
			})
		}
	}

	return nil
}

// testCommandInjection tests for command injection vulnerabilities
func (pt *PenetrationTester) testCommandInjection() error {
	payloads := []string{
		"; ls -la",
		"&& cat /etc/passwd",
		"| whoami",
		"`id`",
		"$(id)",
		"; ping -c 1 127.0.0.1",
	}

	for _, payload := range payloads {
		data := map[string]string{
			"command": "ls" + payload,
		}

		jsonData, _ := json.Marshal(data)
		resp, err := pt.Client.Post(pt.BaseURL+"/api/exec", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for command execution evidence
		cmdEvidence := []string{
			"root:", "uid=", "gid=", "PING", "64 bytes from",
		}

		for _, evidence := range cmdEvidence {
			if strings.Contains(bodyStr, evidence) {
				pt.addFinding(PenTestFinding{
					TestName:    "Command Injection",
					Severity:    "HIGH",
					Category:    "Injection",
					Description: "Command injection vulnerability detected",
					Evidence:    fmt.Sprintf("Evidence: %s", evidence),
					Impact:      "Remote code execution, system compromise",
					Remediation: "Avoid system calls with user input, use whitelisting",
					CVSS:        9.8,
					URL:         pt.BaseURL + "/api/exec",
					Method:      "POST",
					Payload:     payload,
					Response:    bodyStr,
				})
			}
		}
	}

	return nil
}

// testXSS tests for Cross-Site Scripting vulnerabilities
func (pt *PenetrationTester) testXSS() error {
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"<iframe src=javascript:alert('XSS')></iframe>",
	}

	endpoints := []string{
		"/api/search?q=%s",
		"/api/echo?message=%s",
	}

	for _, endpoint := range endpoints {
		for _, payload := range payloads {
			url := pt.BaseURL + fmt.Sprintf(endpoint, url.QueryEscape(payload))
			resp, err := pt.Client.Get(url)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Check if payload is reflected without encoding
			if strings.Contains(bodyStr, "<script>") || strings.Contains(bodyStr, "onerror=") {
				pt.addFinding(PenTestFinding{
					TestName:    "Cross-Site Scripting (XSS)",
					Severity:    "MEDIUM",
					Category:    "XSS",
					Description: "XSS vulnerability detected",
					Evidence:    "Unescaped script tags in response",
					Impact:      "Session hijacking, defacement, malware distribution",
					Remediation: "Implement proper output encoding and CSP",
					CVSS:        6.1,
					URL:         url,
					Method:      "GET",
					Payload:     payload,
					Response:    bodyStr,
				})
			}
		}
	}

	return nil
}

// testRateLimitingBypass tests rate limiting bypass techniques
func (pt *PenetrationTester) testRateLimitingBypass() error {
	bypassHeaders := map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Real-IP":        "127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
		"X-Remote-IP":      "127.0.0.1",
		"X-Remote-Addr":    "127.0.0.1",
	}

	for header, value := range bypassHeaders {
		var successCount int
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("GET", pt.BaseURL+"/api/health", nil)
			req.Header.Set(header, value+strconv.Itoa(i))

			resp, err := pt.Client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != 429 {
				successCount++
			}
		}

		if successCount > 40 { // If most requests succeeded
			pt.addFinding(PenTestFinding{
				TestName:    "Rate Limiting Bypass",
				Severity:    "MEDIUM",
				Category:    "Business Logic",
				Description: "Rate limiting can be bypassed using headers",
				Evidence:    fmt.Sprintf("Header: %s, Success rate: %d/50", header, successCount),
				Impact:      "DoS attacks, resource exhaustion",
				Remediation: "Implement proper rate limiting based on multiple factors",
				CVSS:        5.3,
			})
		}
	}

	return nil
}

// testRaceConditions tests for race condition vulnerabilities
func (pt *PenetrationTester) testRaceConditions() error {
	var wg sync.WaitGroup
	var responses []int
	var mu sync.Mutex

	// Concurrent requests to test race conditions
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := pt.Client.Post(pt.BaseURL+"/api/transfer", "application/json",
				bytes.NewBuffer([]byte(`{"from":"account1","to":"account2","amount":100}`)))
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			responses = append(responses, resp.StatusCode)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Check if multiple requests succeeded (potential race condition)
	successCount := 0
	for _, status := range responses {
		if status == 200 {
			successCount++
		}
	}

	if successCount > 1 {
		pt.addFinding(PenTestFinding{
			TestName:    "Race Condition",
			Severity:    "MEDIUM",
			Category:    "Business Logic",
			Description: "Race condition vulnerability detected",
			Evidence:    fmt.Sprintf("Multiple concurrent requests succeeded: %d", successCount),
			Impact:      "Data inconsistency, financial loss",
			Remediation: "Implement proper locking mechanisms",
			CVSS:        6.5,
		})
	}

	return nil
}

// testSSLTLSConfiguration tests SSL/TLS configuration
func (pt *PenetrationTester) testSSLTLSConfiguration() error {
	if !strings.HasPrefix(pt.BaseURL, "https://") {
		pt.addFinding(PenTestFinding{
			TestName:    "No HTTPS",
			Severity:    "HIGH",
			Category:    "Cryptography",
			Description: "Application not using HTTPS",
			Impact:      "Data interception, man-in-the-middle attacks",
			Remediation: "Implement HTTPS with proper SSL/TLS configuration",
			CVSS:        7.4,
		})
		return nil
	}

	// Test weak SSL/TLS configurations
	url, _ := url.Parse(pt.BaseURL)
	conn, err := tls.Dial("tcp", url.Host, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS10, // Test for weak TLS versions
	})

	if err == nil {
		conn.Close()
		pt.addFinding(PenTestFinding{
			TestName:    "Weak TLS Version",
			Severity:    "MEDIUM",
			Category:    "Cryptography",
			Description: "Server accepts weak TLS versions",
			Impact:      "Cryptographic attacks, data interception",
			Remediation: "Disable TLS 1.0 and 1.1, use TLS 1.2+",
			CVSS:        5.9,
		})
	}

	return nil
}

// testSecurityHeaders tests HTTP security headers
func (pt *PenetrationTester) testSecurityHeaders() error {
	resp, err := pt.Client.Get(pt.BaseURL + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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
			pt.addFinding(PenTestFinding{
				TestName:    "Missing Security Header",
				Severity:    "MEDIUM",
				Category:    "Configuration",
				Description: fmt.Sprintf("Missing security header: %s", header),
				Impact:      "Various security vulnerabilities",
				Remediation: fmt.Sprintf("Add %s header", header),
				CVSS:        4.3,
			})
		} else if expectedValue != "" && actualValue != expectedValue {
			pt.addFinding(PenTestFinding{
				TestName:    "Incorrect Security Header",
				Severity:    "LOW",
				Category:    "Configuration",
				Description: fmt.Sprintf("Incorrect value for %s header", header),
				Evidence:    fmt.Sprintf("Expected: %s, Got: %s", expectedValue, actualValue),
				Impact:      "Reduced security posture",
				Remediation: fmt.Sprintf("Set correct value for %s header", header),
				CVSS:        3.1,
			})
		}
	}

	return nil
}

// testInformationDisclosure tests for information disclosure
func (pt *PenetrationTester) testInformationDisclosure() error {
	sensitiveEndpoints := []string{
		"/.env",
		"/config.yaml",
		"/admin",
		"/debug",
		"/api/debug",
		"/metrics",
		"/health",
		"/status",
	}

	for _, endpoint := range sensitiveEndpoints {
		resp, err := pt.Client.Get(pt.BaseURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for sensitive information
		sensitiveInfo := []string{
			"password", "secret", "key", "token",
			"database", "config", "admin",
		}

		for _, info := range sensitiveInfo {
			if strings.Contains(strings.ToLower(bodyStr), info) {
				pt.addFinding(PenTestFinding{
					TestName:    "Information Disclosure",
					Severity:    "LOW",
					Category:    "Information Disclosure",
					Description: "Sensitive information disclosed",
					Evidence:    fmt.Sprintf("Endpoint: %s, Info: %s", endpoint, info),
					Impact:      "Information gathering for further attacks",
					Remediation: "Remove or protect sensitive endpoints",
					CVSS:        3.7,
					URL:         pt.BaseURL + endpoint,
					Method:      "GET",
				})
			}
		}
	}

	return nil
}

// addFinding adds a finding to the penetration test results
func (pt *PenetrationTester) addFinding(finding PenTestFinding) {
	pt.Findings = append(pt.Findings, finding)
}

// GenerateReport generates a penetration testing report
func (pt *PenetrationTester) GenerateReport() string {
	var report strings.Builder

	report.WriteString("Penetration Testing Report\n")
	report.WriteString("=========================\n\n")

	// Executive Summary
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range pt.Findings {
		switch finding.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	report.WriteString("Executive Summary:\n")
	report.WriteString(fmt.Sprintf("Total Findings: %d\n", len(pt.Findings)))
	report.WriteString(fmt.Sprintf("Critical: %d\n", criticalCount))
	report.WriteString(fmt.Sprintf("High: %d\n", highCount))
	report.WriteString(fmt.Sprintf("Medium: %d\n", mediumCount))
	report.WriteString(fmt.Sprintf("Low: %d\n\n", lowCount))

	// Detailed Findings
	report.WriteString("Detailed Findings:\n")
	report.WriteString("==================\n\n")

	for i, finding := range pt.Findings {
		report.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, finding.Severity, finding.TestName))
		report.WriteString(fmt.Sprintf("   Category: %s\n", finding.Category))
		report.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))
		if finding.Evidence != "" {
			report.WriteString(fmt.Sprintf("   Evidence: %s\n", finding.Evidence))
		}
		report.WriteString(fmt.Sprintf("   Impact: %s\n", finding.Impact))
		report.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
		if finding.CVSS > 0 {
			report.WriteString(fmt.Sprintf("   CVSS Score: %.1f\n", finding.CVSS))
		}
		if finding.URL != "" {
			report.WriteString(fmt.Sprintf("   URL: %s %s\n", finding.Method, finding.URL))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// Test functions
func TestPenetrationTesting(t *testing.T) {
	// This test requires a running instance of the application
	baseURL := "http://localhost:8080" // Adjust as needed

	// Check if server is running
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/api/health")
	if err != nil {
		t.Skipf("Server not running at %s, skipping penetration tests: %v", baseURL, err)
	}
	resp.Body.Close()

	pentester := NewPenetrationTester(baseURL)

	// Run all penetration tests
	err = pentester.RunAllTests()
	if err != nil {
		t.Fatalf("Failed to run penetration tests: %v", err)
	}

	// Generate and print report
	report := pentester.GenerateReport()
	t.Logf("Penetration Testing Report:\n%s", report)

	// Fail test if critical or high severity findings
	criticalCount := 0
	highCount := 0
	for _, finding := range pentester.Findings {
		if finding.Severity == "CRITICAL" {
			criticalCount++
		} else if finding.Severity == "HIGH" {
			highCount++
		}
	}

	if criticalCount > 0 {
		t.Errorf("Found %d critical severity findings", criticalCount)
	}
	if highCount > 0 {
		t.Errorf("Found %d high severity findings", highCount)
	}
}
