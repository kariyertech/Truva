package security_tests

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// DependencyVulnerability represents a vulnerability in a dependency
type DependencyVulnerability struct {
	Package     string    `json:"package"`
	Version     string    `json:"version"`
	VulnID      string    `json:"vuln_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CVSS        float64   `json:"cvss"`
	CVE         string    `json:"cve"`
	Published   time.Time `json:"published"`
	Fixed       string    `json:"fixed_version"`
	References  []string  `json:"references"`
}

// DependencyScanner scans for vulnerable dependencies
type DependencyScanner struct {
	ProjectRoot     string
	Vulnerabilities []DependencyVulnerability
	KnownVulnDB     map[string][]DependencyVulnerability
}

// NewDependencyScanner creates a new dependency scanner
func NewDependencyScanner(projectRoot string) *DependencyScanner {
	return &DependencyScanner{
		ProjectRoot:     projectRoot,
		Vulnerabilities: make([]DependencyVulnerability, 0),
		KnownVulnDB:     getKnownVulnerabilities(),
	}
}

// getKnownVulnerabilities returns a database of known vulnerabilities
func getKnownVulnerabilities() map[string][]DependencyVulnerability {
	return map[string][]DependencyVulnerability{
		// Example vulnerabilities for common Go packages
		"github.com/gin-gonic/gin": {
			{
				Package:     "github.com/gin-gonic/gin",
				VulnID:      "GHSA-h395-qcrw-5vmq",
				Severity:    "MEDIUM",
				Title:       "Gin Web Framework vulnerable to directory traversal",
				Description: "A directory traversal vulnerability exists in Gin Web Framework",
				CVSS:        5.3,
				CVE:         "CVE-2020-28483",
				Fixed:       "v1.6.0",
			},
		},
		"github.com/gorilla/websocket": {
			{
				Package:     "github.com/gorilla/websocket",
				VulnID:      "GHSA-jf24-p9p9-4rjh",
				Severity:    "HIGH",
				Title:       "WebSocket library vulnerable to compression bomb attacks",
				Description: "The WebSocket library is vulnerable to compression bomb attacks",
				CVSS:        7.5,
				CVE:         "CVE-2020-27813",
				Fixed:       "v1.4.1",
			},
		},
		"gopkg.in/yaml.v2": {
			{
				Package:     "gopkg.in/yaml.v2",
				VulnID:      "GHSA-wxc4-f4m6-wwqv",
				Severity:    "MEDIUM",
				Title:       "YAML library vulnerable to billion laughs attack",
				Description: "The YAML library is vulnerable to billion laughs attack",
				CVSS:        6.2,
				CVE:         "CVE-2019-11254",
				Fixed:       "v2.2.8",
			},
		},
		"github.com/dgrijalva/jwt-go": {
			{
				Package:     "github.com/dgrijalva/jwt-go",
				VulnID:      "GHSA-w73w-5m7g-f7qc",
				Severity:    "HIGH",
				Title:       "JWT library vulnerable to key confusion attack",
				Description: "The JWT library is vulnerable to key confusion attacks",
				CVSS:        7.7,
				CVE:         "CVE-2020-26160",
				Fixed:       "v4.0.0-preview1",
			},
		},
	}
}

// ScanGoMod scans go.mod file for vulnerable dependencies
func (ds *DependencyScanner) ScanGoMod() error {
	goModPath := filepath.Join(ds.ProjectRoot, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return fmt.Errorf("failed to open go.mod: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	requireSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			requireSection = true
			continue
		}

		if requireSection && line == ")" {
			requireSection = false
			continue
		}

		if requireSection || strings.HasPrefix(line, "require ") {
			ds.parseDependencyLine(line)
		}
	}

	return scanner.Err()
}

// parseDependencyLine parses a dependency line from go.mod
func (ds *DependencyScanner) parseDependencyLine(line string) {
	// Remove "require " prefix if present
	line = strings.TrimPrefix(line, "require ")
	line = strings.TrimSpace(line)

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "//") {
		return
	}

	// Parse package and version
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	pkg := parts[0]
	version := parts[1]

	// Check against known vulnerabilities
	if vulns, exists := ds.KnownVulnDB[pkg]; exists {
		for _, vuln := range vulns {
			if ds.isVersionVulnerable(version, vuln.Fixed) {
				vuln.Version = version
				ds.Vulnerabilities = append(ds.Vulnerabilities, vuln)
			}
		}
	}
}

// isVersionVulnerable checks if a version is vulnerable
func (ds *DependencyScanner) isVersionVulnerable(current, fixed string) bool {
	// Simple version comparison (in real implementation, use proper semver)
	if fixed == "" {
		return true // No fix available
	}

	// Remove 'v' prefix if present
	current = strings.TrimPrefix(current, "v")
	fixed = strings.TrimPrefix(fixed, "v")

	// Simple string comparison (should use proper semver comparison)
	return current < fixed
}

// ScanWithGovulncheck uses govulncheck tool if available
func (ds *DependencyScanner) ScanWithGovulncheck() error {
	// Check if govulncheck is installed
	_, err := exec.LookPath("govulncheck")
	if err != nil {
		return fmt.Errorf("govulncheck not found: %w", err)
	}

	// Run govulncheck
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = ds.ProjectRoot

	output, err := cmd.Output()
	if err != nil {
		// govulncheck returns non-zero exit code when vulnerabilities are found
		if exitError, ok := err.(*exec.ExitError); ok {
			output = exitError.Stderr
		}
	}

	// Parse JSON output
	return ds.parseGovulncheckOutput(output)
}

// parseGovulncheckOutput parses govulncheck JSON output
func (ds *DependencyScanner) parseGovulncheckOutput(output []byte) error {
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue // Skip invalid JSON lines
		}

		// Check if this is a vulnerability finding
		if msgType, ok := result["message"].(map[string]interface{}); ok {
			if vuln, ok := msgType["Vuln"].(map[string]interface{}); ok {
				ds.parseVulnerabilityFromGovulncheck(vuln)
			}
		}
	}

	return nil
}

// parseVulnerabilityFromGovulncheck parses vulnerability from govulncheck output
func (ds *DependencyScanner) parseVulnerabilityFromGovulncheck(vuln map[string]interface{}) {
	vulnerability := DependencyVulnerability{}

	if id, ok := vuln["ID"].(string); ok {
		vulnerability.VulnID = id
	}

	if summary, ok := vuln["Summary"].(string); ok {
		vulnerability.Title = summary
	}

	if details, ok := vuln["Details"].(string); ok {
		vulnerability.Description = details
	}

	if aliases, ok := vuln["Aliases"].([]interface{}); ok {
		for _, alias := range aliases {
			if aliasStr, ok := alias.(string); ok {
				if strings.HasPrefix(aliasStr, "CVE-") {
					vulnerability.CVE = aliasStr
				}
			}
		}
	}

	// Set severity based on CVSS or other factors
	vulnerability.Severity = "MEDIUM" // Default

	ds.Vulnerabilities = append(ds.Vulnerabilities, vulnerability)
}

// ScanDockerfile scans Dockerfile for vulnerable base images
func (ds *DependencyScanner) ScanDockerfile() error {
	dockerfilePath := filepath.Join(ds.ProjectRoot, "Dockerfile")
	file, err := os.Open(dockerfilePath)
	if err != nil {
		return fmt.Errorf("failed to open Dockerfile: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "FROM ") {
			ds.checkBaseImage(line)
		}
	}

	return scanner.Err()
}

// checkBaseImage checks if a base image has known vulnerabilities
func (ds *DependencyScanner) checkBaseImage(fromLine string) {
	// Extract image name and tag
	parts := strings.Fields(fromLine)
	if len(parts) < 2 {
		return
	}

	image := parts[1]

	// Check for known vulnerable images
	vulnerableImages := map[string]DependencyVulnerability{
		"alpine:3.7": {
			Package:     "alpine:3.7",
			VulnID:      "ALPINE-3.7-VULN",
			Severity:    "HIGH",
			Title:       "Alpine 3.7 contains known vulnerabilities",
			Description: "Alpine 3.7 base image contains multiple CVEs",
			Fixed:       "alpine:3.14",
		},
		"ubuntu:18.04": {
			Package:     "ubuntu:18.04",
			VulnID:      "UBUNTU-18.04-VULN",
			Severity:    "MEDIUM",
			Title:       "Ubuntu 18.04 approaching end of life",
			Description: "Ubuntu 18.04 will reach end of life soon",
			Fixed:       "ubuntu:22.04",
		},
	}

	if vuln, exists := vulnerableImages[image]; exists {
		ds.Vulnerabilities = append(ds.Vulnerabilities, vuln)
	}

	// Check for latest tag usage
	if strings.Contains(image, ":latest") || !strings.Contains(image, ":") {
		vuln := DependencyVulnerability{
			Package:     image,
			VulnID:      "LATEST-TAG-USAGE",
			Severity:    "LOW",
			Title:       "Use of latest tag in Docker image",
			Description: "Using latest tag can lead to unpredictable builds",
		}
		ds.Vulnerabilities = append(ds.Vulnerabilities, vuln)
	}
}

// CheckOutdatedDependencies checks for outdated dependencies
func (ds *DependencyScanner) CheckOutdatedDependencies() error {
	// Run go list to get current dependencies
	cmd := exec.Command("go", "list", "-m", "-u", "all")
	cmd.Dir = ds.ProjectRoot

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run go list: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "[") && strings.Contains(line, "]") {
			// This indicates an available update
			ds.parseOutdatedDependency(line)
		}
	}

	return nil
}

// parseOutdatedDependency parses outdated dependency information
func (ds *DependencyScanner) parseOutdatedDependency(line string) {
	// Parse line like: "github.com/example/pkg v1.0.0 [v1.1.0]"
	re := regexp.MustCompile(`^([^\s]+)\s+([^\s]+)\s+\[([^\]]+)\]`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 4 {
		vuln := DependencyVulnerability{
			Package:     matches[1],
			Version:     matches[2],
			VulnID:      "OUTDATED-DEPENDENCY",
			Severity:    "LOW",
			Title:       "Outdated dependency",
			Description: fmt.Sprintf("Dependency %s has update available: %s", matches[1], matches[3]),
			Fixed:       matches[3],
		}
		ds.Vulnerabilities = append(ds.Vulnerabilities, vuln)
	}
}

// GenerateReport generates a dependency security report
func (ds *DependencyScanner) GenerateReport() string {
	var report strings.Builder

	report.WriteString("Dependency Security Scan Report\n")
	report.WriteString("===============================\n\n")

	// Summary
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vuln := range ds.Vulnerabilities {
		switch vuln.Severity {
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

	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n", len(ds.Vulnerabilities)))
	report.WriteString(fmt.Sprintf("Critical: %d\n", criticalCount))
	report.WriteString(fmt.Sprintf("High: %d\n", highCount))
	report.WriteString(fmt.Sprintf("Medium: %d\n", mediumCount))
	report.WriteString(fmt.Sprintf("Low: %d\n\n", lowCount))

	// Detailed vulnerabilities
	report.WriteString("Detailed Vulnerabilities:\n")
	report.WriteString("========================\n\n")

	for _, vuln := range ds.Vulnerabilities {
		report.WriteString(fmt.Sprintf("[%s] %s\n", vuln.Severity, vuln.Title))
		report.WriteString(fmt.Sprintf("Package: %s %s\n", vuln.Package, vuln.Version))
		report.WriteString(fmt.Sprintf("Vulnerability ID: %s\n", vuln.VulnID))
		if vuln.CVE != "" {
			report.WriteString(fmt.Sprintf("CVE: %s\n", vuln.CVE))
		}
		if vuln.CVSS > 0 {
			report.WriteString(fmt.Sprintf("CVSS Score: %.1f\n", vuln.CVSS))
		}
		report.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))
		if vuln.Fixed != "" {
			report.WriteString(fmt.Sprintf("Fixed in: %s\n", vuln.Fixed))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// Test functions
func TestDependencyScanning(t *testing.T) {
	projectRoot := "../"
	scanner := NewDependencyScanner(projectRoot)

	// Scan go.mod
	err := scanner.ScanGoMod()
	if err != nil {
		t.Fatalf("Failed to scan go.mod: %v", err)
	}

	// Try to scan with govulncheck if available
	err = scanner.ScanWithGovulncheck()
	if err != nil {
		t.Logf("govulncheck scan failed (tool may not be installed): %v", err)
	}

	// Scan Dockerfile
	err = scanner.ScanDockerfile()
	if err != nil {
		t.Logf("Dockerfile scan failed: %v", err)
	}

	// Check for outdated dependencies
	err = scanner.CheckOutdatedDependencies()
	if err != nil {
		t.Logf("Outdated dependency check failed: %v", err)
	}

	// Generate and print report
	report := scanner.GenerateReport()
	t.Logf("Dependency Security Report:\n%s", report)

	// Fail test if critical or high severity vulnerabilities found
	criticalCount := 0
	highCount := 0
	for _, vuln := range scanner.Vulnerabilities {
		if vuln.Severity == "CRITICAL" {
			criticalCount++
		} else if vuln.Severity == "HIGH" {
			highCount++
		}
	}

	if criticalCount > 0 {
		t.Errorf("Found %d critical severity vulnerabilities", criticalCount)
	}
	if highCount > 0 {
		t.Errorf("Found %d high severity vulnerabilities", highCount)
	}
}

func TestGovulncheckInstallation(t *testing.T) {
	// Check if govulncheck is installed
	_, err := exec.LookPath("govulncheck")
	if err != nil {
		t.Log("govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
		t.Skip("Skipping govulncheck tests")
	}

	// Test govulncheck version
	cmd := exec.Command("govulncheck", "-version")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get govulncheck version: %v", err)
	}

	t.Logf("govulncheck version: %s", string(output))
}
