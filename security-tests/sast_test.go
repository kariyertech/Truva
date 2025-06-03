package security_tests

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SecurityIssue represents a security vulnerability found during SAST
type SecurityIssue struct {
	File        string
	Line        int
	Column      int
	Severity    string
	Type        string
	Description string
	Rule        string
}

// SASTScanner performs static application security testing
type SASTScanner struct {
	Issues []SecurityIssue
	Rules  []SecurityRule
}

// SecurityRule defines a security rule for scanning
type SecurityRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Pattern     *regexp.Regexp
	FileTypes   []string
}

// NewSASTScanner creates a new SAST scanner with predefined rules
func NewSASTScanner() *SASTScanner {
	return &SASTScanner{
		Issues: make([]SecurityIssue, 0),
		Rules:  getSecurityRules(),
	}
}

// getSecurityRules returns predefined security rules
func getSecurityRules() []SecurityRule {
	return []SecurityRule{
		{
			ID:          "HARDCODED_SECRET",
			Name:        "Hardcoded Secret",
			Description: "Potential hardcoded secret or API key found",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`(?i)(password|secret|key|token|api_key)\s*[:=]\s*["'][^"']{8,}["']`),
			FileTypes:   []string{".go", ".yaml", ".yml", ".json"},
		},
		{
			ID:          "SQL_INJECTION",
			Name:        "SQL Injection Risk",
			Description: "Potential SQL injection vulnerability",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`(?i)(query|exec)\s*\(.*\+.*\)`),
			FileTypes:   []string{".go"},
		},
		{
			ID:          "WEAK_CRYPTO",
			Name:        "Weak Cryptography",
			Description: "Use of weak cryptographic algorithms",
			Severity:    "MEDIUM",
			Pattern:     regexp.MustCompile(`(?i)(md5|sha1|des|rc4)\.`),
			FileTypes:   []string{".go"},
		},
		{
			ID:          "UNSAFE_HTTP",
			Name:        "Unsafe HTTP",
			Description: "HTTP used instead of HTTPS",
			Severity:    "MEDIUM",
			Pattern:     regexp.MustCompile(`http://[^\s"']+`),
			FileTypes:   []string{".go", ".yaml", ".yml", ".json"},
		},
		{
			ID:          "COMMAND_INJECTION",
			Name:        "Command Injection Risk",
			Description: "Potential command injection vulnerability",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`exec\.Command\([^)]*\+[^)]*\)`),
			FileTypes:   []string{".go"},
		},
		{
			ID:          "PATH_TRAVERSAL",
			Name:        "Path Traversal Risk",
			Description: "Potential path traversal vulnerability",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`\.\./`),
			FileTypes:   []string{".go", ".yaml", ".yml", ".json"},
		},
		{
			ID:          "INSECURE_RANDOM",
			Name:        "Insecure Random",
			Description: "Use of insecure random number generation",
			Severity:    "MEDIUM",
			Pattern:     regexp.MustCompile(`math/rand`),
			FileTypes:   []string{".go"},
		},
	}
}

// ScanDirectory scans a directory for security vulnerabilities
func (s *SASTScanner) ScanDirectory(rootDir string) error {
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		for _, rule := range s.Rules {
			for _, fileType := range rule.FileTypes {
				if ext == fileType {
					if err := s.scanFile(path, rule); err != nil {
						return err
					}
					break
				}
			}
		}

		return nil
	})
}

// scanFile scans a single file for security issues
func (s *SASTScanner) scanFile(filePath string, rule SecurityRule) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if matches := rule.Pattern.FindAllStringIndex(line, -1); matches != nil {
			for _, match := range matches {
				issue := SecurityIssue{
					File:        filePath,
					Line:        lineNum,
					Column:      match[0] + 1,
					Severity:    rule.Severity,
					Type:        rule.Name,
					Description: rule.Description,
					Rule:        rule.ID,
				}
				s.Issues = append(s.Issues, issue)
			}
		}
	}

	return scanner.Err()
}

// ScanGoAST performs AST-based security scanning for Go files
func (s *SASTScanner) ScanGoAST(filePath string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			s.checkUnsafeFunctions(fset, x, filePath)
		case *ast.BasicLit:
			s.checkHardcodedSecrets(fset, x, filePath)
		}
		return true
	})

	return nil
}

// checkUnsafeFunctions checks for unsafe function calls
func (s *SASTScanner) checkUnsafeFunctions(fset *token.FileSet, call *ast.CallExpr, filePath string) {
	unsafeFunctions := []string{
		"eval", "exec", "system", "popen",
		"unsafe.Pointer", "reflect.UnsafeAddr",
	}

	if ident, ok := call.Fun.(*ast.Ident); ok {
		for _, unsafeFunc := range unsafeFunctions {
			if ident.Name == unsafeFunc {
				pos := fset.Position(call.Pos())
				issue := SecurityIssue{
					File:        filePath,
					Line:        pos.Line,
					Column:      pos.Column,
					Severity:    "HIGH",
					Type:        "Unsafe Function Call",
					Description: fmt.Sprintf("Use of unsafe function: %s", ident.Name),
					Rule:        "UNSAFE_FUNCTION",
				}
				s.Issues = append(s.Issues, issue)
			}
		}
	}
}

// checkHardcodedSecrets checks for hardcoded secrets in string literals
func (s *SASTScanner) checkHardcodedSecrets(fset *token.FileSet, lit *ast.BasicLit, filePath string) {
	if lit.Kind == token.STRING {
		value := strings.Trim(lit.Value, `"`)
		if len(value) > 20 && isLikelySecret(value) {
			pos := fset.Position(lit.Pos())
			issue := SecurityIssue{
				File:        filePath,
				Line:        pos.Line,
				Column:      pos.Column,
				Severity:    "HIGH",
				Type:        "Hardcoded Secret",
				Description: "Potential hardcoded secret detected",
				Rule:        "HARDCODED_SECRET_AST",
			}
			s.Issues = append(s.Issues, issue)
		}
	}
}

// isLikelySecret checks if a string looks like a secret
func isLikelySecret(s string) bool {
	// Check for base64-like patterns
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
	if base64Pattern.MatchString(s) {
		return true
	}

	// Check for hex patterns
	hexPattern := regexp.MustCompile(`^[a-fA-F0-9]{32,}$`)
	if hexPattern.MatchString(s) {
		return true
	}

	// Check for JWT-like patterns
	jwtPattern := regexp.MustCompile(`^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`)
	if jwtPattern.MatchString(s) {
		return true
	}

	return false
}

// GenerateReport generates a security report
func (s *SASTScanner) GenerateReport() string {
	var report strings.Builder

	report.WriteString("SAST Security Scan Report\n")
	report.WriteString("========================\n\n")

	// Summary
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, issue := range s.Issues {
		switch issue.Severity {
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	report.WriteString(fmt.Sprintf("Total Issues: %d\n", len(s.Issues)))
	report.WriteString(fmt.Sprintf("High Severity: %d\n", highCount))
	report.WriteString(fmt.Sprintf("Medium Severity: %d\n", mediumCount))
	report.WriteString(fmt.Sprintf("Low Severity: %d\n\n", lowCount))

	// Detailed issues
	report.WriteString("Detailed Issues:\n")
	report.WriteString("================\n\n")

	for _, issue := range s.Issues {
		report.WriteString(fmt.Sprintf("[%s] %s\n", issue.Severity, issue.Type))
		report.WriteString(fmt.Sprintf("File: %s:%d:%d\n", issue.File, issue.Line, issue.Column))
		report.WriteString(fmt.Sprintf("Description: %s\n", issue.Description))
		report.WriteString(fmt.Sprintf("Rule: %s\n\n", issue.Rule))
	}

	return report.String()
}

// Test functions
func TestSASTScanner(t *testing.T) {
	scanner := NewSASTScanner()

	// Test scanning the project directory
	projectRoot := "../"
	err := scanner.ScanDirectory(projectRoot)
	if err != nil {
		t.Fatalf("Failed to scan directory: %v", err)
	}

	// Generate and print report
	report := scanner.GenerateReport()
	t.Logf("Security Scan Report:\n%s", report)

	// Fail test if high severity issues found
	highSeverityCount := 0
	for _, issue := range scanner.Issues {
		if issue.Severity == "HIGH" {
			highSeverityCount++
		}
	}

	if highSeverityCount > 0 {
		t.Errorf("Found %d high severity security issues", highSeverityCount)
	}
}

func TestGoASTScanning(t *testing.T) {
	scanner := NewSASTScanner()

	// Scan Go files using AST
	projectRoot := "../"
	err := filepath.Walk(projectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".go" {
			if err := scanner.ScanGoAST(path); err != nil {
				t.Logf("Warning: Failed to scan %s: %v", path, err)
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	// Generate report
	report := scanner.GenerateReport()
	t.Logf("AST Security Scan Report:\n%s", report)
}
