package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Validator provides input validation methods
type Validator struct {
	// Add configuration if needed
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateKubernetesName validates Kubernetes resource names
func (v *Validator) ValidateKubernetesName(name, fieldName string) error {
	if name == "" {
		return ValidationError{Field: fieldName, Message: "cannot be empty"}
	}

	if len(name) > 253 {
		return ValidationError{Field: fieldName, Message: "cannot exceed 253 characters"}
	}

	// Kubernetes name pattern: lowercase alphanumeric, hyphens, dots
	pattern := `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	matched, err := regexp.MatchString(pattern, name)
	if err != nil {
		return ValidationError{Field: fieldName, Message: "regex validation failed"}
	}

	if !matched {
		return ValidationError{Field: fieldName, Message: "must contain only lowercase alphanumeric characters, hyphens, and dots"}
	}

	return nil
}

// ValidateNamespace validates Kubernetes namespace
func (v *Validator) ValidateNamespace(namespace string) error {
	return v.ValidateKubernetesName(namespace, "namespace")
}

// ValidateDeployment validates Kubernetes deployment name
func (v *Validator) ValidateDeployment(deployment string) error {
	return v.ValidateKubernetesName(deployment, "deployment")
}

// ValidatePath validates file paths and prevents path traversal
func (v *Validator) ValidatePath(path, fieldName string) error {
	if path == "" {
		return ValidationError{Field: fieldName, Message: "cannot be empty"}
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return ValidationError{Field: fieldName, Message: "path traversal not allowed"}
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return ValidationError{Field: fieldName, Message: "null bytes not allowed"}
	}

	// Clean the path
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return ValidationError{Field: fieldName, Message: "path contains invalid sequences"}
	}

	// Check for absolute paths in container paths (security concern)
	if fieldName == "containerPath" && filepath.IsAbs(path) {
		return ValidationError{Field: fieldName, Message: "absolute paths not allowed for container paths"}
	}

	return nil
}

// ValidateLocalPath validates local file paths
func (v *Validator) ValidateLocalPath(path string) error {
	return v.ValidatePath(path, "localPath")
}

// ValidateContainerPath validates container file paths
func (v *Validator) ValidateContainerPath(path string) error {
	return v.ValidatePath(path, "containerPath")
}

// SanitizeString removes potentially dangerous characters from strings
func (v *Validator) SanitizeString(input string) string {
	// Remove control characters except tab, newline, and carriage return
	result := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return -1 // Remove the character
		}
		return r
	}, input)

	// Trim whitespace
	return strings.TrimSpace(result)
}

// ValidateQueryParams validates sync endpoint query parameters
func (v *Validator) ValidateQueryParams(namespace, deployment, localPath, containerPath string) []error {
	var errors []error

	if err := v.ValidateNamespace(namespace); err != nil {
		errors = append(errors, err)
	}

	if err := v.ValidateDeployment(deployment); err != nil {
		errors = append(errors, err)
	}

	if err := v.ValidateLocalPath(localPath); err != nil {
		errors = append(errors, err)
	}

	if err := v.ValidateContainerPath(containerPath); err != nil {
		errors = append(errors, err)
	}

	return errors
}

// ValidateJSONInput validates JSON input for potential injection
func (v *Validator) ValidateJSONInput(input string) error {
	if input == "" {
		return nil
	}

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"<script",
		"javascript:",
		"vbscript:",
		"onload=",
		"onerror=",
		"eval(",
		"Function(",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerInput, pattern) {
			return ValidationError{Field: "input", Message: "potentially malicious content detected"}
		}
	}

	return nil
}
