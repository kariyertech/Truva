package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

func validateUpCommand(namespace, targetType, targetName, localPath, containerPath string) error {
	var errors ValidationErrors

	// Validate namespace
	if namespace == "" {
		errors = append(errors, ValidationError{
			Field:   "namespace",
			Message: "namespace is required",
		})
	} else if len(namespace) > 63 {
		errors = append(errors, ValidationError{
			Field:   "namespace",
			Message: "namespace must be 63 characters or less",
		})
	}

	// Validate targetType
	validTargetTypes := []string{"deployment", "pod"}
	if targetType == "" {
		errors = append(errors, ValidationError{
			Field:   "targetType",
			Message: "targetType is required (deployment or pod)",
		})
	} else {
		valid := false
		for _, validType := range validTargetTypes {
			if targetType == validType {
				valid = true
				break
			}
		}
		if !valid {
			errors = append(errors, ValidationError{
				Field:   "targetType",
				Message: fmt.Sprintf("targetType must be one of: %s", strings.Join(validTargetTypes, ", ")),
			})
		}
	}

	// Validate targetName
	if targetName == "" {
		errors = append(errors, ValidationError{
			Field:   "targetName",
			Message: "targetName is required",
		})
	} else if len(targetName) > 253 {
		errors = append(errors, ValidationError{
			Field:   "targetName",
			Message: "targetName must be 253 characters or less",
		})
	}

	// Validate localPath
	if localPath == "" {
		errors = append(errors, ValidationError{
			Field:   "localPath",
			Message: "localPath is required",
		})
	} else {
		// Convert to absolute path if relative
		if !filepath.IsAbs(localPath) {
			cwd, err := os.Getwd()
			if err != nil {
				errors = append(errors, ValidationError{
					Field:   "localPath",
					Message: "failed to get current directory",
				})
			} else {
				localPath = filepath.Join(cwd, localPath)
			}
		}

		// Check if path exists
		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			errors = append(errors, ValidationError{
				Field:   "localPath",
				Message: fmt.Sprintf("path does not exist: %s", localPath),
			})
		}
	}

	// Validate containerPath
	if containerPath == "" {
		errors = append(errors, ValidationError{
			Field:   "containerPath",
			Message: "containerPath is required",
		})
	} else if !filepath.IsAbs(containerPath) {
		errors = append(errors, ValidationError{
			Field:   "containerPath",
			Message: "containerPath must be an absolute path",
		})
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}
