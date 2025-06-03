package errors

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

// ErrorLevel defines the severity of an error
type ErrorLevel int

const (
	LevelInfo ErrorLevel = iota
	LevelWarning
	LevelError
	LevelFatal
)

// AppError represents a standardized application error
type AppError struct {
	Level   ErrorLevel
	Code    string
	Message string
	Cause   error
	Context map[string]interface{}
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// New creates a new AppError
func New(level ErrorLevel, code, message string) *AppError {
	return &AppError{
		Level:   level,
		Code:    code,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, level ErrorLevel, code, message string) *AppError {
	return &AppError{
		Level:   level,
		Code:    code,
		Message: message,
		Cause:   err,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	e.Context[key] = value
	return e
}

// Handle processes the error according to its level
func Handle(err error) {
	if err == nil {
		return
	}

	appErr, ok := err.(*AppError)
	if !ok {
		// Convert regular error to AppError
		appErr = Wrap(err, LevelError, "UNKNOWN", "Unhandled error")
	}

	// Get caller information
	_, file, line, _ := runtime.Caller(1)
	appErr.WithContext("file", file).WithContext("line", line)

	switch appErr.Level {
	case LevelInfo:
		log.Printf("INFO: %s [code=%s, context=%v]", appErr.Message, appErr.Code, appErr.Context)
	case LevelWarning:
		log.Printf("WARN: %s [code=%s, context=%v, cause=%v]", appErr.Message, appErr.Code, appErr.Context, appErr.Cause)
	case LevelError:
		log.Printf("ERROR: %s [code=%s, context=%v, cause=%v]", appErr.Message, appErr.Code, appErr.Context, appErr.Cause)
	case LevelFatal:
		log.Printf("FATAL: %s [code=%s, context=%v, cause=%v]", appErr.Message, appErr.Code, appErr.Context, appErr.Cause)
		os.Exit(1)
	}
}

// HandleWithExit processes the error and exits if it's an error level or above
func HandleWithExit(err error) {
	if err == nil {
		return
	}

	appErr, ok := err.(*AppError)
	if !ok {
		appErr = Wrap(err, LevelError, "UNKNOWN", "Unhandled error")
	}

	Handle(err)

	if appErr.Level >= LevelError {
		os.Exit(1)
	}
}

// Info creates and handles an info-level error
func Info(code, message string) {
	Handle(New(LevelInfo, code, message))
}

// Infof creates and handles an info-level error with formatting
func Infof(code, format string, args ...interface{}) {
	Handle(New(LevelInfo, code, fmt.Sprintf(format, args...)))
}

// Warning creates and handles a warning-level error
func Warning(code, message string) {
	Handle(New(LevelWarning, code, message))
}

// Warningf creates and handles a warning-level error with formatting
func Warningf(code, format string, args ...interface{}) {
	Handle(New(LevelWarning, code, fmt.Sprintf(format, args...)))
}

// Error creates and handles an error-level error
func Error(code, message string) {
	Handle(New(LevelError, code, message))
}

// Errorf creates and handles an error-level error with formatting
func Errorf(code, format string, args ...interface{}) {
	Handle(New(LevelError, code, fmt.Sprintf(format, args...)))
}

// Fatal creates and handles a fatal-level error
func Fatal(code, message string) {
	Handle(New(LevelFatal, code, message))
}

// Fatalf creates and handles a fatal-level error with formatting
func Fatalf(code, format string, args ...interface{}) {
	Handle(New(LevelFatal, code, fmt.Sprintf(format, args...)))
}

// Must panics if err is not nil, useful for initialization
func Must(err error) {
	if err != nil {
		panic(err)
	}
}

// Check handles an error if it's not nil
func Check(err error) {
	if err != nil {
		Handle(err)
	}
}

// CheckWithCode handles an error with a specific code if it's not nil
func CheckWithCode(err error, code string) {
	if err != nil {
		Handle(Wrap(err, LevelError, code, err.Error()))
	}
}

// Validation error helpers
func ValidationError(field, message string) *AppError {
	return New(LevelError, "VALIDATION_ERROR", fmt.Sprintf("Validation failed for %s: %s", field, message))
}

// Network error helpers
func NetworkError(operation string, err error) *AppError {
	return Wrap(err, LevelError, "NETWORK_ERROR", fmt.Sprintf("Network operation failed: %s", operation))
}

// File operation error helpers
func FileError(operation, path string, err error) *AppError {
	return Wrap(err, LevelError, "FILE_ERROR", fmt.Sprintf("File operation failed: %s on %s", operation, path))
}

// Kubernetes error helpers
func K8sError(operation string, err error) *AppError {
	return Wrap(err, LevelError, "K8S_ERROR", fmt.Sprintf("Kubernetes operation failed: %s", operation))
}

// Configuration error helpers
func ConfigError(message string) *AppError {
	return New(LevelError, "CONFIG_ERROR", fmt.Sprintf("Configuration error: %s", message))
}

// Authentication error helpers
func AuthError(message string) *AppError {
	return New(LevelError, "AUTH_ERROR", fmt.Sprintf("Authentication error: %s", message))
}

// Authorization error helpers
func AuthzError(message string) *AppError {
	return New(LevelError, "AUTHZ_ERROR", fmt.Sprintf("Authorization error: %s", message))
}
