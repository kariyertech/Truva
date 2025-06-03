package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected logrus.Level
	}{
		{"debug", "debug", logrus.DebugLevel},
		{"info", "info", logrus.InfoLevel},
		{"warn", "warn", logrus.WarnLevel},
		{"warning", "warning", logrus.WarnLevel},
		{"error", "error", logrus.ErrorLevel},
		{"fatal", "fatal", logrus.FatalLevel},
		{"panic", "panic", logrus.PanicLevel},
		{"uppercase", "INFO", logrus.InfoLevel},
		{"mixed case", "WaRn", logrus.WarnLevel},
		{"invalid", "invalid", logrus.InfoLevel},
		{"empty", "", logrus.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLogLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected LogFormat
	}{
		{"json", "json", JSONFormat},
		{"text", "text", TextFormat},
		{"uppercase", "JSON", JSONFormat},
		{"mixed case", "TeXt", TextFormat},
		{"invalid", "invalid", TextFormat},
		{"empty", "", TextFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLogFormat(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInitLogger(t *testing.T) {
	// Create temporary directory for test log files
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	// Test successful initialization
	err := InitLogger(logFile, logrus.InfoLevel)
	require.NoError(t, err)

	// Verify log file was created
	_, err = os.Stat(logFile)
	assert.NoError(t, err)

	// Verify logger level was set
	assert.Equal(t, logrus.InfoLevel, Logger.Level)

	// Test with invalid directory
	invalidFile := "/invalid/path/test.log"
	err = InitLogger(invalidFile, logrus.InfoLevel)
	assert.Error(t, err)
}

func TestInitLoggerWithFormat(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	// Test JSON format
	err := InitLoggerWithFormat(logFile, logrus.DebugLevel, JSONFormat)
	require.NoError(t, err)

	// Verify formatter is JSON
	_, ok := Logger.Formatter.(*logrus.JSONFormatter)
	assert.True(t, ok, "Expected JSON formatter")

	// Test Text format
	err = InitLoggerWithFormat(logFile, logrus.WarnLevel, TextFormat)
	require.NoError(t, err)

	// Verify formatter is Text
	_, ok = Logger.Formatter.(*logrus.TextFormatter)
	assert.True(t, ok, "Expected Text formatter")

	// Verify level was set
	assert.Equal(t, logrus.WarnLevel, Logger.Level)
}

func TestLoggingFunctions(t *testing.T) {
	// Capture logger output
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})
	defer func() {
		Logger.SetOutput(originalOutput)
	}()

	// Test basic logging functions
	Info("test info")
	assert.Contains(t, buf.String(), "level=info")
	assert.Contains(t, buf.String(), "test info")
	buf.Reset()

	Warn("test warn")
	assert.Contains(t, buf.String(), "level=warning")
	assert.Contains(t, buf.String(), "test warn")
	buf.Reset()

	Error("test error")
	assert.Contains(t, buf.String(), "level=error")
	assert.Contains(t, buf.String(), "test error")
	buf.Reset()

	Debug("test debug")
	assert.Contains(t, buf.String(), "level=debug")
	assert.Contains(t, buf.String(), "test debug")
	buf.Reset()
}

func TestFormattedLoggingFunctions(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})
	defer func() {
		Logger.SetOutput(originalOutput)
	}()

	// Test formatted logging functions
	Infof("test %s %d", "info", 123)
	assert.Contains(t, buf.String(), "test info 123")
	buf.Reset()

	Warnf("test %s", "warning")
	assert.Contains(t, buf.String(), "test warning")
	buf.Reset()

	Errorf("error code: %d", 500)
	assert.Contains(t, buf.String(), "error code: 500")
	buf.Reset()

	Debugf("debug %v", true)
	assert.Contains(t, buf.String(), "debug true")
	buf.Reset()
}

func TestStructuredLoggingFunctions(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})
	defer func() {
		Logger.SetOutput(originalOutput)
	}()

	fields := logrus.Fields{
		"user_id": 123,
		"action":  "login",
	}

	// Test structured logging with fields
	InfoWithFields(fields, "user logged in")
	output := buf.String()
	assert.Contains(t, output, "user logged in")
	assert.Contains(t, output, "user_id=123")
	assert.Contains(t, output, "action=login")
	buf.Reset()

	WarnWithFields(fields, "suspicious activity")
	output = buf.String()
	assert.Contains(t, output, "suspicious activity")
	assert.Contains(t, output, "level=warning")
	buf.Reset()

	ErrorWithFields(fields, "login failed")
	output = buf.String()
	assert.Contains(t, output, "login failed")
	assert.Contains(t, output, "level=error")
	buf.Reset()

	DebugWithFields(fields, "debug info")
	output = buf.String()
	assert.Contains(t, output, "debug info")
	assert.Contains(t, output, "level=debug")
	buf.Reset()
}

func TestStructuredFormattedLoggingFunctions(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})
	defer func() {
		Logger.SetOutput(originalOutput)
	}()

	fields := logrus.Fields{
		"component": "auth",
		"version":   "1.0",
	}

	// Test structured formatted logging
	InfofWithFields(fields, "processing %d requests", 42)
	output := buf.String()
	assert.Contains(t, output, "processing 42 requests")
	assert.Contains(t, output, "component=auth")
	assert.Contains(t, output, "version=1.0")
	buf.Reset()

	WarnfWithFields(fields, "high load: %d%%", 85)
	output = buf.String()
	assert.Contains(t, output, "high load: 85%")
	assert.Contains(t, output, "level=warning")
	buf.Reset()

	ErrorfWithFields(fields, "failed with code %d", 500)
	output = buf.String()
	assert.Contains(t, output, "failed with code 500")
	assert.Contains(t, output, "level=error")
	buf.Reset()

	DebugfWithFields(fields, "cache hit rate: %.2f%%", 95.67)
	output = buf.String()
	assert.Contains(t, output, "cache hit rate: 95.67%")
	assert.Contains(t, output, "level=debug")
	buf.Reset()
}

func TestLoggerOutputToFile(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "output_test.log")

	// Initialize logger with file output
	err := InitLogger(logFile, logrus.InfoLevel)
	require.NoError(t, err)

	// Log some messages
	Info("test message 1")
	Warn("test message 2")
	Error("test message 3")

	// Give some time for the write to complete
	time.Sleep(100 * time.Millisecond)

	// Read the log file
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logContent := string(content)
	assert.Contains(t, logContent, "test message 1")
	assert.Contains(t, logContent, "test message 2")
	assert.Contains(t, logContent, "test message 3")
	assert.Contains(t, logContent, "level=info")
	assert.Contains(t, logContent, "level=warning")
	assert.Contains(t, logContent, "level=error")
}

func TestJSONFormatterOutput(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	Logger.SetLevel(logrus.InfoLevel)

	// Set JSON formatter
	Logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	defer func() {
		Logger.SetOutput(originalOutput)
	}()

	Info("json test message")
	output := buf.String()

	// Verify JSON structure
	assert.Contains(t, output, `"level":"info"`)
	assert.Contains(t, output, `"message":"json test message"`)
	assert.Contains(t, output, `"timestamp":`)
	assert.True(t, strings.HasPrefix(output, "{"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(output), "}"))
}
