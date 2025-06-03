// pkg/utils/logger.go
package utils

import (
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var Logger = logrus.New()

// LogFormat represents the logging format type
type LogFormat string

const (
	TextFormat LogFormat = "text"
	JSONFormat LogFormat = "json"
)

// InitLogger initializes the logger with specified configuration
func InitLogger(logFile string, level logrus.Level) error {
	return InitLoggerWithFormat(logFile, level, TextFormat)
}

// InitLoggerWithFormat initializes the logger with specified format
func InitLoggerWithFormat(logFile string, level logrus.Level, format LogFormat) error {
	// Set formatter based on format type
	switch format {
	case JSONFormat:
		Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
				logrus.FieldKeyFile:  "file",
			},
		})
	default:
		Logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}

	Logger.SetLevel(level)

	logFileHandler, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	multiWriter := io.MultiWriter(os.Stdout, logFileHandler)
	Logger.SetOutput(multiWriter)

	return nil
}

// ParseLogLevel parses string log level to logrus.Level
func ParseLogLevel(level string) logrus.Level {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn", "warning":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	case "panic":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}

// ParseLogFormat parses string log format to LogFormat
func ParseLogFormat(format string) LogFormat {
	switch strings.ToLower(format) {
	case "json":
		return JSONFormat
	case "text":
		return TextFormat
	default:
		return TextFormat
	}
}

// Standard logging functions
func Info(args ...interface{}) {
	Logger.Info(args...)
}

func Warn(args ...interface{}) {
	Logger.Warn(args...)
}

func Error(args ...interface{}) {
	Logger.Error(args...)
}

func Debug(args ...interface{}) {
	Logger.Debug(args...)
}

// Structured logging functions with fields
func InfoWithFields(fields logrus.Fields, args ...interface{}) {
	Logger.WithFields(fields).Info(args...)
}

func WarnWithFields(fields logrus.Fields, args ...interface{}) {
	Logger.WithFields(fields).Warn(args...)
}

func ErrorWithFields(fields logrus.Fields, args ...interface{}) {
	Logger.WithFields(fields).Error(args...)
}

func DebugWithFields(fields logrus.Fields, args ...interface{}) {
	Logger.WithFields(fields).Debug(args...)
}

// Formatted logging functions
func Infof(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

func Debugf(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

// Structured formatted logging functions
func InfofWithFields(fields logrus.Fields, format string, args ...interface{}) {
	Logger.WithFields(fields).Infof(format, args...)
}

func WarnfWithFields(fields logrus.Fields, format string, args ...interface{}) {
	Logger.WithFields(fields).Warnf(format, args...)
}

func ErrorfWithFields(fields logrus.Fields, format string, args ...interface{}) {
	Logger.WithFields(fields).Errorf(format, args...)
}

func DebugfWithFields(fields logrus.Fields, format string, args ...interface{}) {
	Logger.WithFields(fields).Debugf(format, args...)
}
