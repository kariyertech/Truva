// pkg/utils/logger.go
package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	Logger         = logrus.New()
	tracer         trace.Tracer
	tracingEnabled bool
	tracingMutex   sync.RWMutex
	logShipper     *SignozLogShipper
	shippingMutex  sync.RWMutex
)

// LogFormat represents the logging format type
type LogFormat string

const (
	TextFormat LogFormat = "text"
	JSONFormat LogFormat = "json"
)

// TracingConfig holds tracing configuration
type TracingConfig struct {
	Enabled     bool    `yaml:"enabled" json:"enabled"`
	ServiceName string  `yaml:"service_name" json:"service_name"`
	JaegerURL   string  `yaml:"jaeger_url" json:"jaeger_url"`
	SampleRate  float64 `yaml:"sample_rate" json:"sample_rate"`
}

// SignozConfig holds Signoz log aggregation configuration
type SignozConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Endpoint      string        `yaml:"endpoint" json:"endpoint"`
	APIKey        string        `yaml:"api_key" json:"api_key"`
	BatchSize     int           `yaml:"batch_size" json:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
}

// LogAggregationConfig holds complete log aggregation configuration
type LogAggregationConfig struct {
	Signoz  SignozConfig `yaml:"signoz" json:"signoz"`
	Enabled bool         `yaml:"enabled" json:"enabled"`
}

// TraceContext holds trace information
type TraceContext struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
}

// TracedLogger wraps logrus with tracing capabilities
type TracedLogger struct {
	*logrus.Logger
	tracer trace.Tracer
}

// SignozLogEntry represents a log entry for Signoz
type SignozLogEntry struct {
	Timestamp  string                 `json:"timestamp"`
	Level      string                 `json:"level"`
	Message    string                 `json:"message"`
	Service    string                 `json:"service"`
	TraceID    string                 `json:"trace_id,omitempty"`
	SpanID     string                 `json:"span_id,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Resource   map[string]interface{} `json:"resource,omitempty"`
}

// SignozLogShipper handles shipping logs to Signoz
type SignozLogShipper struct {
	config      SignozConfig
	buffer      []SignozLogEntry
	bufferMux   sync.Mutex
	client      *http.Client
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	serviceName string
}

// InitLogger initializes the logger with specified configuration
func InitLogger(logFile string, level logrus.Level) error {
	return InitLoggerWithFormat(logFile, level, TextFormat)
}

// InitLoggerWithFormat initializes the logger with specified format
func InitLoggerWithFormat(logFile string, level logrus.Level, format LogFormat) error {
	// Set formatter based on format type
	switch format {
	case JSONFormat:
		Logger.SetFormatter(&TracingJSONFormatter{
			JSONFormatter: &logrus.JSONFormatter{
				TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
				FieldMap: logrus.FieldMap{
					logrus.FieldKeyTime:  "timestamp",
					logrus.FieldKeyLevel: "level",
					logrus.FieldKeyMsg:   "message",
					logrus.FieldKeyFunc:  "function",
					logrus.FieldKeyFile:  "file",
				},
			},
		})
	default:
		Logger.SetFormatter(&TracingTextFormatter{
			TextFormatter: &logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			},
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

// InitTracing initializes OpenTelemetry tracing
func InitTracing(config TracingConfig) error {
	tracingMutex.Lock()
	defer tracingMutex.Unlock()

	if !config.Enabled {
		tracingEnabled = false
		return nil
	}

	// Create Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerURL)))
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(config.SampleRate)),
	)

	// Set global trace provider
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Get tracer
	tracer = otel.Tracer(config.ServiceName)
	tracingEnabled = true

	Logger.Info("Distributed tracing initialized successfully")
	return nil
}

// TracingJSONFormatter adds tracing information to JSON logs
type TracingJSONFormatter struct {
	*logrus.JSONFormatter
}

func (f *TracingJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Add tracing information if available
	if ctx := entry.Context; ctx != nil {
		if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
			entry.Data["trace_id"] = span.SpanContext().TraceID().String()
			entry.Data["span_id"] = span.SpanContext().SpanID().String()
		}
	}
	return f.JSONFormatter.Format(entry)
}

// TracingTextFormatter adds tracing information to text logs
type TracingTextFormatter struct {
	*logrus.TextFormatter
}

func (f *TracingTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Add tracing information if available
	if ctx := entry.Context; ctx != nil {
		if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
			entry.Data["trace_id"] = span.SpanContext().TraceID().String()
			entry.Data["span_id"] = span.SpanContext().SpanID().String()
		}
	}
	return f.TextFormatter.Format(entry)
}

// StartSpan starts a new span with the given name
func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	tracingMutex.RLock()
	enabled := tracingEnabled
	currentTracer := tracer
	tracingMutex.RUnlock()

	if !enabled || currentTracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}

	return currentTracer.Start(ctx, spanName, opts...)
}

// AddSpanAttributes adds attributes to the current span
func AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		span.SetAttributes(attrs...)
	}
}

// AddSpanEvent adds an event to the current span
func AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// RecordError records an error in the current span
func RecordError(ctx context.Context, err error, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		span.RecordError(err, trace.WithAttributes(attrs...))
		span.SetStatus(codes.Error, err.Error())
	}
}

// GetTraceContext extracts trace context from the current context
func GetTraceContext(ctx context.Context) *TraceContext {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return nil
	}

	return &TraceContext{
		TraceID: span.SpanContext().TraceID().String(),
		SpanID:  span.SpanContext().SpanID().String(),
	}
}

// WithTraceContext creates a new context with trace information
func WithTraceContext(ctx context.Context, traceID, spanID string) context.Context {
	// This would require parsing the trace/span IDs and creating a span context
	// Implementation depends on the specific tracing backend
	return ctx
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

// WriteJSONResponse writes a JSON response to the HTTP response writer
func WriteJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode JSON response", http.StatusInternalServerError)
		Error("Failed to encode JSON response:", err)
	}
}

// WriteJSONError writes a JSON error response
func WriteJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	errorResponse := map[string]interface{}{
		"error":   true,
		"message": message,
		"status":  statusCode,
	}
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		Error("Failed to encode JSON error response:", err)
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

// Audit logging types
type AuditEventType string

const (
	AuditEventAuth       AuditEventType = "authentication"
	AuditEventAuthz      AuditEventType = "authorization"
	AuditEventAccess     AuditEventType = "access"
	AuditEventDataAccess AuditEventType = "data_access"
	AuditEventConfig     AuditEventType = "configuration"
	AuditEventSecurity   AuditEventType = "security"
	AuditEventAdmin      AuditEventType = "admin"
	AuditEventError      AuditEventType = "error"
	AuditEventCompliance AuditEventType = "compliance"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	EventType  AuditEventType         `json:"event_type"`
	UserID     string                 `json:"user_id,omitempty"`
	UserIP     string                 `json:"user_ip,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Resource   string                 `json:"resource,omitempty"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"`
	Reason     string                 `json:"reason,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Timestamp  string                 `json:"timestamp"`
	Severity   string                 `json:"severity"`
	Compliance []string               `json:"compliance,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Audit logging functions
func AuditLog(event AuditEvent, message string) {
	fields := logrus.Fields{
		"audit":      true,
		"event_type": event.EventType,
		"action":     event.Action,
		"result":     event.Result,
		"severity":   event.Severity,
		"timestamp":  event.Timestamp,
	}

	if event.UserID != "" {
		fields["user_id"] = event.UserID
	}
	if event.UserIP != "" {
		fields["user_ip"] = event.UserIP
	}
	if event.UserAgent != "" {
		fields["user_agent"] = event.UserAgent
	}
	if event.Resource != "" {
		fields["resource"] = event.Resource
	}
	if event.Reason != "" {
		fields["reason"] = event.Reason
	}
	if event.SessionID != "" {
		fields["session_id"] = event.SessionID
	}
	if event.RequestID != "" {
		fields["request_id"] = event.RequestID
	}
	if len(event.Compliance) > 0 {
		fields["compliance"] = event.Compliance
	}
	if event.Metadata != nil {
		for k, v := range event.Metadata {
			fields[k] = v
		}
	}

	Logger.WithFields(fields).Info(message)
}

// Security event logging helpers
func AuditAuthSuccess(userID, userIP, userAgent, sessionID string) {
	AuditLog(AuditEvent{
		EventType:  AuditEventAuth,
		UserID:     userID,
		UserIP:     userIP,
		UserAgent:  userAgent,
		SessionID:  sessionID,
		Action:     "login",
		Result:     "success",
		Severity:   "info",
		Timestamp:  getCurrentTimestamp(),
		Compliance: []string{"SOC2", "GDPR"},
	}, "User authentication successful")
}

func AuditAuthFailure(userID, userIP, userAgent, reason string) {
	AuditLog(AuditEvent{
		EventType:  AuditEventAuth,
		UserID:     userID,
		UserIP:     userIP,
		UserAgent:  userAgent,
		Action:     "login",
		Result:     "failure",
		Reason:     reason,
		Severity:   "warning",
		Timestamp:  getCurrentTimestamp(),
		Compliance: []string{"SOC2", "GDPR"},
	}, "User authentication failed")
}

func AuditAuthzFailure(userID, userIP, resource, action, reason string) {
	AuditLog(AuditEvent{
		EventType:  AuditEventAuthz,
		UserID:     userID,
		UserIP:     userIP,
		Resource:   resource,
		Action:     action,
		Result:     "denied",
		Reason:     reason,
		Severity:   "warning",
		Timestamp:  getCurrentTimestamp(),
		Compliance: []string{"SOC2", "GDPR"},
	}, "Authorization denied")
}

func AuditDataAccess(userID, userIP, resource, action string, metadata map[string]interface{}) {
	AuditLog(AuditEvent{
		EventType:  AuditEventDataAccess,
		UserID:     userID,
		UserIP:     userIP,
		Resource:   resource,
		Action:     action,
		Result:     "success",
		Severity:   "info",
		Timestamp:  getCurrentTimestamp(),
		Metadata:   metadata,
		Compliance: []string{"SOC2", "GDPR", "HIPAA"},
	}, "Data access event")
}

func AuditConfigChange(userID, userIP, resource, action string, metadata map[string]interface{}) {
	AuditLog(AuditEvent{
		EventType:  AuditEventConfig,
		UserID:     userID,
		UserIP:     userIP,
		Resource:   resource,
		Action:     action,
		Result:     "success",
		Severity:   "info",
		Timestamp:  getCurrentTimestamp(),
		Metadata:   metadata,
		Compliance: []string{"SOC2", "GDPR"},
	}, "Configuration change")
}

func AuditSecurityEvent(eventType, userID, userIP, action, result, reason string, severity string) {
	AuditLog(AuditEvent{
		EventType:  AuditEventSecurity,
		UserID:     userID,
		UserIP:     userIP,
		Action:     action,
		Result:     result,
		Reason:     reason,
		Severity:   severity,
		Timestamp:  getCurrentTimestamp(),
		Compliance: []string{"SOC2", "GDPR"},
	}, "Security event: "+eventType)
}

func AuditAdminAction(userID, userIP, resource, action string, metadata map[string]interface{}) {
	AuditLog(AuditEvent{
		EventType:  AuditEventAdmin,
		UserID:     userID,
		UserIP:     userIP,
		Resource:   resource,
		Action:     action,
		Result:     "success",
		Severity:   "info",
		Timestamp:  getCurrentTimestamp(),
		Metadata:   metadata,
		Compliance: []string{"SOC2", "GDPR"},
	}, "Administrative action")
}

func AuditError(userID, userIP, resource, action, errorMsg string, metadata map[string]interface{}) {
	AuditLog(AuditEvent{
		EventType:  AuditEventError,
		UserID:     userID,
		UserIP:     userIP,
		Resource:   resource,
		Action:     action,
		Result:     "error",
		Reason:     errorMsg,
		Severity:   "error",
		Timestamp:  getCurrentTimestamp(),
		Metadata:   metadata,
		Compliance: []string{"SOC2", "GDPR"},
	}, "Error event")
}

// Helper function to get current timestamp
func getCurrentTimestamp() string {
	return time.Now().Format("2006-01-02T15:04:05.000Z07:00")
}

// InitLogAggregation initializes log aggregation with Signoz
func InitLogAggregation(config LogAggregationConfig, serviceName string) error {
	shippingMutex.Lock()
	defer shippingMutex.Unlock()

	if !config.Enabled || !config.Signoz.Enabled {
		return nil
	}

	// Set default values
	if config.Signoz.BatchSize == 0 {
		config.Signoz.BatchSize = 100
	}
	if config.Signoz.FlushInterval == 0 {
		config.Signoz.FlushInterval = 5 * time.Second
	}
	if config.Signoz.Timeout == 0 {
		config.Signoz.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	logShipper = &SignozLogShipper{
		config: config.Signoz,
		buffer: make([]SignozLogEntry, 0, config.Signoz.BatchSize),
		client: &http.Client{
			Timeout: config.Signoz.Timeout,
		},
		ctx:         ctx,
		cancel:      cancel,
		serviceName: serviceName,
	}

	// Start background flusher
	logShipper.wg.Add(1)
	go logShipper.backgroundFlusher()

	// Add Signoz hook to logger
	Logger.AddHook(&SignozHook{shipper: logShipper})

	Logger.Info("Log aggregation with Signoz initialized successfully")
	return nil
}

// NewSignozLogShipper creates a new Signoz log shipper
func NewSignozLogShipper(config SignozConfig, serviceName string) *SignozLogShipper {
	ctx, cancel := context.WithCancel(context.Background())
	return &SignozLogShipper{
		config: config,
		buffer: make([]SignozLogEntry, 0, config.BatchSize),
		client: &http.Client{
			Timeout: config.Timeout,
		},
		ctx:         ctx,
		cancel:      cancel,
		serviceName: serviceName,
	}
}

// AddLog adds a log entry to the buffer
func (s *SignozLogShipper) AddLog(entry SignozLogEntry) {
	s.bufferMux.Lock()
	defer s.bufferMux.Unlock()

	entry.Service = s.serviceName
	entry.Resource = map[string]interface{}{
		"service.name":    s.serviceName,
		"service.version": "1.0.0",
	}

	s.buffer = append(s.buffer, entry)

	// Flush if buffer is full
	if len(s.buffer) >= s.config.BatchSize {
		go s.flush()
	}
}

// flush sends buffered logs to Signoz
func (s *SignozLogShipper) flush() {
	s.bufferMux.Lock()
	if len(s.buffer) == 0 {
		s.bufferMux.Unlock()
		return
	}

	// Copy buffer and reset
	logs := make([]SignozLogEntry, len(s.buffer))
	copy(logs, s.buffer)
	s.buffer = s.buffer[:0]
	s.bufferMux.Unlock()

	// Send to Signoz
	if err := s.sendToSignoz(logs); err != nil {
		Logger.WithError(err).Error("Failed to send logs to Signoz")
	}
}

// sendToSignoz sends logs to Signoz endpoint
func (s *SignozLogShipper) sendToSignoz(logs []SignozLogEntry) error {
	payload := map[string]interface{}{
		"resourceLogs": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": map[string]interface{}{
						"service.name":    s.serviceName,
						"service.version": "1.0.0",
					},
				},
				"scopeLogs": []map[string]interface{}{
					{
						"scope": map[string]interface{}{
							"name":    "truva-logger",
							"version": "1.0.0",
						},
						"logRecords": logs,
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal logs: %w", err)
	}

	req, err := http.NewRequestWithContext(s.ctx, "POST", s.config.Endpoint+"/v1/logs", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Signoz API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// backgroundFlusher periodically flushes the buffer
func (s *SignozLogShipper) backgroundFlusher() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Final flush before shutdown
			s.flush()
			return
		case <-ticker.C:
			s.flush()
		}
	}
}

// Close gracefully shuts down the log shipper
func (s *SignozLogShipper) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

// SignozHook implements logrus.Hook for Signoz integration
type SignozHook struct {
	shipper *SignozLogShipper
}

// Levels returns the log levels this hook should fire for
func (h *SignozHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when a log entry is written
func (h *SignozHook) Fire(entry *logrus.Entry) error {
	if h.shipper == nil {
		return nil
	}

	// Create Signoz log entry
	signozEntry := SignozLogEntry{
		Timestamp:  entry.Time.Format("2006-01-02T15:04:05.000Z07:00"),
		Level:      entry.Level.String(),
		Message:    entry.Message,
		Attributes: make(map[string]interface{}),
	}

	// Add trace information if available
	if entry.Context != nil {
		if span := trace.SpanFromContext(entry.Context); span.SpanContext().IsValid() {
			signozEntry.TraceID = span.SpanContext().TraceID().String()
			signozEntry.SpanID = span.SpanContext().SpanID().String()
		}
	}

	// Add all fields as attributes
	for key, value := range entry.Data {
		signozEntry.Attributes[key] = value
	}

	// Add log entry to shipper
	h.shipper.AddLog(signozEntry)
	return nil
}

// ShutdownLogAggregation gracefully shuts down log aggregation
func ShutdownLogAggregation() error {
	shippingMutex.Lock()
	defer shippingMutex.Unlock()

	if logShipper != nil {
		return logShipper.Close()
	}
	return nil
}
