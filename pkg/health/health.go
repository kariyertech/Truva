package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type HealthStatus struct {
	Status    string           `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
	Version   string           `json:"version"`
	Uptime    string           `json:"uptime"`
	Checks    map[string]Check `json:"checks"`
	Metrics   *SystemMetrics   `json:"metrics,omitempty"`
}

type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

type SystemMetrics struct {
	MemoryUsage  uint64  `json:"memory_usage_bytes"`
	Goroutines   int     `json:"goroutines"`
	CPUUsage     float64 `json:"cpu_usage_percent"`
	RequestCount int64   `json:"request_count"`
	ErrorCount   int64   `json:"error_count"`
	ResponseTime float64 `json:"avg_response_time_ms"`
}

type MetricsCollector struct {
	mu                 sync.RWMutex
	requestCount       int64
	errorCount         int64
	totalResponseTime  float64
	requestDurations   []float64
	lastMetricsUpdate  time.Time
	customMetrics      map[string]interface{}
	healthCheckers     []HealthChecker
	prometheusRegistry *prometheus.Registry
	prometheusMetrics  *PrometheusMetrics
}

type HealthChecker interface {
	Name() string
	Check(ctx context.Context) Check
}

type PrometheusMetrics struct {
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	ErrorsTotal      *prometheus.CounterVec
	SystemMemory     prometheus.Gauge
	SystemGoroutines prometheus.Gauge
	SystemCPU        prometheus.Gauge
	HealthStatus     *prometheus.GaugeVec
	CustomMetrics    map[string]prometheus.Collector
}

type DatabaseHealthChecker struct {
	name string
	ping func() error
}

type KubernetesHealthChecker struct {
	name string
	ping func() error
}

type RedisHealthChecker struct {
	name string
	ping func() error
}

var (
	startTime       = time.Now()
	globalCollector *MetricsCollector
	collectorMutex  sync.RWMutex
)

// Initialize metrics collector
func InitMetricsCollector() *MetricsCollector {
	collectorMutex.Lock()
	defer collectorMutex.Unlock()

	if globalCollector != nil {
		return globalCollector
	}

	registry := prometheus.NewRegistry()
	prometheusMetrics := &PrometheusMetrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "truva_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "truva_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "truva_errors_total",
				Help: "Total number of errors",
			},
			[]string{"type", "component"},
		),
		SystemMemory: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "truva_system_memory_bytes",
				Help: "System memory usage in bytes",
			},
		),
		SystemGoroutines: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "truva_system_goroutines",
				Help: "Number of goroutines",
			},
		),
		SystemCPU: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "truva_system_cpu_usage",
				Help: "CPU usage percentage",
			},
		),
		HealthStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "truva_health_status",
				Help: "Health status of components (1=healthy, 0=unhealthy)",
			},
			[]string{"component"},
		),
		CustomMetrics: make(map[string]prometheus.Collector),
	}

	// Register metrics
	registry.MustRegister(
		prometheusMetrics.RequestsTotal,
		prometheusMetrics.RequestDuration,
		prometheusMetrics.ErrorsTotal,
		prometheusMetrics.SystemMemory,
		prometheusMetrics.SystemGoroutines,
		prometheusMetrics.SystemCPU,
		prometheusMetrics.HealthStatus,
	)

	globalCollector = &MetricsCollector{
		customMetrics:      make(map[string]interface{}),
		healthCheckers:     []HealthChecker{},
		prometheusRegistry: registry,
		prometheusMetrics:  prometheusMetrics,
	}

	// Start metrics collection routine
	go globalCollector.startMetricsCollection()

	return globalCollector
}

// GetMetricsCollector returns the global metrics collector
func GetMetricsCollector() *MetricsCollector {
	collectorMutex.RLock()
	defer collectorMutex.RUnlock()
	return globalCollector
}

// RecordRequest records an HTTP request
func (mc *MetricsCollector) RecordRequest(method, endpoint, status string, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.requestCount++
	durationMs := float64(duration.Nanoseconds()) / 1e6
	mc.totalResponseTime += durationMs
	mc.requestDurations = append(mc.requestDurations, durationMs)

	// Keep only last 1000 durations for average calculation
	if len(mc.requestDurations) > 1000 {
		mc.requestDurations = mc.requestDurations[1:]
	}

	// Record Prometheus metrics
	if mc.prometheusMetrics != nil {
		mc.prometheusMetrics.RequestsTotal.WithLabelValues(method, endpoint, status).Inc()
		mc.prometheusMetrics.RequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
	}
}

// RecordError records an error
func (mc *MetricsCollector) RecordError(errorType, component string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.errorCount++

	// Record Prometheus metrics
	if mc.prometheusMetrics != nil {
		mc.prometheusMetrics.ErrorsTotal.WithLabelValues(errorType, component).Inc()
	}
}

// SetCustomMetric sets a custom metric
func (mc *MetricsCollector) SetCustomMetric(name string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.customMetrics[name] = value
}

// AddHealthChecker adds a health checker
func (mc *MetricsCollector) AddHealthChecker(checker HealthChecker) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.healthCheckers = append(mc.healthCheckers, checker)
}

// RegisterCustomPrometheusMetric registers a custom Prometheus metric
func (mc *MetricsCollector) RegisterCustomPrometheusMetric(name string, metric prometheus.Collector) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.prometheusMetrics == nil {
		return fmt.Errorf("prometheus metrics not initialized")
	}

	err := mc.prometheusRegistry.Register(metric)
	if err != nil {
		return err
	}

	mc.prometheusMetrics.CustomMetrics[name] = metric
	return nil
}

// startMetricsCollection starts the metrics collection routine
func (mc *MetricsCollector) startMetricsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mc.updateSystemMetrics()
	}
}

// updateSystemMetrics updates system metrics
func (mc *MetricsCollector) updateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if mc.prometheusMetrics != nil {
		mc.prometheusMetrics.SystemMemory.Set(float64(m.Alloc))
		mc.prometheusMetrics.SystemGoroutines.Set(float64(runtime.NumGoroutine()))
		// CPU usage would require additional implementation
		mc.prometheusMetrics.SystemCPU.Set(0) // Placeholder
	}

	mc.mu.Lock()
	mc.lastMetricsUpdate = time.Now()
	mc.mu.Unlock()
}

// GetSystemMetrics returns current system metrics
func (mc *MetricsCollector) GetSystemMetrics() SystemMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	avgResponseTime := float64(0)
	if len(mc.requestDurations) > 0 {
		sum := float64(0)
		for _, duration := range mc.requestDurations {
			sum += duration
		}
		avgResponseTime = sum / float64(len(mc.requestDurations))
	}

	return SystemMetrics{
		MemoryUsage:  m.Alloc,
		Goroutines:   runtime.NumGoroutine(),
		CPUUsage:     0, // Would need additional implementation
		RequestCount: mc.requestCount,
		ErrorCount:   mc.errorCount,
		ResponseTime: avgResponseTime,
	}
}

// Health checker implementations
func NewDatabaseHealthChecker(name string, pingFunc func() error) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		name: name,
		ping: pingFunc,
	}
}

func (d *DatabaseHealthChecker) Name() string {
	return d.name
}

func (d *DatabaseHealthChecker) Check(ctx context.Context) Check {
	start := time.Now()
	err := d.ping()
	latency := time.Since(start)

	if err != nil {
		return Check{
			Status:  "error",
			Message: err.Error(),
			Latency: latency.String(),
		}
	}

	return Check{
		Status:  "ok",
		Message: "Database connection healthy",
		Latency: latency.String(),
	}
}

func NewKubernetesHealthChecker(name string, pingFunc func() error) *KubernetesHealthChecker {
	return &KubernetesHealthChecker{
		name: name,
		ping: pingFunc,
	}
}

func (k *KubernetesHealthChecker) Name() string {
	return k.name
}

func (k *KubernetesHealthChecker) Check(ctx context.Context) Check {
	start := time.Now()
	err := k.ping()
	latency := time.Since(start)

	if err != nil {
		return Check{
			Status:  "error",
			Message: err.Error(),
			Latency: latency.String(),
		}
	}

	return Check{
		Status:  "ok",
		Message: "Kubernetes API healthy",
		Latency: latency.String(),
	}
}

// HTTP Handlers
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cfg := config.GetConfig()
	if !cfg.Monitoring.HealthCheckEnabled {
		http.Error(w, "Health check disabled", http.StatusServiceUnavailable)
		return
	}

	collector := GetMetricsCollector()
	if collector == nil {
		collector = InitMetricsCollector()
	}

	health := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Uptime:    time.Since(startTime).String(),
		Checks:    make(map[string]Check),
	}

	// Include metrics if requested
	if r.URL.Query().Get("metrics") == "true" {
		metrics := collector.GetSystemMetrics()
		health.Metrics = &metrics
	}

	// Add basic checks
	health.Checks["config"] = Check{
		Status:  "ok",
		Message: "Configuration loaded successfully",
	}

	// Check if we can access the config
	if cfg == nil {
		health.Status = "unhealthy"
		health.Checks["config"] = Check{
			Status:  "error",
			Message: "Configuration not loaded",
		}
	}

	// Run health checkers
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collector.mu.RLock()
	healthCheckers := collector.healthCheckers
	collector.mu.RUnlock()

	for _, checker := range healthCheckers {
		check := checker.Check(ctx)
		health.Checks[checker.Name()] = check

		if check.Status != "ok" {
			health.Status = "unhealthy"
		}

		// Update Prometheus health status
		if collector.prometheusMetrics != nil {
			status := float64(0)
			if check.Status == "ok" {
				status = 1
			}
			collector.prometheusMetrics.HealthStatus.WithLabelValues(checker.Name()).Set(status)
		}
	}

	// Set HTTP status based on health
	statusCode := http.StatusOK
	if health.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(health)
}

func ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Simple readiness check
	readiness := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now(),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(readiness)
}

func LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Simple liveness check
	liveness := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now(),
		"uptime":    time.Since(startTime).String(),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(liveness)
}

// MetricsHandler returns Prometheus metrics
func MetricsHandler() http.Handler {
	collector := GetMetricsCollector()
	if collector == nil {
		collector = InitMetricsCollector()
	}

	return promhttp.HandlerFor(collector.prometheusRegistry, promhttp.HandlerOpts{})
}

// Middleware for recording HTTP metrics
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		collector := GetMetricsCollector()
		if collector != nil {
			collector.RecordRequest(r.Method, r.URL.Path, fmt.Sprintf("%d", wrapped.statusCode), duration)
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Utility functions for easy metrics recording
func RecordRequest(method, endpoint, status string, duration time.Duration) {
	collector := GetMetricsCollector()
	if collector != nil {
		collector.RecordRequest(method, endpoint, status, duration)
	}
}

func RecordError(errorType, component string) {
	collector := GetMetricsCollector()
	if collector != nil {
		collector.RecordError(errorType, component)
	}
}

func SetCustomMetric(name string, value interface{}) {
	collector := GetMetricsCollector()
	if collector != nil {
		collector.SetCustomMetric(name, value)
	}
}

func AddHealthChecker(checker HealthChecker) {
	collector := GetMetricsCollector()
	if collector != nil {
		collector.AddHealthChecker(checker)
	}
}
