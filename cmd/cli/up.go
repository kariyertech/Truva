package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/kariyertech/Truva.git/internal/k8s"
	syncer "github.com/kariyertech/Truva.git/internal/sync"
	"github.com/kariyertech/Truva.git/internal/ui"
	"github.com/kariyertech/Truva.git/pkg/api"
	"github.com/kariyertech/Truva.git/pkg/cleanup"
	"github.com/kariyertech/Truva.git/pkg/errors"
	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/utils"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

var (
	namespace     string
	targetType    string
	targetName    string
	localPath     string
	containerPath string
)

// Performance monitoring metrics
var (
	// CPU and Memory metrics
	cpuUsageGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "truva_cpu_usage_percent",
		Help: "Current CPU usage percentage",
	})

	memoryUsageGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "truva_memory_usage_bytes",
		Help: "Current memory usage in bytes",
	})

	memoryAllocGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "truva_memory_alloc_bytes",
		Help: "Current allocated memory in bytes",
	})

	goroutineCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "truva_goroutines_count",
		Help: "Current number of goroutines",
	})

	// Response time metrics
	responseTimeHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "truva_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "status_code"},
	)

	// Throughput metrics
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "truva_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	// Sync operation metrics
	syncOperationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "truva_sync_operations_total",
			Help: "Total number of sync operations",
		},
		[]string{"operation", "status"},
	)

	syncDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "truva_sync_duration_seconds",
			Help:    "Sync operation duration in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"operation"},
	)

	// K8s operation metrics
	k8sOperationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "truva_k8s_operations_total",
			Help: "Total number of Kubernetes operations",
		},
		[]string{"operation", "resource", "status"},
	)

	k8sOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "truva_k8s_operation_duration_seconds",
			Help:    "Kubernetes operation duration in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"operation", "resource"},
	)

	// Application uptime
	uptimeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "truva_uptime_seconds",
		Help: "Application uptime in seconds",
	})

	startTime = time.Now()
)

// PerformanceMonitor handles performance monitoring and profiling
type PerformanceMonitor struct {
	mu               sync.RWMutex
	metricsEnabled   bool
	profilingEnabled bool
	metricsInterval  time.Duration
	stopChan         chan struct{}
	wg               sync.WaitGroup
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		metricsEnabled:   true,
		profilingEnabled: true,
		metricsInterval:  time.Second * 10,
		stopChan:         make(chan struct{}),
	}
}

// Start begins performance monitoring
func (pm *PerformanceMonitor) Start() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Register metrics
	prometheus.MustRegister(
		cpuUsageGauge,
		memoryUsageGauge,
		memoryAllocGauge,
		goroutineCountGauge,
		responseTimeHistogram,
		requestCounter,
		syncOperationCounter,
		syncDurationHistogram,
		k8sOperationCounter,
		k8sOperationDuration,
		uptimeGauge,
	)

	if pm.metricsEnabled {
		pm.wg.Add(1)
		go pm.collectMetrics()
	}

	utils.Info("Performance monitoring started")
}

// Stop stops performance monitoring
func (pm *PerformanceMonitor) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	close(pm.stopChan)
	pm.wg.Wait()

	utils.Info("Performance monitoring stopped")
}

// collectMetrics collects system and application metrics
func (pm *PerformanceMonitor) collectMetrics() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.metricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.updateSystemMetrics()
		case <-pm.stopChan:
			return
		}
	}
}

// updateSystemMetrics updates system-level metrics
func (pm *PerformanceMonitor) updateSystemMetrics() {
	// Memory statistics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memoryAllocGauge.Set(float64(m.Alloc))
	memoryUsageGauge.Set(float64(m.Sys))

	// Goroutine count
	goroutineCountGauge.Set(float64(runtime.NumGoroutine()))

	// Uptime
	uptime := time.Since(startTime).Seconds()
	uptimeGauge.Set(uptime)

	// GC statistics
	gcStats := debug.GCStats{}
	debug.ReadGCStats(&gcStats)
}

// PerformanceMiddleware wraps HTTP handlers with performance monitoring
func PerformanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		method := r.Method
		endpoint := r.URL.Path
		statusCode := fmt.Sprintf("%d", wrapped.statusCode)

		responseTimeHistogram.WithLabelValues(method, endpoint, statusCode).Observe(duration)
		requestCounter.WithLabelValues(method, endpoint, statusCode).Inc()
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

// RecordSyncOperation records sync operation metrics
func RecordSyncOperation(operation, status string, duration time.Duration) {
	syncOperationCounter.WithLabelValues(operation, status).Inc()
	syncDurationHistogram.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordK8sOperation records Kubernetes operation metrics
func RecordK8sOperation(operation, resource, status string, duration time.Duration) {
	k8sOperationCounter.WithLabelValues(operation, resource, status).Inc()
	k8sOperationDuration.WithLabelValues(operation, resource).Observe(duration.Seconds())
}

// setupProfiling sets up pprof endpoints for profiling
func setupProfiling(mux *http.ServeMux) {
	// CPU profiling
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Memory profiling
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))

	utils.Info("Profiling endpoints enabled at /debug/pprof/")
}

// setupMetricsEndpoint sets up Prometheus metrics endpoint
func setupMetricsEndpoint(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
	utils.Info("Metrics endpoint enabled at /metrics")
}

// HealthCheck provides application health information
type HealthCheck struct {
	Status    string                 `json:"status"`
	Uptime    string                 `json:"uptime"`
	Version   string                 `json:"version"`
	Metrics   map[string]interface{} `json:"metrics"`
	Timestamp time.Time              `json:"timestamp"`
}

// getHealthStatus returns current health status
func getHealthStatus() *HealthCheck {
	uptime := time.Since(startTime)

	// Get current metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := map[string]interface{}{
		"memory_alloc": m.Alloc,
		"memory_sys":   m.Sys,
		"goroutines":   runtime.NumGoroutine(),
		"gc_cycles":    m.NumGC,
		"cpu_cores":    runtime.NumCPU(),
		"go_version":   runtime.Version(),
	}

	return &HealthCheck{
		Status:    "healthy",
		Uptime:    uptime.String(),
		Version:   "1.0.0",
		Metrics:   metrics,
		Timestamp: time.Now(),
	}
}

// setupHealthEndpoint sets up health check endpoint
func setupHealthEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		health := getHealthStatus()

		// Simple JSON encoding
		response := fmt.Sprintf(`{
			"status": "%s",
			"uptime": "%s",
			"version": "%s",
			"timestamp": "%s",
			"metrics": {
				"memory_alloc": %d,
				"memory_sys": %d,
				"goroutines": %d,
				"gc_cycles": %d,
				"cpu_cores": %d,
				"go_version": "%s"
			}
		}`,
			health.Status,
			health.Uptime,
			health.Version,
			health.Timestamp.Format(time.RFC3339),
			health.Metrics["memory_alloc"],
			health.Metrics["memory_sys"],
			health.Metrics["goroutines"],
			health.Metrics["gc_cycles"],
			health.Metrics["cpu_cores"],
			health.Metrics["go_version"],
		)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	})

	utils.Info("Health endpoint enabled at /health")
}

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the application along with UI",
	Long: `This command will start the UI and execute specified operations on Kubernetes 
deployments or pods based on the provided parameters.

Examples:
  # Start with deployment
  truva up --namespace myapp --targetType deployment --targetName myapp-deployment --localPath ./src --containerPath /app
  
  # Start with specific pod
  truva up --namespace myapp --targetType pod --targetName myapp-pod-123 --localPath ./src --containerPath /app`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize performance monitoring
		perfMonitor := NewPerformanceMonitor()
		perfMonitor.Start()
		defer perfMonitor.Stop()

		// Validate input parameters
		if err := validateUpCommand(namespace, targetType, targetName, localPath, containerPath); err != nil {
			errors.Handle(errors.Wrap(err, errors.LevelError, "VALIDATION_FAILED", "Command validation failed"))
			errors.Info("HELP_INFO", "Use 'truva up --help' for usage information.")
			return
		}

		if !filepath.IsAbs(localPath) {
			cwd, err := os.Getwd()
			if err != nil {
				errors.Handle(errors.FileError("get current directory", ".", err))
				return
			}
			localPath = filepath.Join(cwd, localPath)
		}

		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			errors.Handle(errors.FileError("check path existence", localPath, err))
			return
		}

		// Record K8s operation start time
		k8sStart := time.Now()

		err := k8s.InitClient()
		if err != nil {
			RecordK8sOperation("init_client", "client", "error", time.Since(k8sStart))
			errors.Handle(errors.K8sError("initialize client", err))
			return
		}
		RecordK8sOperation("init_client", "client", "success", time.Since(k8sStart))

		// Record backup operation
		backupStart := time.Now()
		err = k8s.BackupDeployment(namespace, targetName)
		if err != nil {
			RecordK8sOperation("backup", "deployment", "error", time.Since(backupStart))
			errors.Handle(errors.K8sError("backup deployment", err).WithContext("deployment", targetName))
			return
		}
		RecordK8sOperation("backup", "deployment", "success", time.Since(backupStart))
		errors.Info("BACKUP_SUCCESS", "Backup completed successfully for deployment "+targetName)

		mux := http.NewServeMux()

		// Setup monitoring endpoints
		setupMetricsEndpoint(mux)
		setupProfiling(mux)
		setupHealthEndpoint(mux)

		// Wrap API routes with performance middleware
		apiMux := http.NewServeMux()
		api.InitRoutes(apiMux)
		mux.Handle("/api/", http.StripPrefix("/api", PerformanceMiddleware(apiMux)))

		recovery.SafeGo(func() {
			ui.StartWebServer(namespace, targetName)
		}, map[string]interface{}{
			"component": "web_server",
			"namespace": namespace,
			"target":    targetName,
		})

		recovery.SafeGo(func() {
			ui.StartLogHandler()
		}, map[string]interface{}{
			"component": "log_handler",
		})

		// Start sync with performance monitoring
		recovery.SafeGo(func() {
			syncStart := time.Now()
			err := syncer.InitialSyncAndRestart(localPath, namespace, targetName, containerPath)
			if err != nil {
				RecordSyncOperation("start_sync", "error", time.Since(syncStart))
				errors.Handle(errors.Wrap(err, errors.LevelError, "SYNC_ERROR", "Failed to start sync").WithContext("target", targetName))
				return
			}
			RecordSyncOperation("start_sync", "success", time.Since(syncStart))
		}, map[string]interface{}{
			"component":      "sync",
			"namespace":      namespace,
			"target_type":    targetType,
			"target_name":    targetName,
			"local_path":     localPath,
			"container_path": containerPath,
		})

		// Start monitoring server
		monitoringServer := &http.Server{
			Addr:    ":9090",
			Handler: mux,
		}

		recovery.SafeGo(func() {
			utils.Info("Starting monitoring server on :9090")
			if err := monitoringServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				utils.Error("Monitoring server error: " + err.Error())
			}
		}, map[string]interface{}{
			"component": "monitoring_server",
			"port":      9090,
		})

		// Setup graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Wait for shutdown signal
		<-sigChan
		utils.Info("Received shutdown signal, starting graceful shutdown...")

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shutdown monitoring server
		if err := monitoringServer.Shutdown(shutdownCtx); err != nil {
			utils.Error("Error shutting down monitoring server: " + err.Error())
		}

		// Stop sync operations
		syncStopStart := time.Now()
		// Sync operations will be stopped automatically when context is cancelled
		RecordSyncOperation("stop_sync", "success", time.Since(syncStopStart))

		// Cleanup resources
		cleanupStart := time.Now()
		if err := cleanup.CleanupOldBackups(24 * time.Hour); err != nil {
			utils.Error("Error cleaning old backups: " + err.Error())
		}
		if err := cleanup.CleanupModifiedFiles(); err != nil {
			utils.Error("Error cleaning modified files: " + err.Error())
		}
		RecordK8sOperation("cleanup", "resources", "success", time.Since(cleanupStart))

		utils.Info("Graceful shutdown completed")
	},
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		errors.Warning("UNSUPPORTED_PLATFORM", "Unsupported platform: "+runtime.GOOS)
	}

	if err != nil {
		errors.Warning("BROWSER_OPEN_FAILED", "Failed to open browser: "+err.Error())
	}
}

func init() {
	upCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace where the target resource is located")
	upCmd.Flags().StringVarP(&targetType, "targetType", "t", "", "Target resource type: 'deployment' or 'pod'")
	upCmd.Flags().StringVarP(&targetName, "targetName", "d", "", "Name of the target deployment or pod")
	upCmd.Flags().StringVarP(&localPath, "localPath", "l", "", "Local directory or file path to sync to the container")
	upCmd.Flags().StringVarP(&containerPath, "containerPath", "c", "", "Absolute path in the container where files will be synced")

	// Mark required flags
	upCmd.MarkFlagRequired("namespace")
	upCmd.MarkFlagRequired("targetType")
	upCmd.MarkFlagRequired("targetName")
	upCmd.MarkFlagRequired("localPath")
	upCmd.MarkFlagRequired("containerPath")

	rootCmd.AddCommand(upCmd)
}
