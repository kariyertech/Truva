package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/kariyertech/Truva.git/pkg/memory"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// MemoryAPI provides HTTP endpoints for memory monitoring and management
type MemoryAPI struct {
	monitor      *memory.MemoryMonitor
	leakDetector *memory.LeakDetector
	profiler     *memory.Profiler
}

// NewMemoryAPI creates a new memory API instance
func NewMemoryAPI() *MemoryAPI {
	return &MemoryAPI{}
}

// SetMonitor sets the memory monitor instance
func (api *MemoryAPI) SetMonitor(monitor *memory.MemoryMonitor) {
	api.monitor = monitor
}

// SetLeakDetector sets the leak detector instance
func (api *MemoryAPI) SetLeakDetector(detector *memory.LeakDetector) {
	api.leakDetector = detector
}

// SetProfiler sets the profiler instance
func (api *MemoryAPI) SetProfiler(profiler *memory.Profiler) {
	api.profiler = profiler
}

// RegisterRoutes registers memory-related HTTP routes
func (api *MemoryAPI) RegisterRoutes(router *mux.Router) {
	memoryRouter := router.PathPrefix("/api/memory").Subrouter()

	// Memory statistics endpoints
	memoryRouter.HandleFunc("/stats", api.getMemoryStats).Methods("GET")
	memoryRouter.HandleFunc("/stats/detailed", api.getDetailedMemoryStats).Methods("GET")

	// Memory management endpoints
	memoryRouter.HandleFunc("/gc", api.forceGarbageCollection).Methods("POST")
	memoryRouter.HandleFunc("/gc/stats", api.getGCStats).Methods("GET")

	// Leak detection endpoints
	memoryRouter.HandleFunc("/leaks/status", api.getLeakDetectionStatus).Methods("GET")
	memoryRouter.HandleFunc("/leaks/reset", api.resetLeakDetection).Methods("POST")

	// Profiling endpoints
	memoryRouter.HandleFunc("/profile/snapshot", api.captureMemorySnapshot).Methods("POST")
	memoryRouter.HandleFunc("/profile/analyze", api.analyzeMemoryGrowth).Methods("POST")

	// Health check endpoint
	memoryRouter.HandleFunc("/health", api.getMemoryHealth).Methods("GET")
}

// getMemoryStats returns basic memory statistics
func (api *MemoryAPI) getMemoryStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.monitor == nil {
		http.Error(w, "Memory monitor not available", http.StatusServiceUnavailable)
		return
	}

	stats := api.monitor.GetCurrentStats()
	response := map[string]interface{}{
		"timestamp":     time.Now().Unix(),
		"memory_mb":     stats.Alloc / (1024 * 1024),
		"memory_sys_mb": stats.Sys / (1024 * 1024),
		"goroutines":    stats.Goroutines,
		"gc_cycles":     stats.NumGC,
		"status":        "ok",
	}

	json.NewEncoder(w).Encode(response)
}

// getDetailedMemoryStats returns detailed memory statistics
func (api *MemoryAPI) getDetailedMemoryStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"timestamp": time.Now().Unix(),
	}

	// Add monitor stats if available
	if api.monitor != nil {
		stats := api.monitor.GetCurrentStats()
		response["monitor"] = map[string]interface{}{
			"memory_alloc_mb":   stats.Alloc / (1024 * 1024),
			"memory_total_mb":   stats.TotalAlloc / (1024 * 1024),
			"memory_sys_mb":     stats.Sys / (1024 * 1024),
			"goroutines":        stats.Goroutines,
			"gc_cycles":         stats.NumGC,
			"monitoring_active": true,
		}
	} else {
		response["monitor"] = map[string]interface{}{
			"monitoring_active": false,
		}
	}

	// Add leak detector stats if available
	if api.leakDetector != nil {
		response["leak_detection"] = api.leakDetector.GetCurrentStatus()
	} else {
		response["leak_detection"] = map[string]interface{}{
			"active": false,
		}
	}

	// Add profiler stats if available
	if api.profiler != nil {
		response["profiler"] = map[string]interface{}{
			"active":        true,
			"current_usage": api.profiler.GetMemoryUsage(),
		}
	} else {
		response["profiler"] = map[string]interface{}{
			"active": false,
		}
	}

	json.NewEncoder(w).Encode(response)
}

// forceGarbageCollection triggers garbage collection
func (api *MemoryAPI) forceGarbageCollection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.monitor == nil {
		http.Error(w, "Memory monitor not available", http.StatusServiceUnavailable)
		return
	}

	before, after := api.monitor.ForceGC()

	response := map[string]interface{}{
		"timestamp":        time.Now().Unix(),
		"gc_triggered":     true,
		"memory_before_mb": before.Alloc / (1024 * 1024),
		"memory_after_mb":  after.Alloc / (1024 * 1024),
		"memory_freed_mb":  (before.Alloc - after.Alloc) / (1024 * 1024),
		"gc_cycles":        after.NumGC,
	}

	utils.Logger.Info(fmt.Sprintf("Manual GC triggered via API: %d MB -> %d MB",
		before.Alloc/(1024*1024), after.Alloc/(1024*1024)))

	json.NewEncoder(w).Encode(response)
}

// getGCStats returns garbage collection statistics
func (api *MemoryAPI) getGCStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.monitor == nil {
		http.Error(w, "Memory monitor not available", http.StatusServiceUnavailable)
		return
	}

	stats := api.monitor.GetCurrentStats()
	response := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"gc_cycles": stats.NumGC,
		"memory_mb": stats.Alloc / (1024 * 1024),
		"sys_mb":    stats.Sys / (1024 * 1024),
	}

	json.NewEncoder(w).Encode(response)
}

// getLeakDetectionStatus returns leak detection status
func (api *MemoryAPI) getLeakDetectionStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.leakDetector == nil {
		response := map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"active":    false,
			"message":   "Leak detection not available",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	status := api.leakDetector.GetCurrentStatus()
	status["timestamp"] = time.Now().Unix()
	json.NewEncoder(w).Encode(status)
}

// resetLeakDetection resets the leak detection baseline
func (api *MemoryAPI) resetLeakDetection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.leakDetector == nil {
		http.Error(w, "Leak detector not available", http.StatusServiceUnavailable)
		return
	}

	api.leakDetector.ResetBaseline()

	response := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"reset":     true,
		"message":   "Leak detection baseline reset successfully",
	}

	utils.Logger.Info("Leak detection baseline reset via API")
	json.NewEncoder(w).Encode(response)
}

// captureMemorySnapshot captures a memory profile snapshot
func (api *MemoryAPI) captureMemorySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.profiler == nil {
		http.Error(w, "Profiler not available", http.StatusServiceUnavailable)
		return
	}

	// Get snapshot name from query parameter
	snapshotName := r.URL.Query().Get("name")
	if snapshotName == "" {
		snapshotName = "api_request"
	}

	err := api.profiler.CaptureSnapshot(snapshotName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to capture snapshot: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"timestamp":     time.Now().Unix(),
		"snapshot_name": snapshotName,
		"captured":      true,
		"message":       "Memory snapshot captured successfully",
	}

	utils.Logger.Info(fmt.Sprintf("Memory snapshot captured via API: %s", snapshotName))
	json.NewEncoder(w).Encode(response)
}

// analyzeMemoryGrowth analyzes memory growth over a specified duration
func (api *MemoryAPI) analyzeMemoryGrowth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if api.profiler == nil {
		http.Error(w, "Profiler not available", http.StatusServiceUnavailable)
		return
	}

	// Get duration from query parameter (default: 60 seconds)
	durationStr := r.URL.Query().Get("duration")
	duration := 60 * time.Second
	if durationStr != "" {
		if seconds, err := strconv.Atoi(durationStr); err == nil && seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}

	// Limit analysis duration to prevent long-running requests
	if duration > 5*time.Minute {
		duration = 5 * time.Minute
	}

	analysis := api.profiler.AnalyzeMemoryGrowth(duration)

	response := map[string]interface{}{
		"timestamp":         time.Now().Unix(),
		"analysis_duration": duration.Seconds(),
		"initial_memory_mb": analysis.InitialMemory / (1024 * 1024),
		"final_memory_mb":   analysis.FinalMemory / (1024 * 1024),
		"growth_rate_kb_s":  analysis.GrowthRate / 1024,
		"gc_efficiency":     analysis.GCEfficiency,
		"goroutine_growth":  analysis.GoroutineGrowth,
		"leak_suspected":    analysis.IsMemoryLeakSuspected(),
		"analysis_summary":  analysis.String(),
	}

	utils.Logger.Info(fmt.Sprintf("Memory growth analysis completed via API: %v duration", duration))
	json.NewEncoder(w).Encode(response)
}

// getMemoryHealth returns overall memory health status
func (api *MemoryAPI) getMemoryHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"status":    "healthy",
		"checks":    make(map[string]interface{}),
	}

	checks := health["checks"].(map[string]interface{})

	// Check memory monitor
	if api.monitor != nil {
		stats := api.monitor.GetCurrentStats()
		memoryMB := stats.Alloc / (1024 * 1024)

		memoryStatus := "healthy"
		if memoryMB > 500 {
			memoryStatus = "warning"
			health["status"] = "warning"
		}
		if memoryMB > 1000 {
			memoryStatus = "critical"
			health["status"] = "critical"
		}

		checks["memory_monitor"] = map[string]interface{}{
			"status":     memoryStatus,
			"memory_mb":  memoryMB,
			"goroutines": stats.Goroutines,
			"available":  true,
		}
	} else {
		checks["memory_monitor"] = map[string]interface{}{
			"status":    "unavailable",
			"available": false,
		}
	}

	// Check leak detector
	if api.leakDetector != nil {
		status := api.leakDetector.GetCurrentStatus()
		leakStatus := "healthy"
		if growthRate, ok := status["growth_rate_kb_s"].(float64); ok && growthRate > 1024 {
			leakStatus = "warning"
			if health["status"] == "healthy" {
				health["status"] = "warning"
			}
		}

		checks["leak_detector"] = map[string]interface{}{
			"status":    leakStatus,
			"running":   status["running"],
			"available": true,
		}
	} else {
		checks["leak_detector"] = map[string]interface{}{
			"status":    "unavailable",
			"available": false,
		}
	}

	// Check profiler
	checks["profiler"] = map[string]interface{}{
		"available": api.profiler != nil,
	}

	json.NewEncoder(w).Encode(health)
}
