package health

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kariyertech/Truva.git/pkg/config"
)

type HealthStatus struct {
	Status    string           `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
	Version   string           `json:"version"`
	Uptime    string           `json:"uptime"`
	Checks    map[string]Check `json:"checks"`
}

type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

var startTime = time.Now()

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cfg := config.GetConfig()
	if !cfg.Monitoring.HealthCheckEnabled {
		http.Error(w, "Health check disabled", http.StatusServiceUnavailable)
		return
	}

	health := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0", // This could be injected at build time
		Uptime:    time.Since(startTime).String(),
		Checks:    make(map[string]Check),
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
