package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kariyertech/Truva.git/pkg/config"
)

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name           string
		config         *config.Config
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "health check enabled",
			config: &config.Config{
				Monitoring: config.MonitoringConfig{
					HealthCheckEnabled: true,
				},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
		{
			name: "health check disabled",
			config: &config.Config{
				Monitoring: config.MonitoringConfig{
					HealthCheckEnabled: false,
				},
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Health check disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global config for test
			config.GlobalConfig = tt.config

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			HealthHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HealthHandler() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if !strings.Contains(w.Body.String(), tt.expectedBody) {
				t.Errorf("HealthHandler() body = %v, want to contain %v", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestReadinessHandler(t *testing.T) {
	tests := []struct {
		name           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "readiness check",
			expectedStatus: http.StatusOK,
			expectedBody:   "ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ready", nil)
			w := httptest.NewRecorder()

			ReadinessHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("ReadinessHandler() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if !strings.Contains(w.Body.String(), tt.expectedBody) {
				t.Errorf("ReadinessHandler() body = %v, want to contain %v", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestLivenessHandler(t *testing.T) {
	tests := []struct {
		name           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "liveness check",
			expectedStatus: http.StatusOK,
			expectedBody:   "alive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/live", nil)
			w := httptest.NewRecorder()

			LivenessHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("LivenessHandler() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if !strings.Contains(w.Body.String(), tt.expectedBody) {
				t.Errorf("LivenessHandler() body = %v, want to contain %v", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestHealthStatusJSON(t *testing.T) {
	startTime := time.Now()
	time.Sleep(10 * time.Millisecond) // Small delay to ensure uptime > 0

	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Uptime:    time.Since(startTime).String(),
		Checks: map[string]Check{
			"config": {
				Status:  "ok",
				Message: "Configuration loaded successfully",
			},
		},
	}

	jsonData, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Failed to marshal HealthStatus: %v", err)
	}

	var unmarshaled HealthStatus
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal HealthStatus: %v", err)
	}

	if unmarshaled.Status != status.Status {
		t.Errorf("Unmarshaled status = %v, want %v", unmarshaled.Status, status.Status)
	}
	if len(unmarshaled.Checks) != len(status.Checks) {
		t.Errorf("Unmarshaled checks length = %v, want %v", len(unmarshaled.Checks), len(status.Checks))
	}
	if unmarshaled.Checks["config"].Status != "ok" {
		t.Errorf("Unmarshaled config check status = %v, want %v", unmarshaled.Checks["config"].Status, "ok")
	}
}
