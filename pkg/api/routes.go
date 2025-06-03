package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/auth"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/ratelimit"
	"github.com/kariyertech/Truva.git/pkg/utils"
	"github.com/kariyertech/Truva.git/pkg/validation"
)

func syncHandler(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	deployment := r.URL.Query().Get("deployment")
	localPath := r.URL.Query().Get("local-path")
	containerPath := r.URL.Query().Get("container-path")

	// Get user info for audit logging
	userID := getUserIDFromContext(r)
	clientIP := getClientIP(r)
	resource := "deployment:" + namespace + "/" + deployment

	// Basic parameter check
	if namespace == "" || deployment == "" || localPath == "" || containerPath == "" {
		utils.AuditError(userID, clientIP, resource, "sync", "missing required parameters", map[string]interface{}{
			"namespace":      namespace,
			"deployment":     deployment,
			"local_path":     localPath,
			"container_path": containerPath,
		})
		http.Error(w, "Missing required query parameters", http.StatusBadRequest)
		return
	}

	// Validate input parameters
	validator := validation.NewValidator()
	validationErrors := validator.ValidateQueryParams(namespace, deployment, localPath, containerPath)
	if len(validationErrors) > 0 {
		errorMessages := make([]string, len(validationErrors))
		for i, err := range validationErrors {
			errorMessages[i] = err.Error()
		}
		utils.AuditError(userID, clientIP, resource, "sync", "validation failed", map[string]interface{}{
			"validation_errors": errorMessages,
		})
		http.Error(w, "Validation failed: "+strings.Join(errorMessages, "; "), http.StatusBadRequest)
		return
	}

	// Audit the sync operation
	utils.AuditAdminAction(userID, clientIP, resource, "sync", map[string]interface{}{
		"namespace":      namespace,
		"deployment":     deployment,
		"local_path":     localPath,
		"container_path": containerPath,
	})

	err := k8s.ModifyDeployment(namespace, deployment)
	if err != nil {
		utils.AuditError(userID, clientIP, resource, "sync", "deployment modification failed: "+err.Error(), nil)
		http.Error(w, "Failed to modify deployment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"message": "Deployment modified successfully"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func logHandler(w http.ResponseWriter, r *http.Request) {
	// Validate content length
	if r.ContentLength > 10*1024*1024 { // 10MB limit
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read and validate request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Validate JSON input for potential injection
	validator := validation.NewValidator()
	if err := validator.ValidateJSONInput(string(body)); err != nil {
		http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Sanitize the input
	sanitizedBody := validator.SanitizeString(string(body))

	logFile, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Failed to open log file", http.StatusInternalServerError)
		return
	}
	defer logFile.Close()

	_, err = logFile.WriteString(sanitizedBody + "\n")
	if err != nil {
		http.Error(w, "Failed to write logs", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func InitRoutes(mux *http.ServeMux) {
	// Initialize configuration
	cfg := config.GetConfig()

	// Initialize rate limiter
	rateLimiter := ratelimit.NewRateLimiter(&ratelimit.Config{
		RequestsPerMinute: cfg.RateLimit.RequestsPerMinute,
		BurstSize:         cfg.RateLimit.BurstSize,
		CleanupInterval:   5 * time.Minute,
		BlockDuration:     cfg.RateLimit.BlockDuration,
		Whitelist:         cfg.RateLimit.Whitelist,
		Enabled:           cfg.RateLimit.Enabled,
	})

	// Initialize authentication manager
	authManager := auth.NewAuthManager(&auth.AuthConfig{
		Enabled:     cfg.Auth.Enabled,
		RequireAuth: cfg.Auth.RequireAuth,
		JWTSecret:   cfg.Auth.JWTSecret,
		TokenExpiry: cfg.Auth.TokenExpiry,
		APIKeys:     cfg.Auth.APIKeys,
	})

	// Protected API endpoints
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/sync", syncHandler)
	protectedMux.HandleFunc("/api/logs", logHandler)

	// Add rate limiting stats endpoint
	protectedMux.HandleFunc("/api/rate-limit/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := rateLimiter.GetStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// Apply middleware chain: rate limiting -> authentication
	middlewareChain := rateLimiter.Middleware(authManager.AuthMiddleware(protectedMux))
	mux.Handle("/api/", http.StripPrefix("/api", middlewareChain))
}

// getUserIDFromContext extracts user ID from request context
func getUserIDFromContext(r *http.Request) string {
	if userCtx := r.Context().Value(auth.UserContextKey); userCtx != nil {
		if claims, ok := userCtx.(*auth.Claims); ok {
			return claims.UserID
		}
	}
	return "anonymous"
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}
