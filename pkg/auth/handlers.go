package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/pkg/utils"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	APIKey   string `json:"api_key,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Message   string    `json:"message"`
	Success   bool      `json:"success"`
}

// TokenRequest represents a token validation request
type TokenRequest struct {
	Token string `json:"token"`
}

// TokenResponse represents a token validation response
type TokenResponse struct {
	Valid    bool     `json:"valid"`
	UserID   string   `json:"user_id,omitempty"`
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Message  string   `json:"message"`
}

// LoginHandler handles login requests
func (am *AuthManager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseJSON(w, LoginResponse{
			Message: "Invalid request body",
			Success: false,
		}, http.StatusBadRequest)
		return
	}

	// Get client info for audit logging
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Check API key authentication
	if req.APIKey != "" {
		if am.ValidateAPIKey(req.APIKey) {
			// Generate token for API key user
			token, err := am.GenerateToken("api-user", "API User", []string{"api"})
			if err != nil {
				utils.AuditAuthFailure("api-user", clientIP, userAgent, "token generation failed")
				responseJSON(w, LoginResponse{
					Message: "Failed to generate token",
					Success: false,
				}, http.StatusInternalServerError)
				return
			}

			utils.AuditAuthSuccess("api-user", clientIP, userAgent, "api-session")
			responseJSON(w, LoginResponse{
				Token:     token,
				ExpiresAt: time.Now().Add(am.config.TokenExpiry),
				Message:   "Login successful",
				Success:   true,
			}, http.StatusOK)
			return
		}

		utils.AuditAuthFailure("api-user", clientIP, userAgent, "invalid API key")
		responseJSON(w, LoginResponse{
			Message: "Invalid API key",
			Success: false,
		}, http.StatusUnauthorized)
		return
	}

	// Simple username/password authentication (for demo purposes)
	// In production, this should integrate with your user management system
	if req.Username == "" || req.Password == "" {
		responseJSON(w, LoginResponse{
			Message: "Username and password are required",
			Success: false,
		}, http.StatusBadRequest)
		return
	}

	// Demo authentication - replace with real authentication logic
	if req.Username == "admin" && req.Password == "admin123" {
		token, err := am.GenerateToken("admin-user", req.Username, []string{"admin", "user"})
		if err != nil {
			utils.AuditAuthFailure(req.Username, clientIP, userAgent, "token generation failed")
			responseJSON(w, LoginResponse{
				Message: "Failed to generate token",
				Success: false,
			}, http.StatusInternalServerError)
			return
		}

		utils.AuditAuthSuccess("admin-user", clientIP, userAgent, "admin-session")
		responseJSON(w, LoginResponse{
			Token:     token,
			ExpiresAt: time.Now().Add(am.config.TokenExpiry),
			Message:   "Login successful",
			Success:   true,
		}, http.StatusOK)
		return
	}

	if req.Username == "user" && req.Password == "user123" {
		token, err := am.GenerateToken("regular-user", req.Username, []string{"user"})
		if err != nil {
			utils.AuditAuthFailure(req.Username, clientIP, userAgent, "token generation failed")
			responseJSON(w, LoginResponse{
				Message: "Failed to generate token",
				Success: false,
			}, http.StatusInternalServerError)
			return
		}

		utils.AuditAuthSuccess("regular-user", clientIP, userAgent, "user-session")
		responseJSON(w, LoginResponse{
			Token:     token,
			ExpiresAt: time.Now().Add(am.config.TokenExpiry),
			Message:   "Login successful",
			Success:   true,
		}, http.StatusOK)
		return
	}

	utils.AuditAuthFailure(req.Username, clientIP, userAgent, "invalid credentials")
	responseJSON(w, LoginResponse{
		Message: "Invalid credentials",
		Success: false,
	}, http.StatusUnauthorized)
}

// ValidateTokenHandler handles token validation requests
func (am *AuthManager) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseJSON(w, TokenResponse{
			Valid:   false,
			Message: "Invalid request body",
		}, http.StatusBadRequest)
		return
	}

	claims, err := am.ValidateToken(req.Token)
	if err != nil {
		responseJSON(w, TokenResponse{
			Valid:   false,
			Message: "Invalid token: " + err.Error(),
		}, http.StatusUnauthorized)
		return
	}

	responseJSON(w, TokenResponse{
		Valid:    true,
		UserID:   claims.UserID,
		Username: claims.Username,
		Roles:    claims.Roles,
		Message:  "Token is valid",
	}, http.StatusOK)
}

// LogoutHandler handles logout requests
func (am *AuthManager) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// In a real implementation, you might want to blacklist the token
	// For now, we just return a success response
	responseJSON(w, map[string]interface{}{
		"message": "Logout successful",
		"success": true,
	}, http.StatusOK)
}

// responseJSON sends a JSON response
func responseJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
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
