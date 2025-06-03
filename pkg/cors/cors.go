package cors

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
	Enabled          bool
}

// DefaultCORSConfig returns a default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
		Enabled:          true,
	}
}

// CORSMiddleware creates a CORS middleware
type CORSMiddleware struct {
	config *CORSConfig
}

// NewCORSMiddleware creates a new CORS middleware instance
func NewCORSMiddleware(config *CORSConfig) *CORSMiddleware {
	if config == nil {
		config = DefaultCORSConfig()
	}
	return &CORSMiddleware{config: config}
}

// isOriginAllowed checks if the origin is allowed
func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	if !c.config.Enabled {
		return true
	}

	if origin == "" {
		return false
	}

	// Check for wildcard
	for _, allowedOrigin := range c.config.AllowedOrigins {
		if allowedOrigin == "*" {
			return true
		}
		if origin == allowedOrigin {
			return true
		}
	}

	return false
}

// Handler wraps an HTTP handler with CORS support
func (c *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			c.handlePreflight(w, r, origin)
			return
		}

		// Handle actual requests
		c.handleActualRequest(w, r, origin)
		next.ServeHTTP(w, r)
	})
}

// handlePreflight handles CORS preflight requests
func (c *CORSMiddleware) handlePreflight(w http.ResponseWriter, r *http.Request, origin string) {
	if !c.isOriginAllowed(origin) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Set CORS headers for preflight
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.config.AllowedMethods, ", "))
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.config.AllowedHeaders, ", "))

	if c.config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if c.config.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(c.config.MaxAge))
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleActualRequest handles actual CORS requests
func (c *CORSMiddleware) handleActualRequest(w http.ResponseWriter, r *http.Request, origin string) {
	if !c.isOriginAllowed(origin) {
		return // Don't set CORS headers for disallowed origins
	}

	// Set CORS headers for actual requests
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if len(c.config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.config.ExposedHeaders, ", "))
	}

	if c.config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// HandlerFunc wraps an HTTP handler function with CORS support
func (c *CORSMiddleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return c.Handler(next).ServeHTTP
}
