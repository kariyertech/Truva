package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// RateLimiter represents a rate limiter for HTTP requests
type RateLimiter struct {
	clients map[string]*ClientLimiter
	mu      sync.RWMutex
	config  *Config
}

// ClientLimiter tracks rate limiting for a specific client
type ClientLimiter struct {
	tokens     int
	lastRefill time.Time
	mu         sync.Mutex
}

// Config holds rate limiting configuration
type Config struct {
	RequestsPerMinute int           // Number of requests allowed per minute
	BurstSize         int           // Maximum burst size
	CleanupInterval   time.Duration // How often to clean up old clients
	BlockDuration     time.Duration // How long to block clients that exceed limits
	Whitelist         []string      // IP addresses to whitelist
	Enabled           bool          // Whether rate limiting is enabled
}

// DefaultConfig returns a default rate limiting configuration
func DefaultConfig() *Config {
	return &Config{
		RequestsPerMinute: 60,
		BurstSize:         10,
		CleanupInterval:   5 * time.Minute,
		BlockDuration:     1 * time.Minute,
		Whitelist:         []string{"127.0.0.1", "::1"},
		Enabled:           true,
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *Config) *RateLimiter {
	if config == nil {
		config = DefaultConfig()
	}

	rl := &RateLimiter{
		clients: make(map[string]*ClientLimiter),
		config:  config,
	}

	// Start cleanup goroutine
	recovery.SafeGo(func() {
		rl.cleanup()
	}, map[string]interface{}{
		"component": "rate_limiter",
		"action":    "cleanup",
	})

	return rl
}

// getClientIP extracts the real client IP from the request
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isWhitelisted checks if an IP is in the whitelist
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	for _, whitelistedIP := range rl.config.Whitelist {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(r *http.Request) bool {
	if !rl.config.Enabled {
		return true
	}

	clientIP := rl.getClientIP(r)

	// Check if IP is whitelisted
	if rl.isWhitelisted(clientIP) {
		return true
	}

	rl.mu.Lock()
	client, exists := rl.clients[clientIP]
	if !exists {
		client = &ClientLimiter{
			tokens:     rl.config.BurstSize,
			lastRefill: time.Now(),
		}
		rl.clients[clientIP] = client
	}
	rl.mu.Unlock()

	client.mu.Lock()
	defer client.mu.Unlock()

	now := time.Now()
	timePassed := now.Sub(client.lastRefill)

	// Refill tokens based on time passed
	tokensToAdd := int(timePassed.Minutes() * float64(rl.config.RequestsPerMinute))
	if tokensToAdd > 0 {
		client.tokens += tokensToAdd
		if client.tokens > rl.config.BurstSize {
			client.tokens = rl.config.BurstSize
		}
		client.lastRefill = now
	}

	// Check if request can be allowed
	if client.tokens > 0 {
		client.tokens--
		return true
	}

	return false
}

// Middleware returns an HTTP middleware that applies rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(r) {
			clientIP := rl.getClientIP(r)
			utils.Logger.Warn(fmt.Sprintf("Rate limit exceeded for IP: %s, Path: %s", clientIP, r.URL.Path))

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rl.config.BlockDuration.Seconds()))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Rate limit exceeded","retry_after":"` + rl.config.BlockDuration.String() + `"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// cleanup removes old client entries to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, client := range rl.clients {
			client.mu.Lock()
			// Remove clients that haven't been active for twice the cleanup interval
			if now.Sub(client.lastRefill) > 2*rl.config.CleanupInterval {
				delete(rl.clients, ip)
			}
			client.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// GetStats returns current rate limiting statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled":        rl.config.Enabled,
		"active_clients": len(rl.clients),
		"config": map[string]interface{}{
			"requests_per_minute": rl.config.RequestsPerMinute,
			"burst_size":          rl.config.BurstSize,
			"block_duration":      rl.config.BlockDuration.String(),
		},
	}

	return stats
}

// WebSocketRateLimiter provides rate limiting for WebSocket connections
type WebSocketRateLimiter struct {
	connections map[string]*WSClientLimiter
	mu          sync.RWMutex
	config      *WSConfig
}

// WSClientLimiter tracks WebSocket rate limiting for a specific client
type WSClientLimiter struct {
	connectionCount int
	lastConnection  time.Time
	mu              sync.Mutex
}

// WSConfig holds WebSocket rate limiting configuration
type WSConfig struct {
	MaxConnections    int           // Maximum concurrent connections per IP
	ConnectionTimeout time.Duration // How long to track connections
	CleanupInterval   time.Duration // How often to clean up old entries
	Whitelist         []string      // IP addresses to whitelist
	Enabled           bool          // Whether WebSocket rate limiting is enabled
}

// DefaultWSConfig returns a default WebSocket rate limiting configuration
func DefaultWSConfig() *WSConfig {
	return &WSConfig{
		MaxConnections:    5,
		ConnectionTimeout: 1 * time.Hour,
		CleanupInterval:   10 * time.Minute,
		Whitelist:         []string{"127.0.0.1", "::1"},
		Enabled:           true,
	}
}

// NewWebSocketRateLimiter creates a new WebSocket rate limiter
func NewWebSocketRateLimiter(config *WSConfig) *WebSocketRateLimiter {
	if config == nil {
		config = DefaultWSConfig()
	}

	wsrl := &WebSocketRateLimiter{
		connections: make(map[string]*WSClientLimiter),
		config:      config,
	}

	// Start cleanup goroutine
	recovery.SafeGo(func() {
		wsrl.cleanup()
	}, map[string]interface{}{
		"component": "websocket_rate_limiter",
		"action":    "cleanup",
	})

	return wsrl
}

// AllowConnection checks if a WebSocket connection should be allowed
func (wsrl *WebSocketRateLimiter) AllowConnection(clientIP string) bool {
	if !wsrl.config.Enabled {
		return true
	}

	// Check if IP is whitelisted
	for _, whitelistedIP := range wsrl.config.Whitelist {
		if clientIP == whitelistedIP {
			return true
		}
	}

	wsrl.mu.Lock()
	client, exists := wsrl.connections[clientIP]
	if !exists {
		client = &WSClientLimiter{
			connectionCount: 0,
			lastConnection:  time.Now(),
		}
		wsrl.connections[clientIP] = client
	}
	wsrl.mu.Unlock()

	client.mu.Lock()
	defer client.mu.Unlock()

	// Check if connection limit is exceeded
	if client.connectionCount >= wsrl.config.MaxConnections {
		return false
	}

	client.connectionCount++
	client.lastConnection = time.Now()
	return true
}

// ReleaseConnection decrements the connection count for a client
func (wsrl *WebSocketRateLimiter) ReleaseConnection(clientIP string) {
	if !wsrl.config.Enabled {
		return
	}

	wsrl.mu.RLock()
	client, exists := wsrl.connections[clientIP]
	wsrl.mu.RUnlock()

	if !exists {
		return
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	if client.connectionCount > 0 {
		client.connectionCount--
	}
}

// cleanup removes old WebSocket client entries
func (wsrl *WebSocketRateLimiter) cleanup() {
	ticker := time.NewTicker(wsrl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		wsrl.mu.Lock()
		now := time.Now()
		for ip, client := range wsrl.connections {
			client.mu.Lock()
			// Remove clients with no connections and old last connection time
			if client.connectionCount == 0 && now.Sub(client.lastConnection) > wsrl.config.ConnectionTimeout {
				delete(wsrl.connections, ip)
			}
			client.mu.Unlock()
		}
		wsrl.mu.Unlock()
	}
}
