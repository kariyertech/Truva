package ui

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/api"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/cors"
	"github.com/kariyertech/Truva.git/pkg/health"
	"github.com/kariyertech/Truva.git/pkg/ratelimit"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// BufferConfig holds dynamic buffer configuration
type BufferConfig struct {
	MinSize         int           // Minimum buffer size
	MaxSize         int           // Maximum buffer size
	GrowthFactor    float64       // Growth factor when scaling up
	ShrinkFactor    float64       // Shrink factor when scaling down
	MemoryThreshold float64       // Memory usage threshold (0.0-1.0)
	CheckInterval   time.Duration // Interval to check memory usage
}

// DefaultBufferConfig returns default buffer configuration
func DefaultBufferConfig() *BufferConfig {
	return &BufferConfig{
		MinSize:         1024,  // 1KB minimum
		MaxSize:         65536, // 64KB maximum
		GrowthFactor:    1.5,   // 50% growth
		ShrinkFactor:    0.75,  // 25% shrink
		MemoryThreshold: 0.8,   // 80% memory threshold
		CheckInterval:   5 * time.Second,
	}
}

// DynamicBuffer manages dynamic buffer sizing based on memory pressure
type DynamicBuffer struct {
	mu          sync.RWMutex
	currentSize int64
	config      *BufferConfig
	memStats    runtime.MemStats
	lastCheck   time.Time
	adjustments int64
}

// NewDynamicBuffer creates a new dynamic buffer manager
func NewDynamicBuffer(config *BufferConfig) *DynamicBuffer {
	if config == nil {
		config = DefaultBufferConfig()
	}

	db := &DynamicBuffer{
		currentSize: int64(config.MinSize),
		config:      config,
		lastCheck:   time.Now(),
	}

	// Start memory monitoring
	go db.monitorMemory()

	return db
}

// GetBufferSize returns the current optimal buffer size
func (db *DynamicBuffer) GetBufferSize() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return int(atomic.LoadInt64(&db.currentSize))
}

// monitorMemory continuously monitors memory usage and adjusts buffer size
func (db *DynamicBuffer) monitorMemory() {
	ticker := time.NewTicker(db.config.CheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		db.adjustBufferSize()
	}
}

// adjustBufferSize adjusts buffer size based on current memory pressure
func (db *DynamicBuffer) adjustBufferSize() {
	runtime.ReadMemStats(&db.memStats)

	// Calculate memory usage percentage
	memoryUsage := float64(db.memStats.Alloc) / float64(db.memStats.Sys)

	db.mu.Lock()
	defer db.mu.Unlock()

	currentSize := atomic.LoadInt64(&db.currentSize)
	newSize := currentSize

	if memoryUsage > db.config.MemoryThreshold {
		// High memory pressure - shrink buffer
		newSize = int64(float64(currentSize) * db.config.ShrinkFactor)
		if newSize < int64(db.config.MinSize) {
			newSize = int64(db.config.MinSize)
		}
	} else if memoryUsage < db.config.MemoryThreshold*0.5 {
		// Low memory pressure - grow buffer
		newSize = int64(float64(currentSize) * db.config.GrowthFactor)
		if newSize > int64(db.config.MaxSize) {
			newSize = int64(db.config.MaxSize)
		}
	}

	if newSize != currentSize {
		atomic.StoreInt64(&db.currentSize, newSize)
		atomic.AddInt64(&db.adjustments, 1)
		utils.Logger.Debug(fmt.Sprintf("Buffer size adjusted from %d to %d (memory usage: %.2f%%)",
			currentSize, newSize, memoryUsage*100))
	}

	db.lastCheck = time.Now()
}

// GetStats returns buffer statistics
func (db *DynamicBuffer) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
		"current_size": atomic.LoadInt64(&db.currentSize),
		"min_size":     db.config.MinSize,
		"max_size":     db.config.MaxSize,
		"adjustments":  atomic.LoadInt64(&db.adjustments),
		"last_check":   db.lastCheck,
		"memory_alloc": db.memStats.Alloc,
		"memory_sys":   db.memStats.Sys,
		"memory_usage": float64(db.memStats.Alloc) / float64(db.memStats.Sys),
	}
}

// Global dynamic buffer instance
var (
	globalDynamicBuffer *DynamicBuffer
	bufferOnce          sync.Once
)

// GetDynamicBuffer returns the global dynamic buffer instance
func GetDynamicBuffer() *DynamicBuffer {
	bufferOnce.Do(func() {
		globalDynamicBuffer = NewDynamicBuffer(DefaultBufferConfig())
	})
	return globalDynamicBuffer
}

var upgrader = websocket.Upgrader{
	CheckOrigin:      checkOrigin,
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   GetDynamicBuffer().GetBufferSize(),
	WriteBufferSize:  GetDynamicBuffer().GetBufferSize(),
}

// UpdateUpgraderBuffers updates WebSocket upgrader buffer sizes
func UpdateUpgraderBuffers() {
	bufferSize := GetDynamicBuffer().GetBufferSize()
	upgrader.ReadBufferSize = bufferSize
	upgrader.WriteBufferSize = bufferSize
}

// checkOrigin validates WebSocket origin based on configuration
func checkOrigin(r *http.Request) bool {
	cfg := config.GetConfig()
	if !cfg.Auth.Enabled {
		return true // Allow all origins in development mode
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false // Reject requests without origin
	}

	// Add your allowed origins here
	allowedOrigins := []string{
		"http://localhost:8080",
		"https://localhost:8080",
		"http://127.0.0.1:8080",
		"https://127.0.0.1:8080",
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	return false
}

// StartWebServer starts the web server with the given namespace and target name
func StartWebServer(namespace, targetName string) {
	// Create main context for the application
	mainCtx := context.Background()

	// Initialize WebSocket manager
	wsManager := NewWebSocketManager(mainCtx)

	// Initialize configuration
	cfg := config.GetConfig()

	// Initialize WebSocket rate limiter
	wsRateLimiter := ratelimit.NewWebSocketRateLimiter(&ratelimit.WSConfig{
		Enabled:           cfg.RateLimit.WebSocket.Enabled,
		MaxConnections:    cfg.RateLimit.WebSocket.MaxConnections,
		ConnectionTimeout: cfg.RateLimit.WebSocket.ConnectionTimeout,
		CleanupInterval:   10 * time.Minute,
		Whitelist:         cfg.RateLimit.WebSocket.Whitelist,
	})

	// Start buffer size monitoring
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			UpdateUpgraderBuffers()
		}
	}()

	// Create HTTP server mux
	mux := http.NewServeMux()

	// Initialize API routes
	api.InitRoutes(mux)

	// Add WebSocket endpoint
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		logWebSocketHandler(w, r, namespace, targetName, wsRateLimiter)
	})

	// Add health check endpoint
	mux.HandleFunc("/health", health.HealthHandler)

	// Add buffer stats endpoint
	mux.HandleFunc("/api/buffer-stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := GetDynamicBuffer().GetStats()
		utils.WriteJSONResponse(w, stats)
	})

	// Add root handler to serve index.html with template rendering
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	    client, err := k8s.NewKubernetesClient()
	    if err != nil {
	        http.Error(w, "Failed to create Kubernetes client", http.StatusInternalServerError)
	        return
	    }
	    labelSelector, err := k8s.GetDeploymentSelector(namespace, targetName)
	    if err != nil {
	        http.Error(w, "Failed to get deployment selector", http.StatusInternalServerError)
	        return
	    }
	    pods, err := client.GetPodNames(namespace, labelSelector)
	    if err != nil {
	        http.Error(w, "Failed to get pods", http.StatusInternalServerError)
	        return
	    }
	    tmpl, err := template.ParseFiles("templates/index.html")
	    if err != nil {
	        http.Error(w, "Failed to parse template", http.StatusInternalServerError)
	        return
	    }
	    err = tmpl.Execute(w, pods)
	    if err != nil {
	        http.Error(w, "Failed to execute template", http.StatusInternalServerError)
	        return
	    }
	})

	// CORS configuration
	corsConfig := cors.DefaultCORSConfig()
	corsHandler := cors.NewCORSMiddleware(corsConfig).Handler(mux)

	// Create servers
	var httpServer, httpsServer *http.Server
	var serverErrors = make(chan error, 2)

	// Start HTTP server
	httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: corsHandler,
	}

	go func() {
		utils.Logger.Info(fmt.Sprintf("Starting HTTP server on %s:%d", cfg.Server.Host, cfg.Server.Port))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if TLS is enabled
	if cfg.Server.TLS.Enabled {
		httpsServer = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.TLS.HTTPSPort),
			Handler: corsHandler,
		}

		go func() {
			utils.Logger.Info(fmt.Sprintf("Starting HTTPS server on %s:%d", cfg.Server.Host, cfg.Server.TLS.HTTPSPort))
			if err := httpsServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrors <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal or server error
	select {
	case <-stop:
		utils.Logger.Info("Received shutdown signal")
	case err := <-serverErrors:
		utils.Logger.Error(fmt.Sprintf("Server error: %v", err))
		os.Exit(1)
	}

	// Graceful shutdown
	utils.Logger.Info("Shutting down servers gracefully...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Close all WebSocket connections
	wsManager.CloseAllConnections()

	// Shutdown servers
	if httpServer != nil {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			utils.Logger.Error(fmt.Sprintf("HTTP server forced to shutdown: %v", err))
		}
	}

	if httpsServer != nil {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			utils.Logger.Error(fmt.Sprintf("HTTPS server forced to shutdown: %v", err))
		}
	}

	utils.Logger.Info("Servers gracefully stopped")
}

// WebSocketManager manages WebSocket connections with enhanced buffer management
type WebSocketManager struct {
	connections      map[*websocket.Conn]*ConnectionInfo
	mutex            sync.RWMutex
	ctx              context.Context
	maxConnections   int
	bytesTransmitted int64
	messagesSent     int64
}

// ConnectionInfo holds information about a WebSocket connection
type ConnectionInfo struct {
	conn         *websocket.Conn
	createdAt    time.Time
	lastActivity time.Time
	bytesWritten int64
	messagesSent int64
	bufferSize   int
}

// NewWebSocketManager creates a new WebSocket manager with enhanced features
func NewWebSocketManager(ctx context.Context) *WebSocketManager {
	return &WebSocketManager{
		connections:    make(map[*websocket.Conn]*ConnectionInfo),
		ctx:            ctx,
		maxConnections: 1000, // Default max connections
	}
}

// AddConnection adds a new WebSocket connection with buffer optimization
func (wsm *WebSocketManager) AddConnection(conn *websocket.Conn) error {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()

	if len(wsm.connections) >= wsm.maxConnections {
		return fmt.Errorf("maximum connections reached")
	}

	bufferSize := GetDynamicBuffer().GetBufferSize()
	wsm.connections[conn] = &ConnectionInfo{
		conn:         conn,
		createdAt:    time.Now(),
		lastActivity: time.Now(),
		bufferSize:   bufferSize,
	}

	return nil
}

// RemoveConnection removes a WebSocket connection
func (wsm *WebSocketManager) RemoveConnection(conn *websocket.Conn) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	delete(wsm.connections, conn)
	conn.Close()
}

// CloseAllConnections closes all WebSocket connections
func (wsm *WebSocketManager) CloseAllConnections() {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	for conn := range wsm.connections {
		conn.Close()
	}
	wsm.connections = make(map[*websocket.Conn]*ConnectionInfo)
}

// GetConnectionCount returns the number of active connections
func (wsm *WebSocketManager) GetConnectionCount() int {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()
	return len(wsm.connections)
}

// BroadcastMessage sends a message to all connected clients with optimized buffering
func (wsm *WebSocketManager) BroadcastMessage(message []byte) {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()

	for conn, info := range wsm.connections {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			utils.Logger.Error(fmt.Sprintf("Error broadcasting message: %v", err))
			delete(wsm.connections, conn)
			conn.Close()
		} else {
			// Update statistics
			info.lastActivity = time.Now()
			info.bytesWritten += int64(len(message))
			info.messagesSent++
			atomic.AddInt64(&wsm.bytesTransmitted, int64(len(message)))
			atomic.AddInt64(&wsm.messagesSent, 1)
		}
	}
}

// GetStats returns WebSocket manager statistics
func (wsm *WebSocketManager) GetStats() map[string]interface{} {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()

	return map[string]interface{}{
		"active_connections": len(wsm.connections),
		"max_connections":    wsm.maxConnections,
		"bytes_transmitted":  atomic.LoadInt64(&wsm.bytesTransmitted),
		"messages_sent":      atomic.LoadInt64(&wsm.messagesSent),
	}
}

// logWebSocketHandler handles WebSocket connections for log streaming with optimized buffering
func logWebSocketHandler(w http.ResponseWriter, r *http.Request, namespace, deployment string, wsRateLimiter *ratelimit.WebSocketRateLimiter) {
	// Rate limiting check
	if wsRateLimiter != nil && !wsRateLimiter.AllowConnection(r.RemoteAddr) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Update upgrader with current buffer sizes
	UpdateUpgraderBuffers()

	// Upgrade connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("WebSocket upgrade failed: %v", err))
		return
	}
	defer conn.Close()

	// Create context for this connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start log streaming with optimized buffering
	streamLogsOptimized(ctx, conn, namespace, deployment)
}

// streamLogsOptimized streams logs with dynamic buffer management and memory pressure handling
func streamLogsOptimized(ctx context.Context, conn *websocket.Conn, namespace, deployment string) {
	// Create Kubernetes client
	client, err := k8s.NewKubernetesClient()
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to create Kubernetes client: %v", err))
		return
	}

	// Get pods for the deployment
	pods, err := client.GetPodNames(namespace, deployment)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to get pods: %v", err))
		return
	}

	// Create buffered log channel with dynamic sizing
	bufferSize := GetDynamicBuffer().GetBufferSize()
	logChan := make(chan []byte, bufferSize/100) // Adjust channel buffer based on memory buffer

	// Stream logs from all pods
	for _, pod := range pods {
		go func(podName string) {
			err := client.StreamPodLogsWithContext(ctx, namespace, podName, conn.UnderlyingConn())
			if err != nil {
				utils.Logger.Error(fmt.Sprintf("Failed to stream logs from pod %s: %v", podName, err))
			}
		}(pod)
	}

	// Handle log rotation and memory pressure
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check memory pressure and adjust if needed
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryUsage := float64(m.Alloc) / float64(m.Sys)

				if memoryUsage > 0.9 {
					// High memory pressure - trigger GC and reduce buffer
					runtime.GC()
					utils.Logger.Warning(fmt.Sprintf("High memory pressure detected: %.2f%%, triggering cleanup", memoryUsage*100))
				}
			}
		}
	}()

	// Keep connection alive with optimized ping interval
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			// Send ping to keep connection alive
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case logData := <-logChan:
			// Send log data with current buffer optimization
			if err := conn.WriteMessage(websocket.TextMessage, logData); err != nil {
				return
			}
		}
	}
}

// streamLogs maintains backward compatibility
func streamLogs(ctx context.Context, conn *websocket.Conn, namespace, deployment string) {
	streamLogsOptimized(ctx, conn, namespace, deployment)
}
