package ui

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/health"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin in development
	},
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   4096, // Increased for better performance
	WriteBufferSize:  4096, // Increased for better performance
}

// WebSocketConnection represents a WebSocket connection with metadata
type WebSocketConnection struct {
	conn     *websocket.Conn
	lastPong time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

// WebSocketManager manages active WebSocket connections
type WebSocketManager struct {
	connections map[*websocket.Conn]*WebSocketConnection
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(ctx context.Context) *WebSocketManager {
	ctx, cancel := context.WithCancel(ctx)
	wsm := &WebSocketManager{
		connections: make(map[*websocket.Conn]*WebSocketConnection),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start heartbeat monitoring
	go wsm.startHeartbeatMonitor()

	return wsm
}

// AddConnection adds a WebSocket connection to the manager
func (wsm *WebSocketManager) AddConnection(conn *websocket.Conn) {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	// Create context for this connection
	ctx, cancel := context.WithCancel(wsm.ctx)

	// Create WebSocket connection wrapper
	wsConn := &WebSocketConnection{
		conn:     conn,
		lastPong: time.Now(),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Set up pong handler
	conn.SetPongHandler(func(string) error {
		wsConn.lastPong = time.Now()
		return nil
	})

	// Set read deadline and ping/pong timeouts
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	wsm.connections[conn] = wsConn
	utils.Logger.Info(fmt.Sprintf("WebSocket connection added. Total connections: %d", len(wsm.connections)))
}

// RemoveConnection removes a WebSocket connection from the manager
func (wsm *WebSocketManager) RemoveConnection(conn *websocket.Conn) {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()
	if wsConn, exists := wsm.connections[conn]; exists {
		// Cancel the connection context
		wsConn.cancel()

		// Close the connection gracefully
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Connection closed"))
		conn.Close()

		// Remove from connections map
		delete(wsm.connections, conn)
		utils.Logger.Info(fmt.Sprintf("WebSocket connection removed. Total connections: %d", len(wsm.connections)))
	}
}

// CloseAllConnections closes all active WebSocket connections
func (wsm *WebSocketManager) CloseAllConnections() {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	utils.Logger.Info(fmt.Sprintf("Closing %d WebSocket connections...", len(wsm.connections)))
	for conn, wsConn := range wsm.connections {
		// Cancel connection context
		wsConn.cancel()

		// Send close message
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server shutting down"))
		conn.Close()
	}
	wsm.connections = make(map[*websocket.Conn]*WebSocketConnection)
	wsm.cancel()
}

// GetConnectionCount returns the number of active connections
func (wsm *WebSocketManager) GetConnectionCount() int {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()
	return len(wsm.connections)
}

// startHeartbeatMonitor monitors WebSocket connections and sends ping messages
func (wsm *WebSocketManager) startHeartbeatMonitor() {
	ticker := time.NewTicker(30 * time.Second) // Send ping every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wsm.sendPingToAll()
			wsm.cleanupStaleConnections()
		case <-wsm.ctx.Done():
			return
		}
	}
}

// sendPingToAll sends ping messages to all active connections
func (wsm *WebSocketManager) sendPingToAll() {
	wsm.mu.RLock()
	connections := make([]*websocket.Conn, 0, len(wsm.connections))
	for conn := range wsm.connections {
		connections = append(connections, conn)
	}
	wsm.mu.RUnlock()

	for _, conn := range connections {
		if err := conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
			utils.Logger.Error(fmt.Sprintf("Failed to send ping: %v", err))
			wsm.RemoveConnection(conn)
		}
	}
}

// cleanupStaleConnections removes connections that haven't responded to ping
func (wsm *WebSocketManager) cleanupStaleConnections() {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	staleTimeout := time.Now().Add(-90 * time.Second) // 90 seconds timeout
	staleConnections := make([]*websocket.Conn, 0)

	for conn, wsConn := range wsm.connections {
		if wsConn.lastPong.Before(staleTimeout) {
			staleConnections = append(staleConnections, conn)
		}
	}

	// Remove stale connections
	for _, conn := range staleConnections {
		utils.Logger.Info("Removing stale WebSocket connection")
		if wsConn, exists := wsm.connections[conn]; exists {
			wsConn.cancel()
			conn.Close()
			delete(wsm.connections, conn)
		}
	}

	if len(staleConnections) > 0 {
		utils.Logger.Info(fmt.Sprintf("Cleaned up %d stale connections. Active connections: %d", len(staleConnections), len(wsm.connections)))
	}
}

// BroadcastMessage sends a message to all active WebSocket connections
func (wsm *WebSocketManager) BroadcastMessage(message []byte) {
	wsm.mu.RLock()
	connections := make([]*websocket.Conn, 0, len(wsm.connections))
	for conn := range wsm.connections {
		connections = append(connections, conn)
	}
	wsm.mu.RUnlock()

	for _, conn := range connections {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			utils.Logger.Error(fmt.Sprintf("Failed to broadcast message: %v", err))
			wsm.RemoveConnection(conn)
		}
	}
}

var wsManager *WebSocketManager

// logWebSocketHandler handles WebSocket connections for real-time log streaming.
// This function upgrades HTTP connections to WebSocket and manages the complete lifecycle
// of log streaming from Kubernetes pods to connected clients. It implements:
//
// 1. WebSocket connection upgrade with proper error handling
// 2. Multi-container log streaming with automatic container discovery
// 3. Concurrent log processing from multiple pods and containers
// 4. Error aggregation and client notification
// 5. Graceful connection cleanup and resource management
// 6. Context-based cancellation for clean shutdown
//
// The handler discovers all containers in the specified deployment and streams logs
// from each container concurrently, prefixing each log line with [pod:container] for
// easy identification by clients.
//
// Parameters:
//   - w: HTTP ResponseWriter for WebSocket upgrade
//   - r: HTTP Request containing WebSocket upgrade headers
//   - namespace: Kubernetes namespace containing the target deployment
//   - deployment: Name of the deployment whose pod logs should be streamed
func logWebSocketHandler(w http.ResponseWriter, r *http.Request, namespace, deployment string) {
	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("WebSocket upgrade failed: %v", err))
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	// Add connection to manager
	wsManager.AddConnection(conn)
	defer func() {
		// Ensure connection is properly removed on exit
		wsManager.RemoveConnection(conn)
	}()

	// Get the connection context from manager
	wsm := wsManager
	wsm.mu.RLock()
	wsConn, exists := wsm.connections[conn]
	wsm.mu.RUnlock()

	if !exists {
		utils.Logger.Error("WebSocket connection not found in manager")
		return
	}

	logChannel := make(chan string, 500) // Increased buffer for high-volume logs
	errorChannel := make(chan error, 10) // Error channel for handling errors
	var wg sync.WaitGroup

	// Get deployment selector for label-based pod selection
	labelSelector, err := k8s.GetDeploymentSelectorWithContext(wsConn.ctx, namespace, deployment)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to get deployment selector: %v", err))
		errorChannel <- fmt.Errorf("deployment selector error: %w", err)
		return
	}

	// Get all containers from all pods matching the deployment
	containers, err := k8s.GetPodContainersWithContext(wsConn.ctx, namespace, labelSelector)
	if err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to get pod containers: %v", err))
		errorChannel <- fmt.Errorf("pod containers error: %w", err)
		return
	}

	utils.Logger.Info(fmt.Sprintf("Starting log streaming for %d containers", len(containers)))

	// Start log streaming goroutines for each container
	for _, container := range containers {
		wg.Add(1)
		go streamContainerLogsWithContext(wsConn.ctx, container, logChannel, errorChannel, &wg)
	}

	// Handle log messages and context cancellation
	go func() {
		defer close(logChannel)
		defer close(errorChannel)
		wg.Wait()
	}()

	// Main message handling loop with improved error handling
	for {
		select {
		case log, ok := <-logChannel:
			if !ok {
				utils.Logger.Info("Log channel closed, ending WebSocket session")
				return
			}

			// Set write deadline for each message
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

			if err := conn.WriteMessage(websocket.TextMessage, []byte(log)); err != nil {
				utils.Logger.Error(fmt.Sprintf("Failed to send log message: %v", err))
				return
			}

		case err, ok := <-errorChannel:
			if !ok {
				return
			}

			// Send error message to client
			errorMsg := fmt.Sprintf("Error: %v", err)
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

			if writeErr := conn.WriteMessage(websocket.TextMessage, []byte(errorMsg)); writeErr != nil {
				utils.Logger.Error(fmt.Sprintf("Failed to send error message: %v", writeErr))
				return
			}

		case <-wsConn.ctx.Done():
			utils.Logger.Info("WebSocket context cancelled, closing connection")
			return
		}
	}
}

// streamContainerLogsWithContext streams logs from a specific container in real-time.
// This function creates a kubectl logs process to stream logs from a specific container
// within a pod and forwards them to a channel for WebSocket broadcasting. It implements:
//
// 1. Context-aware cancellation for graceful shutdown
// 2. Error handling and propagation through error channels
// 3. Process cleanup to prevent resource leaks
// 4. Buffered reading for efficient log processing
// 5. Container-specific log prefixing for multi-container pods
//
// The function runs concurrently and coordinates with other log streaming operations
// through WaitGroup synchronization.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - container: PodContainer struct containing pod, container, and namespace information
//   - logChannel: Channel to send formatted log messages to WebSocket clients
//   - errorChannel: Channel to report errors during log streaming
//   - wg: WaitGroup for coordinating concurrent log streaming operations
func streamContainerLogsWithContext(ctx context.Context, container k8s.PodContainer, logChannel chan<- string, errorChannel chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	// Create command with context for cancellation, specifying the container
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-f", container.PodName, "-c", container.ContainerName, "-n", container.Namespace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errorMsg := fmt.Errorf("failed to create stdout pipe for pod %s container %s: %w", container.PodName, container.ContainerName, err)
		utils.Logger.Error(errorMsg.Error())
		select {
		case errorChannel <- errorMsg:
		case <-ctx.Done():
		}
		return
	}

	if err := cmd.Start(); err != nil {
		errorMsg := fmt.Errorf("failed to start kubectl logs for pod %s container %s: %w", container.PodName, container.ContainerName, err)
		utils.Logger.Error(errorMsg.Error())
		select {
		case errorChannel <- errorMsg:
		case <-ctx.Done():
		}
		return
	}

	// Ensure command cleanup
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			utils.Logger.Info(fmt.Sprintf("Context cancelled for pod %s container %s log streaming", container.PodName, container.ContainerName))
			return
		default:
			n, err := stdout.Read(buffer)
			if err != nil {
				if ctx.Err() == nil {
					errorMsg := fmt.Errorf("error reading logs from pod %s container %s: %w", container.PodName, container.ContainerName, err)
					utils.Logger.Error(errorMsg.Error())
					select {
					case errorChannel <- errorMsg:
					case <-ctx.Done():
					}
				}
				return
			}
			if n > 0 {
				select {
				case logChannel <- fmt.Sprintf("[%s:%s] %s", container.PodName, container.ContainerName, string(buffer[:n])):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// streamPodLogsWithContext streams logs from the default container of a pod (backward compatibility)
func streamPodLogsWithContext(ctx context.Context, podName, namespace string, logChannel chan<- string, errorChannel chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	// Create command with context for cancellation
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-f", podName, "-n", namespace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errorMsg := fmt.Errorf("failed to create stdout pipe for pod %s: %w", podName, err)
		utils.Logger.Error(errorMsg.Error())
		select {
		case errorChannel <- errorMsg:
		case <-ctx.Done():
		}
		return
	}

	if err := cmd.Start(); err != nil {
		errorMsg := fmt.Errorf("failed to start kubectl logs for pod %s: %w", podName, err)
		utils.Logger.Error(errorMsg.Error())
		select {
		case errorChannel <- errorMsg:
		case <-ctx.Done():
		}
		return
	}

	// Ensure command cleanup
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			utils.Logger.Info(fmt.Sprintf("Context cancelled for pod %s log streaming", podName))
			return
		default:
			n, err := stdout.Read(buffer)
			if err != nil {
				if ctx.Err() == nil {
					errorMsg := fmt.Errorf("error reading logs from pod %s: %w", podName, err)
					utils.Logger.Error(errorMsg.Error())
					select {
					case errorChannel <- errorMsg:
					case <-ctx.Done():
					}
				}
				return
			}
			if n > 0 {
				select {
				case logChannel <- fmt.Sprintf("[%s] %s", podName, string(buffer[:n])):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func getPodNames(namespace, deployment string) ([]string, error) {
	// Get the actual label selector for the deployment
	labelSelector, err := k8s.GetDeploymentSelector(namespace, deployment)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment selector: %w", err)
	}

	// Use the generic label selector to get pods
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", labelSelector, "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get pods with selector %s: %w", labelSelector, err)
	}
	podNames := strings.Fields(string(output))
	return podNames, nil
}

func homeHandler(w http.ResponseWriter, _ *http.Request, namespace, deployment string) {
	pods, err := getPodNames(namespace, deployment)
	if err != nil {
		fmt.Println("Failed to get pod names:", err)
		http.Error(w, "Failed to get pod names", http.StatusInternalServerError)
		return
	}

	cfg := config.GetConfig()
	tmpl := template.Must(template.ParseFiles(cfg.UI.TemplatePath))
	err = tmpl.Execute(w, pods)
	if err != nil {
		fmt.Println("Failed to render template:", err)
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func StartWebServer(namespace, deployment string) {
	// Create main context for the application
	mainCtx := context.Background()

	// Initialize WebSocket manager
	wsManager = NewWebSocketManager(mainCtx)

	// Create HTTP server mux
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		homeHandler(w, r, namespace, deployment)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		logWebSocketHandler(w, r, namespace, deployment)
	})

	// Health check endpoints
	mux.HandleFunc("/health", health.HealthHandler)
	mux.HandleFunc("/health/ready", health.ReadinessHandler)
	mux.HandleFunc("/health/live", health.LivenessHandler)

	// WebSocket status endpoint
	mux.HandleFunc("/ws/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active_connections": %d}`, wsManager.GetConnectionCount())
	})

	// API Documentation endpoints
	mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/docs/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/swagger-ui.html")
	})
	mux.HandleFunc("/docs/swagger.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		http.ServeFile(w, r, "docs/swagger.yaml")
	})
	mux.HandleFunc("/docs/api.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown")
		http.ServeFile(w, r, "docs/API.md")
	})

	cfg := config.GetConfig()
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Create HTTP server with timeouts
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		utils.Logger.Info(fmt.Sprintf("Starting web server on %s", addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			utils.Logger.Error(fmt.Sprintf("Server failed to start: %v", err))
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	<-stop

	// Graceful shutdown
	utils.Logger.Info("Shutting down server gracefully...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Close all WebSocket connections
	wsManager.CloseAllConnections()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		utils.Logger.Error(fmt.Sprintf("Server forced to shutdown: %v", err))
		os.Exit(1)
	}

	utils.Logger.Info("Server gracefully stopped")
}
