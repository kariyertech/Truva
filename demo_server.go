package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Demo log messages for testing
var demoLogs = []string{
	"2024-01-15 10:30:15 [INFO] Application started successfully",
	"2024-01-15 10:30:16 [DEBUG] Database connection established",
	"2024-01-15 10:30:17 [INFO] Server listening on port 8080",
	"2024-01-15 10:30:18 [WARN] High memory usage detected: 85%",
	"2024-01-15 10:30:19 [ERROR] Failed to connect to external API: timeout",
	"2024-01-15 10:30:20 [INFO] Processing user request: GET /api/users",
	"2024-01-15 10:30:21 [DEBUG] Query executed in 45ms",
	"2024-01-15 10:30:22 [INFO] Response sent successfully",
	"2024-01-15 10:30:23 [WARN] Rate limit approaching for user 12345",
	"2024-01-15 10:30:24 [ERROR] Database query failed: connection lost",
	"2024-01-15 10:30:25 [INFO] Retrying database connection...",
	"2024-01-15 10:30:26 [INFO] Database connection restored",
	"2024-01-15 10:30:27 [DEBUG] Cache hit for key: user_profile_12345",
	"2024-01-15 10:30:28 [INFO] User authentication successful",
	"2024-01-15 10:30:29 [WARN] Unusual login pattern detected",
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	data := struct {
		Namespace  string
		Deployment string
	}{
		Namespace:  "demo",
		Deployment: "demo-app",
	}

	tmpl.Execute(w, data)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("WebSocket upgrade failed: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("WebSocket connection established")

	// Send demo logs with realistic timing
	go func() {
		for i, log := range demoLogs {
			// Send initial batch quickly
			if i < 5 {
				time.Sleep(500 * time.Millisecond)
			} else {
				// Then send logs more slowly to simulate real-time
				time.Sleep(2 * time.Second)
			}

			err := conn.WriteMessage(websocket.TextMessage, []byte(log))
			if err != nil {
				fmt.Printf("Error sending message: %v\n", err)
				return
			}
		}

		// Continue sending random logs
		for {
			time.Sleep(3 * time.Second)
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			levels := []string{"INFO", "DEBUG", "WARN", "ERROR"}
			messages := []string{
				"Processing request",
				"Database query completed",
				"Cache miss for key",
				"Memory usage normal",
				"User session created",
				"API call successful",
			}

			level := levels[time.Now().Second()%len(levels)]
			message := messages[time.Now().Second()%len(messages)]
			logLine := fmt.Sprintf("%s [%s] %s", timestamp, level, message)

			err := conn.WriteMessage(websocket.TextMessage, []byte(logLine))
			if err != nil {
				fmt.Printf("Error sending message: %v\n", err)
				return
			}
		}
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("WebSocket connection closed: %v\n", err)
			break
		}
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/ws", wsHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Println("Demo server starting on http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	<-stop
	fmt.Println("\nShutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Server shutdown error: %v\n", err)
	}
	fmt.Println("Server stopped")
}
