package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebSocketManager(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)

	require.NotNil(t, manager)
	assert.NotNil(t, manager.connections)
	assert.NotNil(t, manager.ctx)
	assert.Equal(t, 0, manager.GetConnectionCount())

	// Clean up
	manager.CloseAllConnections()
}

func TestWebSocketManager_AddConnection(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	// Create a mock WebSocket connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		// Add connection to manager
		manager.AddConnection(conn)
		assert.Equal(t, 1, manager.GetConnectionCount())

		// Keep connection alive briefly
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to the test server
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Give time for connection to be added
	time.Sleep(200 * time.Millisecond)
}

func TestWebSocketManager_RemoveConnection(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		// Add and then remove connection
		manager.AddConnection(conn)
		assert.Equal(t, 1, manager.GetConnectionCount())

		manager.RemoveConnection(conn)
		assert.Equal(t, 0, manager.GetConnectionCount())

		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(200 * time.Millisecond)
}

func TestWebSocketManager_BroadcastMessage(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	// Test that BroadcastMessage method exists and can be called
	// without panicking, even with no connections
	require.NotPanics(t, func() {
		manager.BroadcastMessage([]byte("test message"))
	})

	// Verify connection count is still 0
	assert.Equal(t, 0, manager.GetConnectionCount())
}

func TestWebSocketManager_GetConnectionCount(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	// Initially should be 0
	assert.Equal(t, 0, manager.GetConnectionCount())

	// Test with mock connections
	connectionCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		manager.AddConnection(conn)
		connectionCount++
		assert.Equal(t, connectionCount, manager.GetConnectionCount())

		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	// Create multiple connections
	var connections []*websocket.Conn
	for i := 0; i < 3; i++ {
		url := "ws" + strings.TrimPrefix(server.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		require.NoError(t, err)
		connections = append(connections, conn)
	}

	// Clean up connections
	for _, conn := range connections {
		conn.Close()
	}

	time.Sleep(300 * time.Millisecond)
}

func TestWebSocketManager_CloseAllConnections(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)

	connectionsClosed := make(chan bool, 3)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer func() {
			conn.Close()
			connectionsClosed <- true
		}()

		manager.AddConnection(conn)

		// Keep connection alive until closed
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Create multiple connections
	var connections []*websocket.Conn
	for i := 0; i < 3; i++ {
		url := "ws" + strings.TrimPrefix(server.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		require.NoError(t, err)
		connections = append(connections, conn)
	}

	// Give time for connections to be established
	time.Sleep(200 * time.Millisecond)

	// Close all connections
	manager.CloseAllConnections()

	// Verify connections are closed
	for i := 0; i < 3; i++ {
		select {
		case <-connectionsClosed:
			// Connection closed successfully
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for connection to close")
		}
	}

	// Verify connection count is 0
	assert.Equal(t, 0, manager.GetConnectionCount())
}

func TestWebSocketUpgrader(t *testing.T) {
	// Test the upgrader configuration
	assert.NotNil(t, upgrader)
	assert.Equal(t, 10*time.Second, upgrader.HandshakeTimeout)
	assert.Equal(t, 4096, upgrader.ReadBufferSize)
	assert.Equal(t, 4096, upgrader.WriteBufferSize)

	// Test CheckOrigin function
	req, err := http.NewRequest("GET", "/ws", nil)
	require.NoError(t, err)
	assert.True(t, upgrader.CheckOrigin(req))
}

func TestWebSocketConnection_Context(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	// Test context cancellation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		manager.AddConnection(conn)

		// Cancel context after a short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		// Wait for context cancellation
		<-ctx.Done()
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Wait for context to be cancelled
	select {
	case <-ctx.Done():
		// Context cancelled successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for context cancellation")
	}
}

func TestConcurrentWebSocketOperations(t *testing.T) {
	ctx := context.Background()
	manager := NewWebSocketManager(ctx)
	defer manager.CloseAllConnections()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		manager.AddConnection(conn)

		// Keep connection alive
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Create multiple concurrent connections
	numConnections := 5
	var connections []*websocket.Conn

	for i := 0; i < numConnections; i++ {
		url := "ws" + strings.TrimPrefix(server.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		require.NoError(t, err)
		connections = append(connections, conn)
	}

	// Give time for all connections to be established
	time.Sleep(300 * time.Millisecond)

	// Verify connection count
	assert.Equal(t, numConnections, manager.GetConnectionCount())

	// Clean up
	for _, conn := range connections {
		conn.Close()
	}

	time.Sleep(200 * time.Millisecond)
}
