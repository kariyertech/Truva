package memory

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/pkg/recovery"
)

// ConnectionPool manages a pool of connections with automatic cleanup
type ConnectionPool struct {
	mu            sync.RWMutex
	connections   map[string]*PooledConnection
	maxSize       int
	ttl           time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	cleanupTicker *time.Ticker
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	ID          string
	CreatedAt   time.Time
	LastUsed    time.Time
	Data        interface{}
	CleanupFunc func() error
	InUse       bool
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(ctx context.Context, maxSize int, ttl time.Duration) *ConnectionPool {
	ctx, cancel := context.WithCancel(ctx)
	pool := &ConnectionPool{
		connections: make(map[string]*PooledConnection),
		maxSize:     maxSize,
		ttl:         ttl,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start cleanup routine
	pool.startCleanup()
	return pool
}

// Add adds a connection to the pool
func (cp *ConnectionPool) Add(id string, data interface{}, cleanupFunc func() error) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	// Check if pool is full
	if len(cp.connections) >= cp.maxSize {
		// Try to remove expired connections first
		cp.removeExpiredConnections()

		// If still full, remove oldest connection
		if len(cp.connections) >= cp.maxSize {
			cp.removeOldestConnection()
		}
	}

	conn := &PooledConnection{
		ID:          id,
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
		Data:        data,
		CleanupFunc: cleanupFunc,
		InUse:       false,
	}

	cp.connections[id] = conn
	log.Printf("INFO: Connection added to pool: %s (total: %d)", id, len(cp.connections))
	return nil
}

// Get retrieves a connection from the pool
func (cp *ConnectionPool) Get(id string) (*PooledConnection, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	conn, exists := cp.connections[id]
	if !exists {
		return nil, false
	}

	// Update last used time
	conn.LastUsed = time.Now()
	conn.InUse = true
	return conn, true
}

// Release marks a connection as not in use
func (cp *ConnectionPool) Release(id string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if conn, exists := cp.connections[id]; exists {
		conn.InUse = false
		conn.LastUsed = time.Now()
	}
}

// Remove removes a connection from the pool
func (cp *ConnectionPool) Remove(id string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	conn, exists := cp.connections[id]
	if !exists {
		return fmt.Errorf("connection not found: %s", id)
	}

	// Call cleanup function if provided
	if conn.CleanupFunc != nil {
		if err := conn.CleanupFunc(); err != nil {
			log.Printf("ERROR: Error cleaning up connection %s: %v", id, err)
		}
	}

	delete(cp.connections, id)
	log.Printf("INFO: Connection removed from pool: %s (remaining: %d)", id, len(cp.connections))
	return nil
}

// Size returns the current size of the pool
func (cp *ConnectionPool) Size() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.connections)
}

// GetActiveConnections returns the number of connections currently in use
func (cp *ConnectionPool) GetActiveConnections() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	active := 0
	for _, conn := range cp.connections {
		if conn.InUse {
			active++
		}
	}
	return active
}

// Close closes the connection pool and cleans up all connections
func (cp *ConnectionPool) Close() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	log.Printf("INFO: Closing connection pool with %d connections", len(cp.connections))

	// Stop cleanup routine
	if cp.cleanupTicker != nil {
		cp.cleanupTicker.Stop()
	}
	cp.cancel()

	// Clean up all connections
	for id, conn := range cp.connections {
		if conn.CleanupFunc != nil {
			if err := conn.CleanupFunc(); err != nil {
				log.Printf("ERROR: Error cleaning up connection %s: %v", id, err)
			}
		}
	}

	cp.connections = make(map[string]*PooledConnection)
	return nil
}

// startCleanup starts the background cleanup routine
func (cp *ConnectionPool) startCleanup() {
	cp.cleanupTicker = time.NewTicker(30 * time.Second)

	recovery.SafeGoWithContext(cp.ctx, func(ctx context.Context) {
		for {
			select {
			case <-cp.cleanupTicker.C:
				cp.performCleanup()
			case <-cp.ctx.Done():
				return
			}
		}
	}, map[string]interface{}{
		"component": "connection_pool",
		"action":    "cleanup_routine",
	})
}

// performCleanup removes expired and unused connections
func (cp *ConnectionPool) performCleanup() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	initialCount := len(cp.connections)
	cp.removeExpiredConnections()
	finalCount := len(cp.connections)

	if initialCount != finalCount {
		log.Printf("INFO: Connection pool cleanup: removed %d expired connections", initialCount-finalCount)
	}
}

// removeExpiredConnections removes connections that have exceeded TTL
func (cp *ConnectionPool) removeExpiredConnections() {
	now := time.Now()
	expiredIDs := make([]string, 0)

	for id, conn := range cp.connections {
		// Don't remove connections that are currently in use
		if conn.InUse {
			continue
		}

		// Check if connection has expired
		if now.Sub(conn.LastUsed) > cp.ttl {
			expiredIDs = append(expiredIDs, id)
		}
	}

	// Remove expired connections
	for _, id := range expiredIDs {
		conn := cp.connections[id]
		if conn.CleanupFunc != nil {
			if err := conn.CleanupFunc(); err != nil {
				log.Printf("ERROR: Error cleaning up connection %s: %v", id, err)
			}
		}
		delete(cp.connections, id)
	}
}

// removeOldestConnection removes the oldest unused connection
func (cp *ConnectionPool) removeOldestConnection() {
	var oldestID string
	var oldestTime time.Time

	// Find oldest unused connection
	for id, conn := range cp.connections {
		if conn.InUse {
			continue
		}

		if oldestID == "" || conn.CreatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = conn.CreatedAt
		}
	}

	// Remove oldest connection if found
	if oldestID != "" {
		conn := cp.connections[oldestID]
		if conn.CleanupFunc != nil {
			if err := conn.CleanupFunc(); err != nil {
				log.Printf("ERROR: Error cleaning up oldest connection %s: %v", oldestID, err)
			}
		}
		delete(cp.connections, oldestID)
		log.Printf("INFO: Removed oldest connection from pool: %s", oldestID)
	}
}

// GetStats returns pool statistics
func (cp *ConnectionPool) GetStats() map[string]interface{} {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	active := 0
	oldest := time.Now()
	newest := time.Time{}

	for _, conn := range cp.connections {
		if conn.InUse {
			active++
		}

		if conn.CreatedAt.Before(oldest) {
			oldest = conn.CreatedAt
		}

		if conn.CreatedAt.After(newest) {
			newest = conn.CreatedAt
		}
	}

	return map[string]interface{}{
		"total_connections":  len(cp.connections),
		"active_connections": active,
		"idle_connections":   len(cp.connections) - active,
		"max_size":           cp.maxSize,
		"ttl_seconds":        cp.ttl.Seconds(),
		"oldest_connection":  oldest,
		"newest_connection":  newest,
	}
}
