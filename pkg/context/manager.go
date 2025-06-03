package context

import (
	"context"
	"sync"
	"time"
)

type Manager struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (m *Manager) Context() context.Context {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ctx
}

func (m *Manager) WithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return context.WithTimeout(m.ctx, timeout)
}

func (m *Manager) AddWorker() {
	m.wg.Add(1)
}

func (m *Manager) WorkerDone() {
	m.wg.Done()
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.cancel()
	m.mu.Unlock()

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers finished gracefully
	case <-time.After(30 * time.Second):
		// Timeout waiting for workers
	}
}

func (m *Manager) IsShuttingDown() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	select {
	case <-m.ctx.Done():
		return true
	default:
		return false
	}
}
