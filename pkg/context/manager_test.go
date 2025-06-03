package context

import (
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Errorf("NewManager() should return a non-nil manager")
	}

	// Test that context is properly initialized
	ctx := manager.Context()
	if ctx == nil {
		t.Errorf("NewManager() should initialize context")
	}

	// Test that manager is not shutting down initially
	if manager.IsShuttingDown() {
		t.Errorf("NewManager() should not be shutting down initially")
	}
}

func TestContext(t *testing.T) {
	manager := NewManager()
	ctx := manager.Context()
	if ctx == nil {
		t.Error("Context() should return a valid context")
	}

	// Test context cancellation
	manager.Shutdown()
	select {
	case <-ctx.Done():
		// Context should be cancelled
	default:
		t.Error("Context should be cancelled after shutdown")
	}
}

func TestAddWorker(t *testing.T) {
	manager := NewManager()

	// Add workers
	manager.AddWorker()
	manager.AddWorker()

	// We can't directly check the internal counter,
	// but we can test that WorkerDone() works correctly
	go func() {
		defer manager.WorkerDone()
		time.Sleep(10 * time.Millisecond)
	}()

	go func() {
		defer manager.WorkerDone()
		time.Sleep(10 * time.Millisecond)
	}()

	// Test that shutdown waits for workers
	start := time.Now()
	manager.Shutdown()
	duration := time.Since(start)

	if duration < 10*time.Millisecond {
		t.Error("Shutdown should wait for workers to complete")
	}
}

func TestWorkerDone(t *testing.T) {
	manager := NewManager()

	// Add a worker
	manager.AddWorker()

	// Test that WorkerDone() completes without panic
	go func() {
		defer manager.WorkerDone()
		time.Sleep(5 * time.Millisecond)
	}()

	// Test that shutdown waits for the worker
	start := time.Now()
	manager.Shutdown()
	duration := time.Since(start)

	if duration < 5*time.Millisecond {
		t.Error("Shutdown should wait for worker to complete")
	}
}

func TestShutdown(t *testing.T) {
	manager := NewManager()
	ctx := manager.Context()

	// Verify context is not cancelled initially
	select {
	case <-ctx.Done():
		t.Errorf("Context should not be cancelled initially")
	default:
		// Expected behavior
	}

	// Shutdown the manager
	manager.Shutdown()

	// Verify context is cancelled after shutdown
	select {
	case <-ctx.Done():
		// Expected behavior
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Context should be cancelled after shutdown")
	}

	// Verify shutdown flag is set
	if !manager.IsShuttingDown() {
		t.Errorf("IsShuttingDown() should return true after shutdown")
	}
}

func TestIsShuttingDown(t *testing.T) {
	manager := NewManager()

	if manager.IsShuttingDown() {
		t.Error("Manager should not be shutting down initially")
	}

	manager.Shutdown()

	if !manager.IsShuttingDown() {
		t.Error("Manager should be shutting down after calling Shutdown()")
	}
}

func TestWorkerExecution(t *testing.T) {
	manager := NewManager()

	// Create a channel to signal worker completion
	workerDone := make(chan bool, 1)

	// Add worker and start goroutine
	manager.AddWorker()
	go func() {
		defer manager.WorkerDone()
		ctx := manager.Context()
		select {
		case <-ctx.Done():
			workerDone <- true
		case <-time.After(5 * time.Second):
			// Timeout to prevent test hanging
			workerDone <- false
		}
	}()

	// Shutdown manager to trigger worker cancellation
	manager.Shutdown()

	// Wait for worker to complete
	select {
	case completed := <-workerDone:
		if !completed {
			t.Errorf("Worker should complete when context is cancelled")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("Worker should complete within timeout")
	}
}

func TestConcurrentWorkers(t *testing.T) {
	manager := NewManager()
	numWorkers := 10
	workersDone := make(chan bool, numWorkers)

	// Create multiple workers
	for i := 0; i < numWorkers; i++ {
		manager.AddWorker()
		go func() {
			defer manager.WorkerDone()
			ctx := manager.Context()
			select {
			case <-ctx.Done():
				workersDone <- true
			case <-time.After(5 * time.Second):
				workersDone <- false
			}
		}()
	}

	// Shutdown manager
	manager.Shutdown()

	// Wait for all workers to complete
	completedCount := 0
	for i := 0; i < numWorkers; i++ {
		select {
		case completed := <-workersDone:
			if completed {
				completedCount++
			}
		case <-time.After(2 * time.Second):
			t.Errorf("Worker %d should complete within timeout", i)
		}
	}

	if completedCount != numWorkers {
		t.Errorf("Expected %d workers to complete, got %d", numWorkers, completedCount)
	}
}

func TestMultipleShutdowns(t *testing.T) {
	manager := NewManager()

	// Multiple shutdowns should not panic
	manager.Shutdown()
	manager.Shutdown()
	manager.Shutdown()

	// Should still be shutting down
	if !manager.IsShuttingDown() {
		t.Errorf("IsShuttingDown() should return true after multiple shutdowns")
	}
}

func TestWorkerPanic(t *testing.T) {
	manager := NewManager()

	// Add a worker that will panic
	manager.AddWorker()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Recover from panic and mark worker as done
				manager.WorkerDone()
			}
		}()
		panic("test panic")
	}()

	// Give some time for potential panic
	time.Sleep(100 * time.Millisecond)

	// Manager should still be functional
	if manager.IsShuttingDown() {
		t.Errorf("Manager should not be shutting down due to worker panic")
	}

	// Should be able to shutdown normally
	manager.Shutdown()
	if !manager.IsShuttingDown() {
		t.Errorf("Manager should be shutting down after explicit shutdown")
	}
}
