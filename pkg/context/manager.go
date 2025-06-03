package context

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// WorkerPool manages a pool of goroutines with lifecycle management
type WorkerPool struct {
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	mu            sync.RWMutex
	maxWorkers    int
	activeWorkers int64
	taskQueue     chan func()
	shutdownCh    chan struct{}
	running       bool
	stats         *PoolStats
}

// PoolStats tracks worker pool statistics
type PoolStats struct {
	mu             sync.RWMutex
	TasksSubmitted int64
	TasksCompleted int64
	TasksFailed    int64
	PeakWorkers    int64
	TotalWorkers   int64
	StartTime      time.Time
	LastActivity   time.Time
}

// NewWorkerPool creates a new worker pool with specified max workers
func NewWorkerPool(maxWorkers int) *WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU() * 2 // Default to 2x CPU cores
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		ctx:        ctx,
		cancel:     cancel,
		maxWorkers: maxWorkers,
		taskQueue:  make(chan func(), maxWorkers*2), // Buffer for tasks
		shutdownCh: make(chan struct{}),
		stats: &PoolStats{
			StartTime:    time.Now(),
			LastActivity: time.Now(),
		},
	}
}

// Start initializes and starts the worker pool
func (wp *WorkerPool) Start() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return fmt.Errorf("worker pool is already running")
	}

	wp.running = true
	utils.Logger.Info(fmt.Sprintf("Starting worker pool with %d max workers", wp.maxWorkers))

	// Start initial workers
	for i := 0; i < wp.maxWorkers; i++ {
		wp.startWorker()
	}

	return nil
}

// startWorker starts a new worker goroutine
func (wp *WorkerPool) startWorker() {
	atomic.AddInt64(&wp.activeWorkers, 1)
	atomic.AddInt64(&wp.stats.TotalWorkers, 1)

	// Update peak workers
	current := atomic.LoadInt64(&wp.activeWorkers)
	for {
		peak := atomic.LoadInt64(&wp.stats.PeakWorkers)
		if current <= peak || atomic.CompareAndSwapInt64(&wp.stats.PeakWorkers, peak, current) {
			break
		}
	}

	wp.wg.Add(1)
	recovery.SafeGoWithContext(wp.ctx, func(ctx context.Context) {
		defer func() {
			atomic.AddInt64(&wp.activeWorkers, -1)
			wp.wg.Done()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-wp.shutdownCh:
				return
			case task, ok := <-wp.taskQueue:
				if !ok {
					return
				}
				wp.executeTask(task)
			}
		}
	}, map[string]interface{}{
		"component": "worker_pool",
		"worker_id": atomic.LoadInt64(&wp.stats.TotalWorkers),
	})
}

// executeTask executes a task with error handling and statistics
func (wp *WorkerPool) executeTask(task func()) {
	defer func() {
		wp.stats.mu.Lock()
		wp.stats.LastActivity = time.Now()
		wp.stats.mu.Unlock()
	}()

	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&wp.stats.TasksFailed, 1)
			utils.Logger.Error(fmt.Sprintf("Worker pool task panicked: %v", r))
		}
	}()

	task()
	atomic.AddInt64(&wp.stats.TasksCompleted, 1)
}

// Submit submits a task to the worker pool
func (wp *WorkerPool) Submit(task func()) error {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return fmt.Errorf("worker pool is not running")
	}

	atomic.AddInt64(&wp.stats.TasksSubmitted, 1)

	select {
	case wp.taskQueue <- task:
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool is shutting down")
	default:
		// Queue is full, try to add a worker if possible
		current := atomic.LoadInt64(&wp.activeWorkers)
		if int(current) < wp.maxWorkers {
			wp.startWorker()
		}

		// Try again with timeout
		select {
		case wp.taskQueue <- task:
			return nil
		case <-time.After(1 * time.Second):
			return fmt.Errorf("worker pool queue is full and timeout reached")
		case <-wp.ctx.Done():
			return fmt.Errorf("worker pool is shutting down")
		}
	}
}

// SubmitWithTimeout submits a task with a timeout
func (wp *WorkerPool) SubmitWithTimeout(task func(), timeout time.Duration) error {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return fmt.Errorf("worker pool is not running")
	}

	atomic.AddInt64(&wp.stats.TasksSubmitted, 1)

	select {
	case wp.taskQueue <- task:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout submitting task to worker pool")
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool is shutting down")
	}
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return nil
	}

	utils.Logger.Info("Stopping worker pool...")

	// Cancel context to signal shutdown
	wp.cancel()

	// Close shutdown channel
	close(wp.shutdownCh)

	// Close task queue to prevent new submissions
	close(wp.taskQueue)

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		utils.Logger.Info("Worker pool stopped gracefully")
	case <-time.After(10 * time.Second):
		utils.Logger.Warning("Worker pool shutdown timeout, forcing stop")
	}

	wp.running = false
	return nil
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() PoolStats {
	wp.stats.mu.RLock()
	defer wp.stats.mu.RUnlock()

	return PoolStats{
		TasksSubmitted: atomic.LoadInt64(&wp.stats.TasksSubmitted),
		TasksCompleted: atomic.LoadInt64(&wp.stats.TasksCompleted),
		TasksFailed:    atomic.LoadInt64(&wp.stats.TasksFailed),
		PeakWorkers:    atomic.LoadInt64(&wp.stats.PeakWorkers),
		TotalWorkers:   atomic.LoadInt64(&wp.stats.TotalWorkers),
		StartTime:      wp.stats.StartTime,
		LastActivity:   wp.stats.LastActivity,
	}
}

// GetActiveWorkers returns the current number of active workers
func (wp *WorkerPool) GetActiveWorkers() int64 {
	return atomic.LoadInt64(&wp.activeWorkers)
}

// IsRunning returns whether the worker pool is currently running
func (wp *WorkerPool) IsRunning() bool {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.running
}

// Manager maintains the original context manager functionality
type Manager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	workerPool *WorkerPool
}

func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		ctx:        ctx,
		cancel:     cancel,
		workerPool: NewWorkerPool(runtime.NumCPU() * 2),
	}
}

// StartWorkerPool starts the managed worker pool
func (m *Manager) StartWorkerPool() error {
	return m.workerPool.Start()
}

// GetWorkerPool returns the managed worker pool
func (m *Manager) GetWorkerPool() *WorkerPool {
	return m.workerPool
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

	// Stop worker pool first
	if m.workerPool != nil {
		m.workerPool.Stop()
	}

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	recovery.SafeGo(func() {
		m.wg.Wait()
		close(done)
	}, map[string]interface{}{
		"component": "context_manager",
		"action":    "wait_workers",
	})

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

// Global worker pool instance
var (
	globalWorkerPool *WorkerPool
	workerPoolOnce   sync.Once
)

// GetGlobalWorkerPool returns the global worker pool instance
func GetGlobalWorkerPool() *WorkerPool {
	workerPoolOnce.Do(func() {
		globalWorkerPool = NewWorkerPool(runtime.NumCPU() * 2)
		if err := globalWorkerPool.Start(); err != nil {
			utils.Logger.Error(fmt.Sprintf("Failed to start global worker pool: %v", err))
		}
	})
	return globalWorkerPool
}

// StopGlobalWorkerPool stops the global worker pool
func StopGlobalWorkerPool() error {
	if globalWorkerPool != nil {
		return globalWorkerPool.Stop()
	}
	return nil
}
