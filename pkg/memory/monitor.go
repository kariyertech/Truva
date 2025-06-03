package memory

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/pkg/recovery"
)

// MemoryStats holds memory usage statistics
type MemoryStats struct {
	Alloc      uint64    // bytes allocated and not yet freed
	TotalAlloc uint64    // bytes allocated (even if freed)
	Sys        uint64    // bytes obtained from system
	NumGC      uint32    // number of garbage collections
	Goroutines int       // number of goroutines
	Timestamp  time.Time // when the stats were collected
}

// MemoryMonitor monitors memory usage and detects potential leaks
type MemoryMonitor struct {
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	stats              []MemoryStats
	maxStats           int
	monitorInterval    time.Duration
	leakThreshold      uint64 // bytes
	goroutineThreshold int
	alertCallback      func(alert MemoryAlert)
	running            bool
}

// MemoryAlert represents a memory-related alert
type MemoryAlert struct {
	Type       string
	Message    string
	CurrentMem uint64
	Goroutines int
	Timestamp  time.Time
	Severity   string // "warning", "critical"
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(ctx context.Context) *MemoryMonitor {
	ctx, cancel := context.WithCancel(ctx)
	return &MemoryMonitor{
		ctx:                ctx,
		cancel:             cancel,
		stats:              make([]MemoryStats, 0),
		maxStats:           100, // Keep last 100 measurements
		monitorInterval:    30 * time.Second,
		leakThreshold:      100 * 1024 * 1024, // 100MB
		goroutineThreshold: 1000,
		running:            false,
	}
}

// SetAlertCallback sets the callback function for memory alerts
func (mm *MemoryMonitor) SetAlertCallback(callback func(alert MemoryAlert)) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.alertCallback = callback
}

// SetThresholds sets memory and goroutine thresholds
func (mm *MemoryMonitor) SetThresholds(memoryThreshold uint64, goroutineThreshold int) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.leakThreshold = memoryThreshold
	mm.goroutineThreshold = goroutineThreshold
}

// Start begins memory monitoring
func (mm *MemoryMonitor) Start() {
	mm.mu.Lock()
	if mm.running {
		mm.mu.Unlock()
		return
	}
	mm.running = true
	mm.mu.Unlock()

	log.Println("INFO: Starting memory monitor")
	recovery.SafeGoWithContext(mm.ctx, func(ctx context.Context) {
		mm.monitorLoop()
	}, map[string]interface{}{
		"component": "memory_monitor",
		"action":    "monitor_loop",
	})
}

// Stop stops memory monitoring
func (mm *MemoryMonitor) Stop() {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if !mm.running {
		return
	}
	mm.running = false
	mm.cancel()
	log.Println("INFO: Memory monitor stopped")
}

// GetCurrentStats returns current memory statistics
func (mm *MemoryMonitor) GetCurrentStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemoryStats{
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		NumGC:      m.NumGC,
		Goroutines: runtime.NumGoroutine(),
		Timestamp:  time.Now(),
	}
}

// GetStats returns historical memory statistics
func (mm *MemoryMonitor) GetStats() []MemoryStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Return a copy to avoid race conditions
	stats := make([]MemoryStats, len(mm.stats))
	copy(stats, mm.stats)
	return stats
}

// ForceGC triggers garbage collection and returns memory stats before and after
func (mm *MemoryMonitor) ForceGC() (before, after MemoryStats) {
	before = mm.GetCurrentStats()
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Give GC time to complete
	after = mm.GetCurrentStats()
	return before, after
}

// monitorLoop is the main monitoring loop
func (mm *MemoryMonitor) monitorLoop() {
	ticker := time.NewTicker(mm.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.collectStats()
			mm.analyzeMemoryTrends()
		case <-mm.ctx.Done():
			return
		}
	}
}

// collectStats collects current memory statistics
func (mm *MemoryMonitor) collectStats() {
	stats := mm.GetCurrentStats()

	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Add new stats
	mm.stats = append(mm.stats, stats)

	// Keep only the last maxStats entries
	if len(mm.stats) > mm.maxStats {
		mm.stats = mm.stats[len(mm.stats)-mm.maxStats:]
	}

	// Check immediate thresholds
	mm.checkThresholds(stats)
}

// checkThresholds checks if current stats exceed thresholds
func (mm *MemoryMonitor) checkThresholds(stats MemoryStats) {
	if mm.alertCallback == nil {
		return
	}

	// Check memory threshold
	if stats.Alloc > mm.leakThreshold {
		alert := MemoryAlert{
			Type:       "memory_threshold",
			Message:    fmt.Sprintf("Memory usage exceeded threshold: %d MB (threshold: %d MB)", stats.Alloc/(1024*1024), mm.leakThreshold/(1024*1024)),
			CurrentMem: stats.Alloc,
			Goroutines: stats.Goroutines,
			Timestamp:  stats.Timestamp,
			Severity:   "warning",
		}

		if stats.Alloc > mm.leakThreshold*2 {
			alert.Severity = "critical"
		}

		mm.alertCallback(alert)
	}

	// Check goroutine threshold
	if stats.Goroutines > mm.goroutineThreshold {
		alert := MemoryAlert{
			Type:       "goroutine_threshold",
			Message:    fmt.Sprintf("Goroutine count exceeded threshold: %d (threshold: %d)", stats.Goroutines, mm.goroutineThreshold),
			CurrentMem: stats.Alloc,
			Goroutines: stats.Goroutines,
			Timestamp:  stats.Timestamp,
			Severity:   "warning",
		}

		if stats.Goroutines > mm.goroutineThreshold*2 {
			alert.Severity = "critical"
		}

		mm.alertCallback(alert)
	}
}

// analyzeMemoryTrends analyzes memory usage trends for potential leaks
func (mm *MemoryMonitor) analyzeMemoryTrends() {
	mm.mu.RLock()
	statsLen := len(mm.stats)
	if statsLen < 10 { // Need at least 10 data points
		mm.mu.RUnlock()
		return
	}

	// Get recent stats for trend analysis
	recentStats := mm.stats[statsLen-10:]
	mm.mu.RUnlock()

	// Calculate memory growth trend
	if mm.detectMemoryLeak(recentStats) {
		if mm.alertCallback != nil {
			alert := MemoryAlert{
				Type:       "memory_leak_detected",
				Message:    "Potential memory leak detected: consistent memory growth over time",
				CurrentMem: recentStats[len(recentStats)-1].Alloc,
				Goroutines: recentStats[len(recentStats)-1].Goroutines,
				Timestamp:  time.Now(),
				Severity:   "critical",
			}
			mm.alertCallback(alert)
		}
	}
}

// detectMemoryLeak analyzes memory usage patterns to detect potential leaks
func (mm *MemoryMonitor) detectMemoryLeak(stats []MemoryStats) bool {
	if len(stats) < 5 {
		return false
	}

	// Check for consistent memory growth
	growthCount := 0
	for i := 1; i < len(stats); i++ {
		if stats[i].Alloc > stats[i-1].Alloc {
			growthCount++
		}
	}

	// If memory grew in 80% of measurements, consider it a potential leak
	growthRatio := float64(growthCount) / float64(len(stats)-1)
	if growthRatio > 0.8 {
		// Additional check: ensure significant growth
		totalGrowth := stats[len(stats)-1].Alloc - stats[0].Alloc
		if totalGrowth > 50*1024*1024 { // 50MB growth
			return true
		}
	}

	return false
}

// GetMemoryReport generates a detailed memory usage report
func (mm *MemoryMonitor) GetMemoryReport() string {
	current := mm.GetCurrentStats()
	stats := mm.GetStats()

	report := fmt.Sprintf("Memory Usage Report\n")
	report += fmt.Sprintf("==================\n")
	report += fmt.Sprintf("Current Memory: %d MB\n", current.Alloc/(1024*1024))
	report += fmt.Sprintf("System Memory: %d MB\n", current.Sys/(1024*1024))
	report += fmt.Sprintf("Total Allocated: %d MB\n", current.TotalAlloc/(1024*1024))
	report += fmt.Sprintf("Goroutines: %d\n", current.Goroutines)
	report += fmt.Sprintf("GC Cycles: %d\n", current.NumGC)

	if len(stats) > 1 {
		first := stats[0]
		last := stats[len(stats)-1]
		duration := last.Timestamp.Sub(first.Timestamp)
		memGrowth := int64(last.Alloc) - int64(first.Alloc)
		goroutineGrowth := last.Goroutines - first.Goroutines

		report += fmt.Sprintf("\nTrend Analysis (over %v):\n", duration)
		report += fmt.Sprintf("Memory Growth: %+d MB\n", memGrowth/(1024*1024))
		report += fmt.Sprintf("Goroutine Growth: %+d\n", goroutineGrowth)
	}

	return report
}

// NewMonitor creates a new memory monitor with specified thresholds and callback
// This function matches the usage pattern in sync.go
func NewMonitor(memoryThreshold uint64, goroutineThreshold int, alertCallback func(MemoryAlert)) *MemoryMonitor {
	ctx := context.Background()
	monitor := NewMemoryMonitor(ctx)
	monitor.SetThresholds(memoryThreshold, goroutineThreshold)
	monitor.SetAlertCallback(alertCallback)
	return monitor
}
