package memory

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// LeakDetector monitors for potential memory leaks
type LeakDetector struct {
	mu                 sync.RWMutex
	baseline           MemoryStats
	samples            []MemoryStats
	maxSamples         int
	monitorInterval    time.Duration
	leakThreshold      float64 // Growth rate threshold in bytes/second
	goroutineThreshold int
	alertCallback      func(LeakAlert)
	running            bool
	stopChan           chan struct{}
}

// LeakAlert represents a memory leak alert
type LeakAlert struct {
	Timestamp       time.Time
	Severity        string
	Message         string
	CurrentMemory   uint64
	GrowthRate      float64
	GoroutineCount  int
	GoroutineGrowth int
	Suggestions     []string
}

// NewLeakDetector creates a new memory leak detector
func NewLeakDetector(alertCallback func(LeakAlert)) *LeakDetector {
	return &LeakDetector{
		maxSamples:         100,
		monitorInterval:    30 * time.Second,
		leakThreshold:      1024 * 1024, // 1MB/s
		goroutineThreshold: 100,
		alertCallback:      alertCallback,
		stopChan:           make(chan struct{}),
	}
}

// SetThresholds configures the leak detection thresholds
func (ld *LeakDetector) SetThresholds(memoryThreshold float64, goroutineThreshold int) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.leakThreshold = memoryThreshold
	ld.goroutineThreshold = goroutineThreshold
}

// Start begins leak detection monitoring
func (ld *LeakDetector) Start() {
	ld.mu.Lock()
	if ld.running {
		ld.mu.Unlock()
		return
	}
	ld.running = true
	ld.baseline = getCurrentMemoryStats()
	ld.mu.Unlock()

	go ld.monitorLoop()
}

// Stop stops the leak detection monitoring
func (ld *LeakDetector) Stop() {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	if !ld.running {
		return
	}

	ld.running = false
	close(ld.stopChan)
}

// monitorLoop runs the continuous monitoring
func (ld *LeakDetector) monitorLoop() {
	ticker := time.NewTicker(ld.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ld.checkForLeaks()
		case <-ld.stopChan:
			return
		}
	}
}

// checkForLeaks analyzes current memory usage for potential leaks
func (ld *LeakDetector) checkForLeaks() {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	currentStats := getCurrentMemoryStats()
	ld.samples = append(ld.samples, currentStats)

	// Keep only the last maxSamples
	if len(ld.samples) > ld.maxSamples {
		ld.samples = ld.samples[1:]
	}

	// Need at least 3 samples for trend analysis
	if len(ld.samples) < 3 {
		return
	}

	// Analyze memory growth trend
	growthRate := ld.calculateGrowthRate()
	goroutineGrowth := ld.calculateGoroutineGrowth()

	// Check for memory leak indicators
	if growthRate > ld.leakThreshold {
		ld.triggerAlert("memory", currentStats, growthRate, goroutineGrowth)
	}

	if goroutineGrowth > ld.goroutineThreshold {
		ld.triggerAlert("goroutine", currentStats, growthRate, goroutineGrowth)
	}

	// Check for sustained growth over multiple samples
	if ld.isSustainedGrowth() {
		ld.triggerAlert("sustained", currentStats, growthRate, goroutineGrowth)
	}
}

// calculateGrowthRate calculates the memory growth rate in bytes per second
func (ld *LeakDetector) calculateGrowthRate() float64 {
	if len(ld.samples) < 2 {
		return 0
	}

	// Use linear regression for more accurate trend analysis
	n := len(ld.samples)
	last5 := ld.samples
	if n > 5 {
		last5 = ld.samples[n-5:] // Use last 5 samples
	}

	if len(last5) < 2 {
		return 0
	}

	// Simple linear regression
	sumX, sumY, sumXY, sumX2 := 0.0, 0.0, 0.0, 0.0
	for i, sample := range last5 {
		x := float64(i)
		y := float64(sample.Alloc)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	n64 := float64(len(last5))
	slope := (n64*sumXY - sumX*sumY) / (n64*sumX2 - sumX*sumX)

	// Convert slope to bytes per second
	return slope / ld.monitorInterval.Seconds()
}

// calculateGoroutineGrowth calculates goroutine growth
func (ld *LeakDetector) calculateGoroutineGrowth() int {
	if len(ld.samples) < 2 {
		return 0
	}

	first := ld.samples[0]
	last := ld.samples[len(ld.samples)-1]
	return int(last.Goroutines) - int(first.Goroutines)
}

// isSustainedGrowth checks if there's sustained memory growth
func (ld *LeakDetector) isSustainedGrowth() bool {
	if len(ld.samples) < 5 {
		return false
	}

	// Check if memory has been consistently growing
	growthCount := 0
	for i := 1; i < len(ld.samples); i++ {
		if ld.samples[i].Alloc > ld.samples[i-1].Alloc {
			growthCount++
		}
	}

	// If 80% of samples show growth, consider it sustained
	return float64(growthCount)/float64(len(ld.samples)-1) > 0.8
}

// triggerAlert sends a leak alert
func (ld *LeakDetector) triggerAlert(alertType string, currentStats MemoryStats, growthRate float64, goroutineGrowth int) {
	if ld.alertCallback == nil {
		return
	}

	var severity string
	var message string
	var suggestions []string

	switch alertType {
	case "memory":
		severity = "warning"
		if growthRate > ld.leakThreshold*2 {
			severity = "critical"
		}
		message = fmt.Sprintf("High memory growth rate detected: %.2f KB/s", growthRate/1024)
		suggestions = []string{
			"Check for unclosed resources (files, connections, channels)",
			"Review goroutine lifecycle management",
			"Consider implementing connection pooling",
			"Run memory profiling to identify allocation hotspots",
		}

	case "goroutine":
		severity = "warning"
		if goroutineGrowth > ld.goroutineThreshold*2 {
			severity = "critical"
		}
		message = fmt.Sprintf("Goroutine leak detected: %d new goroutines", goroutineGrowth)
		suggestions = []string{
			"Check for goroutines that are not properly terminated",
			"Ensure all goroutines have proper exit conditions",
			"Review context cancellation usage",
			"Consider using goroutine pools for better management",
		}

	case "sustained":
		severity = "critical"
		message = "Sustained memory growth pattern detected - possible memory leak"
		suggestions = []string{
			"Immediate investigation required",
			"Capture memory profiles for analysis",
			"Review recent code changes",
			"Consider restarting the application if memory usage is critical",
		}
	}

	alert := LeakAlert{
		Timestamp:       time.Now(),
		Severity:        severity,
		Message:         message,
		CurrentMemory:   currentStats.Alloc,
		GrowthRate:      growthRate,
		GoroutineCount:  int(currentStats.Goroutines),
		GoroutineGrowth: goroutineGrowth,
		Suggestions:     suggestions,
	}

	ld.alertCallback(alert)
}

// GetCurrentStatus returns the current leak detection status
func (ld *LeakDetector) GetCurrentStatus() map[string]interface{} {
	ld.mu.RLock()
	defer ld.mu.RUnlock()

	status := map[string]interface{}{
		"running":             ld.running,
		"samples_collected":   len(ld.samples),
		"monitor_interval":    ld.monitorInterval.String(),
		"leak_threshold_mb":   ld.leakThreshold / (1024 * 1024),
		"goroutine_threshold": ld.goroutineThreshold,
	}

	if len(ld.samples) > 0 {
		current := ld.samples[len(ld.samples)-1]
		status["current_memory_mb"] = current.Alloc / (1024 * 1024)
		status["current_goroutines"] = current.Goroutines
		status["growth_rate_kb_s"] = ld.calculateGrowthRate() / 1024
		status["goroutine_growth"] = ld.calculateGoroutineGrowth()
	}

	return status
}

// ResetBaseline resets the baseline measurements
func (ld *LeakDetector) ResetBaseline() {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	ld.baseline = getCurrentMemoryStats()
	ld.samples = nil
}

// getCurrentMemoryStats gets current memory statistics
func getCurrentMemoryStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemoryStats{
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		NumGC:      m.NumGC,
		Goroutines: runtime.NumGoroutine(),
	}
}
