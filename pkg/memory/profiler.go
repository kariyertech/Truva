package memory

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/kariyertech/Truva.git/pkg/errors"
)

// Profiler provides memory profiling capabilities
type Profiler struct {
	enabled   bool
	outputDir string
	interval  time.Duration
	stopChan  chan struct{}
	running   bool
}

// NewProfiler creates a new memory profiler
func NewProfiler(outputDir string, interval time.Duration) *Profiler {
	return &Profiler{
		enabled:   true,
		outputDir: outputDir,
		interval:  interval,
		stopChan:  make(chan struct{}),
	}
}

// Start begins continuous memory profiling
func (p *Profiler) Start() error {
	if !p.enabled || p.running {
		return nil
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(p.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	p.running = true
	go p.profileLoop()
	return nil
}

// Stop stops the profiling
func (p *Profiler) Stop() {
	if !p.running {
		return
	}

	close(p.stopChan)
	p.running = false
}

// profileLoop runs the continuous profiling
func (p *Profiler) profileLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.captureMemoryProfile()
		case <-p.stopChan:
			return
		}
	}
}

// captureMemoryProfile captures a memory profile snapshot
func (p *Profiler) captureMemoryProfile() {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s/mem_profile_%s.prof", p.outputDir, timestamp)

	f, err := os.Create(filename)
	if err != nil {
		errors.Warning("MEMORY_PROFILE_FILE_FAILED", "Failed to create memory profile file: "+err.Error())
		return
	}
	defer f.Close()

	// Force garbage collection before profiling
	runtime.GC()

	if err := pprof.WriteHeapProfile(f); err != nil {
		f.Close()
		errors.Warning("MEMORY_PROFILE_WRITE_FAILED", "Failed to write memory profile: "+err.Error())
		return
	}

	errors.Info("MEMORY_PROFILE_SUCCESS", "Memory profile captured: "+filename)
}

// CaptureSnapshot captures a one-time memory profile
func (p *Profiler) CaptureSnapshot(name string) error {
	if !p.enabled {
		return nil
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(p.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s/mem_snapshot_%s_%s.prof", p.outputDir, name, timestamp)

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create snapshot file: %w", err)
	}
	defer f.Close()

	// Force garbage collection before profiling
	runtime.GC()

	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("failed to write memory snapshot: %w", err)
	}

	fmt.Printf("Memory snapshot captured: %s\n", filename)
	return nil
}

// GetMemoryUsage returns current memory usage statistics
func (p *Profiler) GetMemoryUsage() MemoryStats {
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

// AnalyzeMemoryGrowth analyzes memory growth patterns
func (p *Profiler) AnalyzeMemoryGrowth(duration time.Duration) *MemoryGrowthAnalysis {
	initialStats := p.GetMemoryUsage()
	time.Sleep(duration)
	finalStats := p.GetMemoryUsage()

	growthRate := float64(finalStats.Alloc-initialStats.Alloc) / duration.Seconds()
	gcEfficiency := float64(finalStats.NumGC-initialStats.NumGC) / duration.Seconds()

	return &MemoryGrowthAnalysis{
		InitialMemory:   initialStats.Alloc,
		FinalMemory:     finalStats.Alloc,
		GrowthRate:      growthRate,
		GCEfficiency:    gcEfficiency,
		GoroutineGrowth: int64(finalStats.Goroutines) - int64(initialStats.Goroutines),
		Duration:        duration,
	}
}

// MemoryGrowthAnalysis contains memory growth analysis results
type MemoryGrowthAnalysis struct {
	InitialMemory   uint64
	FinalMemory     uint64
	GrowthRate      float64 // bytes per second
	GCEfficiency    float64 // GC cycles per second
	GoroutineGrowth int64
	Duration        time.Duration
}

// String returns a formatted string representation of the analysis
func (mga *MemoryGrowthAnalysis) String() string {
	return fmt.Sprintf(
		"Memory Growth Analysis:\n"+
			"  Duration: %v\n"+
			"  Initial Memory: %d MB\n"+
			"  Final Memory: %d MB\n"+
			"  Growth Rate: %.2f KB/s\n"+
			"  GC Efficiency: %.2f cycles/s\n"+
			"  Goroutine Growth: %d\n",
		mga.Duration,
		mga.InitialMemory/(1024*1024),
		mga.FinalMemory/(1024*1024),
		mga.GrowthRate/1024,
		mga.GCEfficiency,
		mga.GoroutineGrowth,
	)
}

// IsMemoryLeakSuspected returns true if memory leak is suspected
func (mga *MemoryGrowthAnalysis) IsMemoryLeakSuspected() bool {
	// Heuristics for memory leak detection
	growthThreshold := 1024.0 * 1024.0 // 1MB/s growth rate threshold
	goroutineThreshold := int64(50)    // 50 goroutines growth threshold

	return mga.GrowthRate > growthThreshold || mga.GoroutineGrowth > goroutineThreshold
}
