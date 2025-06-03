package utils

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kariyertech/Truva.git/pkg/memory"
	"github.com/kariyertech/Truva.git/pkg/recovery"
)

// WatcherConfig holds configuration for file watcher optimization
type WatcherConfig struct {
	MaxWatchedPaths   int           // Maximum number of paths to watch
	DebounceInterval  time.Duration // Debounce interval for events
	IgnorePatterns    []string      // Patterns to ignore
	SelectivePatterns []string      // Patterns to selectively watch
	MaxEventBuffer    int           // Maximum event buffer size
	PerformanceMode   bool          // Enable performance optimizations
}

// DefaultWatcherConfig returns default watcher configuration
func DefaultWatcherConfig() *WatcherConfig {
	return &WatcherConfig{
		MaxWatchedPaths:  1000,
		DebounceInterval: 100 * time.Millisecond,
		IgnorePatterns: []string{
			"\\.git/.*",
			"\\.DS_Store",
			"\\._.*",
			"\\.tmp",
			"\\.temp",
			"node_modules/.*",
			"\\.vscode/.*",
			"\\.idea/.*",
			"\\*.log",
			"\\*.swp",
			"\\*.swo",
		},
		SelectivePatterns: []string{
			"\\*.go",
			"\\*.yaml",
			"\\*.yml",
			"\\*.json",
			"\\*.toml",
			"\\*.md",
		},
		MaxEventBuffer:  10000,
		PerformanceMode: true,
	}
}

// WatcherStats tracks file watcher performance statistics
type WatcherStats struct {
	EventsProcessed  int64
	EventsIgnored    int64
	EventsDebounced  int64
	PathsWatched     int64
	StartTime        time.Time
	LastEventTime    time.Time
	AverageEventRate float64
	PeakEventRate    float64
	MemoryUsage      int64
}

// EventInfo holds information about a file system event
type EventInfo struct {
	Event     fsnotify.Event
	Timestamp time.Time
	Processed bool
}

type Watcher struct {
	watcher          *fsnotify.Watcher
	memoryMonitor    *memory.MemoryMonitor
	lastCleanup      time.Time
	cleanupMutex     sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	shutdownCh       chan struct{}
	mu               sync.RWMutex
	running          bool
	watchPaths       map[string]bool
	config           *WatcherConfig
	ignoreRegexps    []*regexp.Regexp
	selectiveRegexps []*regexp.Regexp
	stats            *WatcherStats
	eventBuffer      chan *EventInfo
	debounceMap      map[string]*time.Timer
	debounceMutex    sync.RWMutex
	performanceMode  bool
}

func NewWatcher() (*Watcher, error) {
	return NewWatcherWithConfig(DefaultWatcherConfig())
}

func NewWatcherWithConfig(config *WatcherConfig) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	// Initialize memory monitor for file watcher
	memMonitor := memory.NewMonitor(
		100*1024*1024, // 100MB threshold
		200,           // 200 goroutines threshold
		func(alert memory.MemoryAlert) {
			Logger.Warning(fmt.Sprintf("File Watcher Memory Alert [%s]: %s", alert.Severity, alert.Message))
		},
	)
	memMonitor.Start()

	ctx, cancel := context.WithCancel(context.Background())

	// Compile ignore patterns
	ignoreRegexps := make([]*regexp.Regexp, 0, len(config.IgnorePatterns))
	for _, pattern := range config.IgnorePatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			ignoreRegexps = append(ignoreRegexps, regex)
		} else {
			Logger.Warning(fmt.Sprintf("Invalid ignore pattern '%s': %v", pattern, err))
		}
	}

	// Compile selective patterns
	selectiveRegexps := make([]*regexp.Regexp, 0, len(config.SelectivePatterns))
	for _, pattern := range config.SelectivePatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			selectiveRegexps = append(selectiveRegexps, regex)
		} else {
			Logger.Warning(fmt.Sprintf("Invalid selective pattern '%s': %v", pattern, err))
		}
	}

	w := &Watcher{
		watcher:          watcher,
		memoryMonitor:    memMonitor,
		lastCleanup:      time.Now(),
		ctx:              ctx,
		cancel:           cancel,
		shutdownCh:       make(chan struct{}),
		watchPaths:       make(map[string]bool),
		config:           config,
		ignoreRegexps:    ignoreRegexps,
		selectiveRegexps: selectiveRegexps,
		stats: &WatcherStats{
			StartTime: time.Now(),
		},
		eventBuffer:     make(chan *EventInfo, config.MaxEventBuffer),
		debounceMap:     make(map[string]*time.Timer),
		performanceMode: config.PerformanceMode,
	}

	// Start performance monitoring if enabled
	if w.performanceMode {
		go w.monitorPerformance()
	}

	return w, nil
}

// shouldIgnoreEvent checks if an event should be ignored based on patterns
func (w *Watcher) shouldIgnoreEvent(event fsnotify.Event) bool {
	filePath := event.Name

	// Check ignore patterns
	for _, regex := range w.ignoreRegexps {
		if regex.MatchString(filepath.Base(filePath)) || regex.MatchString(filePath) {
			atomic.AddInt64(&w.stats.EventsIgnored, 1)
			return true
		}
	}

	// Check selective patterns (if any are defined, only allow matching files)
	if len(w.selectiveRegexps) > 0 {
		for _, regex := range w.selectiveRegexps {
			if regex.MatchString(filepath.Base(filePath)) || regex.MatchString(filePath) {
				return false // Don't ignore, it matches selective pattern
			}
		}
		// No selective pattern matched, ignore the event
		atomic.AddInt64(&w.stats.EventsIgnored, 1)
		return true
	}

	return false
}

// debounceEvent implements event debouncing to reduce noise
func (w *Watcher) debounceEvent(event fsnotify.Event, onChange func(event fsnotify.Event)) {
	w.debounceMutex.Lock()
	defer w.debounceMutex.Unlock()

	filePath := event.Name

	// Cancel existing timer for this file
	if timer, exists := w.debounceMap[filePath]; exists {
		timer.Stop()
		atomic.AddInt64(&w.stats.EventsDebounced, 1)
	}

	// Create new timer
	w.debounceMap[filePath] = time.AfterFunc(w.config.DebounceInterval, func() {
		w.debounceMutex.Lock()
		delete(w.debounceMap, filePath)
		w.debounceMutex.Unlock()

		// Process the event
		onChange(event)
		atomic.AddInt64(&w.stats.EventsProcessed, 1)
		w.stats.LastEventTime = time.Now()
	})
}

// monitorPerformance monitors watcher performance and adjusts settings
func (w *Watcher) monitorPerformance() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	lastEventCount := int64(0)

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			currentEvents := atomic.LoadInt64(&w.stats.EventsProcessed)
			eventRate := float64(currentEvents-lastEventCount) / 30.0 // events per second
			lastEventCount = currentEvents

			// Update average and peak event rates
			if w.stats.AverageEventRate == 0 {
				w.stats.AverageEventRate = eventRate
			} else {
				w.stats.AverageEventRate = (w.stats.AverageEventRate + eventRate) / 2
			}

			if eventRate > w.stats.PeakEventRate {
				w.stats.PeakEventRate = eventRate
			}

			// Log performance metrics
			Logger.Debug(fmt.Sprintf("File Watcher Performance: %.2f events/sec (avg: %.2f, peak: %.2f)",
				eventRate, w.stats.AverageEventRate, w.stats.PeakEventRate))

			// Adjust debounce interval based on event rate
			if eventRate > 100 { // High event rate
				w.config.DebounceInterval = 500 * time.Millisecond
			} else if eventRate > 50 {
				w.config.DebounceInterval = 200 * time.Millisecond
			} else {
				w.config.DebounceInterval = 100 * time.Millisecond
			}
		}
	}
}

func (w *Watcher) Watch(path string, onChange func(event fsnotify.Event)) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return fmt.Errorf("watcher is already running, stop it first")
	}

	// Check if we've reached the maximum number of watched paths
	if len(w.watchPaths) >= w.config.MaxWatchedPaths {
		return fmt.Errorf("maximum watched paths limit reached (%d)", w.config.MaxWatchedPaths)
	}

	err := w.watcher.Add(path)
	if err != nil {
		return fmt.Errorf("failed to watch path %s: %w", path, err)
	}

	w.watchPaths[path] = true
	atomic.AddInt64(&w.stats.PathsWatched, 1)
	w.running = true

	w.wg.Add(1)
	recovery.SafeGoWithContext(w.ctx, func(ctx context.Context) {
		defer w.wg.Done()
		w.processEvents(ctx, onChange)
	}, map[string]interface{}{
		"component": "file_watcher",
		"path":      path,
	})

	return nil
}

// WatchSelective watches a path with selective file filtering
func (w *Watcher) WatchSelective(path string, patterns []string, onChange func(event fsnotify.Event)) error {
	// Temporarily override selective patterns
	originalPatterns := w.config.SelectivePatterns
	w.config.SelectivePatterns = patterns

	// Recompile selective regexps
	selectiveRegexps := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			selectiveRegexps = append(selectiveRegexps, regex)
		} else {
			Logger.Warning(fmt.Sprintf("Invalid selective pattern '%s': %v", pattern, err))
		}
	}
	w.selectiveRegexps = selectiveRegexps

	err := w.Watch(path, onChange)

	// Restore original patterns
	w.config.SelectivePatterns = originalPatterns

	return err
}

// processEvents handles file system events with performance optimizations
func (w *Watcher) processEvents(ctx context.Context, onChange func(event fsnotify.Event)) {
	cleanupTicker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			Logger.Info("File watcher stopped due to context cancellation")
			return
		case <-w.shutdownCh:
			Logger.Info("File watcher stopped due to shutdown signal")
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				Logger.Warning("File watcher events channel closed")
				return
			}

			// Apply performance optimizations
			if w.shouldIgnoreEvent(event) {
				continue
			}

			// Use debouncing to reduce event noise
			if w.config.DebounceInterval > 0 {
				w.debounceEvent(event, onChange)
			} else {
				// Process immediately if debouncing is disabled
				onChange(event)
				atomic.AddInt64(&w.stats.EventsProcessed, 1)
				w.stats.LastEventTime = time.Now()
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				Logger.Warning("File watcher errors channel closed")
				return
			}
			Logger.Error(fmt.Sprintf("File watcher error: %v", err))

		case <-cleanupTicker.C:
			w.checkMemoryUsage()
		}
	}
}

func (w *Watcher) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return nil
	}

	Logger.Info("Stopping file watcher...")

	// Signal shutdown
	close(w.shutdownCh)

	// Cancel context
	w.cancel()

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		Logger.Info("File watcher stopped gracefully")
	case <-time.After(10 * time.Second):
		Logger.Warning("File watcher shutdown timeout")
	}

	w.running = false
	return w.cleanup()
}

func (w *Watcher) Close() error {
	return w.Stop()
}

func (w *Watcher) cleanup() error {
	// Clear debounce timers
	w.debounceMutex.Lock()
	for path, timer := range w.debounceMap {
		timer.Stop()
		delete(w.debounceMap, path)
	}
	w.debounceMutex.Unlock()

	// Close event buffer
	close(w.eventBuffer)

	// Stop memory monitor
	if w.memoryMonitor != nil {
		w.memoryMonitor.Stop()
	}

	// Close file system watcher
	if w.watcher != nil {
		return w.watcher.Close()
	}

	return nil
}

func (w *Watcher) checkMemoryUsage() {
	w.cleanupMutex.Lock()
	defer w.cleanupMutex.Unlock()

	if time.Since(w.lastCleanup) < 5*time.Minute {
		return
	}

	if w.memoryMonitor != nil {
		memStats := w.memoryMonitor.GetCurrentStats()
		w.stats.MemoryUsage = int64(memStats.Alloc)

		if memStats.Alloc > 50*1024*1024 { // 50MB threshold
			w.performPeriodicCleanup()
		}
	}

	w.lastCleanup = time.Now()
}

func (w *Watcher) performPeriodicCleanup() {
	// Trigger garbage collection if memory usage is high
	if w.memoryMonitor != nil {
		memStats := w.memoryMonitor.GetCurrentStats()
		if memStats.Alloc > 100*1024*1024 { // 100MB
			w.memoryMonitor.ForceGC()
			Logger.Info(fmt.Sprintf("File watcher triggered GC due to high memory usage: %d MB", memStats.Alloc/(1024*1024)))
		}
	}
}

// GetStats returns current watcher statistics
func (w *Watcher) GetStats() WatcherStats {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return WatcherStats{
		EventsProcessed:  atomic.LoadInt64(&w.stats.EventsProcessed),
		EventsIgnored:    atomic.LoadInt64(&w.stats.EventsIgnored),
		EventsDebounced:  atomic.LoadInt64(&w.stats.EventsDebounced),
		PathsWatched:     atomic.LoadInt64(&w.stats.PathsWatched),
		StartTime:        w.stats.StartTime,
		LastEventTime:    w.stats.LastEventTime,
		AverageEventRate: w.stats.AverageEventRate,
		PeakEventRate:    w.stats.PeakEventRate,
		MemoryUsage:      w.stats.MemoryUsage,
	}
}

func (w *Watcher) GetMemoryStats() map[string]interface{} {
	if w.memoryMonitor == nil {
		return map[string]interface{}{"error": "memory monitor not available"}
	}
	stats := w.memoryMonitor.GetStats()
	if len(stats) == 0 {
		return map[string]interface{}{"message": "no stats available"}
	}
	latestStats := stats[len(stats)-1]
	return map[string]interface{}{
		"alloc":       latestStats.Alloc,
		"total_alloc": latestStats.TotalAlloc,
		"sys":         latestStats.Sys,
		"num_gc":      latestStats.NumGC,
		"goroutines":  latestStats.Goroutines,
		"timestamp":   latestStats.Timestamp,
	}
}

func (w *Watcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

func (w *Watcher) GetWatchedPaths() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	paths := make([]string, 0, len(w.watchPaths))
	for path := range w.watchPaths {
		paths = append(paths, path)
	}
	return paths
}

// AddIgnorePattern adds a new ignore pattern at runtime
func (w *Watcher) AddIgnorePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid ignore pattern '%s': %w", pattern, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.ignoreRegexps = append(w.ignoreRegexps, regex)
	w.config.IgnorePatterns = append(w.config.IgnorePatterns, pattern)

	return nil
}

// RemoveIgnorePattern removes an ignore pattern
func (w *Watcher) RemoveIgnorePattern(pattern string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove from config
	for i, p := range w.config.IgnorePatterns {
		if p == pattern {
			w.config.IgnorePatterns = append(w.config.IgnorePatterns[:i], w.config.IgnorePatterns[i+1:]...)
			break
		}
	}

	// Recompile regexps
	ignoreRegexps := make([]*regexp.Regexp, 0, len(w.config.IgnorePatterns))
	for _, p := range w.config.IgnorePatterns {
		if regex, err := regexp.Compile(p); err == nil {
			ignoreRegexps = append(ignoreRegexps, regex)
		}
	}
	w.ignoreRegexps = ignoreRegexps
}

// GetConfig returns the current watcher configuration
func (w *Watcher) GetConfig() *WatcherConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return a copy to prevent external modifications
	config := *w.config
	return &config
}
