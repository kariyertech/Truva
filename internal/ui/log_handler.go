package ui

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// LogHandler manages log file watching and streaming with graceful shutdown
type LogHandler struct {
	ctx        context.Context
	cancel     context.CancelFunc
	watcher    *fsnotify.Watcher
	logFile    *os.File
	wg         sync.WaitGroup
	shutdownCh chan struct{}
	mu         sync.RWMutex
	running    bool
}

// NewLogHandler creates a new log handler with graceful shutdown support
func NewLogHandler() *LogHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &LogHandler{
		ctx:        ctx,
		cancel:     cancel,
		shutdownCh: make(chan struct{}),
	}
}

// Start begins log file watching and streaming
func (lh *LogHandler) Start() error {
	lh.mu.Lock()
	defer lh.mu.Unlock()

	if lh.running {
		return fmt.Errorf("log handler already running")
	}

	// Open log file
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	lh.logFile = logFile

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		lh.logFile.Close()
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	lh.watcher = watcher

	// Add log file to watcher
	err = watcher.Add("app.log")
	if err != nil {
		lh.cleanup()
		return fmt.Errorf("failed to watch log file: %w", err)
	}

	lh.running = true
	utils.Logger.Info("Log handler started, sending logs to UI...")

	// Start log processing goroutine
	lh.wg.Add(1)
	recovery.SafeGoWithContext(lh.ctx, func(ctx context.Context) {
		defer lh.wg.Done()
		lh.processLogs(ctx)
	}, map[string]interface{}{
		"component": "log_handler",
		"operation": "process_logs",
	})

	return nil
}

// Stop gracefully shuts down the log handler
func (lh *LogHandler) Stop() error {
	lh.mu.Lock()
	defer lh.mu.Unlock()

	if !lh.running {
		return nil
	}

	utils.Logger.Info("Stopping log handler...")

	// Cancel context to signal shutdown
	lh.cancel()

	// Close shutdown channel
	close(lh.shutdownCh)

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		lh.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		utils.Logger.Info("Log handler stopped gracefully")
	case <-time.After(5 * time.Second):
		utils.Logger.Warning("Log handler shutdown timeout, forcing stop")
	}

	// Cleanup resources
	lh.cleanup()
	lh.running = false

	return nil
}

// cleanup closes all resources
func (lh *LogHandler) cleanup() {
	if lh.watcher != nil {
		lh.watcher.Close()
		lh.watcher = nil
	}
	if lh.logFile != nil {
		lh.logFile.Close()
		lh.logFile = nil
	}
}

// processLogs handles log file changes and streaming
func (lh *LogHandler) processLogs(ctx context.Context) {
	reader := bufio.NewReader(lh.logFile)

	for {
		select {
		case <-ctx.Done():
			utils.Logger.Info("Log processing stopped due to context cancellation")
			return
		case <-lh.shutdownCh:
			utils.Logger.Info("Log processing stopped due to shutdown signal")
			return
		case event, ok := <-lh.watcher.Events:
			if !ok {
				utils.Logger.Warning("Log watcher events channel closed")
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				lh.handleLogWrite(reader)
			}
		case err, ok := <-lh.watcher.Errors:
			if !ok {
				utils.Logger.Warning("Log watcher errors channel closed")
				return
			}
			utils.Logger.Error(fmt.Sprintf("Log watcher error: %v", err))
			// Continue processing despite errors
		}
	}
}

// handleLogWrite processes new log entries
func (lh *LogHandler) handleLogWrite(reader *bufio.Reader) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// No more lines to read
			break
		}

		if strings.TrimSpace(line) != "" {
			if err := lh.sendLogToUI(line); err != nil {
				utils.Logger.Error(fmt.Sprintf("Failed to send log to UI: %v", err))
			}
		}
	}
}

// sendLogToUI sends log entry to the UI
func (lh *LogHandler) sendLogToUI(log string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Post("http://localhost:8080/api/logs", "text/plain", strings.NewReader(log))
	if err != nil {
		return fmt.Errorf("failed to send log to UI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// Global log handler instance
var (
	globalLogHandler *LogHandler
	logHandlerOnce   sync.Once
)

// GetLogHandler returns the global log handler instance
func GetLogHandler() *LogHandler {
	logHandlerOnce.Do(func() {
		globalLogHandler = NewLogHandler()
	})
	return globalLogHandler
}

// StartLogHandler starts the global log handler (backward compatibility)
func StartLogHandler() {
	handler := GetLogHandler()
	if err := handler.Start(); err != nil {
		utils.Logger.Error(fmt.Sprintf("Failed to start log handler: %v", err))
	}
}

// StopLogHandler stops the global log handler
func StopLogHandler() error {
	if globalLogHandler != nil {
		return globalLogHandler.Stop()
	}
	return nil
}
