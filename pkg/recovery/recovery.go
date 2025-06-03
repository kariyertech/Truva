package recovery

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// PanicHandler defines the interface for handling panics
type PanicHandler interface {
	HandlePanic(panicValue interface{}, stack []byte, context map[string]interface{})
}

// DefaultPanicHandler provides default panic handling behavior
type DefaultPanicHandler struct {
	logger *logrus.Logger
}

// NewDefaultPanicHandler creates a new default panic handler
func NewDefaultPanicHandler() *DefaultPanicHandler {
	return &DefaultPanicHandler{
		logger: logrus.New(),
	}
}

// HandlePanic handles a panic with logging and optional reporting
func (h *DefaultPanicHandler) HandlePanic(panicValue interface{}, stack []byte, context map[string]interface{}) {
	fields := logrus.Fields{
		"panic_value":  fmt.Sprintf("%v", panicValue),
		"stack_trace":  string(stack),
		"goroutine_id": getGoroutineID(),
		"timestamp":    time.Now().UTC(),
	}

	// Add context information
	for key, value := range context {
		fields[key] = value
	}

	h.logger.WithFields(fields).Error("Panic recovered in goroutine")

	// Optional: Send to external monitoring/alerting system
	// This could be extended to integrate with services like Sentry, DataDog, etc.
}

// getGoroutineID extracts the current goroutine ID from the stack trace
func getGoroutineID() string {
	buf := make([]byte, 64)
	buf = buf[:runtime.Stack(buf, false)]
	// Parse goroutine ID from stack trace
	// Format: "goroutine 123 [running]:"
	for i := 0; i < len(buf); i++ {
		if buf[i] == ' ' {
			for j := i + 1; j < len(buf); j++ {
				if buf[j] == ' ' {
					return string(buf[i+1 : j])
				}
			}
			break
		}
	}
	return "unknown"
}

// RecoveryManager manages panic recovery across the application
type RecoveryManager struct {
	handler PanicHandler
	mu      sync.RWMutex
	stats   *RecoveryStats
}

// RecoveryStats tracks panic recovery statistics
type RecoveryStats struct {
	TotalPanics     int64            `json:"total_panics"`
	LastPanicTime   time.Time        `json:"last_panic_time"`
	PanicsByType    map[string]int64 `json:"panics_by_type"`
	PanicsByContext map[string]int64 `json:"panics_by_context"`
	mu              sync.RWMutex
}

// NewRecoveryStats creates a new recovery stats tracker
func NewRecoveryStats() *RecoveryStats {
	return &RecoveryStats{
		PanicsByType:    make(map[string]int64),
		PanicsByContext: make(map[string]int64),
	}
}

// RecordPanic records a panic occurrence
func (s *RecoveryStats) RecordPanic(panicType, context string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalPanics++
	s.LastPanicTime = time.Now()
	s.PanicsByType[panicType]++
	s.PanicsByContext[context]++
}

// GetStats returns a copy of the current stats
func (s *RecoveryStats) GetStats() RecoveryStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create deep copy
	statsCopy := RecoveryStats{
		TotalPanics:     s.TotalPanics,
		LastPanicTime:   s.LastPanicTime,
		PanicsByType:    make(map[string]int64),
		PanicsByContext: make(map[string]int64),
	}

	for k, v := range s.PanicsByType {
		statsCopy.PanicsByType[k] = v
	}
	for k, v := range s.PanicsByContext {
		statsCopy.PanicsByContext[k] = v
	}

	return statsCopy
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(handler PanicHandler) *RecoveryManager {
	if handler == nil {
		handler = NewDefaultPanicHandler()
	}

	return &RecoveryManager{
		handler: handler,
		stats:   NewRecoveryStats(),
	}
}

// Global recovery manager instance
var globalRecoveryManager *RecoveryManager
var once sync.Once

// GetGlobalRecoveryManager returns the global recovery manager instance
func GetGlobalRecoveryManager() *RecoveryManager {
	once.Do(func() {
		globalRecoveryManager = NewRecoveryManager(nil)
	})
	return globalRecoveryManager
}

// SetGlobalPanicHandler sets the global panic handler
func SetGlobalPanicHandler(handler PanicHandler) {
	manager := GetGlobalRecoveryManager()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.handler = handler
}

// SafeGo executes a function in a goroutine with panic recovery
func SafeGo(fn func(), context map[string]interface{}) {
	go SafeExecute(fn, context)
}

// SafeGoWithContext executes a function in a goroutine with context and panic recovery
func SafeGoWithContext(ctx context.Context, fn func(context.Context), contextInfo map[string]interface{}) {
	go SafeExecuteWithContext(ctx, fn, contextInfo)
}

// SafeExecute executes a function with panic recovery
func SafeExecute(fn func(), context map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			manager := GetGlobalRecoveryManager()

			// Record panic statistics
			panicType := fmt.Sprintf("%T", r)
			contextName := "unknown"
			if context != nil {
				if name, ok := context["name"]; ok {
					contextName = fmt.Sprintf("%v", name)
				}
			}
			manager.stats.RecordPanic(panicType, contextName)

			// Handle the panic
			manager.handler.HandlePanic(r, stack, context)
		}
	}()

	fn()
}

// SafeExecuteWithContext executes a function with context and panic recovery
func SafeExecuteWithContext(ctx context.Context, fn func(context.Context), contextInfo map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			manager := GetGlobalRecoveryManager()

			// Add context information
			if contextInfo == nil {
				contextInfo = make(map[string]interface{})
			}
			contextInfo["context_deadline"] = ctx.Err() != nil
			contextInfo["context_cancelled"] = ctx.Err() == context.Canceled

			// Record panic statistics
			panicType := fmt.Sprintf("%T", r)
			contextName := "unknown"
			if name, ok := contextInfo["name"]; ok {
				contextName = fmt.Sprintf("%v", name)
			}
			manager.stats.RecordPanic(panicType, contextName)

			// Handle the panic
			manager.handler.HandlePanic(r, stack, contextInfo)
		}
	}()

	fn(ctx)
}

// SafeExecuteWithRetry executes a function with panic recovery and retry logic
func SafeExecuteWithRetry(fn func() error, maxRetries int, retryDelay time.Duration, context map[string]interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					stack := debug.Stack()
					manager := GetGlobalRecoveryManager()

					// Add retry information to context
					if context == nil {
						context = make(map[string]interface{})
					}
					context["retry_attempt"] = attempt
					context["max_retries"] = maxRetries

					// Record panic statistics
					panicType := fmt.Sprintf("%T", r)
					contextName := "retry_operation"
					if name, ok := context["name"]; ok {
						contextName = fmt.Sprintf("%v", name)
					}
					manager.stats.RecordPanic(panicType, contextName)

					// Handle the panic
					manager.handler.HandlePanic(r, stack, context)

					// Convert panic to error for retry logic
					err = fmt.Errorf("panic recovered: %v", r)
				}
			}()

			return fn()
		}()

		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Don't sleep after the last attempt
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxRetries+1, lastErr)
}

// GetRecoveryStats returns the current recovery statistics
func GetRecoveryStats() RecoveryStats {
	manager := GetGlobalRecoveryManager()
	return manager.stats.GetStats()
}

// RecoveryMiddleware provides HTTP middleware for panic recovery
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				manager := GetGlobalRecoveryManager()

				context := map[string]interface{}{
					"name":           "http_handler",
					"request_method": r.Method,
					"request_url":    r.URL.String(),
					"remote_addr":    r.RemoteAddr,
					"user_agent":     r.UserAgent(),
				}

				// Record panic statistics
				panicType := fmt.Sprintf("%T", rec)
				manager.stats.RecordPanic(panicType, "http_handler")

				// Handle the panic
				manager.handler.HandlePanic(rec, stack, context)

				// Send error response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"Internal server error","message":"An unexpected error occurred"}`))
			}
		}()

		next.ServeHTTP(w, r)
	})
}
