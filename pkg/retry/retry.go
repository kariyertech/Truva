package retry

import (
	"context"
	"fmt"
	"time"

	"github.com/kariyertech/Truva.git/pkg/utils"
)

// RetryConfig defines the configuration for retry operations
type RetryConfig struct {
	MaxAttempts     int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	RetryableErrors []string
}

// DefaultConfig returns a default retry configuration
func DefaultConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"network is unreachable",
			"no such host",
			"context deadline exceeded",
		},
	}
}

// KubernetesConfig returns a retry configuration optimized for Kubernetes operations
func KubernetesConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   5,
		InitialDelay:  2 * time.Second,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 1.5,
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"network is unreachable",
			"no such host",
			"context deadline exceeded",
			"server is currently unable to handle the request",
			"too many requests",
			"service unavailable",
			"internal server error",
			"bad gateway",
			"gateway timeout",
		},
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryableFuncWithResult is a function that returns a result and can be retried
type RetryableFuncWithResult[T any] func() (T, error)

// Do executes a function with retry logic
func Do(ctx context.Context, config *RetryConfig, fn RetryableFunc) error {
	if config == nil {
		config = DefaultConfig()
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := fn()
		if err == nil {
			if attempt > 1 {
				utils.Logger.Info(fmt.Sprintf("Operation succeeded after %d attempts", attempt))
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err, config.RetryableErrors) {
			utils.Logger.Error(fmt.Sprintf("Non-retryable error on attempt %d: %v", attempt, err))
			return err
		}

		if attempt == config.MaxAttempts {
			utils.Logger.Error(fmt.Sprintf("Max attempts (%d) reached. Last error: %v", config.MaxAttempts, err))
			break
		}

		utils.Logger.Warn(fmt.Sprintf("Attempt %d failed: %v. Retrying in %v...", attempt, err, delay))

		// Wait before retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		// Calculate next delay with exponential backoff
		delay = time.Duration(float64(delay) * config.BackoffFactor)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// DoWithResult executes a function with retry logic and returns a result
func DoWithResult[T any](ctx context.Context, config *RetryConfig, fn RetryableFuncWithResult[T]) (T, error) {
	var zero T
	if config == nil {
		config = DefaultConfig()
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		default:
		}

		result, err := fn()
		if err == nil {
			if attempt > 1 {
				utils.Logger.Info(fmt.Sprintf("Operation succeeded after %d attempts", attempt))
			}
			return result, nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err, config.RetryableErrors) {
			utils.Logger.Error(fmt.Sprintf("Non-retryable error on attempt %d: %v", attempt, err))
			return zero, err
		}

		if attempt == config.MaxAttempts {
			utils.Logger.Error(fmt.Sprintf("Max attempts (%d) reached. Last error: %v", config.MaxAttempts, err))
			break
		}

		utils.Logger.Warn(fmt.Sprintf("Attempt %d failed: %v. Retrying in %v...", attempt, err, delay))

		// Wait before retry
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(delay):
		}

		// Calculate next delay with exponential backoff
		delay = time.Duration(float64(delay) * config.BackoffFactor)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return zero, fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// isRetryableError checks if an error should trigger a retry
func isRetryableError(err error, retryableErrors []string) bool {
	if err == nil {
		return false
	}

	errorStr := err.Error()
	for _, retryableError := range retryableErrors {
		if contains(errorStr, retryableError) {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					indexOfSubstring(s, substr) >= 0))
}

// indexOfSubstring finds the index of a substring in a string
func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Circuit breaker pattern for additional resilience
type CircuitBreaker struct {
	maxFailures     int
	resetTimeout    time.Duration
	failureCount    int
	lastFailureTime time.Time
	state           CircuitState
}

type CircuitState int

const (
	Closed CircuitState = iota
	Open
	HalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        Closed,
	}
}

// Execute runs a function through the circuit breaker
func (cb *CircuitBreaker) Execute(fn RetryableFunc) error {
	if cb.state == Open {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = HalfOpen
			utils.Logger.Info("Circuit breaker transitioning to half-open state")
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	err := fn()
	if err != nil {
		cb.onFailure()
		return err
	}

	cb.onSuccess()
	return nil
}

func (cb *CircuitBreaker) onSuccess() {
	cb.failureCount = 0
	if cb.state == HalfOpen {
		cb.state = Closed
		utils.Logger.Info("Circuit breaker closed after successful operation")
	}
}

func (cb *CircuitBreaker) onFailure() {
	cb.failureCount++
	cb.lastFailureTime = time.Now()

	if cb.failureCount >= cb.maxFailures {
		cb.state = Open
		utils.Logger.Warn(fmt.Sprintf("Circuit breaker opened after %d failures", cb.failureCount))
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	return cb.state
}
