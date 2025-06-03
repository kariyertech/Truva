package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts to be 3, got %d", config.MaxAttempts)
	}
	if config.InitialDelay != 1*time.Second {
		t.Errorf("Expected InitialDelay to be 1s, got %v", config.InitialDelay)
	}
	if config.BackoffFactor != 2.0 {
		t.Errorf("Expected BackoffFactor to be 2.0, got %f", config.BackoffFactor)
	}
}

func TestKubernetesConfig(t *testing.T) {
	config := KubernetesConfig()
	if config.MaxAttempts != 5 {
		t.Errorf("Expected MaxAttempts to be 5, got %d", config.MaxAttempts)
	}
	if config.InitialDelay != 2*time.Second {
		t.Errorf("Expected InitialDelay to be 2s, got %v", config.InitialDelay)
	}
}

func TestDoSuccess(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	callCount := 0
	fn := func() error {
		callCount++
		return nil
	}

	err := Do(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}
}

func TestDoRetrySuccess(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        100 * time.Millisecond,
		BackoffFactor:   2.0,
		RetryableErrors: []string{"timeout"},
	}

	callCount := 0
	fn := func() error {
		callCount++
		if callCount < 3 {
			return errors.New("timeout error")
		}
		return nil
	}

	err := Do(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("Expected function to be called 3 times, got %d", callCount)
	}
}

func TestDoMaxAttemptsReached(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxAttempts:     2,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        100 * time.Millisecond,
		BackoffFactor:   2.0,
		RetryableErrors: []string{"timeout"},
	}

	callCount := 0
	fn := func() error {
		callCount++
		return errors.New("timeout error")
	}

	err := Do(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if callCount != 2 {
		t.Errorf("Expected function to be called 2 times, got %d", callCount)
	}
}

func TestDoNonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        100 * time.Millisecond,
		BackoffFactor:   2.0,
		RetryableErrors: []string{"timeout"},
	}

	callCount := 0
	fn := func() error {
		callCount++
		return errors.New("non-retryable error")
	}

	err := Do(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}
}

func TestDoWithResultSuccess(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	expectedResult := "success"
	fn := func() (string, error) {
		return expectedResult, nil
	}

	result, err := DoWithResult(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result != expectedResult {
		t.Errorf("Expected result %s, got %s", expectedResult, result)
	}
}

func TestDoContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := &RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    100 * time.Millisecond,
		MaxDelay:        1 * time.Second,
		BackoffFactor:   2.0,
		RetryableErrors: []string{"timeout"},
	}

	callCount := 0
	fn := func() error {
		callCount++
		if callCount == 1 {
			cancel() // Cancel context after first call
		}
		return errors.New("timeout error")
	}

	err := Do(ctx, config, fn)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		retryableErrors []string
		expected        bool
	}{
		{
			name:            "retryable error",
			err:             errors.New("connection refused"),
			retryableErrors: []string{"connection refused", "timeout"},
			expected:        true,
		},
		{
			name:            "non-retryable error",
			err:             errors.New("invalid input"),
			retryableErrors: []string{"connection refused", "timeout"},
			expected:        false,
		},
		{
			name:            "nil error",
			err:             nil,
			retryableErrors: []string{"connection refused"},
			expected:        false,
		},
		{
			name:            "partial match",
			err:             errors.New("network timeout occurred"),
			retryableErrors: []string{"timeout"},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err, tt.retryableErrors)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(2, 100*time.Millisecond)

	// Test initial state
	if cb.GetState() != Closed {
		t.Errorf("Expected initial state to be Closed, got %v", cb.GetState())
	}

	// Test successful execution
	err := cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test failures leading to open state
	for i := 0; i < 2; i++ {
		err = cb.Execute(func() error {
			return errors.New("test error")
		})
		if err == nil {
			t.Error("Expected error, got nil")
		}
	}

	// Circuit should be open now
	if cb.GetState() != Open {
		t.Errorf("Expected state to be Open, got %v", cb.GetState())
	}

	// Test that circuit breaker rejects calls when open
	err = cb.Execute(func() error {
		return nil
	})
	if err == nil {
		t.Error("Expected circuit breaker to reject call when open")
	}

	// Wait for reset timeout
	time.Sleep(150 * time.Millisecond)

	// Test successful execution after timeout (should transition to closed)
	err = cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error after reset, got %v", err)
	}

	if cb.GetState() != Closed {
		t.Errorf("Expected state to be Closed after successful execution, got %v", cb.GetState())
	}
}
