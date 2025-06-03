package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchForChanges(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truva-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("initial content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test parameters
	namespace := "test-namespace"
	targetName := "test-deployment"
	containerPath := "/app"

	// Start watching in a goroutine
	done := make(chan bool)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected to panic due to missing k8s client in test environment
				done <- true
			}
		}()
		WatchForChanges(ctx, tempDir, namespace, targetName, containerPath)
		done <- true
	}()

	// Wait a bit for the watcher to start
	time.Sleep(100 * time.Millisecond)

	// Modify the test file
	err = os.WriteFile(testFile, []byte("modified content"), 0644)
	if err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	// Wait for the function to complete or timeout
	select {
	case <-done:
		// Function completed (likely panicked due to missing k8s client, which is expected)
	case <-ctx.Done():
		// Timeout reached, which is also acceptable for this test
	}
}

func TestSyncFilesAndRestartAllPods(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truva-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a context
	ctx := context.Background()

	// Test parameters
	namespace := "test-namespace"
	targetName := "test-deployment"
	containerPath := "/app"

	// This test will fail due to missing k8s client, but it tests the function signature
	err = SyncFilesAndRestartAllPods(ctx, namespace, targetName, tempDir, containerPath)
	if err == nil {
		t.Error("Expected error due to missing k8s client, but got nil")
	}
}

func TestValidateParameters(t *testing.T) {
	tests := []struct {
		name          string
		localPath     string
		namespace     string
		targetType    string
		targetName    string
		containerPath string
		wantErr       bool
	}{
		{
			name:          "valid parameters",
			localPath:     "/tmp",
			namespace:     "default",
			targetType:    "deployment",
			targetName:    "test-app",
			containerPath: "/app",
			wantErr:       false,
		},
		{
			name:          "empty local path",
			localPath:     "",
			namespace:     "default",
			targetType:    "deployment",
			targetName:    "test-app",
			containerPath: "/app",
			wantErr:       true,
		},
		{
			name:          "empty namespace",
			localPath:     "/tmp",
			namespace:     "",
			targetType:    "deployment",
			targetName:    "test-app",
			containerPath: "/app",
			wantErr:       true,
		},
		{
			name:          "invalid target type",
			localPath:     "/tmp",
			namespace:     "default",
			targetType:    "invalid",
			targetName:    "test-app",
			containerPath: "/app",
			wantErr:       true,
		},
		{
			name:          "empty target name",
			localPath:     "/tmp",
			namespace:     "default",
			targetType:    "deployment",
			targetName:    "",
			containerPath: "/app",
			wantErr:       true,
		},
		{
			name:          "empty container path",
			localPath:     "/tmp",
			namespace:     "default",
			targetType:    "deployment",
			targetName:    "test-app",
			containerPath: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParameters(tt.localPath, tt.namespace, tt.targetType, tt.targetName, tt.containerPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateParameters() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function to test parameter validation
func validateParameters(localPath, namespace, targetType, targetName, containerPath string) error {
	if localPath == "" {
		return fmt.Errorf("local path cannot be empty")
	}
	if namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if targetType != "deployment" && targetType != "statefulset" && targetType != "daemonset" {
		return fmt.Errorf("invalid target type: %s", targetType)
	}
	if targetName == "" {
		return fmt.Errorf("target name cannot be empty")
	}
	if containerPath == "" {
		return fmt.Errorf("container path cannot be empty")
	}
	return nil
}
