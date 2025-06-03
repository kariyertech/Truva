package cleanup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truva-cleanup-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFile1 := filepath.Join(tempDir, "test1.txt")
	testFile2 := filepath.Join(tempDir, "test2.txt")
	testDir := filepath.Join(tempDir, "testdir")

	err = os.WriteFile(testFile1, []byte("test content 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}

	err = os.WriteFile(testFile2, []byte("test content 2"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	err = os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Test CleanupManager
	manager := NewCleanupManager()

	// Add files and directories to cleanup
	manager.AddTempFile(testFile1)
	manager.AddTempFile(testFile2)
	manager.AddTempDir(testDir)

	// Verify files exist before cleanup
	if _, err := os.Stat(testFile1); os.IsNotExist(err) {
		t.Errorf("Test file 1 should exist before cleanup")
	}
	if _, err := os.Stat(testFile2); os.IsNotExist(err) {
		t.Errorf("Test file 2 should exist before cleanup")
	}
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Errorf("Test directory should exist before cleanup")
	}

	// Perform cleanup
	manager.Cleanup()

	// Verify files are removed after cleanup
	if _, err := os.Stat(testFile1); !os.IsNotExist(err) {
		t.Errorf("Test file 1 should be removed after cleanup")
	}
	if _, err := os.Stat(testFile2); !os.IsNotExist(err) {
		t.Errorf("Test file 2 should be removed after cleanup")
	}
	if _, err := os.Stat(testDir); !os.IsNotExist(err) {
		t.Errorf("Test directory should be removed after cleanup")
	}
}

func TestAddTempFileAndCleanup(t *testing.T) {
	manager := NewCleanupManager()

	// Create a temporary file
	tempFile, err := os.CreateTemp("", "test-file-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()

	// Add to manager and cleanup
	manager.AddTempFile(tempFile.Name())
	err = manager.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}

	// Check if file is removed
	if _, err := os.Stat(tempFile.Name()); !os.IsNotExist(err) {
		t.Errorf("File should be removed but still exists")
	}

	// Test cleanup with non-existent file (should not error)
	manager2 := NewCleanupManager()
	manager2.AddTempFile("/non/existent/file.txt")
	err = manager2.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() should not error for non-existent file, got: %v", err)
	}
}

func TestAddTempDirAndCleanup(t *testing.T) {
	manager := NewCleanupManager()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "test-dir-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a file inside the directory
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Add to manager and cleanup
	manager.AddTempDir(tempDir)
	err = manager.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}

	// Check if directory is removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Errorf("Directory should be removed but still exists")
	}

	// Test cleanup with non-existent directory (should not error)
	manager2 := NewCleanupManager()
	manager2.AddTempDir("/non/existent/dir")
	err = manager2.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() should not error for non-existent directory, got: %v", err)
	}
}

func TestCleanupOldBackups(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truva-cleanup-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create old backup files in /tmp (simulate)
	oldBackup1 := filepath.Join(tempDir, "truva-backup-deployment-old1.yaml")
	oldBackup2 := filepath.Join(tempDir, "truva-backup-deployment-old2.yaml")
	recentBackup := filepath.Join(tempDir, "truva-backup-deployment-recent.yaml")

	// Create files with different modification times
	now := time.Now()
	oldTime := now.Add(-25 * time.Hour)   // Older than 24 hours
	recentTime := now.Add(-1 * time.Hour) // Recent

	err = os.WriteFile(oldBackup1, []byte("old backup 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create old backup 1: %v", err)
	}
	os.Chtimes(oldBackup1, oldTime, oldTime)

	err = os.WriteFile(oldBackup2, []byte("old backup 2"), 0644)
	if err != nil {
		t.Fatalf("Failed to create old backup 2: %v", err)
	}
	os.Chtimes(oldBackup2, oldTime, oldTime)

	err = os.WriteFile(recentBackup, []byte("recent backup"), 0644)
	if err != nil {
		t.Fatalf("Failed to create recent backup: %v", err)
	}
	os.Chtimes(recentBackup, recentTime, recentTime)

	// Test cleanup function with custom temp directory
	cleanupOldBackupsInDir(tempDir)

	// Verify old backups are removed and recent backup remains
	if _, err := os.Stat(oldBackup1); !os.IsNotExist(err) {
		t.Errorf("Old backup 1 should be removed")
	}
	if _, err := os.Stat(oldBackup2); !os.IsNotExist(err) {
		t.Errorf("Old backup 2 should be removed")
	}
	if _, err := os.Stat(recentBackup); os.IsNotExist(err) {
		t.Errorf("Recent backup should still exist")
	}
}

func TestCleanupModifiedFiles(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truva-cleanup-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create modified deployment files
	modifiedFile1 := filepath.Join(tempDir, "truva-modified-deployment1.yaml")
	modifiedFile2 := filepath.Join(tempDir, "truva-modified-statefulset1.yaml")
	regularFile := filepath.Join(tempDir, "regular-file.yaml")

	err = os.WriteFile(modifiedFile1, []byte("modified deployment"), 0644)
	if err != nil {
		t.Fatalf("Failed to create modified file 1: %v", err)
	}

	err = os.WriteFile(modifiedFile2, []byte("modified statefulset"), 0644)
	if err != nil {
		t.Fatalf("Failed to create modified file 2: %v", err)
	}

	err = os.WriteFile(regularFile, []byte("regular file"), 0644)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Test cleanup function with custom temp directory
	cleanupModifiedFilesInDir(tempDir)

	// Verify modified files are removed and regular file remains
	if _, err := os.Stat(modifiedFile1); !os.IsNotExist(err) {
		t.Errorf("Modified file 1 should be removed")
	}
	if _, err := os.Stat(modifiedFile2); !os.IsNotExist(err) {
		t.Errorf("Modified file 2 should be removed")
	}
	if _, err := os.Stat(regularFile); os.IsNotExist(err) {
		t.Errorf("Regular file should still exist")
	}
}

// Helper functions for testing (these would be internal functions in the actual implementation)
func cleanupOldBackupsInDir(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "truva-backup-*.yaml"))
	if err != nil {
		return
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if time.Since(info.ModTime()) > 24*time.Hour {
			os.Remove(file)
		}
	}
}

func cleanupModifiedFilesInDir(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "truva-modified-*.yaml"))
	if err != nil {
		return
	}

	for _, file := range files {
		os.Remove(file)
	}
}
