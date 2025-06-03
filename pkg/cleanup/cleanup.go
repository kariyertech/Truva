package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/pkg/utils"
)

type CleanupManager struct {
	tempFiles []string
	tempDirs  []string
}

func NewCleanupManager() *CleanupManager {
	return &CleanupManager{
		tempFiles: make([]string, 0),
		tempDirs:  make([]string, 0),
	}
}

func (c *CleanupManager) AddTempFile(path string) {
	c.tempFiles = append(c.tempFiles, path)
}

func (c *CleanupManager) AddTempDir(path string) {
	c.tempDirs = append(c.tempDirs, path)
}

func (c *CleanupManager) Cleanup() error {
	var errors []string

	// Clean up temporary files
	for _, file := range c.tempFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("failed to remove file %s: %v", file, err))
			utils.Logger.Warn("Failed to remove temporary file:", file, err)
		} else {
			utils.Logger.Debug("Removed temporary file:", file)
		}
	}

	// Clean up temporary directories
	for _, dir := range c.tempDirs {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("failed to remove directory %s: %v", dir, err))
			utils.Logger.Warn("Failed to remove temporary directory:", dir, err)
		} else {
			utils.Logger.Debug("Removed temporary directory:", dir)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}
	return nil
}

// CleanupOldBackups removes backup files older than the specified duration
func CleanupOldBackups(maxAge time.Duration) error {
	tempDir := "/tmp"
	cutoff := time.Now().Add(-maxAge)

	pattern := filepath.Join(tempDir, "*_backup.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find backup files: %w", err)
	}

	var errors []string
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(file); err != nil {
				errors = append(errors, fmt.Sprintf("failed to remove old backup %s: %v", file, err))
				utils.Logger.Warn("Failed to remove old backup:", file, err)
			} else {
				utils.Logger.Info("Removed old backup:", file)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}
	return nil
}

// CleanupModifiedFiles removes modified deployment files
func CleanupModifiedFiles() error {
	tempDir := "/tmp"
	pattern := filepath.Join(tempDir, "*_modified.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find modified files: %w", err)
	}

	var errors []string
	for _, file := range files {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("failed to remove modified file %s: %v", file, err))
			utils.Logger.Warn("Failed to remove modified file:", file, err)
		} else {
			utils.Logger.Debug("Removed modified file:", file)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}
	return nil
}
