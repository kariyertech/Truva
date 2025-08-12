package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/memory"
	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/utils"
	"github.com/sirupsen/logrus"
)

// FileSystemError represents different types of file system errors
type FileSystemError struct {
	Type    string
	Path    string
	Op      string
	Err     error
	Details map[string]interface{}
}

func (e *FileSystemError) Error() string {
	return fmt.Sprintf("filesystem error [%s] on %s during %s: %v", e.Type, e.Path, e.Op, e.Err)
}

// FileSystemChecker provides comprehensive file system validation
type FileSystemChecker struct {
	mu                  sync.RWMutex
	minDiskSpaceBytes   int64
	minDiskSpacePercent float64
	maxFileSize         int64
	allowedExtensions   map[string]bool
	blockedPaths        map[string]bool
	permissionCache     map[string]time.Time
	permissionCacheTTL  time.Duration
}

// NewFileSystemChecker creates a new file system checker with default settings
func NewFileSystemChecker() *FileSystemChecker {
	return &FileSystemChecker{
		minDiskSpaceBytes:   100 * 1024 * 1024, // 100MB minimum
		minDiskSpacePercent: 5.0,               // 5% minimum free space
		maxFileSize:         100 * 1024 * 1024, // 100MB max file size
		allowedExtensions: map[string]bool{
			".dll":    true,
			".exe":    true,
			".config": true,
			".json":   true,
			".xml":    true,
			".txt":    true,
			".log":    true,
		},
		blockedPaths: map[string]bool{
			"/etc/passwd":  true,
			"/etc/shadow":  true,
			"/etc/sudoers": true,
		},
		permissionCache:    make(map[string]time.Time),
		permissionCacheTTL: 5 * time.Minute,
	}
}

// CheckDiskSpace validates available disk space
func (fsc *FileSystemChecker) CheckDiskSpace(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return &FileSystemError{
			Type: "disk_space_check_failed",
			Path: path,
			Op:   "statfs",
			Err:  err,
		}
	}

	// Calculate available space
	availableBytes := int64(stat.Bavail) * int64(stat.Bsize)
	totalBytes := int64(stat.Blocks) * int64(stat.Bsize)
	usedBytes := totalBytes - availableBytes
	usedPercent := float64(usedBytes) / float64(totalBytes) * 100
	availablePercent := 100 - usedPercent

	// Check minimum space requirements
	if availableBytes < fsc.minDiskSpaceBytes {
		return &FileSystemError{
			Type: "insufficient_disk_space",
			Path: path,
			Op:   "space_check",
			Err:  fmt.Errorf("available space %d bytes < minimum %d bytes", availableBytes, fsc.minDiskSpaceBytes),
			Details: map[string]interface{}{
				"available_bytes":   availableBytes,
				"available_percent": availablePercent,
				"used_percent":      usedPercent,
				"total_bytes":       totalBytes,
			},
		}
	}

	if availablePercent < fsc.minDiskSpacePercent {
		return &FileSystemError{
			Type: "insufficient_disk_space_percent",
			Path: path,
			Op:   "space_check",
			Err:  fmt.Errorf("available space %.2f%% < minimum %.2f%%", availablePercent, fsc.minDiskSpacePercent),
			Details: map[string]interface{}{
				"available_percent": availablePercent,
				"used_percent":      usedPercent,
				"available_bytes":   availableBytes,
			},
		}
	}

	utils.Logger.Debug(fmt.Sprintf("Disk space check passed for %s: %.2f%% available (%d bytes)",
		path, availablePercent, availableBytes))
	return nil
}

// CheckPermissions validates file/directory permissions with caching
func (fsc *FileSystemChecker) CheckPermissions(path string, requiredPerms os.FileMode) error {
	fsc.mu.RLock()
	lastCheck, exists := fsc.permissionCache[path]
	fsc.mu.RUnlock()

	// Use cached result if recent
	if exists && time.Since(lastCheck) < fsc.permissionCacheTTL {
		return nil
	}

	// Check if path is blocked
	fsc.mu.RLock()
	if fsc.blockedPaths[path] {
		fsc.mu.RUnlock()
		return &FileSystemError{
			Type: "blocked_path",
			Path: path,
			Op:   "permission_check",
			Err:  fmt.Errorf("path is in blocked list"),
		}
	}
	fsc.mu.RUnlock()

	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &FileSystemError{
				Type: "file_not_found",
				Path: path,
				Op:   "stat",
				Err:  err,
			}
		}
		return &FileSystemError{
			Type: "stat_failed",
			Path: path,
			Op:   "stat",
			Err:  err,
		}
	}

	// Check permissions
	currentPerms := info.Mode().Perm()
	if currentPerms&requiredPerms != requiredPerms {
		return &FileSystemError{
			Type: "insufficient_permissions",
			Path: path,
			Op:   "permission_check",
			Err:  fmt.Errorf("current permissions %v insufficient for required %v", currentPerms, requiredPerms),
			Details: map[string]interface{}{
				"current_permissions":  currentPerms,
				"required_permissions": requiredPerms,
				"file_mode":            info.Mode(),
			},
		}
	}

	// Cache successful check
	fsc.mu.Lock()
	fsc.permissionCache[path] = time.Now()
	fsc.mu.Unlock()

	return nil
}

// CheckFileSize validates file size constraints
func (fsc *FileSystemChecker) CheckFileSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return &FileSystemError{
			Type: "file_stat_failed",
			Path: path,
			Op:   "size_check",
			Err:  err,
		}
	}

	if info.Size() > fsc.maxFileSize {
		return &FileSystemError{
			Type: "file_too_large",
			Path: path,
			Op:   "size_check",
			Err:  fmt.Errorf("file size %d bytes exceeds maximum %d bytes", info.Size(), fsc.maxFileSize),
			Details: map[string]interface{}{
				"file_size": info.Size(),
				"max_size":  fsc.maxFileSize,
			},
		}
	}

	return nil
}

// CheckFileExtension validates file extension
func (fsc *FileSystemChecker) CheckFileExtension(path string) error {
	ext := filepath.Ext(path)
	fsc.mu.RLock()
	allowed := fsc.allowedExtensions[ext]
	fsc.mu.RUnlock()

	if !allowed {
		return &FileSystemError{
			Type: "invalid_file_extension",
			Path: path,
			Op:   "extension_check",
			Err:  fmt.Errorf("file extension %s not allowed", ext),
			Details: map[string]interface{}{
				"extension": ext,
			},
		}
	}

	return nil
}

// ValidateFileOperation performs comprehensive file operation validation
func (fsc *FileSystemChecker) ValidateFileOperation(path string, operation string) error {
	// Check disk space for the directory containing the file
	dir := filepath.Dir(path)
	if err := fsc.CheckDiskSpace(dir); err != nil {
		return fmt.Errorf("disk space validation failed: %w", err)
	}

	// Check permissions based on operation
	var requiredPerms os.FileMode
	switch operation {
	case "read":
		requiredPerms = 0444 // Read permission
	case "write", "create":
		requiredPerms = 0644 // Read/write permission
	case "execute":
		requiredPerms = 0755 // Execute permission
	default:
		requiredPerms = 0644 // Default to read/write
	}

	// For existing files, check permissions and size
	if _, err := os.Stat(path); err == nil {
		if err := fsc.CheckPermissions(path, requiredPerms); err != nil {
			return fmt.Errorf("permission validation failed: %w", err)
		}

		if err := fsc.CheckFileSize(path); err != nil {
			return fmt.Errorf("file size validation failed: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return &FileSystemError{
			Type: "file_access_failed",
			Path: path,
			Op:   operation,
			Err:  err,
		}
	}

	// Check file extension
	// If the path is a directory, skip extension validation
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil
	}
	if err := fsc.CheckFileExtension(path); err != nil {
		return fmt.Errorf("file extension validation failed: %w", err)
	}

	return nil
}

// Global file system checker instance
var (
	fsChecker     *FileSystemChecker
	fsCheckerOnce sync.Once
)

// GetFileSystemChecker returns the global file system checker instance
func GetFileSystemChecker() *FileSystemChecker {
	fsCheckerOnce.Do(func() {
		fsChecker = NewFileSystemChecker()
	})
	return fsChecker
}

// Global variables for change detection and debouncing
var (
	changeBuffer   = make(map[string]bool)
	changeMutex    sync.Mutex
	changeDetected = make(chan struct{}, 1)
	// Enhanced debouncing with timer management
	debounceTimer *time.Timer
	timerMutex    sync.Mutex
	// Rate limiting for concurrent pod operations
	maxConcurrentOps = 5 // Maximum number of concurrent pod operations
	semaphore        = make(chan struct{}, maxConcurrentOps)
	// Memory monitoring for sync operations
	syncMemoryMonitor *memory.MemoryMonitor
	syncMemoryOnce    sync.Once
)

// SyncFilesAndRestartPod copies files to a specific pod and restarts the dotnet process.
// This function handles the complete workflow of file synchronization and process restart
// for a single pod, including proper error handling and logging.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - namespace: Kubernetes namespace containing the pod
//   - podName: Name of the specific pod to sync
//   - localPath: Local file system path to copy from
//   - containerPath: Target path inside the pod's container
//
// Returns:
//   - error: Any error encountered during file copying or process restart
func SyncFilesAndRestartPod(ctx context.Context, namespace, podName, localPath, containerPath string) error {
	// Get file system checker instance
	fsChecker := GetFileSystemChecker()

	// Validate file operation before proceeding
	if err := fsChecker.ValidateFileOperation(localPath, "read"); err != nil {
		utils.Logger.Error(fmt.Sprintf("File system validation failed for %s: %v", localPath, err))
		return fmt.Errorf("file system validation failed: %w", err)
	}

	// Check if source path exists and is accessible
	if _, err := os.Stat(localPath); err != nil {
		if os.IsNotExist(err) {
			return &FileSystemError{
				Type: "source_not_found",
				Path: localPath,
				Op:   "sync_validation",
				Err:  err,
			}
		}
		return &FileSystemError{
			Type: "source_access_failed",
			Path: localPath,
			Op:   "sync_validation",
			Err:  err,
		}
	}

	targetPath := containerPath
	if isDirectory(localPath) {
		targetPath = containerPath
	}

	utils.InfoWithFields(logrus.Fields{
		"pod_name": podName,
		"action":   "sync_and_restart",
		"source":   localPath,
		"target":   targetPath,
	}, "Syncing files and restarting process in pod")

	// Enhanced error handling for copy operation
	err := k8s.CopyToPod(localPath, namespace, podName, targetPath)
	if err != nil {
		fsError := &FileSystemError{
			Type: "copy_to_pod_failed",
			Path: localPath,
			Op:   "copy_operation",
			Err:  err,
			Details: map[string]interface{}{
				"pod_name":    podName,
				"namespace":   namespace,
				"target_path": targetPath,
				"operation":   "k8s_copy",
			},
		}
		utils.Logger.Error(fmt.Sprintf("Failed to copy files to pod %s: %v", podName, fsError))
		return fsError
	}

	// Enhanced error handling for restart operation
	client, clientErr := k8s.NewKubernetesClient()
	if clientErr != nil {
		restartError := fmt.Errorf("failed to create Kubernetes client: %w", clientErr)
		utils.Logger.Error(restartError.Error())
		return restartError
	}
	err = client.RestartDotnetProcess(namespace, podName)
	if err != nil {
		restartError := fmt.Errorf("failed to restart process in pod %s: %w", podName, err)
		utils.Logger.Error(restartError.Error())
		return restartError
	}

	utils.Logger.Info(fmt.Sprintf("Sync and restart completed successfully for pod: %s", podName))
	return nil
}

// Enhanced isDirectory function with better error handling
func isDirectory(path string) bool {
	fsChecker := GetFileSystemChecker()

	// Validate file access first
	if err := fsChecker.CheckPermissions(path, 0444); err != nil {
		utils.Logger.Warning(fmt.Sprintf("Permission check failed for %s: %v", path, err))
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		utils.Logger.Warning(fmt.Sprintf("Failed to stat path %s: %v", path, err))
		return false
	}
	return info.IsDir()
}

// SyncFilesAndRestartAllPods synchronizes files to all pods in a deployment and restarts their processes.
// This function discovers all pods belonging to a deployment using label selectors and performs
// concurrent file synchronization and process restart operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - namespace: Kubernetes namespace containing the deployment
//   - deployment: Name of the deployment whose pods should be updated
//   - localPath: Local file system path to sync from
//   - containerPath: Target path inside the containers
//
// Returns:
//   - error: Only returns error if ALL pods fail or critical system issues occur
func SyncFilesAndRestartAllPods(ctx context.Context, namespace, deployment, localPath, containerPath string) error {
	deploymentLabels, err := k8s.GetDeploymentSelector(namespace, deployment)
	if err != nil {
		return fmt.Errorf("failed to get deployment selector: %w", err)
	}

	podNames, err := k8s.GetPodNames(namespace, deploymentLabels)
	if err != nil {
		return fmt.Errorf("failed to get pod names: %w", err)
	}

	if len(podNames) == 0 {
		utils.Logger.Warning("No pods found for deployment " + deployment + ", this might be normal during scaling or restart")
		return nil // Don't treat as fatal error
	}

	var wg sync.WaitGroup
	successCount := int32(0)
	failureCount := int32(0)
	
	utils.Logger.Info(fmt.Sprintf("Starting sync for %d pods with rate limiting (max %d concurrent operations)", len(podNames), maxConcurrentOps))

	for _, podName := range podNames {
		wg.Add(1)
		recovery.SafeGo(func() {
			defer wg.Done()

			// Graceful semaphore acquisition with timeout
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-time.After(30 * time.Second):
				utils.Logger.Warning(fmt.Sprintf("Rate limit timeout for pod %s, skipping to avoid blocking", podName))
				atomic.AddInt32(&failureCount, 1)
				return
			case <-ctx.Done():
				return
			}

			utils.Logger.Info(fmt.Sprintf("Starting sync for pod: %s", podName))

			err := SyncFilesAndRestartPod(ctx, namespace, podName, localPath, containerPath)
			if err != nil {
				atomic.AddInt32(&failureCount, 1)
				// Log errors as warnings instead of errors to reduce terminal noise
				utils.Logger.Warning(fmt.Sprintf("Failed to sync pod %s: %v", podName, err))
			} else {
				atomic.AddInt32(&successCount, 1)
				utils.Logger.Info(fmt.Sprintf("Successfully synced pod: %s", podName))
			}
		}, map[string]interface{}{
			"name":      "sync_pod_worker",
			"pod":       podName,
			"namespace": namespace,
			"operation": "sync_and_restart",
		})
	}

	wg.Wait()

	totalPods := len(podNames)
	successes := int(atomic.LoadInt32(&successCount))
	failures := int(atomic.LoadInt32(&failureCount))

	// Professional success/failure reporting
	if successes > 0 {
		utils.Logger.Info(fmt.Sprintf("Sync completed: %d/%d pods successful", successes, totalPods))
	}
	
	if failures > 0 {
		utils.Logger.Warning(fmt.Sprintf("Some pods encountered issues: %d/%d failed (this is often normal during pod lifecycle changes)", failures, totalPods))
	}

	// Only return error if ALL pods failed AND we have pods to work with
	if failures == totalPods && totalPods > 0 {
		return fmt.Errorf("all %d pods failed synchronization", totalPods)
	}

	return nil // Partial failures are acceptable
}

// WatchForChanges sets up file system monitoring and implements a debounced file synchronization system.
// This function creates a file watcher that monitors the local path for changes and automatically
// synchronizes files to all pods in the deployment when changes are detected. It implements:
//
// 1. Recursive directory watching with automatic addition of new directories
// 2. Debouncing mechanism to batch multiple rapid changes
// 3. Concurrent processing of file events and synchronization
// 4. Graceful shutdown on context cancellation
// 5. Enhanced file system validation and error handling
//
// The debouncing mechanism prevents excessive synchronization operations when multiple files
// change rapidly (e.g., during a build process).
//
// Parameters:
//   - ctx: Context for cancellation and shutdown coordination
//   - localPath: Local directory to monitor for changes
//   - namespace: Kubernetes namespace containing the target deployment
//   - deployment: Name of the deployment to sync files to
//   - containerPath: Target path inside the containers
func WatchForChanges(ctx context.Context, localPath, namespace, deployment, containerPath string) {
	// Get file system checker instance
	fsChecker := GetFileSystemChecker()

	// Validate the local path before starting to watch
	if err := fsChecker.ValidateFileOperation(localPath, "read"); err != nil {
		utils.Logger.Error(fmt.Sprintf("File system validation failed for watch path %s: %v", localPath, err))
		return
	}

	// Check disk space before starting
	if err := fsChecker.CheckDiskSpace(localPath); err != nil {
		utils.Logger.Error(fmt.Sprintf("Insufficient disk space for watching %s: %v", localPath, err))
		return
	}

	// Initialize memory monitor once
	syncMemoryOnce.Do(func() {
		syncMemoryMonitor = memory.NewMonitor(
			150*1024*1024, // 150MB threshold
			300,           // 300 goroutines threshold
			func(alert memory.MemoryAlert) {
				utils.Logger.Warning(fmt.Sprintf("Sync Memory Alert [%s]: %s (Memory: %d MB, Goroutines: %d)",
					alert.Severity, alert.Message, alert.CurrentMem/(1024*1024), alert.Goroutines))

				// Force GC on memory alerts
				if alert.Severity == "critical" {
					syncMemoryMonitor.ForceGC()
				}
			},
		)
		syncMemoryMonitor.Start()
	})

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fsError := &FileSystemError{
			Type: "watcher_creation_failed",
			Path: localPath,
			Op:   "fsnotify_new",
			Err:  err,
		}
		utils.Logger.Warning(fmt.Sprintf("Failed to create file watcher: %v (file watching disabled)", fsError))
		return
	}
	defer func() {
		watcher.Close()
		if syncMemoryMonitor != nil {
			syncMemoryMonitor.Stop()
		}
	}()

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		fsError := &FileSystemError{
			Type: "watch_path_not_found",
			Path: localPath,
			Op:   "path_validation",
			Err:  err,
		}
		utils.Logger.Warning(fmt.Sprintf("Local path does not exist: %v (file watching disabled)", fsError))
		return
	}

	// Enhanced file event processing with validation
	recovery.SafeGo(func() {
		cleanupTicker := time.NewTicker(3 * time.Minute) // Memory cleanup every 3 minutes
		defer cleanupTicker.Stop()

		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
					// Validate file before processing
					if event.Op != fsnotify.Remove {
						if err := fsChecker.ValidateFileOperation(event.Name, "read"); err != nil {
							// Log as debug instead of warning to reduce noise
							utils.Logger.Debug(fmt.Sprintf("Skipping invalid file %s: %v", event.Name, err))
							continue
						}
					}

					// Check memory before processing
					if syncMemoryMonitor != nil {
						stats := syncMemoryMonitor.GetCurrentStats()
						if stats.Alloc > 200*1024*1024 { // 200MB threshold
							syncMemoryMonitor.ForceGC()
						}
					}

					changeMutex.Lock()
					changeBuffer[event.Name] = true
					changeMutex.Unlock()

					if event.Op&fsnotify.Create == fsnotify.Create {
						fileInfo, err := os.Stat(event.Name)
						if err == nil && fileInfo.IsDir() {
							// Validate new directory before adding to watcher
							if err := fsChecker.ValidateFileOperation(event.Name, "read"); err != nil {
								utils.Logger.Debug(fmt.Sprintf("Skipping invalid directory %s: %v", event.Name, err))
							} else {
								utils.Logger.Info("New directory detected:", event.Name)
								if err := watcher.Add(event.Name); err != nil {
									utils.Logger.Warning(fmt.Sprintf("Failed to watch new directory %s: %v", event.Name, err))
								}
							}
						}
					}

					select {
					case changeDetected <- struct{}{}:
					default:
					}
				}
			case err := <-watcher.Errors:
				fsError := &FileSystemError{
					Type: "watcher_error",
					Path: localPath,
					Op:   "file_watching",
					Err:  err,
				}
				// Log watcher errors as warnings instead of errors
				utils.Logger.Warning(fmt.Sprintf("File watcher encountered issue: %v (continuing to monitor)", fsError))
			case <-cleanupTicker.C:
				// Periodic memory cleanup
				if syncMemoryMonitor != nil {
					before, after := syncMemoryMonitor.ForceGC()
					utils.Logger.Debug(fmt.Sprintf("Sync periodic cleanup: Memory %d MB -> %d MB",
						before.Alloc/(1024*1024), after.Alloc/(1024*1024)))
				}

				// Periodic disk space check
				if err := fsChecker.CheckDiskSpace(localPath); err != nil {
					utils.Logger.Warning(fmt.Sprintf("Disk space warning during watch: %v", err))
				}
			}
		}
	}, map[string]interface{}{
		"name":       "file_watcher",
		"operation":  "file_system_monitoring",
		"local_path": localPath,
	})

	// Enhanced debouncing goroutine with timer-based approach
	recovery.SafeGo(func() {
		cfg := config.GetConfig()
		debounceDuration := cfg.GetDebounceDuration()

		// processChanges handles the actual file synchronization with validation
		processChanges := func() {
			changeMutex.Lock()
			if len(changeBuffer) > 0 {
				changeCount := len(changeBuffer)
				utils.Logger.Info(fmt.Sprintf("Processing %d file changes...", changeCount))

				// Validate disk space before processing changes
				if err := fsChecker.CheckDiskSpace(localPath); err != nil {
					utils.Logger.Warning(fmt.Sprintf("Insufficient disk space for sync operation: %v (skipping sync)", err))
					changeMutex.Unlock()
					return
				}

				changeBuffer = make(map[string]bool)
				changeMutex.Unlock()

				err := SyncFilesAndRestartAllPods(ctx, namespace, deployment, localPath, containerPath)
				if err != nil {
					utils.Logger.Warning(fmt.Sprintf("Sync operation encountered issues: %v (will retry on next change)", err))
				} else {
					utils.Logger.Info("Files synced and pods restarted successfully.")
				}
			} else {
				changeMutex.Unlock()
			}
		}

		for {
			select {
			case <-ctx.Done():
				utils.Logger.Info("File watcher shutting down...")
				// Cancel any pending timer
				timerMutex.Lock()
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				timerMutex.Unlock()
				return
			case <-changeDetected:
				// Reset or create debounce timer
				timerMutex.Lock()
				if debounceTimer != nil {
					// Reset existing timer to extend the debounce period
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDuration, processChanges)
				timerMutex.Unlock()
			}
		}
	}, map[string]interface{}{
		"name":           "debounce_processor",
		"operation":      "change_debouncing",
		"namespace":      namespace,
		"container_path": containerPath,
	})

	// Enhanced directory walking with validation
	if err := filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.Logger.Debug(fmt.Sprintf("Error walking path %s: %v", path, err))
			return nil // Continue walking despite errors
		}

		if info.IsDir() {
			// Validate directory before adding to watcher
			if err := fsChecker.ValidateFileOperation(path, "read"); err != nil {
				utils.Logger.Debug(fmt.Sprintf("Skipping invalid directory %s: %v", path, err))
				return nil
			}

			if err := watcher.Add(path); err != nil {
				utils.Logger.Debug(fmt.Sprintf("Failed to watch directory %s: %v", path, err))
			}
		}
		return nil
	}); err != nil {
		fsError := &FileSystemError{
			Type: "directory_walk_failed",
			Path: localPath,
			Op:   "filepath_walk",
			Err:  err,
		}
		utils.Logger.Warning(fmt.Sprintf("Failed to walk local path: %v (partial monitoring may be affected)", fsError))
		// Don't return, continue with partial monitoring
	}

	utils.Logger.Info(fmt.Sprintf("Watching for file changes in: %s (with enhanced validation)", localPath))
	select {}
}

// InitialSyncAndRestart performs an initial synchronization of files to all pods in a deployment.
// This function is typically called before starting the file watcher to ensure all pods have
// the latest version of files before monitoring begins. It discovers all pods in the deployment
// and performs concurrent synchronization operations with enhanced error handling.
//
// If no pods are found (replicas=0), it temporarily scales the deployment to 1 replica,
// waits for the pod to be ready, performs the sync, and restores the original replica count.
//
// Parameters:
//   - localPath: Local file system path to sync from
//   - namespace: Kubernetes namespace containing the deployment
//   - deployment: Name of the deployment whose pods should be updated
//   - containerPath: Target path inside the containers
//
// Returns:
//   - error: Any error encountered during pod discovery or initial synchronization
func InitialSyncAndRestart(localPath, namespace, deployment, containerPath string) error {
	// Get file system checker instance
	fsChecker := GetFileSystemChecker()

	// Validate the local path before starting sync
	if err := fsChecker.ValidateFileOperation(localPath, "read"); err != nil {
		return fmt.Errorf("file system validation failed for initial sync: %w", err)
	}

	// Check disk space before starting
	if err := fsChecker.CheckDiskSpace(localPath); err != nil {
		return fmt.Errorf("insufficient disk space for initial sync: %w", err)
	}

	utils.Logger.Info("Starting initial sync and restart for all pods with enhanced validation.")

	labelSelector, err := k8s.GetDeploymentSelector(namespace, deployment)
	if err != nil {
		return fmt.Errorf("failed to get deployment selector for %s: %w", deployment, err)
	}
	utils.Logger.Info("Using label selector:", labelSelector)

	// Enhanced pod discovery with automatic problem resolution
	podNames, err := k8s.GetPodNamesWithDeployment(namespace, labelSelector, deployment)
	scaledUp := false
	originalReplicas := int32(0)

	// The GetPodNames function now handles most edge cases automatically,
	// but we still need to handle the case where it returns an error
	if err != nil {
		utils.Logger.Warning(fmt.Sprintf("Enhanced pod discovery encountered issues for deployment %s: %v", deployment, err))
		
		// Fallback: Try manual scaling approach
		if strings.Contains(fmt.Sprintf("%v", err), "no pods found") || strings.Contains(fmt.Sprintf("%v", err), "timeout") {
			utils.Logger.Info(fmt.Sprintf("Attempting manual deployment scaling for %s...", deployment))

			// Get current replica count
			currentReplicas, getErr := k8s.GetDeploymentReplicas(namespace, deployment)
			if getErr != nil {
				return fmt.Errorf("failed to get current replica count for deployment %s: %w", deployment, getErr)
			}

			originalReplicas = currentReplicas

			if currentReplicas == 0 {
				utils.Logger.Info(fmt.Sprintf("Deployment %s has 0 replicas, scaling to 1 replica temporarily...", deployment))

				// Scale deployment to 1 replica
				if scaleErr := k8s.ScaleDeployment(namespace, deployment, 1); scaleErr != nil {
					return fmt.Errorf("failed to scale deployment %s to 1 replica: %w", deployment, scaleErr)
				}

				scaledUp = true
				utils.Logger.Info(fmt.Sprintf("Deployment %s scaled to 1 replica, waiting for pod to be ready...", deployment))

				// Wait for pod to be ready with timeout
				maxWaitTime := 120 * time.Second
				waitInterval := 5 * time.Second
				totalWaited := time.Duration(0)

				for totalWaited < maxWaitTime {
					time.Sleep(waitInterval)
					totalWaited += waitInterval

					podNames, err = k8s.GetPodNames(namespace, labelSelector)
					if err == nil && len(podNames) > 0 {
						utils.Logger.Info(fmt.Sprintf("Pod ready: %s", podNames[0]))
						break
					}

					if totalWaited%20*time.Second == 0 {
						utils.Logger.Info(fmt.Sprintf("Still waiting for pod to be ready... (%v elapsed)", totalWaited))
					}
				}

				if err != nil || len(podNames) == 0 {
					// Restore original replicas if scaling failed
					if restoreErr := k8s.ScaleDeployment(namespace, deployment, originalReplicas); restoreErr != nil {
						utils.Logger.Warning(fmt.Sprintf("Failed to restore original replica count %d: %v", originalReplicas, restoreErr))
					}
					return fmt.Errorf("timeout waiting for pod to be ready after scaling deployment %s", deployment)
				}
			} else {
				// We have replicas but no running pods - this might be temporary during rolling updates
				utils.Logger.Warning(fmt.Sprintf("Deployment %s has %d replicas but no running pods found - this is often normal during updates", deployment, currentReplicas))
				return nil // Don't treat as fatal error
			}
		} else {
			// Log as warning instead of returning error for less critical issues
			utils.Logger.Warning(fmt.Sprintf("Pod discovery issue for deployment %s: %v - this might resolve automatically", deployment, err))
			return nil // Don't block operation for transient issues
		}
	}

	// Ensure we have pods to work with
	if len(podNames) == 0 {
		utils.Logger.Warning(fmt.Sprintf("No pods found for deployment %s in namespace %s - this might be normal during scaling", deployment, namespace))
		return nil // Don't treat as fatal error
	}

	utils.Logger.Info(fmt.Sprintf("Pods found for deployment %s: %v", deployment, podNames))

	// Setup cleanup to restore original replica count if we scaled up
	defer func() {
		if scaledUp && originalReplicas != 1 {
			utils.Logger.Info(fmt.Sprintf("Restoring original replica count %d for deployment %s...", originalReplicas, deployment))
			if restoreErr := k8s.ScaleDeployment(namespace, deployment, originalReplicas); restoreErr != nil {
				utils.Logger.Warning(fmt.Sprintf("Failed to restore original replica count %d: %v", originalReplicas, restoreErr))
			} else {
				utils.Logger.Info(fmt.Sprintf("Successfully restored deployment %s to %d replicas", deployment, originalReplicas))
			}
		}
	}()

	var wg sync.WaitGroup
	successCount := int32(0)
	failureCount := int32(0)

	for _, podName := range podNames {
		wg.Add(1)
		recovery.SafeGo(func() {
			defer wg.Done()

			// Graceful semaphore acquisition with extended timeout for initial sync
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-time.After(60 * time.Second): // Longer timeout for initial sync
				utils.Logger.Warning(fmt.Sprintf("Rate limit timeout for pod %s during initial sync, skipping to avoid blocking", podName))
				atomic.AddInt32(&failureCount, 1)
				return
			}

			err := SyncFilesAndRestartPod(context.Background(), namespace, podName, localPath, containerPath)
			if err != nil {
				atomic.AddInt32(&failureCount, 1)
				// Log as warning to reduce noise
				utils.Logger.Warning(fmt.Sprintf("Failed to sync pod %s: %v", podName, err))
			} else {
				atomic.AddInt32(&successCount, 1)
				utils.Logger.Info(fmt.Sprintf("Successfully synced pod: %s", podName))
			}
		}, map[string]interface{}{
			"name":      "initial_sync_worker",
			"pod":       podName,
			"namespace": namespace,
			"operation": "initial_sync",
		})
	}

	wg.Wait()

	totalPods := len(podNames)
	successes := int(atomic.LoadInt32(&successCount))
	failures := int(atomic.LoadInt32(&failureCount))

	// Professional success/failure reporting
	if successes > 0 {
		utils.Logger.Info(fmt.Sprintf("Initial sync completed: %d/%d pods successful", successes, totalPods))
	}
	
	if failures > 0 {
		utils.Logger.Warning(fmt.Sprintf("Some pods encountered issues during initial sync: %d/%d failed (this can be normal)", failures, totalPods))
	}

	// Only return error if ALL pods failed AND we have pods to work with
	if failures == totalPods && totalPods > 0 {
		utils.Logger.Error(fmt.Sprintf("Critical: All %d pods failed initial synchronization", totalPods))
		return fmt.Errorf("all %d pods failed initial synchronization", totalPods)
	}

	if successes > 0 {
		utils.Logger.Info("Initial sync and restart completed successfully.")
	}
	
	return nil // Partial failures are acceptable for professional operation
}
