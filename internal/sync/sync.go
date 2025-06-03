package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/utils"
	"github.com/sirupsen/logrus"
)

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
	targetPath := containerPath
	if isDirectory(localPath) {
		targetPath = containerPath
	}

	utils.InfoWithFields(logrus.Fields{
		"pod_name": podName,
		"action":   "sync_and_restart",
	}, "Syncing files and restarting process in pod")

	err := k8s.CopyToPod(podName, namespace, localPath, targetPath)
	if err != nil {
		utils.Logger.Error("Failed to copy files to pod:", podName, "from", localPath, "error:", err)
		return err
	}

	err = k8s.RestartDotnetProcess(namespace, podName)
	if err != nil {
		utils.Logger.Error("Failed to restart process in pod:", podName, err)
		return err
	}

	utils.Logger.Info("Sync and restart completed successfully for pod:", podName)

	return nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
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
//   - error: Any error encountered during pod discovery or synchronization
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
		return fmt.Errorf("no pods found for deployment %s", deployment)
	}

	var wg sync.WaitGroup
	errorChan := make(chan error, len(podNames))

	utils.Logger.Info(fmt.Sprintf("Starting sync for %d pods with rate limiting (max %d concurrent operations)", len(podNames), maxConcurrentOps))

	for _, podName := range podNames {
		wg.Add(1)
		go func(pod string) {
			defer wg.Done()

			// Acquire semaphore for rate limiting
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }() // Release semaphore when done
			case <-ctx.Done():
				errorChan <- ctx.Err()
				return
			}

			utils.Logger.Info(fmt.Sprintf("Starting sync for pod: %s", pod))

			err := SyncFilesAndRestartPod(ctx, namespace, pod, localPath, containerPath)
			if err != nil {
				utils.Logger.Error(fmt.Sprintf("Failed to sync pod %s: %v", pod, err))
				errorChan <- fmt.Errorf("pod %s: %w", pod, err)
			} else {
				utils.Logger.Info(fmt.Sprintf("Successfully synced pod: %s", pod))
			}
		}(podName)
	}

	wg.Wait()
	close(errorChan)

	// Collect any errors that occurred
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("sync failed for %d pods: %v", len(errors), errors)
	}

	return nil
}

// WatchForChanges sets up file system monitoring and implements a debounced file synchronization system.
// This function creates a file watcher that monitors the local path for changes and automatically
// synchronizes files to all pods in the deployment when changes are detected. It implements:
//
// 1. Recursive directory watching with automatic addition of new directories
// 2. Debouncing mechanism to batch multiple rapid changes
// 3. Concurrent processing of file events and synchronization
// 4. Graceful shutdown on context cancellation
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
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		utils.Logger.Error("Failed to create file watcher:", err)
		return
	}
	defer watcher.Close()

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		utils.Logger.Error("Local path does not exist:", localPath)
		return
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
					changeMutex.Lock()
					changeBuffer[event.Name] = true
					changeMutex.Unlock()

					if event.Op&fsnotify.Create == fsnotify.Create {
						fileInfo, err := os.Stat(event.Name)
						if err == nil && fileInfo.IsDir() {
							utils.Logger.Info("New directory detected:", event.Name)
							if err := watcher.Add(event.Name); err != nil {
								utils.Logger.Error("Failed to watch new directory:", event.Name, err)
							}
						}
					}

					select {
					case changeDetected <- struct{}{}:
					default:
					}
				}
			case err := <-watcher.Errors:
				utils.Logger.Error("Error watching files:", err)
			}
		}
	}()

	// Enhanced debouncing goroutine with timer-based approach
	go func() {
		cfg := config.GetConfig()
		debounceDuration := cfg.GetDebounceDuration()

		// processChanges handles the actual file synchronization
		processChanges := func() {
			changeMutex.Lock()
			if len(changeBuffer) > 0 {
				changeCount := len(changeBuffer)
				utils.Logger.Info(fmt.Sprintf("Processing %d file changes...", changeCount))
				changeBuffer = make(map[string]bool)
				changeMutex.Unlock()

				err := SyncFilesAndRestartAllPods(ctx, namespace, deployment, localPath, containerPath)
				if err != nil {
					utils.Logger.Error("Failed to sync files and restart pods:", err)
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
	}()

	if err := filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			if err := watcher.Add(path); err != nil {
				utils.Logger.Error("Failed to watch directory:", path, err)
			}
		}
		return nil
	}); err != nil {
		utils.Logger.Error("Failed to watch local path:", err)
		return
	}

	utils.Logger.Info("Watching for file changes in:", localPath)
	select {}
}

// InitialSyncAndRestart performs an initial synchronization of files to all pods in a deployment.
// This function is typically called before starting the file watcher to ensure all pods have
// the latest version of files before monitoring begins. It discovers all pods in the deployment
// and performs concurrent synchronization operations.
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
	utils.Logger.Info("Starting initial sync and restart for all pods.")

	labelSelector, err := k8s.GetDeploymentSelector(namespace, deployment)
	if err != nil {
		return fmt.Errorf("failed to get deployment selector for %s: %w", deployment, err)
	}
	utils.Logger.Info("Using label selector:", labelSelector)

	podNames, err := k8s.GetPodNames(namespace, labelSelector)
	if err != nil {
		return fmt.Errorf("failed to get pod names: %w", err)
	}
	utils.Logger.Info("Pods found for deployment:", podNames)

	var wg sync.WaitGroup

	for _, podName := range podNames {
		wg.Add(1)
		go func(pod string) {
			defer wg.Done()
			err := SyncFilesAndRestartPod(context.Background(), namespace, pod, localPath, containerPath)
			if err != nil {
				utils.Logger.Error("Failed to sync pod:", pod, err)
			}
		}(podName)
	}

	wg.Wait()

	utils.Logger.Info("Initial sync and restart completed successfully.")
	return nil
}
