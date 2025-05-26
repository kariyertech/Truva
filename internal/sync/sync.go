package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/pkg/utils"

	"github.com/fsnotify/fsnotify"
)

var (
	changeBuffer   = make(map[string]bool)
	changeMutex    = &sync.Mutex{}
	changeDetected = make(chan struct{}, 1)
)

func SyncFilesAndRestartPod(podName, namespace, localPath, containerPath string, wg *sync.WaitGroup) {
	defer wg.Done()

	targetPath := containerPath
	if isDirectory(localPath) {
		targetPath = containerPath
	}

	utils.Logger.Info("Syncing files and restarting process in pod:", podName)

	err := k8s.CopyToPod(podName, namespace, localPath, targetPath)
	if err != nil {
		utils.Logger.Error("Failed to copy files to pod:", podName, err)
		return
	}

	err = k8s.RestartDotnetProcess(podName, namespace, containerPath)
	if err != nil {
		utils.Logger.Error("Failed to restart process in pod:", podName, err)
		return
	}

	utils.Logger.Info("Sync and restart completed successfully for pod:", podName)
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func SyncFilesAndRestartAllPods(namespace, deployment, localPath, containerPath string) error {
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

	for _, podName := range podNames {
		wg.Add(1)
		go SyncFilesAndRestartPod(podName, namespace, localPath, containerPath, &wg)
	}

	wg.Wait()
	return nil
}

func WatchForChanges(localPath, namespace, deployment, containerPath string) {
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

	go func() {
		for {
			<-changeDetected

			time.Sleep(1 * time.Second)

			changeMutex.Lock()
			changes := make([]string, 0, len(changeBuffer))
			for path := range changeBuffer {
				changes = append(changes, path)
			}
			changeBuffer = make(map[string]bool)
			changeMutex.Unlock()

			if len(changes) > 0 {
				utils.Logger.Info("Detected file changes:", changes)
				err := SyncFilesAndRestartAllPods(namespace, deployment, localPath, containerPath)
				if err != nil {
					utils.Logger.Error("Failed to sync files and restart processes in all pods:", err)
				}
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
		go SyncFilesAndRestartPod(podName, namespace, localPath, containerPath, &wg)
	}

	wg.Wait()

	utils.Logger.Info("Initial sync and restart completed successfully.")
	return nil
}
