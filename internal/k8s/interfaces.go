// internal/k8s/interfaces.go
package k8s

import (
	"context"
	"io"
)

// KubernetesClient defines the interface for Kubernetes operations
type KubernetesClient interface {
	// Pod operations
	GetPodNames(namespace, deployment string) ([]string, error)
	GetPodNamesWithContext(ctx context.Context, namespace, deployment string) ([]string, error)
	GetPodContainers(namespace, deployment string) ([]PodContainer, error)
	GetContainersForPod(namespace, podName string) ([]string, error)

	// File operations
	CopyToPod(localPath, namespace, podName, containerPath string) error
	CopyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error
	CopyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error

	// Process operations
	RestartDotnetProcess(namespace, podName string) error
	RestartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error
	RestartProcess(namespace, podName, processName, startCommand string) error
	RestartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error

	// Log operations
	StreamPodLogs(namespace, podName string, output io.Writer) error
	StreamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error
	StreamContainerLogsWithContext(ctx context.Context, namespace, podName, containerName string, output io.Writer) error

	// Deployment operations
	GetDeploymentSelector(namespace, deployment string) (string, error)
	GetDeploymentSelectorWithContext(ctx context.Context, namespace, deployment string) (string, error)
}

// Logger defines the interface for logging operations
type Logger interface {
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Debug(args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// ConfigManager defines the interface for configuration management
type ConfigManager interface {
	LoadConfig(configPath string) error
	GetConfig() interface{}
	GetServerPort() int
	GetServerHost() string
	GetTemplatePath() string
	GetLogLevel() string
	GetLogFile() string
}

// FileWatcher defines the interface for file watching operations
type FileWatcher interface {
	WatchForChanges(ctx context.Context, localPath, namespace, deployment, containerPath string) error
	Stop() error
}

// SyncManager defines the interface for file synchronization operations
type SyncManager interface {
	SyncFilesAndRestartPod(ctx context.Context, localPath, namespace, podName, containerPath string) error
	SyncFilesAndRestartAllPods(ctx context.Context, namespace, deployment, localPath, containerPath string) error
}
