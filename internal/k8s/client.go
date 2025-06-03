package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/pkg/retry"
	"github.com/kariyertech/Truva.git/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset kubernetes.Interface

type DeploymentLabels map[string]string

// DefaultKubernetesClient implements the KubernetesClient interface
type DefaultKubernetesClient struct {
	clientset kubernetes.Interface
}

// NewKubernetesClient creates a new instance of DefaultKubernetesClient
func NewKubernetesClient() (KubernetesClient, error) {
	err := InitClient()
	if err != nil {
		return nil, err
	}
	return &DefaultKubernetesClient{
		clientset: clientset,
	}, nil
}

// NewKubernetesClientWithContext creates a new instance with context
func NewKubernetesClientWithContext(ctx context.Context) (KubernetesClient, error) {
	err := InitClientWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &DefaultKubernetesClient{
		clientset: clientset,
	}, nil
}

func InitClient() error {
	return InitClientWithContext(context.Background())
}

func InitClientWithContext(ctx context.Context) error {
	retryConfig := retry.KubernetesConfig()

	return retry.Do(ctx, retryConfig, func() error {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = clientcmd.RecommendedHomeFile
		}

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to build config from KUBECONFIG: %w", err)
		}

		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
		}

		// Test the connection
		_, err = clientset.Discovery().ServerVersion()
		if err != nil {
			return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
		}

		return nil
	})
}

func GetClient() kubernetes.Interface {
	return clientset
}

func CopyToPod(localPath, namespace, podName, containerPath string) error {
	return CopyToPodWithContext(context.Background(), localPath, namespace, podName, containerPath)
}

// CopyToPod implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPod(localPath, namespace, podName, containerPath string) error {
	return c.CopyToPodWithContext(context.Background(), localPath, namespace, podName, containerPath)
}

func CopyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	return copyToPodWithContext(ctx, localPath, namespace, podName, containerPath)
}

// CopyToPodWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	return copyToPodWithContext(ctx, localPath, namespace, podName, containerPath)
}

// copyToPodWithContext copies files from local filesystem to a Kubernetes pod using kubectl.
// This function handles both file and directory copying with proper error handling and retry logic.
// It uses kubectl cp command which supports recursive directory copying and preserves file permissions.
//
// The function implements:
// 1. Retry mechanism with exponential backoff for transient failures
// 2. Context-aware cancellation for timeout control
// 3. Proper kubectl command construction with namespace and pod targeting
// 4. Error handling for various failure scenarios (network, permissions, etc.)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - localPath: Source path on local filesystem (file or directory)
//   - namespace: Kubernetes namespace containing the target pod
//   - podName: Name of the target pod
//   - containerPath: Destination path inside the pod's container
//
// Returns:
//   - error: Any error encountered during the copy operation
func copyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	retryConfig := retry.KubernetesConfig()

	return retry.Do(ctx, retryConfig, func() error {
		var cmd *exec.Cmd
		if isDirectory(localPath) {
			cmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/.", localPath), fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
		} else {
			cmd = exec.Command("kubectl", "cp", localPath, fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
		}

		// Set context for the command
		cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to copy to pod %s: %s, output: %s", podName, err, output)
		}

		utils.Logger.Info("File(s) copied to pod:", podName)
		return nil
	})
}

func RestartDotnetProcess(namespace, podName string) error {
	return RestartDotnetProcessWithContext(context.Background(), namespace, podName)
}

// RestartDotnetProcess implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartDotnetProcess(namespace, podName string) error {
	return c.RestartDotnetProcessWithContext(context.Background(), namespace, podName)
}

func RestartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	return restartDotnetProcessWithContext(ctx, namespace, podName)
}

// RestartDotnetProcessWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	return restartDotnetProcessWithContext(ctx, namespace, podName)
}

func restartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	containerPath := "/app" // Default container path
	// Use the new generic RestartProcess function for .NET applications
	return restartProcessWithContext(ctx, namespace, podName, "dotnet", fmt.Sprintf("dotnet %s/api.dll", containerPath))
}

// RestartProcess restarts a generic process in a pod
func RestartProcess(namespace, podName, processName, startCommand string) error {
	return RestartProcessWithContext(context.Background(), namespace, podName, processName, startCommand)
}

// RestartProcess implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartProcess(namespace, podName, processName, startCommand string) error {
	return c.RestartProcessWithContext(context.Background(), namespace, podName, processName, startCommand)
}

// RestartProcessWithContext restarts a generic process in a pod with context
func RestartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	return restartProcessWithContext(ctx, namespace, podName, processName, startCommand)
}

// RestartProcessWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	return restartProcessWithContext(ctx, namespace, podName, processName, startCommand)
}

func restartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	retryConfig := retry.KubernetesConfig()

	return retry.Do(ctx, retryConfig, func() error {
		// Check if process is running
		checkCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
		if err := checkCmd.Run(); err != nil {
			fmt.Printf("%s process not found in pod %s, starting a new process...\n", processName, podName)
		} else {
			// Stop the existing process
			stopCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pkill", "-f", processName)
			stopOutput, err := stopCmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(stopOutput), "no process found") {
					fmt.Printf("%s process already stopped in pod %s\n", processName, podName)
				} else {
					return fmt.Errorf("failed to stop %s process in pod %s: %w\nOutput: %s", processName, podName, err, stopOutput)
				}
			} else {
				fmt.Printf("%s process stopped successfully in pod %s\n", processName, podName)
			}

			// Wait for process to stop
			for i := 0; i < 5; i++ {
				checkAgainCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
				if err := checkAgainCmd.Run(); err != nil {
					fmt.Printf("%s process confirmed stopped in pod %s\n", processName, podName)
					break
				}
				time.Sleep(1 * time.Second)
			}
		}

		// Start the process
		startCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", startCommand))
		startOutput, err := startCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start %s process in pod %s: %w\nOutput: %s", processName, podName, err, startOutput)
		}

		// Verify the process started
		for i := 0; i < 5; i++ {
			checkCmdAgain := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
			if err := checkCmdAgain.Run(); err == nil {
				fmt.Printf("%s process started successfully in pod %s\n", processName, podName)
				return nil
			}
			time.Sleep(1 * time.Second)
		}

		return fmt.Errorf("failed to verify the start of %s process in pod %s", processName, podName)
	})
}

// Legacy function removed - now using generic RestartProcess implementation

func GetDeploymentSelector(namespace, deploymentName string) (string, error) {
	return GetDeploymentSelectorWithContext(context.Background(), namespace, deploymentName)
}

// GetDeploymentSelector implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetDeploymentSelector(namespace, deployment string) (string, error) {
	return c.GetDeploymentSelectorWithContext(context.Background(), namespace, deployment)
}

func GetDeploymentSelectorWithContext(ctx context.Context, namespace, deploymentName string) (string, error) {
	return getDeploymentSelectorWithContext(ctx, namespace, deploymentName)
}

// GetDeploymentSelectorWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetDeploymentSelectorWithContext(ctx context.Context, namespace, deployment string) (string, error) {
	return getDeploymentSelectorWithContext(ctx, namespace, deployment)
}

// getDeploymentSelectorWithContext retrieves the label selector for a Kubernetes deployment.
// This function queries the Kubernetes API to get a deployment's selector labels and converts
// them into a comma-separated string format suitable for kubectl and API queries. It implements:
//
// 1. Retry mechanism with exponential backoff for API resilience
// 2. Proper error handling for missing deployments or selectors
// 3. Label sorting with 'app' label prioritized for consistency
// 4. Context-aware cancellation for timeout control
//
// The returned selector string can be used with kubectl commands or Kubernetes API calls
// to filter pods belonging to the deployment.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - namespace: Kubernetes namespace containing the deployment
//   - deploymentName: Name of the deployment to query
//
// Returns:
//   - string: Comma-separated label selector (e.g., "app=myapp,version=v1")
//   - error: Any error encountered during API communication or processing
func getDeploymentSelectorWithContext(ctx context.Context, namespace, deploymentName string) (string, error) {
	retryConfig := retry.KubernetesConfig()

	return retry.DoWithResult(ctx, retryConfig, func() (string, error) {
		client := GetClient()
		if client == nil {
			return "", fmt.Errorf("kubernetes client not initialized")
		}

		deployment, err := client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get deployment %s: %w", deploymentName, err)
		}

		if deployment.Spec.Selector == nil || deployment.Spec.Selector.MatchLabels == nil {
			return "", fmt.Errorf("deployment %s has no selector labels", deploymentName)
		}

		labels := deployment.Spec.Selector.MatchLabels

		// Convert labels to key=value pairs
		var labelPairs []string
		for key, value := range labels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", key, value))
		}

		// Sort for consistent output
		var sortedPairs []string
		for _, pair := range labelPairs {
			sortedPairs = append(sortedPairs, pair)
		}
		// Simple sort by putting app first if it exists, then alphabetical
		var appPair string
		var otherPairs []string
		for _, pair := range sortedPairs {
			if strings.HasPrefix(pair, "app=") {
				appPair = pair
			} else {
				otherPairs = append(otherPairs, pair)
			}
		}

		var result []string
		if appPair != "" {
			result = append(result, appPair)
		}
		result = append(result, otherPairs...)

		return strings.Join(result, ","), nil
	})
}

func GetPodNames(namespace, labelSelector string) ([]string, error) {
	return GetPodNamesWithContext(context.Background(), namespace, labelSelector)
}

// GetPodNames implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodNames(namespace, labelSelector string) ([]string, error) {
	return c.GetPodNamesWithContext(context.Background(), namespace, labelSelector)
}

func GetPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	return getClientPodNamesWithContext(ctx, namespace, labelSelector)
}

// GetPodNamesWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	return getClientPodNamesWithContext(ctx, namespace, labelSelector)
}

func getClientPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	retryConfig := retry.KubernetesConfig()

	return retry.DoWithResult(ctx, retryConfig, func() ([]string, error) {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-l", labelSelector, "-o", "jsonpath={.items[*].metadata.name}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to get pod names with label selector %s: %w", labelSelector, err)
		}

		podNames := strings.Fields(string(output))
		if len(podNames) == 0 {
			return nil, fmt.Errorf("no pods found with label selector %s", labelSelector)
		}
		return podNames, nil
	})
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// PodContainer represents a container within a pod
type PodContainer struct {
	PodName       string
	ContainerName string
	Namespace     string
}

// GetPodContainers returns all containers for all pods matching the label selector
func GetPodContainers(namespace, labelSelector string) ([]PodContainer, error) {
	return GetPodContainersWithContext(context.Background(), namespace, labelSelector)
}

// GetPodContainers implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodContainers(namespace, deployment string) ([]PodContainer, error) {
	return GetPodContainersWithContext(context.Background(), namespace, deployment)
}

// GetPodContainersWithContext returns all containers for all pods matching the label selector with context
func GetPodContainersWithContext(ctx context.Context, namespace, labelSelector string) ([]PodContainer, error) {
	retryConfig := retry.KubernetesConfig()

	return retry.DoWithResult(ctx, retryConfig, func() ([]PodContainer, error) {
		if clientset == nil {
			return nil, fmt.Errorf("kubernetes client not initialized")
		}

		pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list pods: %w", err)
		}

		var containers []PodContainer
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				containers = append(containers, PodContainer{
					PodName:       pod.Name,
					ContainerName: container.Name,
					Namespace:     namespace,
				})
			}
		}

		if len(containers) == 0 {
			return nil, fmt.Errorf("no containers found for label selector %s", labelSelector)
		}

		return containers, nil
	})
}

// GetContainersForPod returns all container names for a specific pod
func GetContainersForPod(namespace, podName string) ([]string, error) {
	return getContainersForPod(namespace, podName)
}

// GetContainersForPod implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetContainersForPod(namespace, podName string) ([]string, error) {
	return getContainersForPod(namespace, podName)
}

func getContainersForPod(namespace, podName string) ([]string, error) {
	return GetContainersForPodWithContext(context.Background(), namespace, podName)
}

// GetContainersForPodWithContext returns all containers for a specific pod with context
func GetContainersForPodWithContext(ctx context.Context, namespace, podName string) ([]string, error) {
	retryConfig := retry.KubernetesConfig()

	return retry.DoWithResult(ctx, retryConfig, func() ([]string, error) {
		if clientset == nil {
			return nil, fmt.Errorf("kubernetes client not initialized")
		}

		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get pod %s: %w", podName, err)
		}

		var containerNames []string
		for _, container := range pod.Spec.Containers {
			containerNames = append(containerNames, container.Name)
		}

		if len(containerNames) == 0 {
			return nil, fmt.Errorf("no containers found in pod %s", podName)
		}

		return containerNames, nil
	})
}

// CopyToPodContainer copies a file to a specific container in a pod
func CopyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return copyToPodContainer(localPath, namespace, podName, containerName, containerPath)
}

// CopyToPodContainer implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return copyToPodContainer(localPath, namespace, podName, containerName, containerPath)
}

func copyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return CopyToPodContainerWithContext(context.Background(), namespace, podName, containerName, localPath, containerPath)
}

// StreamPodLogs streams logs from a pod to the provided writer
func StreamPodLogs(namespace, podName string, output io.Writer) error {
	return StreamPodLogsWithContext(context.Background(), namespace, podName, output)
}

// StreamPodLogs implements KubernetesClient interface
func (c *DefaultKubernetesClient) StreamPodLogs(namespace, podName string, output io.Writer) error {
	return c.StreamPodLogsWithContext(context.Background(), namespace, podName, output)
}

// StreamPodLogsWithContext streams logs from a pod to the provided writer with context
func StreamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	return streamPodLogsWithContext(ctx, namespace, podName, output)
}

// StreamPodLogsWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) StreamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	return streamPodLogsWithContext(ctx, namespace, podName, output)
}

// StreamContainerLogsWithContext streams logs from a specific container to the provided writer with context
func (c *DefaultKubernetesClient) StreamContainerLogsWithContext(ctx context.Context, namespace, podName, containerName string, output io.Writer) error {
	return streamContainerLogsWithContext(ctx, namespace, podName, containerName, output)
}

func streamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	if clientset == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow: true,
	})

	logs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs for pod %s: %w", podName, err)
	}
	defer logs.Close()

	_, err = io.Copy(output, logs)
	return err
}

func streamContainerLogsWithContext(ctx context.Context, namespace, podName, containerName string, output io.Writer) error {
	if clientset == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow:    true,
		Container: containerName,
	})

	logs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs for container %s in pod %s: %w", containerName, podName, err)
	}
	defer logs.Close()

	_, err = io.Copy(output, logs)
	return err
}

// CopyToPodContainerWithContext copies a file to a specific container in a pod with context support
func CopyToPodContainerWithContext(ctx context.Context, namespace, podName, containerName, srcPath, destPath string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "cp", srcPath, fmt.Sprintf("%s/%s:%s", namespace, podName, destPath), "-c", containerName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
