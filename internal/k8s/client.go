package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/pkg/utils"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset *kubernetes.Clientset

type DeploymentLabels map[string]string

func InitClient() error {
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

	return nil
}

func GetClient() *kubernetes.Clientset {
	return clientset
}

func CopyToPod(podName, namespace, localPath, containerPath string) error {
	var cmd *exec.Cmd
	if isDirectory(localPath) {
		cmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/.", localPath), fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
	} else {
		cmd = exec.Command("kubectl", "cp", localPath, fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy to pod %s: %s, output: %s", podName, err, output)
	}

	utils.Logger.Info("File(s) copied to pod:", podName)
	return nil
}

func RestartDotnetProcess(podName, namespace, containerPath string) error {
	checkCmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", "dotnet")
	if err := checkCmd.Run(); err != nil {
		fmt.Printf(".NET process not found in pod %s, starting a new process...\n", podName)
	} else {
		stopCmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "pkill", "-f", "dotnet")
		stopOutput, err := stopCmd.CombinedOutput()
		if err != nil {
			if strings.Contains(string(stopOutput), "no process found") {
				fmt.Printf(".NET process already stopped in pod %s\n", podName)
			} else {
				return fmt.Errorf("failed to stop .NET process in pod %s: %w\nOutput: %s", podName, err, stopOutput)
			}
		} else {
			fmt.Printf(".NET process stopped successfully in pod %s\n", podName)
		}

		for i := 0; i < 5; i++ {
			checkAgainCmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", "dotnet")
			if err := checkAgainCmd.Run(); err != nil {
				fmt.Printf(".NET process confirmed stopped in pod %s\n", podName)
				break
			}
			time.Sleep(1 * time.Second)
		}
	}

	startCmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "sh", "-c", fmt.Sprintf("nohup dotnet %s/api.dll > /dev/null 2>&1 &", containerPath))
	startOutput, err := startCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start .NET process in pod %s: %w\nOutput: %s", podName, err, startOutput)
	}

	for i := 0; i < 5; i++ {
		checkCmdAgain := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", "dotnet")
		if err := checkCmdAgain.Run(); err == nil {
			fmt.Printf(".NET process started successfully in pod %s\n", podName)
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("failed to verify the start of .NET process in pod %s", podName)
}

func GetDeploymentSelector(namespace, deploymentName string) (string, error) {
	cmd := exec.Command("kubectl", "get", "deployment", deploymentName, "-n", namespace, "-o", "jsonpath={.spec.selector.matchLabels}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get deployment selector for %s: %w", deploymentName, err)
	}

	var labels DeploymentLabels
	err = json.Unmarshal(output, &labels)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal deployment labels for %s: %w", deploymentName, err)
	}

	if appLabel, ok := labels["app"]; ok {
		return fmt.Sprintf("app=%s", appLabel), nil
	}

	var labelPairs []string
	for key, value := range labels {
		labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", key, value))
	}

	return strings.Join(labelPairs, ","), nil
}

func GetPodNames(namespace, labelSelector string) ([]string, error) {
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", labelSelector, "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get pod names with label selector %s: %w", labelSelector, err)
	}

	podNames := strings.Fields(string(output))
	if len(podNames) == 0 {
		return nil, fmt.Errorf("no pods found with label selector %s", labelSelector)
	}
	return podNames, nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
