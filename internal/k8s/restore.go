package k8s

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RestoreDeployment(namespace, deploymentName string) error {
	backupFile := filepath.Join("/tmp", fmt.Sprintf("%s_backup.yaml", deploymentName))

	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return fmt.Errorf("backup file %s does not exist", backupFile)
	}

	restoreCmd := exec.Command("kubectl", "replace", "-f", backupFile, "--force")
	restoreOutput, err := restoreCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error replacing deployment: %s\nOutput: %s\n", err, restoreOutput)

		backupData, err := os.ReadFile(backupFile)
		if err != nil {
			return fmt.Errorf("failed to read backup file %s: %w", backupFile, err)
		}

		patchCmd := exec.Command("kubectl", "patch", "deployment", deploymentName, "-n", namespace, "--patch", string(backupData))
		patchOutput, err := patchCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to patch deployment: %s\nOutput: %s", err, patchOutput)
		}

		fmt.Printf("Deployment %s restored successfully using patch.\n", deploymentName)
		return nil
	}

	fmt.Printf("Deployment %s restored successfully.\nOutput: %s\n", deploymentName, restoreOutput)

	restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment", deploymentName, "-n", namespace)
	restartOutput, err := restartCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart deployment: %s\nOutput: %s", err, restartOutput)
	}

	fmt.Printf("Deployment %s restarted successfully.\nOutput: %s\n", deploymentName, restartOutput)
	return nil
}
