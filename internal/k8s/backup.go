package k8s

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func BackupDeployment(namespace, deploymentName string) error {
	backupFile := filepath.Join("/tmp", fmt.Sprintf("%s_backup.yaml", deploymentName))

	cmd := exec.Command("kubectl", "get", "deployment", deploymentName, "-n", namespace, "-o", "yaml")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get deployment %s: %w", deploymentName, err)
	}

	err = os.WriteFile(backupFile, output, 0644)
	if err != nil {
		return fmt.Errorf("failed to write backup file %s: %w", backupFile, err)
	}

	fmt.Printf("Deployment %s backed up successfully to %s\n", deploymentName, backupFile)
	return nil
}
