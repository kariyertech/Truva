package k8s

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kariyertech/Truva.git/pkg/errors"
)

func RestoreDeployment(namespace, deploymentName string) error {
	backupFile := filepath.Join("/tmp", fmt.Sprintf("%s_backup.yaml", deploymentName))

	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return fmt.Errorf("backup file %s does not exist", backupFile)
	}

	restoreCmd := exec.Command("kubectl", "replace", "-f", backupFile, "--force")
	restoreOutput, err := restoreCmd.CombinedOutput()
	if err != nil {
		errors.Handle(errors.K8sError("replace deployment", err).WithContext("output", string(restoreOutput)))

		backupData, err := os.ReadFile(backupFile)
		if err != nil {
			return fmt.Errorf("failed to read backup file %s: %w", backupFile, err)
		}

		patchCmd := exec.Command("kubectl", "patch", "deployment", deploymentName, "-n", namespace, "--patch", string(backupData))
		patchOutput, err := patchCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to patch deployment: %s\nOutput: %s", err, patchOutput)
		}

		errors.Info("DEPLOYMENT_RESTORE_PATCH_SUCCESS", "Deployment "+deploymentName+" restored successfully using patch.")
		return nil
	}

	errors.Info("DEPLOYMENT_RESTORE_SUCCESS", "Deployment "+deploymentName+" restored successfully.")

	restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment", deploymentName, "-n", namespace)
	restartOutput, err := restartCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart deployment: %s\nOutput: %s", err, restartOutput)
	}

	errors.Info("DEPLOYMENT_RESTART_SUCCESS", "Deployment "+deploymentName+" restarted successfully.")
	return nil
}
