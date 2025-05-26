// internal/k8s/modify.go
package k8s

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func ModifyDeployment(namespace, deploymentName string) error {
	modifiedFile := filepath.Join("/tmp", fmt.Sprintf("%s_modified.yaml", deploymentName))

	cmd := exec.Command("kubectl", "get", "deployment", deploymentName, "-n", namespace, "-o", "yaml")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get deployment %s: %w", deploymentName, err)
	}

	err = os.WriteFile(modifiedFile, output, 0644)
	if err != nil {
		return fmt.Errorf("failed to write YAML file: %w", err)
	}

	yqCmd := exec.Command("yq", "e", ".spec.template.spec.containers[0].command = [\"/bin/sh\", \"-c\", \"sleep infinity\"]", "-i", modifiedFile)
	if yqOutput, err := yqCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to modify YAML with yq: %s, %w", yqOutput, err)
	}

	applyCmd := exec.Command("kubectl", "apply", "-f", modifiedFile)
	applyOutput, err := applyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to apply modified deployment: %s, %w", applyOutput, err)
	}

	fmt.Printf("Deployment %s modified successfully and applied.\n", deploymentName)
	return nil
}
