package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/internal/sync"
	"github.com/kariyertech/Truva.git/internal/ui"
	"github.com/kariyertech/Truva.git/pkg/api"

	"github.com/spf13/cobra"
)

var (
	namespace     string
	targetType    string
	targetName    string
	localPath     string
	containerPath string
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the application along with UI",
	Long: `This command will start the UI and execute specified operations on Kubernetes 
deployments or pods based on the provided parameters.`,
	Run: func(cmd *cobra.Command, args []string) {
		if namespace == "" || targetType == "" || targetName == "" || localPath == "" || containerPath == "" {
			fmt.Println("All parameters (namespace, targetType, targetName, localPath, containerPath) must be specified.")
			return
		}

		if !filepath.IsAbs(localPath) {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Println("Failed to get current directory:", err)
				return
			}
			localPath = filepath.Join(cwd, localPath)
		}

		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			fmt.Printf("Local path does not exist: %s\n", localPath)
			return
		}

		err := k8s.InitClient()
		if err != nil {
			fmt.Println("Failed to initialize Kubernetes client:", err)
			return
		}

		err = k8s.BackupDeployment(namespace, targetName)
		if err != nil {
			fmt.Printf("Failed to backup deployment %s: %v\n", targetName, err)
			return
		}
		fmt.Printf("Backup completed successfully for deployment %s\n", targetName)

		api.InitRoutes()

		go ui.StartWebServer(namespace, targetName)

		go ui.StartLogHandler()

		openBrowser("http://localhost:8080")

		err = sync.InitialSyncAndRestart(localPath, namespace, targetName, containerPath)
		if err != nil {
			fmt.Printf("Initial sync and restart failed: %v\n", err)
			return
		}

		go sync.WatchForChanges(localPath, namespace, targetName, containerPath)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		<-quit

		fmt.Println("\nApplication is shutting down... Restoring original deployment.")

		err = k8s.RestoreDeployment(namespace, targetName)
		if err != nil {
			fmt.Printf("Failed to restore deployment: %v\n", err)
		} else {
			fmt.Printf("Deployment %s restored successfully.\n", targetName)
		}
	},
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		fmt.Printf("Unsupported platform: %s\n", runtime.GOOS)
	}

	if err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
	}
}

func init() {
	upCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace")
	upCmd.Flags().StringVarP(&targetType, "targetType", "t", "", "Target type: pod or deployment")
	upCmd.Flags().StringVarP(&targetName, "targetName", "d", "", "Name of the deployment or pod")
	upCmd.Flags().StringVarP(&localPath, "localPath", "l", "", "Local path to sync")
	upCmd.Flags().StringVarP(&containerPath, "containerPath", "c", "", "Path inside container to sync to")

	rootCmd.AddCommand(upCmd)
}
