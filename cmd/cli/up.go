package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/kariyertech/Truva.git/internal/sync"
	"github.com/kariyertech/Truva.git/internal/ui"
	"github.com/kariyertech/Truva.git/pkg/api"
	"github.com/kariyertech/Truva.git/pkg/cleanup"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/context"
	"github.com/kariyertech/Truva.git/pkg/utils"

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
deployments or pods based on the provided parameters.

Examples:
  # Start with deployment
  truva up --namespace myapp --targetType deployment --targetName myapp-deployment --localPath ./src --containerPath /app
  
  # Start with specific pod
  truva up --namespace myapp --targetType pod --targetName myapp-pod-123 --localPath ./src --containerPath /app`,
	Run: func(cmd *cobra.Command, args []string) {
		// Validate input parameters
		if err := validateUpCommand(namespace, targetType, targetName, localPath, containerPath); err != nil {
			fmt.Printf("Validation failed:\n%s\n\n", err.Error())
			fmt.Println("Use 'truva up --help' for usage information.")
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

		// Load configuration
		err = config.LoadConfig("")
		if err != nil {
			fmt.Printf("Warning: Failed to load config, using defaults: %v\n", err)
		}
		cfg := config.GetConfig()

		// Initialize logger with configuration
		logLevel := utils.ParseLogLevel(cfg.Logging.Level)
		logFormat := utils.ParseLogFormat(cfg.Logging.Format)
		err = utils.InitLoggerWithFormat(cfg.Logging.File, logLevel, logFormat)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize logger: %v\n", err)
		}

		openBrowser(fmt.Sprintf("http://%s:%d", cfg.Server.Host, cfg.Server.Port))

		err = sync.InitialSyncAndRestart(localPath, namespace, targetName, containerPath)
		if err != nil {
			fmt.Printf("Initial sync and restart failed: %v\n", err)
			return
		}

		// Initialize context and cleanup managers
		ctxManager := context.NewManager()
		cleanupManager := cleanup.NewCleanupManager()

		go sync.WatchForChanges(ctxManager.Context(), localPath, namespace, targetName, containerPath)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		<-quit

		fmt.Println("\nApplication is shutting down... Restoring original deployment.")

		// Graceful shutdown
		ctxManager.Shutdown()

		// Cleanup temporary files
		if err := cleanupManager.Cleanup(); err != nil {
			fmt.Printf("Warning: Cleanup failed: %v\n", err)
		}

		// Cleanup old backups (older than 24 hours)
		if err := cleanup.CleanupOldBackups(24 * time.Hour); err != nil {
			fmt.Printf("Warning: Failed to cleanup old backups: %v\n", err)
		}

		// Cleanup modified files
		if err := cleanup.CleanupModifiedFiles(); err != nil {
			fmt.Printf("Warning: Failed to cleanup modified files: %v\n", err)
		}

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
	upCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace where the target resource is located")
	upCmd.Flags().StringVarP(&targetType, "targetType", "t", "", "Target resource type: 'deployment' or 'pod'")
	upCmd.Flags().StringVarP(&targetName, "targetName", "d", "", "Name of the target deployment or pod")
	upCmd.Flags().StringVarP(&localPath, "localPath", "l", "", "Local directory or file path to sync to the container")
	upCmd.Flags().StringVarP(&containerPath, "containerPath", "c", "", "Absolute path in the container where files will be synced")

	// Mark required flags
	upCmd.MarkFlagRequired("namespace")
	upCmd.MarkFlagRequired("targetType")
	upCmd.MarkFlagRequired("targetName")
	upCmd.MarkFlagRequired("localPath")
	upCmd.MarkFlagRequired("containerPath")

	rootCmd.AddCommand(upCmd)
}
