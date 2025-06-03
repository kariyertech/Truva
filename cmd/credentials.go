package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kariyertech/Truva.git/cmd/cli"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/credentials"
	"github.com/spf13/cobra"
)

// credentialsCmd represents the credentials command
var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage secure credentials",
	Long:  `Manage secure credentials for Kubernetes and other services.`,
}

// initCmd initializes the credentials store
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize credentials store",
	Long:  `Initialize the secure credentials store with a master password.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.GetConfig()

		// Get master password
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			fmt.Print("Enter master password: ")
			fmt.Scanln(&masterPassword)
		}

		if masterPassword == "" {
			return fmt.Errorf("master password is required")
		}

		// Create credentials manager
		credManager, err := credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		fmt.Printf("Credentials store initialized at: %s\n", cfg.Credentials.StorePath)

		// Test the store
		testData := []byte("test")
		expiresAt := time.Now().Add(time.Hour)
		err = credManager.Store("test", credentials.Generic, testData, "Test credential", &expiresAt)
		if err != nil {
			return fmt.Errorf("failed to test credentials store: %w", err)
		}

		// Clean up test
		err = credManager.Delete("test")
		if err != nil {
			fmt.Printf("Warning: failed to clean up test credential: %v\n", err)
		}

		fmt.Println("Credentials store is working correctly!")
		return nil
	},
}

// listCmd lists stored credentials
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored credentials",
	Long:  `List all stored credentials (metadata only, not the actual secrets).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.GetConfig()

		// Get master password
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			fmt.Print("Enter master password: ")
			fmt.Scanln(&masterPassword)
		}

		if masterPassword == "" {
			return fmt.Errorf("master password is required")
		}

		// Create credentials manager
		credManager, err := credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// List credentials
		creds, err := credManager.List()
		if err != nil {
			return fmt.Errorf("failed to list credentials: %w", err)
		}

		if len(creds) == 0 {
			fmt.Println("No credentials stored.")
			return nil
		}

		fmt.Printf("%-20s %-15s %-30s %-20s %s\n", "ID", "TYPE", "DESCRIPTION", "CREATED", "EXPIRES")
		fmt.Println("--------------------------------------------------------------------------------------------")

		for _, cred := range creds {
			expiresStr := "Never"
			if cred.ExpiresAt != nil {
				expiresStr = cred.ExpiresAt.Format("2006-01-02 15:04")
			}

			fmt.Printf("%-20s %-15s %-30s %-20s %s\n",
				cred.ID,
				cred.Type,
				cred.Description,
				cred.CreatedAt.Format("2006-01-02 15:04"),
				expiresStr,
			)
		}

		return nil
	},
}

// storeCmd stores a new credential
var storeCmd = &cobra.Command{
	Use:   "store [id] [file]",
	Short: "Store a credential from file",
	Long:  `Store a credential from a file with the given ID.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		filePath := args[1]

		cfg := config.GetConfig()

		// Get master password
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			fmt.Print("Enter master password: ")
			fmt.Scanln(&masterPassword)
		}

		if masterPassword == "" {
			return fmt.Errorf("master password is required")
		}

		// Read file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", filePath, err)
		}

		// Create credentials manager
		credManager, err := credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Determine credential type based on file extension
		var credType credentials.CredentialType
		ext := filepath.Ext(filePath)
		switch ext {
		case ".yaml", ".yml":
			if filepath.Base(filePath) == "config" || filepath.Base(filePath) == "kubeconfig" {
				credType = credentials.KubernetesConfig
			} else {
				credType = credentials.Generic
			}
		case ".json":
			credType = credentials.APIKey
		default:
			credType = credentials.Generic
		}

		// Get description
		description, _ := cmd.Flags().GetString("description")
		if description == "" {
			description = fmt.Sprintf("Credential from %s", filePath)
		}

		// Get expiration
		var expiresAt *time.Time
		expiry, _ := cmd.Flags().GetString("expires")
		if expiry != "" {
			parsedTime, err := time.Parse("2006-01-02", expiry)
			if err != nil {
				return fmt.Errorf("invalid expiry date format (use YYYY-MM-DD): %w", err)
			}
			expiresAt = &parsedTime
		}

		// Store credential
		err = credManager.Store(id, credType, data, description, expiresAt)
		if err != nil {
			return fmt.Errorf("failed to store credential: %w", err)
		}

		fmt.Printf("Credential '%s' stored successfully\n", id)
		return nil
	},
}

// deleteCmd deletes a credential
var deleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a stored credential",
	Long:  `Delete a stored credential by ID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		cfg := config.GetConfig()

		// Get master password
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			fmt.Print("Enter master password: ")
			fmt.Scanln(&masterPassword)
		}

		if masterPassword == "" {
			return fmt.Errorf("master password is required")
		}

		// Create credentials manager
		credManager, err := credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Delete credential
		err = credManager.Delete(id)
		if err != nil {
			return fmt.Errorf("failed to delete credential: %w", err)
		}

		fmt.Printf("Credential '%s' deleted successfully\n", id)
		return nil
	},
}

// rotateCmd rotates Kubernetes credentials
var rotateCmd = &cobra.Command{
	Use:   "rotate [kubeconfig-path]",
	Short: "Rotate Kubernetes credentials",
	Long:  `Rotate Kubernetes credentials with a new kubeconfig file.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kubeconfigPath := ""
		if len(args) > 0 {
			kubeconfigPath = args[0]
		}

		cfg := config.GetConfig()

		// Get master password
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			fmt.Print("Enter master password: ")
			fmt.Scanln(&masterPassword)
		}

		if masterPassword == "" {
			return fmt.Errorf("master password is required")
		}

		// Create credentials manager
		credManager, err := credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Create secure client
		secureClient := credentials.NewSecureK8sClient(credManager)

		if kubeconfigPath == "" {
			// Use default kubeconfig path
			kubeconfigPath = os.Getenv("KUBECONFIG")
			if kubeconfigPath == "" {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("failed to get home directory: %w", err)
				}
				kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
			}
		}

		// Rotate credentials
		err = secureClient.RotateCredentials(kubeconfigPath)
		if err != nil {
			return fmt.Errorf("failed to rotate credentials: %w", err)
		}

		fmt.Println("Kubernetes credentials rotated successfully")
		return nil
	},
}

func init() {
	// Add flags
	storeCmd.Flags().StringP("description", "d", "", "Description for the credential")
	storeCmd.Flags().StringP("expires", "e", "", "Expiration date (YYYY-MM-DD)")

	// Add subcommands
	credentialsCmd.AddCommand(initCmd)
	credentialsCmd.AddCommand(listCmd)
	credentialsCmd.AddCommand(storeCmd)
	credentialsCmd.AddCommand(deleteCmd)
	credentialsCmd.AddCommand(rotateCmd)

	// Add to root command
	cli.GetRootCmd().AddCommand(credentialsCmd)
}
