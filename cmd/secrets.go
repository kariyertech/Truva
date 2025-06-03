package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/cmd/cli"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/errors"
	"github.com/kariyertech/Truva.git/pkg/secrets"
	"github.com/spf13/cobra"
)

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage application secrets securely",
	Long: `Manage application secrets with encryption and secure storage.

This command provides subcommands to:
- Store secrets securely with encryption
- Retrieve secrets for configuration
- List stored secrets (without revealing values)
- Delete secrets when no longer needed
- Clean up expired secrets
- Validate secret store integrity`,
}

// secretsInitCmd initializes the secrets store
var secretsInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the secrets store",
	Long: `Initialize a new encrypted secrets store.

This creates a new secrets store with the configured master password.
The store will be encrypted using AES-256-GCM encryption.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()

		// Get master password
		masterPassword, err := getMasterPassword(cfg)
		if err != nil {
			errors.Fatal("MASTER_PASSWORD_FAILED", "Failed to get master password: "+err.Error())
		}

		// Create secret manager
		var secretManager *secrets.SecretManager
		if cfg.Secrets.Encrypted {
			secretManager, err = secrets.NewSecretManager(cfg.Secrets.StorePath, masterPassword)
		} else {
			secretManager = secrets.NewPlainSecretManager(cfg.Secrets.StorePath)
		}
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Initialize store
		if err := secretManager.Initialize(); err != nil {
			errors.Fatal("SECRET_STORE_INIT_FAILED", "Failed to initialize secrets store: "+err.Error())
		}

		fmt.Printf("✓ Secrets store initialized: %s\n", cfg.Secrets.StorePath)
		if cfg.Secrets.Encrypted {
			fmt.Println("✓ Encryption enabled")
		} else {
			fmt.Println("⚠ WARNING: Encryption disabled - secrets stored in plain text")
		}
	},
}

// secretsStoreCmd stores a new secret
var secretsStoreCmd = &cobra.Command{
	Use:   "store <key> <value>",
	Short: "Store a secret securely",
	Long: `Store a secret value with the specified key.

The secret will be encrypted and stored securely.
Optionally, you can set an expiration time and description.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key, value := args[0], args[1]

		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Get optional parameters
		description, _ := cmd.Flags().GetString("description")
		expiresIn, _ := cmd.Flags().GetString("expires")

		// Parse expiration
		var expiresAt *time.Time
		if expiresIn != "" {
			duration, err := time.ParseDuration(expiresIn)
			if err != nil {
				errors.Fatal("INVALID_EXPIRATION_FORMAT", "Invalid expiration format: "+err.Error())
			}
			expiry := time.Now().Add(duration)
			expiresAt = &expiry
		}

		// Store secret
		if err := secretManager.StoreSecret(key, value, description, expiresAt); err != nil {
			errors.Fatal("SECRET_STORE_FAILED", "Failed to store secret: "+err.Error())
		}

		fmt.Printf("✓ Secret stored: %s\n", key)
		if description != "" {
			fmt.Printf("  Description: %s\n", description)
		}
		if expiresAt != nil {
			fmt.Printf("  Expires: %s\n", expiresAt.Format(time.RFC3339))
		}
	},
}

// secretsGetCmd retrieves a secret
var secretsGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Retrieve a secret value",
	Long: `Retrieve and decrypt a secret value by its key.

WARNING: This will display the secret value in plain text.
Use with caution in shared environments.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]

		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Get secret
		value, err := secretManager.GetSecret(key)
		if err != nil {
			errors.Fatal("SECRET_GET_FAILED", "Failed to get secret: "+err.Error())
		}

		// Check if output should be quiet (just the value)
		quiet, _ := cmd.Flags().GetBool("quiet")
		if quiet {
			fmt.Print(value)
		} else {
			fmt.Printf("Secret value for '%s':\n%s\n", key, value)
		}
	},
}

// secretsListCmd lists all secrets
var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored secrets",
	Long: `List all stored secrets with their metadata.

Secret values are not displayed for security reasons.
Use 'secrets get <key>' to retrieve specific values.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// List secrets
		secretsList, err := secretManager.ListSecrets()
		if err != nil {
			errors.Fatal("SECRET_LIST_FAILED", "Failed to list secrets: "+err.Error())
		}

		if len(secretsList) == 0 {
			fmt.Println("No secrets stored")
			return
		}

		// Check output format
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			jsonData, _ := json.MarshalIndent(secretsList, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("Stored Secrets (%d):\n", len(secretsList))
			fmt.Println("====================")
			for _, secret := range secretsList {
				fmt.Printf("Key: %s\n", secret.Key)
				if secret.Description != "" {
					fmt.Printf("  Description: %s\n", secret.Description)
				}
				fmt.Printf("  Created: %s\n", secret.CreatedAt.Format(time.RFC3339))
				fmt.Printf("  Updated: %s\n", secret.UpdatedAt.Format(time.RFC3339))
				if secret.ExpiresAt != nil {
					fmt.Printf("  Expires: %s\n", secret.ExpiresAt.Format(time.RFC3339))
					if time.Now().After(*secret.ExpiresAt) {
						fmt.Printf("  Status: EXPIRED\n")
					} else {
						fmt.Printf("  Status: Active\n")
					}
				} else {
					fmt.Printf("  Status: Active (no expiration)\n")
				}
				fmt.Printf("  Encrypted: %t\n", secret.Encrypted)
				fmt.Println()
			}
		}
	},
}

// secretsDeleteCmd deletes a secret
var secretsDeleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete a stored secret",
	Long: `Delete a secret from the secure store.

This action is irreversible. The secret will be permanently removed.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]

		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Confirm deletion unless --force is used
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("Are you sure you want to delete secret '%s'? (y/N): ", key)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Deletion cancelled")
				return
			}
		}

		// Delete secret
		if err := secretManager.DeleteSecret(key); err != nil {
			errors.Fatal("SECRET_DELETE_FAILED", "Failed to delete secret: "+err.Error())
		}

		fmt.Printf("✓ Secret deleted: %s\n", key)
	},
}

// secretsCleanupCmd cleans up expired secrets
var secretsCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up expired secrets",
	Long: `Remove all expired secrets from the store.

This will permanently delete secrets that have passed their expiration time.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Clean up expired secrets
		expiredCount, err := secretManager.CleanupExpired()
		if err != nil {
			errors.Fatal("SECRET_CLEANUP_FAILED", "Failed to cleanup expired secrets: "+err.Error())
		}

		if expiredCount > 0 {
			fmt.Printf("✓ Cleaned up %d expired secret(s)\n", expiredCount)
		} else {
			fmt.Println("No expired secrets found")
		}
	},
}

// secretsValidateCmd validates the secret store
var secretsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the secrets store",
	Long: `Validate the integrity and accessibility of the secrets store.

This checks:
- Store file exists and is readable
- All secrets can be decrypted
- Store format is valid
- No corruption detected`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		secretManager, err := createSecretManager(cfg)
		if err != nil {
			errors.Fatal("SECRET_MANAGER_FAILED", "Failed to create secret manager: "+err.Error())
		}

		// Validate store
		if err := secretManager.ValidateSecretStore(); err != nil {
			errors.Fatal("SECRET_STORE_VALIDATION_FAILED", "Secret store validation failed: "+err.Error())
		}

		fmt.Println("✓ Secret store validation successful")
	},
}

// Helper functions

// createSecretManager creates a secret manager based on configuration
func createSecretManager(cfg *config.Config) (*secrets.SecretManager, error) {
	if !cfg.Secrets.Enabled {
		return nil, fmt.Errorf("secrets management is disabled")
	}

	masterPassword, err := getMasterPassword(cfg)
	if err != nil {
		return nil, err
	}

	var secretManager *secrets.SecretManager
	if cfg.Secrets.Encrypted {
		secretManager, err = secrets.NewSecretManager(cfg.Secrets.StorePath, masterPassword)
	} else {
		secretManager = secrets.NewPlainSecretManager(cfg.Secrets.StorePath)
	}

	return secretManager, err
}

// getMasterPassword gets the master password from configuration or environment
func getMasterPassword(cfg *config.Config) (string, error) {
	masterPassword := cfg.Secrets.MasterPassword

	// Resolve environment reference if needed
	if strings.HasPrefix(masterPassword, "${") {
		if strings.Contains(masterPassword, "env:") {
			// Extract environment variable name
			envVar := strings.TrimSuffix(strings.TrimPrefix(masterPassword, "${env:"), "}")
			envValue := os.Getenv(envVar)
			if envValue == "" {
				return "", fmt.Errorf("environment variable %s not set", envVar)
			}
			masterPassword = envValue
		} else {
			return "", fmt.Errorf("unsupported password reference: %s", masterPassword)
		}
	}

	if masterPassword == "" {
		return "", fmt.Errorf("master password is required")
	}

	return masterPassword, nil
}

func init() {
	cli.GetRootCmd().AddCommand(secretsCmd)
	secretsCmd.AddCommand(secretsInitCmd)
	secretsCmd.AddCommand(secretsStoreCmd)
	secretsCmd.AddCommand(secretsGetCmd)
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsDeleteCmd)
	secretsCmd.AddCommand(secretsCleanupCmd)
	secretsCmd.AddCommand(secretsValidateCmd)

	// Add flags
	secretsStoreCmd.Flags().String("description", "", "Description for the secret")
	secretsStoreCmd.Flags().String("expires", "", "Expiration duration (e.g., 24h, 7d, 30d)")

	secretsGetCmd.Flags().Bool("quiet", false, "Output only the secret value")

	secretsListCmd.Flags().Bool("json", false, "Output in JSON format")

	secretsDeleteCmd.Flags().Bool("force", false, "Force deletion without confirmation")
}
