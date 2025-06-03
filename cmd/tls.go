package main

import (
	"encoding/json"
	"fmt"

	"github.com/kariyertech/Truva.git/cmd/cli"
	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/errors"
	"github.com/kariyertech/Truva.git/pkg/tls"
	"github.com/kariyertech/Truva.git/pkg/utils"
	"github.com/spf13/cobra"
)

// tlsCmd represents the tls command
var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Manage TLS certificates and configuration",
	Long: `Manage TLS certificates and configuration for secure HTTPS communication.

This command provides subcommands to:
- Generate self-signed certificates for development
- Validate existing certificates
- View certificate information
- Check certificate expiration`,
}

// tlsGenerateCmd generates self-signed certificates
var tlsGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate self-signed TLS certificates",
	Long: `Generate self-signed TLS certificates for development purposes.

This will create a certificate and private key in the configured locations.
The certificates are valid for localhost and 127.0.0.1 for 1 year.

WARNING: Self-signed certificates should only be used for development.
Use proper certificates from a trusted CA in production.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		tlsManager := tls.NewTLSManager(&cfg.Server.TLS)

		if !cfg.Server.TLS.Enabled {
			errors.Fatal("TLS_NOT_ENABLED", "TLS is not enabled in configuration")
		}

		utils.Logger.Info("Generating self-signed TLS certificates...")
		if err := tlsManager.EnsureCertificates(); err != nil {
			errors.Fatal("TLS_CERT_GENERATION_FAILED", "Failed to generate certificates: "+err.Error())
		}

		fmt.Printf("✓ Certificates generated successfully\n")
		fmt.Printf("  Certificate: %s\n", cfg.Server.TLS.CertFile)
		fmt.Printf("  Private Key: %s\n", cfg.Server.TLS.KeyFile)
		fmt.Println("\nNOTE: These are self-signed certificates for development only.")
	},
}

// tlsValidateCmd validates existing certificates
var tlsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate TLS certificates",
	Long: `Validate existing TLS certificates for correctness and expiration.

This command checks:
- Certificate file exists and is readable
- Private key file exists and is readable
- Certificate is not expired
- Certificate is currently valid
- Warns if certificate expires within 30 days`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		tlsManager := tls.NewTLSManager(&cfg.Server.TLS)

		if !cfg.Server.TLS.Enabled {
			errors.Fatal("TLS_NOT_ENABLED", "TLS is not enabled in configuration")
		}

		utils.Logger.Info("Validating TLS certificates...")
		if err := tlsManager.ValidateCertificates(); err != nil {
			errors.Fatal("TLS_CERT_VALIDATION_FAILED", "Certificate validation failed: "+err.Error())
		}

		fmt.Println("✓ Certificates are valid")
	},
}

// tlsInfoCmd shows certificate information
var tlsInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show TLS certificate information",
	Long: `Display detailed information about the current TLS certificates.

Shows:
- Certificate subject and issuer
- Validity period (not before/after dates)
- DNS names and IP addresses
- Serial number
- Current status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		tlsManager := tls.NewTLSManager(&cfg.Server.TLS)

		if !cfg.Server.TLS.Enabled {
			errors.Fatal("TLS_NOT_ENABLED", "TLS is not enabled in configuration")
		}

		info, err := tlsManager.GetCertificateInfo()
		if err != nil {
			errors.Fatal("TLS_CERT_INFO_FAILED", "Failed to get certificate info: "+err.Error())
		}

		// Format output
		if jsonOutput, _ := cmd.Flags().GetBool("json"); jsonOutput {
			jsonData, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Println("TLS Certificate Information:")
			fmt.Println("============================")
			if enabled, ok := info["enabled"].(bool); ok && enabled {
				fmt.Printf("Status: Enabled\n")
				fmt.Printf("Subject: %v\n", info["subject"])
				fmt.Printf("Issuer: %v\n", info["issuer"])
				fmt.Printf("Valid From: %v\n", info["not_before"])
				fmt.Printf("Valid Until: %v\n", info["not_after"])
				fmt.Printf("DNS Names: %v\n", info["dns_names"])
				fmt.Printf("IP Addresses: %v\n", info["ip_addresses"])
				fmt.Printf("Serial Number: %v\n", info["serial_number"])
			} else {
				fmt.Println("Status: Disabled")
			}
		}
	},
}

// tlsCheckCmd checks certificate expiration
var tlsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check certificate expiration",
	Long: `Check if certificates are approaching expiration.

Returns exit code 0 if certificates are valid and not expiring soon.
Returns exit code 1 if certificates are expired or expiring within the warning period.
Returns exit code 2 if there are other errors.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetConfig()
		tlsManager := tls.NewTLSManager(&cfg.Server.TLS)

		if !cfg.Server.TLS.Enabled {
			errors.Info("TLS_NOT_ENABLED", "TLS is not enabled")
			return
		}

		if err := tlsManager.ValidateCertificates(); err != nil {
			errors.Fatal("TLS_CERT_CHECK_FAILED", "Certificate check failed: "+err.Error())
		}

		errors.Info("TLS_CERT_VALID", "Certificates are valid")
	},
}

func init() {
	cli.GetRootCmd().AddCommand(tlsCmd)
	tlsCmd.AddCommand(tlsGenerateCmd)
	tlsCmd.AddCommand(tlsValidateCmd)
	tlsCmd.AddCommand(tlsInfoCmd)
	tlsCmd.AddCommand(tlsCheckCmd)

	// Add flags
	tlsInfoCmd.Flags().Bool("json", false, "Output certificate information in JSON format")
}
