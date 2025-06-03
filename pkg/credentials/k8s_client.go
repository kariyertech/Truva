package credentials

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kariyertech/Truva.git/pkg/retry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// SecureK8sClient provides secure Kubernetes client with credential management
type SecureK8sClient struct {
	credentialsManager *CredentialsManager
	clientset          kubernetes.Interface
	config             *rest.Config
}

// NewSecureK8sClient creates a new secure Kubernetes client
func NewSecureK8sClient(credentialsManager *CredentialsManager) *SecureK8sClient {
	return &SecureK8sClient{
		credentialsManager: credentialsManager,
	}
}

// InitializeFromKubeconfig loads and encrypts kubeconfig, then initializes the client
func (sc *SecureK8sClient) InitializeFromKubeconfig(kubeconfigPath string) error {
	// Read kubeconfig file
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			kubeconfigPath = clientcmd.RecommendedHomeFile
		}
	}

	// Check if kubeconfig exists
	if _, err := os.Stat(kubeconfigPath); os.IsNotExist(err) {
		return fmt.Errorf("kubeconfig file not found: %s", kubeconfigPath)
	}

	// Read kubeconfig content
	kubeconfigData, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to read kubeconfig: %w", err)
	}

	// Store encrypted kubeconfig
	expiresAt := time.Now().Add(24 * time.Hour) // Rotate daily
	err = sc.credentialsManager.Store(
		"kubernetes-config",
		KubernetesConfig,
		kubeconfigData,
		fmt.Sprintf("Kubernetes config from %s", kubeconfigPath),
		&expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store kubeconfig securely: %w", err)
	}

	// Initialize client from stored config
	return sc.InitializeFromStoredConfig()
}

// InitializeFromStoredConfig initializes the client from securely stored config
func (sc *SecureK8sClient) InitializeFromStoredConfig() error {
	// Retrieve stored kubeconfig
	credential, err := sc.credentialsManager.Retrieve("kubernetes-config")
	if err != nil {
		return fmt.Errorf("failed to retrieve stored kubeconfig: %w", err)
	}

	// Parse kubeconfig
	config, err := clientcmd.RESTConfigFromKubeConfig(credential.Data)
	if err != nil {
		return fmt.Errorf("failed to parse stored kubeconfig: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	// Test connection with retry
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		_, err := clientset.Discovery().ServerVersion()
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
	}

	sc.clientset = clientset
	sc.config = config

	return nil
}

// InitializeInCluster initializes the client for in-cluster usage
func (sc *SecureK8sClient) InitializeInCluster() error {
	// Use in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	// Test connection with retry
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		_, err := clientset.Discovery().ServerVersion()
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
	}

	sc.clientset = clientset
	sc.config = config

	return nil
}

// GetClientset returns the Kubernetes clientset
func (sc *SecureK8sClient) GetClientset() kubernetes.Interface {
	return sc.clientset
}

// GetConfig returns the Kubernetes REST config
func (sc *SecureK8sClient) GetConfig() *rest.Config {
	return sc.config
}

// RotateCredentials rotates the stored Kubernetes credentials
func (sc *SecureK8sClient) RotateCredentials(newKubeconfigPath string) error {
	// Read new kubeconfig
	newKubeconfigData, err := os.ReadFile(newKubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to read new kubeconfig: %w", err)
	}

	// Rotate the stored credential
	err = sc.credentialsManager.Rotate("kubernetes-config", newKubeconfigData)
	if err != nil {
		return fmt.Errorf("failed to rotate kubeconfig: %w", err)
	}

	// Reinitialize client with new config
	return sc.InitializeFromStoredConfig()
}

// IsCredentialExpired checks if the stored credential is expired
func (sc *SecureK8sClient) IsCredentialExpired() (bool, error) {
	credential, err := sc.credentialsManager.Retrieve("kubernetes-config")
	if err != nil {
		return true, err
	}

	if credential.ExpiresAt != nil && time.Now().After(*credential.ExpiresAt) {
		return true, nil
	}

	return false, nil
}

// CreateTempKubeconfig creates a temporary kubeconfig file for external tools
// This should be used sparingly and the file should be cleaned up immediately
func (sc *SecureK8sClient) CreateTempKubeconfig() (string, func(), error) {
	credential, err := sc.credentialsManager.Retrieve("kubernetes-config")
	if err != nil {
		return "", nil, fmt.Errorf("failed to retrieve kubeconfig: %w", err)
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", "truva-kubeconfig-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Write kubeconfig data
	if _, err := tempFile.Write(credential.Data); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return "", nil, fmt.Errorf("failed to write temp kubeconfig: %w", err)
	}

	tempFile.Close()

	// Return cleanup function
	cleanup := func() {
		os.Remove(tempFile.Name())
	}

	return tempFile.Name(), cleanup, nil
}

// ValidateStoredConfig validates that the stored kubeconfig is still valid
func (sc *SecureK8sClient) ValidateStoredConfig() error {
	credential, err := sc.credentialsManager.Retrieve("kubernetes-config")
	if err != nil {
		return fmt.Errorf("failed to retrieve stored kubeconfig: %w", err)
	}

	// Parse and validate kubeconfig
	config, err := clientcmd.RESTConfigFromKubeConfig(credential.Data)
	if err != nil {
		return fmt.Errorf("stored kubeconfig is invalid: %w", err)
	}

	// Test connection
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset from stored config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		_, err := clientset.Discovery().ServerVersion()
		return err
	})
	if err != nil {
		return fmt.Errorf("stored kubeconfig cannot connect to cluster: %w", err)
	}

	return nil
}
