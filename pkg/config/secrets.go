package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/kariyertech/Truva.git/pkg/secrets"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// SecretResolver handles resolution of secret references in configuration
type SecretResolver struct {
	secretManager *secrets.SecretManager
}

// NewSecretResolver creates a new secret resolver
func NewSecretResolver(secretManager *secrets.SecretManager) *SecretResolver {
	return &SecretResolver{
		secretManager: secretManager,
	}
}

// ResolveSecrets resolves all secret references in a configuration struct
func (sr *SecretResolver) ResolveSecrets(config interface{}) error {
	return sr.resolveSecretsRecursive(reflect.ValueOf(config))
}

// resolveSecretsRecursive recursively resolves secrets in a struct
func (sr *SecretResolver) resolveSecretsRecursive(v reflect.Value) error {
	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		return sr.resolveStructSecrets(v)
	case reflect.Slice, reflect.Array:
		return sr.resolveSliceSecrets(v)
	case reflect.Map:
		return sr.resolveMapSecrets(v)
	default:
		return nil
	}
}

// resolveStructSecrets resolves secrets in struct fields
func (sr *SecretResolver) resolveStructSecrets(v reflect.Value) error {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Handle string fields that might contain secret references
		if field.Kind() == reflect.String {
			originalValue := field.String()
			if sr.isSecretReference(originalValue) {
				resolvedValue, err := sr.resolveSecretReference(originalValue)
				if err != nil {
					return fmt.Errorf("failed to resolve secret in field %s: %w", fieldType.Name, err)
				}
				field.SetString(resolvedValue)
				utils.Logger.Debug(fmt.Sprintf("Resolved secret reference in field: %s", fieldType.Name))
			}
		} else {
			// Recursively handle nested structs, slices, and maps
			if err := sr.resolveSecretsRecursive(field); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveSliceSecrets resolves secrets in slice elements
func (sr *SecretResolver) resolveSliceSecrets(v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		if err := sr.resolveSecretsRecursive(elem); err != nil {
			return err
		}
	}
	return nil
}

// resolveMapSecrets resolves secrets in map values
func (sr *SecretResolver) resolveMapSecrets(v reflect.Value) error {
	for _, key := range v.MapKeys() {
		mapValue := v.MapIndex(key)
		if err := sr.resolveSecretsRecursive(mapValue); err != nil {
			return err
		}
	}
	return nil
}

// isSecretReference checks if a string is a secret reference
func (sr *SecretResolver) isSecretReference(value string) bool {
	return strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")
}

// resolveSecretReference resolves a single secret reference
func (sr *SecretResolver) resolveSecretReference(reference string) (string, error) {
	if sr.secretManager == nil {
		// Fall back to environment variable resolution
		return sr.resolveEnvironmentReference(reference)
	}

	return sr.secretManager.ResolveSecretValue(reference)
}

// resolveEnvironmentReference resolves environment variable references
func (sr *SecretResolver) resolveEnvironmentReference(reference string) (string, error) {
	if !strings.HasPrefix(reference, "${") || !strings.HasSuffix(reference, "}") {
		return reference, nil
	}

	// Extract reference
	refContent := reference[2 : len(reference)-1] // Remove ${ and }
	parts := strings.SplitN(refContent, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid reference format: %s", reference)
	}

	refType, refKey := parts[0], parts[1]

	switch refType {
	case "env":
		envValue := os.Getenv(refKey)
		if envValue == "" {
			return "", fmt.Errorf("environment variable not found: %s", refKey)
		}
		return envValue, nil
	default:
		return "", fmt.Errorf("unsupported reference type without secret manager: %s", refType)
	}
}

// InitializeSecretsManager initializes the secrets manager based on configuration
func InitializeSecretsManager(cfg *Config) (*secrets.SecretManager, error) {
	if !cfg.Secrets.Enabled {
		return nil, nil
	}

	// Resolve master password
	masterPassword := cfg.Secrets.MasterPassword
	if strings.HasPrefix(masterPassword, "${") {
		// This is a reference, resolve it
		resolvedPassword, err := resolveEnvironmentReference(masterPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve master password: %w", err)
		}
		masterPassword = resolvedPassword
	}

	if masterPassword == "" {
		return nil, fmt.Errorf("master password is required for secrets management")
	}

	var secretManager *secrets.SecretManager
	var err error

	if cfg.Secrets.Encrypted {
		secretManager, err = secrets.NewSecretManager(cfg.Secrets.StorePath, masterPassword)
	} else {
		secretManager = secrets.NewPlainSecretManager(cfg.Secrets.StorePath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager: %w", err)
	}

	// Initialize the secret store
	if err := secretManager.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize secret store: %w", err)
	}

	// Validate the secret store
	if err := secretManager.ValidateSecretStore(); err != nil {
		return nil, fmt.Errorf("secret store validation failed: %w", err)
	}

	utils.Logger.Info("Secrets manager initialized successfully")
	return secretManager, nil
}

// resolveEnvironmentReference is a helper function for resolving environment references
func resolveEnvironmentReference(reference string) (string, error) {
	if !strings.HasPrefix(reference, "${") || !strings.HasSuffix(reference, "}") {
		return reference, nil
	}

	// Extract reference
	refContent := reference[2 : len(reference)-1] // Remove ${ and }
	parts := strings.SplitN(refContent, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid reference format: %s", reference)
	}

	refType, refKey := parts[0], parts[1]

	switch refType {
	case "env":
		envValue := os.Getenv(refKey)
		if envValue == "" {
			return "", fmt.Errorf("environment variable not found: %s", refKey)
		}
		return envValue, nil
	default:
		return "", fmt.Errorf("unsupported reference type: %s", refType)
	}
}

// GetConfigWithSecrets loads configuration and resolves all secret references
func GetConfigWithSecrets() (*Config, *secrets.SecretManager, error) {
	// Load base configuration
	cfg := GetConfig()

	// Initialize secrets manager
	secretManager, err := InitializeSecretsManager(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize secrets manager: %w", err)
	}

	// Resolve secret references in configuration
	if secretManager != nil {
		resolver := NewSecretResolver(secretManager)
		if err := resolver.ResolveSecrets(cfg); err != nil {
			return nil, nil, fmt.Errorf("failed to resolve secrets in configuration: %w", err)
		}
		utils.Logger.Info("Configuration secrets resolved successfully")
	} else {
		// Even without secrets manager, resolve environment references
		resolver := NewSecretResolver(nil)
		if err := resolver.ResolveSecrets(cfg); err != nil {
			return nil, nil, fmt.Errorf("failed to resolve environment references: %w", err)
		}
	}

	return cfg, secretManager, nil
}

// SecureConfigValue represents a configuration value that should be treated as sensitive
type SecureConfigValue struct {
	Value     string
	IsSecret  bool
	Reference string
}

// String returns a safe string representation
func (scv SecureConfigValue) String() string {
	if scv.IsSecret {
		return "[REDACTED]"
	}
	return scv.Value
}

// GetValue returns the actual value (use with caution)
func (scv SecureConfigValue) GetValue() string {
	return scv.Value
}

// NewSecureConfigValue creates a new secure config value
func NewSecureConfigValue(value string, isSecret bool) SecureConfigValue {
	return SecureConfigValue{
		Value:    value,
		IsSecret: isSecret,
	}
}
