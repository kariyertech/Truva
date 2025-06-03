package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kariyertech/Truva.git/pkg/utils"
	"golang.org/x/crypto/pbkdf2"
)

// SecretManager handles secure storage and retrieval of secrets
type SecretManager struct {
	masterKey []byte
	storePath string
	encrypted bool
}

// SecretEntry represents a stored secret
type SecretEntry struct {
	Key         string     `json:"key"`
	Value       string     `json:"value"`
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Encrypted   bool       `json:"encrypted"`
}

// SecretStore represents the encrypted secret storage
type SecretStore struct {
	Version   string                 `json:"version"`
	Secrets   map[string]SecretEntry `json:"secrets"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// NewSecretManager creates a new secret manager
func NewSecretManager(storePath string, masterPassword string) (*SecretManager, error) {
	if storePath == "" {
		storePath = "./secrets.enc"
	}

	// Derive master key from password
	salt := []byte("truva-secrets-salt-v1") // In production, use random salt per store
	masterKey := pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)

	return &SecretManager{
		masterKey: masterKey,
		storePath: storePath,
		encrypted: true,
	}, nil
}

// NewPlainSecretManager creates a secret manager without encryption (for development)
func NewPlainSecretManager(storePath string) *SecretManager {
	if storePath == "" {
		storePath = "./secrets.json"
	}

	return &SecretManager{
		storePath: storePath,
		encrypted: false,
	}
}

// Initialize creates the secret store if it doesn't exist
func (sm *SecretManager) Initialize() error {
	// Check if store already exists
	if _, err := os.Stat(sm.storePath); err == nil {
		return nil // Store already exists
	}

	// Create directory if needed
	dir := filepath.Dir(sm.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	// Create empty store
	store := SecretStore{
		Version:   "1.0",
		Secrets:   make(map[string]SecretEntry),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return sm.saveStore(&store)
}

// StoreSecret stores a secret securely
func (sm *SecretManager) StoreSecret(key, value, description string, expiresAt *time.Time) error {
	store, err := sm.loadStore()
	if err != nil {
		return fmt.Errorf("failed to load secret store: %w", err)
	}

	// Create secret entry
	entry := SecretEntry{
		Key:         key,
		Value:       value,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Encrypted:   sm.encrypted,
	}

	// Encrypt value if encryption is enabled
	if sm.encrypted {
		encryptedValue, err := sm.encrypt(value)
		if err != nil {
			return fmt.Errorf("failed to encrypt secret: %w", err)
		}
		entry.Value = encryptedValue
	}

	// Update existing entry's timestamps
	if existing, exists := store.Secrets[key]; exists {
		entry.CreatedAt = existing.CreatedAt
	}

	store.Secrets[key] = entry
	store.UpdatedAt = time.Now()

	return sm.saveStore(store)
}

// GetSecret retrieves a secret
func (sm *SecretManager) GetSecret(key string) (string, error) {
	store, err := sm.loadStore()
	if err != nil {
		return "", fmt.Errorf("failed to load secret store: %w", err)
	}

	entry, exists := store.Secrets[key]
	if !exists {
		return "", fmt.Errorf("secret not found: %s", key)
	}

	// Check if secret has expired
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return "", fmt.Errorf("secret has expired: %s", key)
	}

	// Decrypt value if encrypted
	if entry.Encrypted && sm.encrypted {
		decryptedValue, err := sm.decrypt(entry.Value)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt secret: %w", err)
		}
		return decryptedValue, nil
	}

	return entry.Value, nil
}

// DeleteSecret removes a secret
func (sm *SecretManager) DeleteSecret(key string) error {
	store, err := sm.loadStore()
	if err != nil {
		return fmt.Errorf("failed to load secret store: %w", err)
	}

	if _, exists := store.Secrets[key]; !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	delete(store.Secrets, key)
	store.UpdatedAt = time.Now()

	return sm.saveStore(store)
}

// ListSecrets returns a list of secret keys with metadata
func (sm *SecretManager) ListSecrets() ([]SecretEntry, error) {
	store, err := sm.loadStore()
	if err != nil {
		return nil, fmt.Errorf("failed to load secret store: %w", err)
	}

	var secrets []SecretEntry
	for _, entry := range store.Secrets {
		// Don't include the actual value in the list
		listEntry := entry
		listEntry.Value = "[HIDDEN]"
		secrets = append(secrets, listEntry)
	}

	return secrets, nil
}

// CleanupExpired removes expired secrets
func (sm *SecretManager) CleanupExpired() (int, error) {
	store, err := sm.loadStore()
	if err != nil {
		return 0, fmt.Errorf("failed to load secret store: %w", err)
	}

	now := time.Now()
	expiredCount := 0

	for key, entry := range store.Secrets {
		if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
			delete(store.Secrets, key)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		store.UpdatedAt = time.Now()
		if err := sm.saveStore(store); err != nil {
			return expiredCount, fmt.Errorf("failed to save store after cleanup: %w", err)
		}
	}

	return expiredCount, nil
}

// GetSecretWithFallback tries to get secret from store, falls back to environment variable
func (sm *SecretManager) GetSecretWithFallback(key, envVar string) (string, error) {
	// Try to get from secret store first
	value, err := sm.GetSecret(key)
	if err == nil {
		return value, nil
	}

	// Fall back to environment variable
	if envValue := os.Getenv(envVar); envValue != "" {
		return envValue, nil
	}

	return "", fmt.Errorf("secret not found in store or environment: %s", key)
}

// encrypt encrypts a value using AES-GCM
func (sm *SecretManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(sm.masterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts a value using AES-GCM
func (sm *SecretManager) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sm.masterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// loadStore loads the secret store from disk
func (sm *SecretManager) loadStore() (*SecretStore, error) {
	data, err := os.ReadFile(sm.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Initialize empty store
			return &SecretStore{
				Version:   "1.0",
				Secrets:   make(map[string]SecretEntry),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}, nil
		}
		return nil, err
	}

	var store SecretStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse secret store: %w", err)
	}

	return &store, nil
}

// saveStore saves the secret store to disk
func (sm *SecretManager) saveStore(store *SecretStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secret store: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(sm.storePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secret store: %w", err)
	}

	return nil
}

// ResolveSecretValue resolves a value that might be a secret reference
// Supports formats: ${secret:key}, ${env:VAR}, or plain text
func (sm *SecretManager) ResolveSecretValue(value string) (string, error) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		// Plain text value
		return value, nil
	}

	// Extract reference
	reference := value[2 : len(value)-1] // Remove ${ and }
	parts := strings.SplitN(reference, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid secret reference format: %s", value)
	}

	refType, refKey := parts[0], parts[1]

	switch refType {
	case "secret":
		return sm.GetSecret(refKey)
	case "env":
		envValue := os.Getenv(refKey)
		if envValue == "" {
			return "", fmt.Errorf("environment variable not found: %s", refKey)
		}
		return envValue, nil
	default:
		return "", fmt.Errorf("unsupported secret reference type: %s", refType)
	}
}

// GetMasterPasswordFromEnv gets master password from environment or prompts user
func GetMasterPasswordFromEnv() (string, error) {
	// Try environment variable first
	if password := os.Getenv("TRUVA_MASTER_PASSWORD"); password != "" {
		return password, nil
	}

	// For now, return an error - in a real implementation, you might prompt the user
	return "", fmt.Errorf("master password not found in TRUVA_MASTER_PASSWORD environment variable")
}

// ValidateSecretStore validates the integrity of the secret store
func (sm *SecretManager) ValidateSecretStore() error {
	store, err := sm.loadStore()
	if err != nil {
		return fmt.Errorf("failed to load secret store: %w", err)
	}

	// Check version compatibility
	if store.Version != "1.0" {
		return fmt.Errorf("unsupported secret store version: %s", store.Version)
	}

	// Validate each secret entry
	for key, entry := range store.Secrets {
		if entry.Key != key {
			return fmt.Errorf("secret key mismatch: %s != %s", entry.Key, key)
		}

		// Try to decrypt if encrypted
		if entry.Encrypted && sm.encrypted {
			if _, err := sm.decrypt(entry.Value); err != nil {
				return fmt.Errorf("failed to decrypt secret %s: %w", key, err)
			}
		}
	}

	utils.Logger.Info(fmt.Sprintf("Secret store validation successful: %d secrets", len(store.Secrets)))
	return nil
}
