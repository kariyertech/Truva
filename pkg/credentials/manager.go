package credentials

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
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// CredentialType represents the type of credential
type CredentialType string

const (
	KubernetesConfig CredentialType = "kubernetes_config"
	APIKey           CredentialType = "api_key"
	JWTSecret        CredentialType = "jwt_secret"
	Generic          CredentialType = "generic"
)

// Credential represents a stored credential
type Credential struct {
	ID          string         `json:"id"`
	Type        CredentialType `json:"type"`
	Data        []byte         `json:"data"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	Description string         `json:"description"`
}

// CredentialsManager handles secure storage and retrieval of credentials
type CredentialsManager struct {
	storePath string
	masterKey []byte
}

// NewCredentialsManager creates a new credentials manager
func NewCredentialsManager(storePath, masterPassword string) (*CredentialsManager, error) {
	if storePath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		storePath = filepath.Join(homeDir, ".truva", "credentials")
	}

	// Ensure store directory exists
	if err := os.MkdirAll(filepath.Dir(storePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create credentials directory: %w", err)
	}

	// Derive master key from password
	salt := []byte("truva-credentials-salt") // In production, use a random salt per installation
	masterKey := pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)

	return &CredentialsManager{
		storePath: storePath,
		masterKey: masterKey,
	}, nil
}

// Store encrypts and stores a credential
func (cm *CredentialsManager) Store(id string, credType CredentialType, data []byte, description string, expiresAt *time.Time) error {
	credential := Credential{
		ID:          id,
		Type:        credType,
		Data:        data,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Description: description,
	}

	// Encrypt the credential data
	encryptedData, err := cm.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt credential: %w", err)
	}
	credential.Data = encryptedData

	// Serialize credential
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to serialize credential: %w", err)
	}

	// Store to file
	filePath := filepath.Join(cm.storePath, id+".cred")
	if err := os.WriteFile(filePath, credentialJSON, 0600); err != nil {
		return fmt.Errorf("failed to write credential file: %w", err)
	}

	return nil
}

// Retrieve decrypts and retrieves a credential
func (cm *CredentialsManager) Retrieve(id string) (*Credential, error) {
	filePath := filepath.Join(cm.storePath, id+".cred")

	// Read credential file
	credentialJSON, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("credential not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read credential file: %w", err)
	}

	// Deserialize credential
	var credential Credential
	if err := json.Unmarshal(credentialJSON, &credential); err != nil {
		return nil, fmt.Errorf("failed to deserialize credential: %w", err)
	}

	// Check if credential has expired
	if credential.ExpiresAt != nil && time.Now().After(*credential.ExpiresAt) {
		return nil, fmt.Errorf("credential has expired: %s", id)
	}

	// Decrypt the credential data
	decryptedData, err := cm.decrypt(credential.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}
	credential.Data = decryptedData

	return &credential, nil
}

// List returns all stored credential IDs and metadata
func (cm *CredentialsManager) List() ([]Credential, error) {
	files, err := filepath.Glob(filepath.Join(cm.storePath, "*.cred"))
	if err != nil {
		return nil, fmt.Errorf("failed to list credential files: %w", err)
	}

	var credentials []Credential
	for _, file := range files {
		credentialJSON, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files that can't be read
		}

		var credential Credential
		if err := json.Unmarshal(credentialJSON, &credential); err != nil {
			continue // Skip files that can't be parsed
		}

		// Don't include the actual data in the list, only metadata
		credential.Data = nil
		credentials = append(credentials, credential)
	}

	return credentials, nil
}

// Delete removes a stored credential
func (cm *CredentialsManager) Delete(id string) error {
	filePath := filepath.Join(cm.storePath, id+".cred")
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("credential not found: %s", id)
		}
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	return nil
}

// Rotate updates an existing credential with new data
func (cm *CredentialsManager) Rotate(id string, newData []byte) error {
	// Retrieve existing credential
	credential, err := cm.Retrieve(id)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing credential: %w", err)
	}

	// Update with new data
	credential.Data = newData
	credential.UpdatedAt = time.Now()

	// Store the updated credential
	return cm.Store(credential.ID, credential.Type, newData, credential.Description, credential.ExpiresAt)
}

// encrypt encrypts data using AES-GCM
func (cm *CredentialsManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// decrypt decrypts data using AES-GCM
func (cm *CredentialsManager) decrypt(encryptedData []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cm.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GetMasterPasswordFromEnv gets the master password from environment variable
func GetMasterPasswordFromEnv() string {
	password := os.Getenv("TRUVA_MASTER_PASSWORD")
	if password == "" {
		// Fallback to a default password (not recommended for production)
		password = "default-truva-password-change-me"
	}
	return password
}
