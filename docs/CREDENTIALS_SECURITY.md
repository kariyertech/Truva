# Credentials Security Implementation

This document describes the secure credentials management system implemented in Truva to address the SEC-004 security vulnerability.

## Overview

The credentials security system provides:
- **Encrypted storage** of Kubernetes configurations and other sensitive credentials
- **Automatic credential rotation** with configurable intervals
- **Secure key derivation** using PBKDF2 with salt
- **AES-GCM encryption** for data protection
- **Expiration management** for time-limited credentials
- **CLI tools** for credential management

## Architecture

### Components

1. **CredentialsManager** (`pkg/credentials/manager.go`)
   - Core credential storage and encryption engine
   - Handles CRUD operations for credentials
   - Implements AES-GCM encryption with PBKDF2 key derivation

2. **SecureK8sClient** (`pkg/credentials/k8s_client.go`)
   - Kubernetes-specific secure client wrapper
   - Manages kubeconfig encryption and storage
   - Provides automatic credential rotation

3. **Enhanced K8s Client** (`internal/k8s/client.go`)
   - Updated to use secure credentials when enabled
   - Fallback to traditional method when disabled
   - Background credential rotation support

4. **CLI Commands** (`cmd/credentials.go`)
   - Command-line interface for credential management
   - Initialize, list, store, delete, and rotate operations

### Security Features

#### Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt**: 32-byte random salt per credential
- **Nonce**: 12-byte random nonce per encryption operation
- **Authentication**: Built-in authentication tag prevents tampering

#### Key Management
- Master password required for all operations
- Keys derived on-demand, never stored in memory long-term
- Environment variable support (`TRUVA_MASTER_PASSWORD`)
- Secure memory handling practices

#### Storage
- Credentials stored as encrypted JSON files
- Metadata includes type, creation time, expiration
- File permissions restricted to owner only
- Directory structure: `{store_path}/{credential_id}.json`

## Configuration

### Config File Settings

```yaml
credentials:
  enabled: true                    # Enable secure credentials
  store_path: "./data/credentials" # Storage directory
  master_password: ""             # Master password (use env var instead)
  rotation_enabled: true           # Enable automatic rotation
  rotation_hours: 24              # Rotation interval in hours
```

### Environment Variables

- `TRUVA_MASTER_PASSWORD`: Master password for credential encryption
- `KUBECONFIG`: Path to Kubernetes configuration file

## Usage

### Initialization

```bash
# Initialize credentials store
export TRUVA_MASTER_PASSWORD="your-secure-password"
./truva credentials init
```

### Kubernetes Integration

When credentials management is enabled, the system will:

1. **First Run**: Load kubeconfig from `$KUBECONFIG` or `~/.kube/config`
2. **Encrypt and Store**: Save encrypted kubeconfig to secure storage
3. **Subsequent Runs**: Load from encrypted storage
4. **Auto-Rotation**: Check and rotate expired credentials

### Manual Operations

```bash
# List stored credentials
./truva credentials list

# Store a credential from file
./truva credentials store my-kubeconfig ~/.kube/config --description "Production cluster"

# Rotate Kubernetes credentials
./truva credentials rotate /path/to/new/kubeconfig

# Delete a credential
./truva credentials delete my-kubeconfig
```

### Programmatic Usage

```go
// Initialize credentials manager
credManager, err := credentials.NewCredentialsManager("/path/to/store", "master-password")
if err != nil {
    return err
}

// Create secure Kubernetes client
secureClient := credentials.NewSecureK8sClient(credManager)

// Initialize from kubeconfig
err = secureClient.InitializeFromKubeconfig("/path/to/kubeconfig")
if err != nil {
    return err
}

// Get standard Kubernetes clientset
clientset := secureClient.GetClientset()
```

## Security Considerations

### Best Practices

1. **Master Password**:
   - Use a strong, unique password
   - Store in environment variable, not config file
   - Consider using a secrets management system

2. **File Permissions**:
   - Ensure credentials directory is accessible only to the application user
   - Use `chmod 700` for the credentials directory
   - Use `chmod 600` for credential files

3. **Rotation**:
   - Enable automatic rotation for production environments
   - Set appropriate rotation intervals based on security requirements
   - Monitor rotation logs for failures

4. **Backup and Recovery**:
   - Backup the master password securely
   - Consider encrypted backups of the credentials store
   - Test recovery procedures regularly

### Threat Model

#### Protected Against
- **File System Access**: Credentials encrypted at rest
- **Memory Dumps**: Keys derived on-demand, not stored
- **Credential Theft**: Encrypted storage prevents direct use
- **Tampering**: Authentication tags detect modifications

#### Not Protected Against
- **Master Password Compromise**: Full access to all credentials
- **Runtime Memory Access**: Decrypted credentials in memory during use
- **Application Compromise**: Running application has access to credentials

## Migration Guide

### From Unencrypted Storage

1. **Enable credentials management** in configuration
2. **Set master password** via environment variable
3. **Initialize credentials store**: `./truva credentials init`
4. **Restart application**: Will automatically encrypt and store existing kubeconfig

### Rollback Procedure

1. **Disable credentials management** in configuration
2. **Ensure kubeconfig file exists** at expected location
3. **Restart application**: Will use traditional kubeconfig loading

## Monitoring and Logging

### Log Events
- Credential store initialization
- Credential rotation attempts and results
- Authentication failures
- Expiration warnings

### Metrics
- Credential rotation frequency
- Authentication success/failure rates
- Storage operation latencies

## Troubleshooting

### Common Issues

1. **"Master password not set"**
   - Ensure `TRUVA_MASTER_PASSWORD` environment variable is set
   - Check configuration file for master_password field

2. **"Failed to decrypt credential"**
   - Verify master password is correct
   - Check if credential file is corrupted
   - Ensure proper file permissions

3. **"Credential expired"**
   - Check credential expiration with `./truva credentials list`
   - Rotate credentials manually if auto-rotation failed
   - Verify kubeconfig file is accessible for rotation

4. **"Failed to connect to Kubernetes cluster"**
   - Validate stored credentials: Check if kubeconfig is still valid
   - Test connection with kubectl using same kubeconfig
   - Check network connectivity to cluster

### Debug Mode

Enable debug logging to troubleshoot credential operations:

```yaml
logging:
  level: debug
```

## Performance Considerations

- **Encryption Overhead**: Minimal impact on application startup
- **Memory Usage**: Credentials decrypted on-demand
- **Storage**: Encrypted files ~30% larger than plaintext
- **CPU**: PBKDF2 iterations add ~100ms to operations

## Compliance

This implementation helps meet various security standards:

- **SOC 2**: Encryption of sensitive data at rest
- **ISO 27001**: Access control and data protection
- **PCI DSS**: Secure storage of authentication credentials
- **GDPR**: Data protection through encryption

## Future Enhancements

- **Hardware Security Module (HSM)** integration
- **Key rotation** for master passwords
- **Multi-factor authentication** for credential access
- **Audit logging** with tamper-proof storage
- **Integration** with external secret management systems