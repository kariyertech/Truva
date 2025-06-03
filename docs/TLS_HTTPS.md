# TLS/HTTPS Security Implementation

This document describes the TLS/HTTPS security implementation for Truva, addressing the SEC-005 security vulnerability by providing secure communication channels.

## Overview

The TLS/HTTPS implementation provides:
- **Secure Communication**: All web traffic encrypted using TLS 1.2+ protocols
- **Certificate Management**: Automated certificate generation and validation
- **Flexible Configuration**: Support for both development and production scenarios
- **HTTP to HTTPS Redirection**: Automatic redirection for enhanced security
- **Certificate Monitoring**: Expiration warnings and validation checks

## Architecture

### Components

1. **TLS Manager** (`pkg/tls/tls.go`)
   - Certificate generation and validation
   - TLS configuration management
   - Security policy enforcement

2. **Enhanced Web Server** (`internal/ui/web.go`)
   - Dual HTTP/HTTPS server support
   - Automatic redirection logic
   - Graceful shutdown handling

3. **Configuration System** (`pkg/config/config.go`)
   - TLS-specific configuration options
   - Environment-based settings
   - Security defaults

4. **CLI Tools** (`cmd/tls.go`)
   - Certificate management commands
   - Validation and monitoring tools
   - Development utilities

### Security Features

#### Encryption Standards
- **TLS Versions**: Support for TLS 1.2 and 1.3
- **Cipher Suites**: Modern, secure cipher suites only
- **Key Exchange**: ECDHE for perfect forward secrecy
- **Certificate Validation**: Comprehensive validation checks

#### Certificate Management
- **Auto-Generation**: Self-signed certificates for development
- **Validation**: Expiration and integrity checks
- **Monitoring**: Proactive expiration warnings
- **Flexible Paths**: Configurable certificate locations

## Configuration

### Configuration File

Add TLS configuration to your `config.yaml`:

```yaml
server:
  port: 8080
  host: "localhost"
  tls:
    enabled: true                    # Enable TLS/HTTPS
    cert_file: "./certs/server.crt"   # Certificate file path
    key_file: "./certs/server.key"    # Private key file path
    auto_tls: true                    # Auto-generate certificates
    https_port: 8443                  # HTTPS port
    redirect_http: true               # Redirect HTTP to HTTPS
    min_tls_version: "1.2"           # Minimum TLS version
```

### Environment Variables

```bash
# TLS Configuration
export TRUVA_SERVER_TLS_ENABLED=true
export TRUVA_SERVER_TLS_CERT_FILE="/path/to/cert.pem"
export TRUVA_SERVER_TLS_KEY_FILE="/path/to/key.pem"
export TRUVA_SERVER_TLS_AUTO_TLS=true
export TRUVA_SERVER_TLS_HTTPS_PORT=8443
export TRUVA_SERVER_TLS_REDIRECT_HTTP=true
export TRUVA_SERVER_TLS_MIN_TLS_VERSION="1.2"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable TLS/HTTPS support |
| `cert_file` | string | `"./certs/server.crt"` | Path to TLS certificate |
| `key_file` | string | `"./certs/server.key"` | Path to private key |
| `auto_tls` | bool | `false` | Auto-generate self-signed certificates |
| `https_port` | int | `8443` | HTTPS server port |
| `redirect_http` | bool | `true` | Redirect HTTP to HTTPS |
| `min_tls_version` | string | `"1.2"` | Minimum TLS version (1.0, 1.1, 1.2, 1.3) |

## Usage

### Development Setup

1. **Enable TLS with Auto-Generation**:
   ```yaml
   server:
     tls:
       enabled: true
       auto_tls: true
   ```

2. **Generate Certificates**:
   ```bash
   ./truva tls generate
   ```

3. **Start Server**:
   ```bash
   ./truva server
   ```

4. **Access Application**:
   - HTTPS: `https://localhost:8443`
   - HTTP: `http://localhost:8080` (redirects to HTTPS)

### Production Setup

1. **Obtain Valid Certificates**:
   - From a trusted Certificate Authority (CA)
   - Using Let's Encrypt
   - From your organization's PKI

2. **Configure Certificate Paths**:
   ```yaml
   server:
     tls:
       enabled: true
       cert_file: "/etc/ssl/certs/truva.crt"
       key_file: "/etc/ssl/private/truva.key"
       auto_tls: false
       redirect_http: true
   ```

3. **Set Secure Permissions**:
   ```bash
   chmod 644 /etc/ssl/certs/truva.crt
   chmod 600 /etc/ssl/private/truva.key
   chown truva:truva /etc/ssl/private/truva.key
   ```

### CLI Commands

#### Generate Self-Signed Certificates
```bash
./truva tls generate
```

#### Validate Certificates
```bash
./truva tls validate
```

#### View Certificate Information
```bash
./truva tls info
./truva tls info --json  # JSON output
```

#### Check Certificate Expiration
```bash
./truva tls check
```

### Programmatic Usage

```go
package main

import (
    "github.com/truva/pkg/config"
    "github.com/truva/pkg/tls"
)

func main() {
    cfg := config.GetConfig()
    tlsManager := tls.NewTLSManager(&cfg.Server.TLS)
    
    // Ensure certificates exist
    if err := tlsManager.EnsureCertificates(); err != nil {
        panic(err)
    }
    
    // Get TLS configuration
    tlsConfig, err := tlsManager.GetTLSConfig()
    if err != nil {
        panic(err)
    }
    
    // Use with HTTP server
    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }
    
    server.ListenAndServeTLS("", "")
}
```

## Security Considerations

### Best Practices

1. **Certificate Management**:
   - Use certificates from trusted CAs in production
   - Implement certificate rotation procedures
   - Monitor certificate expiration dates
   - Store private keys securely with restricted permissions

2. **TLS Configuration**:
   - Use TLS 1.2 or higher
   - Disable weak cipher suites
   - Enable perfect forward secrecy
   - Implement HSTS headers

3. **Operational Security**:
   - Regular certificate validation
   - Automated expiration monitoring
   - Secure key storage and backup
   - Access logging and monitoring

### Threat Model

#### Threats Addressed
- **Man-in-the-Middle Attacks**: TLS encryption prevents eavesdropping
- **Data Interception**: All communication encrypted in transit
- **Session Hijacking**: Secure session management with HTTPS
- **Credential Theft**: Protected authentication flows

#### Remaining Considerations
- **Certificate Pinning**: Consider implementing for enhanced security
- **HSTS**: Implement HTTP Strict Transport Security headers
- **Certificate Transparency**: Monitor CT logs for unauthorized certificates

## Monitoring and Logging

### Certificate Monitoring

```bash
# Check certificate status
./truva tls check

# Get detailed information
./truva tls info --json | jq '.not_after'
```

### Log Messages

- Certificate generation events
- Validation failures and warnings
- Expiration warnings (30 days before)
- TLS handshake errors
- Server startup and shutdown events

### Health Checks

```bash
# Certificate health check
curl -k https://localhost:8443/health

# Certificate expiration check
./truva tls check && echo "Certificates OK" || echo "Certificate issues detected"
```

## Troubleshooting

### Common Issues

#### Certificate Not Found
```
Error: failed to load TLS certificate: open ./certs/server.crt: no such file or directory
```
**Solution**: Generate certificates or check file paths
```bash
./truva tls generate
```

#### Permission Denied
```
Error: failed to read certificate file: permission denied
```
**Solution**: Check file permissions
```bash
chmod 644 /path/to/cert.crt
chmod 600 /path/to/key.key
```

#### Certificate Expired
```
Error: certificate has expired
```
**Solution**: Renew or regenerate certificates
```bash
./truva tls generate  # For development
# Or obtain new certificates from CA for production
```

#### TLS Handshake Failures
```
Error: tls: handshake failure
```
**Solution**: Check TLS version compatibility and cipher suites

### Debug Commands

```bash
# Test TLS connection
openssl s_client -connect localhost:8443 -servername localhost

# Check certificate details
openssl x509 -in ./certs/server.crt -text -noout

# Verify certificate and key match
openssl x509 -noout -modulus -in ./certs/server.crt | openssl md5
openssl rsa -noout -modulus -in ./certs/server.key | openssl md5
```

## Performance Considerations

### TLS Performance
- **CPU Overhead**: TLS adds ~1-3% CPU overhead
- **Memory Usage**: Minimal impact on memory consumption
- **Latency**: Additional ~1-2ms for TLS handshake
- **Throughput**: Negligible impact on data transfer rates

### Optimization Tips
- Use TLS 1.3 for improved performance
- Enable HTTP/2 for multiplexing benefits
- Implement session resumption
- Use hardware acceleration when available

## Compliance

### Standards Compliance
- **PCI DSS**: TLS 1.2+ requirement satisfied
- **HIPAA**: Encryption in transit requirement met
- **SOC 2**: Security controls for data transmission
- **GDPR**: Data protection in transit compliance

### Audit Requirements
- Certificate validation logs
- TLS configuration documentation
- Security policy compliance
- Regular security assessments

## Migration Guide

### From HTTP to HTTPS

1. **Phase 1**: Enable TLS alongside HTTP
   ```yaml
   server:
     tls:
       enabled: true
       redirect_http: false  # Allow both protocols
   ```

2. **Phase 2**: Test HTTPS functionality
   ```bash
   curl -k https://localhost:8443/health
   ```

3. **Phase 3**: Enable HTTP redirection
   ```yaml
   server:
     tls:
       redirect_http: true
   ```

4. **Phase 4**: Update client configurations
   - Update URLs to use HTTPS
   - Update API endpoints
   - Update documentation

### Rollback Procedure

1. **Disable TLS**:
   ```yaml
   server:
     tls:
       enabled: false
   ```

2. **Restart Service**:
   ```bash
   systemctl restart truva
   ```

3. **Verify HTTP Access**:
   ```bash
   curl http://localhost:8080/health
   ```

## Future Enhancements

### Planned Features
- **Certificate Auto-Renewal**: Integration with Let's Encrypt
- **Certificate Pinning**: Enhanced security for known certificates
- **HSTS Support**: HTTP Strict Transport Security headers
- **Certificate Transparency**: CT log monitoring
- **mTLS Support**: Mutual TLS authentication

### Integration Opportunities
- **Service Mesh**: Integration with Istio/Linkerd
- **Load Balancers**: TLS termination at load balancer
- **CDN Integration**: TLS offloading to CDN providers
- **Monitoring**: Integration with Prometheus/Grafana

## Conclusion

The TLS/HTTPS implementation provides comprehensive security for Truva's web communications, addressing the SEC-005 vulnerability with:

- ✅ **Secure Communication**: TLS 1.2+ encryption
- ✅ **Certificate Management**: Automated generation and validation
- ✅ **Flexible Configuration**: Development and production support
- ✅ **Monitoring Tools**: Expiration and health checks
- ✅ **CLI Management**: Complete certificate lifecycle tools

The implementation is production-ready and follows security best practices while maintaining ease of use for development environments.