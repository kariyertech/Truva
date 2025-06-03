package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/utils"
)

// TLSManager handles TLS certificate management
type TLSManager struct {
	config *config.TLSConfig
}

// NewTLSManager creates a new TLS manager
func NewTLSManager(tlsConfig *config.TLSConfig) *TLSManager {
	return &TLSManager{
		config: tlsConfig,
	}
}

// GetTLSConfig returns the TLS configuration for the HTTP server
func (tm *TLSManager) GetTLSConfig() (*tls.Config, error) {
	if !tm.config.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(tm.config.CertFile, tm.config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Parse minimum TLS version
	minVersion, err := tm.parseTLSVersion(tm.config.MinTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid minimum TLS version: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   tls.VersionTLS13,
		// Security-focused cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Prefer server cipher suites
		PreferServerCipherSuites: true,
		// Enable HTTP/2
		NextProtos: []string{"h2", "http/1.1"},
	}

	return tlsConfig, nil
}

// parseTLSVersion converts string version to TLS constant
func (tm *TLSManager) parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// EnsureCertificates checks if certificates exist and creates self-signed ones if needed
func (tm *TLSManager) EnsureCertificates() error {
	if !tm.config.Enabled {
		return nil
	}

	// Check if certificates already exist
	if tm.certificatesExist() {
		utils.Logger.Info("TLS certificates already exist")
		return nil
	}

	if tm.config.AutoTLS {
		utils.Logger.Info("Generating self-signed TLS certificates")
		return tm.generateSelfSignedCertificate()
	}

	return fmt.Errorf("TLS certificates not found and auto-TLS is disabled. Please provide certificates at %s and %s", tm.config.CertFile, tm.config.KeyFile)
}

// certificatesExist checks if both certificate and key files exist
func (tm *TLSManager) certificatesExist() bool {
	_, certErr := os.Stat(tm.config.CertFile)
	_, keyErr := os.Stat(tm.config.KeyFile)
	return certErr == nil && keyErr == nil
}

// generateSelfSignedCertificate creates a self-signed certificate for development
func (tm *TLSManager) generateSelfSignedCertificate() error {
	// Create certificates directory if it doesn't exist
	certDir := filepath.Dir(tm.config.CertFile)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Truva Development"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost", "*.localhost"},
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(tm.config.CertFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(tm.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	// Set restrictive permissions on private key
	if err := keyOut.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	utils.Logger.Info(fmt.Sprintf("Self-signed certificate generated: %s", tm.config.CertFile))
	utils.Logger.Info(fmt.Sprintf("Private key generated: %s", tm.config.KeyFile))
	utils.Logger.Warn("Self-signed certificates are for development only. Use proper certificates in production.")

	return nil
}

// ValidateCertificates checks if the certificates are valid and not expired
func (tm *TLSManager) ValidateCertificates() error {
	if !tm.config.Enabled {
		return nil
	}

	// Load certificate
	certPEM, err := os.ReadFile(tm.config.CertFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %v)", cert.NotAfter)
	}

	// Warn if certificate expires soon (within 30 days)
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		utils.Logger.Warn(fmt.Sprintf("Certificate will expire soon: %v", cert.NotAfter))
	}

	utils.Logger.Info(fmt.Sprintf("Certificate is valid until: %v", cert.NotAfter))
	return nil
}

// GetCertificateInfo returns information about the current certificate
func (tm *TLSManager) GetCertificateInfo() (map[string]interface{}, error) {
	if !tm.config.Enabled {
		return map[string]interface{}{"enabled": false}, nil
	}

	certPEM, err := os.ReadFile(tm.config.CertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return map[string]interface{}{
		"enabled":       true,
		"subject":       cert.Subject.String(),
		"issuer":        cert.Issuer.String(),
		"not_before":    cert.NotBefore,
		"not_after":     cert.NotAfter,
		"dns_names":     cert.DNSNames,
		"ip_addresses":  cert.IPAddresses,
		"serial_number": cert.SerialNumber.String(),
	}, nil
}
