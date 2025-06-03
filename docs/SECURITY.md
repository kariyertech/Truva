# Security Guide

This document provides comprehensive security guidelines, best practices, and procedures for the Truva Kubernetes monitoring application.

## Table of Contents

- [Security Overview](#security-overview)
- [Threat Model](#threat-model)
- [Authentication and Authorization](#authentication-and-authorization)
- [Network Security](#network-security)
- [Container Security](#container-security)
- [Data Protection](#data-protection)
- [Secrets Management](#secrets-management)
- [Monitoring and Logging](#monitoring-and-logging)
- [Incident Response](#incident-response)
- [Security Testing](#security-testing)
- [Compliance](#compliance)
- [Security Checklist](#security-checklist)

## Security Overview

### Security Principles

Truva follows these core security principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Principle of Least Privilege**: Minimal necessary permissions
3. **Zero Trust**: Never trust, always verify
4. **Security by Design**: Security built into the architecture
5. **Continuous Monitoring**: Real-time security monitoring

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet/External Users                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Load Balancer/WAF                          │
│                 - DDoS Protection                          │
│                 - SSL Termination                          │
│                 - Rate Limiting                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Ingress Controller                         │
│                 - TLS Encryption                           │
│                 - Authentication                           │
│                 - Authorization                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Truva Application                          │
│                 - RBAC                                     │
│                 - Input Validation                         │
│                 - Secure Coding                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Kubernetes API                             │
│                 - Service Account                          │
│                 - Network Policies                         │
│                 - Pod Security Standards                   │
└─────────────────────────────────────────────────────────────┘
```

## Threat Model

### Assets

1. **Kubernetes Cluster Data**
   - Pod information
   - Service configurations
   - Deployment details
   - Resource metrics

2. **Application Infrastructure**
   - Truva application
   - Configuration data
   - Log data
   - Metrics data

3. **Credentials and Secrets**
   - API keys
   - JWT tokens
   - Database passwords
   - TLS certificates

### Threat Actors

1. **External Attackers**
   - Malicious hackers
   - Automated bots
   - Nation-state actors

2. **Internal Threats**
   - Malicious insiders
   - Compromised accounts
   - Accidental misuse

3. **Supply Chain Threats**
   - Compromised dependencies
   - Malicious container images
   - Third-party vulnerabilities

### Attack Vectors

1. **Network-based Attacks**
   - DDoS attacks
   - Man-in-the-middle
   - Network sniffing

2. **Application-level Attacks**
   - SQL injection
   - Cross-site scripting (XSS)
   - Command injection
   - Authentication bypass

3. **Infrastructure Attacks**
   - Container escape
   - Privilege escalation
   - Kubernetes API abuse

4. **Social Engineering**
   - Phishing attacks
   - Credential theft
   - Insider threats

### Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk Level | Mitigation Priority |
|--------|------------|--------|------------|--------------------|
| DDoS Attack | High | Medium | High | High |
| SQL Injection | Medium | High | High | High |
| Container Escape | Low | High | Medium | Medium |
| Credential Theft | Medium | High | High | High |
| Data Breach | Low | Critical | High | High |
| Insider Threat | Low | High | Medium | Medium |

## Authentication and Authorization

### Authentication Methods

#### 1. JWT Token Authentication

```yaml
# JWT configuration
apiVersion: v1
kind: Secret
metadata:
  name: jwt-secret
  namespace: truva
type: Opaque
data:
  secret: <base64-encoded-jwt-secret>
```

**Implementation:**
```go
// JWT token validation
func validateJWTToken(tokenString string) (*jwt.Claims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return jwtSecret, nil
    })
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return &claims, nil
    }
    
    return nil, err
}
```

#### 2. Kubernetes Service Account Authentication

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: truva
  namespace: truva
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: truva-reader
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods", "nodes"]
  verbs: ["get", "list"]
```

### Authorization Framework

#### Role-Based Access Control (RBAC)

```yaml
# User roles definition
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: truva
  name: truva-admin
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: truva
  name: truva-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: truva
  name: truva-operator
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "patch"]
```

#### Attribute-Based Access Control (ABAC)

```go
// ABAC policy example
type AccessPolicy struct {
    Subject   string            `json:"subject"`
    Resource  string            `json:"resource"`
    Action    string            `json:"action"`
    Condition map[string]string `json:"condition"`
}

func evaluatePolicy(policy AccessPolicy, request AccessRequest) bool {
    // Check subject
    if policy.Subject != "*" && policy.Subject != request.Subject {
        return false
    }
    
    // Check resource
    if policy.Resource != "*" && !matchResource(policy.Resource, request.Resource) {
        return false
    }
    
    // Check action
    if policy.Action != "*" && policy.Action != request.Action {
        return false
    }
    
    // Check conditions
    for key, value := range policy.Condition {
        if request.Context[key] != value {
            return false
        }
    }
    
    return true
}
```

### Multi-Factor Authentication (MFA)

```yaml
# MFA configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: truva
data:
  mfa_enabled: "true"
  mfa_issuer: "Truva"
  mfa_algorithm: "SHA1"
  mfa_digits: "6"
  mfa_period: "30"
```

## Network Security

### Network Policies

#### Default Deny Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: truva
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

#### Application-Specific Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: truva-network-policy
  namespace: truva
spec:
  podSelector:
    matchLabels:
      app: truva
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 6443 # Kubernetes API
    - protocol: UDP
      port: 53   # DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 443
```

### TLS/SSL Configuration

#### Certificate Management

```yaml
# cert-manager certificate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: truva-tls
  namespace: truva
spec:
  secretName: truva-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - truva.example.com
  - api.truva.example.com
```

#### TLS Configuration

```yaml
# Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: truva-ingress
  namespace: truva
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384"
spec:
  tls:
  - hosts:
    - truva.example.com
    secretName: truva-tls-secret
  rules:
  - host: truva.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: truva
            port:
              number: 8080
```

### Service Mesh Security

#### Istio Configuration

```yaml
# Istio PeerAuthentication
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: truva
spec:
  mtls:
    mode: STRICT
---
# Istio AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: truva-authz
  namespace: truva
spec:
  selector:
    matchLabels:
      app: truva
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/ingress-nginx/sa/ingress-nginx"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*", "/health", "/metrics"]
```

## Container Security

### Pod Security Standards

#### Pod Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: truva
  namespace: truva
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
        supplementalGroups: [1000]
      containers:
      - name: truva
        image: truva:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: var-run
          mountPath: /var/run
      volumes:
      - name: tmp
        emptyDir: {}
      - name: var-run
        emptyDir: {}
```

#### Pod Security Policy (Deprecated) / Pod Security Standards

```yaml
# Pod Security Standards via namespace labels
apiVersion: v1
kind: Namespace
metadata:
  name: truva
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Image Security

#### Dockerfile Security Best Practices

```dockerfile
# Multi-stage build for security
FROM golang:1.19-alpine AS builder

# Create non-root user
RUN adduser -D -s /bin/sh -u 1000 appuser

# Install security updates
RUN apk update && apk upgrade && apk add --no-cache ca-certificates git

# Set working directory
WORKDIR /app

# Copy and build application
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o truva .

# Final stage
FROM scratch

# Import CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import user
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /app/truva /truva

# Use non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["./truva", "health"]

# Run application
ENTRYPOINT ["/truva"]
```

#### Image Scanning

```yaml
# Trivy image scanning
apiVersion: batch/v1
kind: Job
metadata:
  name: image-scan
  namespace: truva
spec:
  template:
    spec:
      containers:
      - name: trivy
        image: aquasec/trivy:latest
        command:
        - trivy
        - image
        - --exit-code
        - "1"
        - --severity
        - "HIGH,CRITICAL"
        - truva:latest
      restartPolicy: Never
```

### Runtime Security

#### Falco Rules

```yaml
# Falco custom rules for Truva
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco
data:
  truva_rules.yaml: |
    - rule: Truva Suspicious Network Activity
      desc: Detect suspicious network activity in Truva pods
      condition: >
        (k8s_audit and ka.verb in (create, update, patch) and
         ka.target.resource=networkpolicies and
         ka.target.namespace=truva)
      output: >
        Suspicious network policy change in Truva namespace
        (user=%ka.user.name verb=%ka.verb resource=%ka.target.resource)
      priority: WARNING
      tags: [network, k8s_audit, truva]
    
    - rule: Truva Privilege Escalation
      desc: Detect privilege escalation attempts in Truva
      condition: >
        spawned_process and container.image.repository="truva" and
        (proc.name in (su, sudo, setuid) or
         proc.args contains "--privileged")
      output: >
        Privilege escalation attempt in Truva container
        (user=%user.name command=%proc.cmdline container=%container.id)
      priority: CRITICAL
      tags: [privilege_escalation, truva]
```

## Data Protection

### Data Classification

| Data Type | Classification | Protection Level | Retention |
|-----------|----------------|------------------|----------|
| Kubernetes Metadata | Internal | Medium | 90 days |
| Application Logs | Internal | Medium | 30 days |
| Metrics Data | Internal | Low | 7 days |
| User Credentials | Confidential | High | N/A |
| API Keys | Confidential | High | N/A |
| TLS Certificates | Confidential | High | Certificate lifetime |

### Encryption

#### Encryption at Rest

```yaml
# StorageClass with encryption
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: encrypted-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  encrypted: "true"
  kmsKeyId: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

#### Encryption in Transit

```go
// TLS configuration for HTTP server
func createTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }
}
```

### Data Loss Prevention (DLP)

```go
// Sensitive data detection and masking
func maskSensitiveData(data string) string {
    // Mask credit card numbers
    ccRegex := regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)
    data = ccRegex.ReplaceAllString(data, "****-****-****-****")
    
    // Mask email addresses
    emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
    data = emailRegex.ReplaceAllString(data, "***@***.***")
    
    // Mask API keys
    apiKeyRegex := regexp.MustCompile(`\b[A-Za-z0-9]{32,}\b`)
    data = apiKeyRegex.ReplaceAllString(data, "[REDACTED]")
    
    return data
}
```

## Secrets Management

### Kubernetes Secrets

#### Secret Creation and Management

```bash
# Create secrets securely
kubectl create secret generic truva-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=api-key=$(openssl rand -hex 16) \
  --namespace=truva

# Encrypt secrets at rest
kubectl patch secret truva-secrets -n truva -p '{
  "metadata": {
    "annotations": {
      "encryption.kubernetes.io/provider": "aescbc"
    }
  }
}'
```

#### External Secrets Operator

```yaml
# External secret from AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: truva
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        secretRef:
          accessKeyID:
            name: aws-credentials
            key: access-key-id
          secretAccessKey:
            name: aws-credentials
            key: secret-access-key
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: truva-external-secret
  namespace: truva
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: truva-secrets
    creationPolicy: Owner
  data:
  - secretKey: jwt-secret
    remoteRef:
      key: truva/jwt-secret
  - secretKey: api-key
    remoteRef:
      key: truva/api-key
```

### HashiCorp Vault Integration

```yaml
# Vault Agent injector
apiVersion: apps/v1
kind: Deployment
metadata:
  name: truva
  namespace: truva
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "truva"
        vault.hashicorp.com/agent-inject-secret-config: "secret/truva/config"
        vault.hashicorp.com/agent-inject-template-config: |
          {{- with secret "secret/truva/config" -}}
          JWT_SECRET={{ .Data.data.jwt_secret }}
          API_KEY={{ .Data.data.api_key }}
          {{- end }}
    spec:
      serviceAccountName: truva
      containers:
      - name: truva
        image: truva:latest
        env:
        - name: VAULT_SECRETS_PATH
          value: "/vault/secrets/config"
```

## Monitoring and Logging

### Security Monitoring

#### Prometheus Security Metrics

```yaml
# Security-focused metrics
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-security-rules
  namespace: monitoring
data:
  security.rules: |
    groups:
    - name: security.rules
      rules:
      - alert: HighFailedAuthenticationRate
        expr: rate(http_requests_total{status="401"}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High failed authentication rate detected"
          description: "Failed authentication rate is {{ $value }} requests/second"
      
      - alert: SuspiciousNetworkActivity
        expr: rate(container_network_transmit_bytes_total[5m]) > 100000000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Suspicious network activity detected"
          description: "High network transmission rate: {{ $value }} bytes/second"
      
      - alert: UnauthorizedAPIAccess
        expr: rate(http_requests_total{status="403"}[5m]) > 0.05
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Unauthorized API access attempts"
          description: "Forbidden requests rate: {{ $value }} requests/second"
```

#### Security Event Logging

```go
// Security event logging
type SecurityEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    EventType   string    `json:"event_type"`
    Severity    string    `json:"severity"`
    Source      string    `json:"source"`
    User        string    `json:"user"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    Result      string    `json:"result"`
    Details     string    `json:"details"`
    RemoteIP    string    `json:"remote_ip"`
    UserAgent   string    `json:"user_agent"`
}

func logSecurityEvent(event SecurityEvent) {
    eventJSON, _ := json.Marshal(event)
    log.Printf("SECURITY_EVENT: %s", string(eventJSON))
    
    // Send to SIEM if configured
    if siemEnabled {
        sendToSIEM(event)
    }
}

// Usage example
func handleAuthenticationFailure(username, remoteIP string) {
    logSecurityEvent(SecurityEvent{
        Timestamp: time.Now(),
        EventType: "authentication_failure",
        Severity:  "medium",
        Source:    "truva-api",
        User:      username,
        Action:    "login",
        Resource:  "/api/login",
        Result:    "failure",
        Details:   "Invalid credentials provided",
        RemoteIP:  remoteIP,
    })
}
```

### Audit Logging

#### Kubernetes Audit Policy

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all requests to Truva namespace
- level: RequestResponse
  namespaces: ["truva"]
  resources:
  - group: ""
    resources: ["*"]
  - group: "apps"
    resources: ["*"]

# Log security-related events
- level: Metadata
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["*"]
  - group: "networking.k8s.io"
    resources: ["networkpolicies"]

# Log secret access
- level: Request
  resources:
  - group: ""
    resources: ["secrets"]
  namespaces: ["truva"]
```

## Incident Response

### Incident Classification

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| Critical | Data breach, system compromise | 15 minutes | Immediate |
| High | Service disruption, security vulnerability | 1 hour | 2 hours |
| Medium | Performance degradation, minor security issue | 4 hours | 8 hours |
| Low | Cosmetic issues, informational alerts | 24 hours | 48 hours |

### Incident Response Playbook

#### 1. Detection and Analysis

```bash
#!/bin/bash
# incident-detection.sh

echo "=== Security Incident Detection ==="
echo "Timestamp: $(date)"

# Check for suspicious activities
echo "1. Checking failed authentication attempts..."
kubectl logs -n truva -l app=truva | grep "401\|authentication failed" | tail -20

echo "2. Checking unauthorized access attempts..."
kubectl logs -n truva -l app=truva | grep "403\|forbidden" | tail -20

echo "3. Checking for privilege escalation..."
kubectl get events -n truva | grep -i "privilege\|escalation\|root"

echo "4. Checking network policies..."
kubectl get networkpolicy -n truva

echo "5. Checking pod security context..."
kubectl get pods -n truva -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'
```

#### 2. Containment

```bash
#!/bin/bash
# incident-containment.sh

NAMESPACE="truva"
INCIDENT_TYPE="$1"

case $INCIDENT_TYPE in
    "data_breach")
        echo "Implementing data breach containment..."
        # Block all external traffic
        kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-deny-all
  namespace: $NAMESPACE
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
        ;;
    "compromised_pod")
        echo "Isolating compromised pod..."
        # Scale down deployment
        kubectl scale deployment truva --replicas=0 -n $NAMESPACE
        # Create forensic copy
        kubectl get pod -n $NAMESPACE -o yaml > compromised-pod-$(date +%Y%m%d_%H%M%S).yaml
        ;;
    "privilege_escalation")
        echo "Containing privilege escalation..."
        # Remove privileged access
        kubectl patch deployment truva -n $NAMESPACE -p '{
          "spec": {
            "template": {
              "spec": {
                "securityContext": {
                  "runAsNonRoot": true,
                  "runAsUser": 1000
                }
              }
            }
          }
        }'
        ;;
esac
```

#### 3. Eradication and Recovery

```bash
#!/bin/bash
# incident-recovery.sh

echo "=== Incident Recovery Process ==="

# 1. Update all secrets
echo "1. Rotating secrets..."
kubectl delete secret truva-secrets -n truva
kubectl create secret generic truva-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=api-key=$(openssl rand -hex 16) \
  --namespace=truva

# 2. Update container images
echo "2. Updating container images..."
kubectl set image deployment/truva truva=truva:latest-secure -n truva

# 3. Restart all pods
echo "3. Restarting all pods..."
kubectl rollout restart deployment/truva -n truva

# 4. Verify security configuration
echo "4. Verifying security configuration..."
kubectl get pods -n truva -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsNonRoot}{"\n"}{end}'

# 5. Re-enable network access gradually
echo "5. Restoring network access..."
kubectl delete networkpolicy emergency-deny-all -n truva
kubectl apply -f k8s/networkpolicy.yaml

echo "Recovery completed. Monitor for 24 hours."
```

### Post-Incident Activities

1. **Forensic Analysis**
   - Collect and analyze logs
   - Identify root cause
   - Document timeline

2. **Lessons Learned**
   - Conduct post-incident review
   - Update security procedures
   - Improve monitoring and detection

3. **Communication**
   - Notify stakeholders
   - Update security team
   - Document incident report

## Security Testing

### Automated Security Testing

#### SAST (Static Application Security Testing)

```yaml
# GitHub Actions security workflow
name: Security Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Gosec Security Scanner
      uses: securecodewarrior/github-action-gosec@master
      with:
        args: '-fmt sarif -out gosec.sarif ./...'
    
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: gosec.sarif
```

#### DAST (Dynamic Application Security Testing)

```yaml
# OWASP ZAP scanning
apiVersion: batch/v1
kind: Job
metadata:
  name: zap-scan
  namespace: truva
spec:
  template:
    spec:
      containers:
      - name: zap
        image: owasp/zap2docker-stable:latest
        command:
        - zap-baseline.py
        - -t
        - http://truva:8080
        - -J
        - zap-report.json
        volumeMounts:
        - name: zap-reports
          mountPath: /zap/wrk
      volumes:
      - name: zap-reports
        emptyDir: {}
      restartPolicy: Never
```

### Penetration Testing

#### Automated Penetration Testing

```bash
#!/bin/bash
# automated-pentest.sh

TARGET_URL="https://truva.example.com"
REPORT_DIR="./pentest-reports/$(date +%Y%m%d_%H%M%S)"

mkdir -p $REPORT_DIR

echo "Starting automated penetration testing..."

# 1. Port scanning
echo "1. Port scanning..."
nmap -sS -O $TARGET_URL > $REPORT_DIR/nmap-scan.txt

# 2. Web application scanning
echo "2. Web application scanning..."
nukto -h $TARGET_URL -output $REPORT_DIR/nukto-scan.txt

# 3. SSL/TLS testing
echo "3. SSL/TLS testing..."
testssl.sh $TARGET_URL > $REPORT_DIR/ssl-test.txt

# 4. Directory enumeration
echo "4. Directory enumeration..."
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt -o $REPORT_DIR/gobuster.txt

# 5. SQL injection testing
echo "5. SQL injection testing..."
sqlmap -u "$TARGET_URL/api/search?q=test" --batch --report $REPORT_DIR/sqlmap.txt

echo "Penetration testing completed. Reports in $REPORT_DIR"
```

## Compliance

### Compliance Frameworks

#### SOC 2 Type II

**Security Controls:**

1. **Access Controls (CC6.1)**
   - Multi-factor authentication
   - Role-based access control
   - Regular access reviews

2. **System Operations (CC7.1)**
   - Change management procedures
   - System monitoring
   - Incident response

3. **Risk Assessment (CC3.1)**
   - Regular security assessments
   - Vulnerability management
   - Threat modeling

#### PCI DSS (if applicable)

**Requirements:**

1. **Build and Maintain Secure Networks**
   - Firewall configuration
   - Network segmentation
   - Secure protocols

2. **Protect Cardholder Data**
   - Data encryption
   - Access restrictions
   - Data retention policies

3. **Maintain Vulnerability Management**
   - Regular security updates
   - Vulnerability scanning
   - Penetration testing

#### GDPR (if applicable)

**Data Protection Measures:**

1. **Data Minimization**
   - Collect only necessary data
   - Regular data purging
   - Purpose limitation

2. **Security Measures**
   - Encryption at rest and in transit
   - Access controls
   - Audit logging

3. **Data Subject Rights**
   - Right to access
   - Right to rectification
   - Right to erasure

### Compliance Monitoring

```yaml
# Compliance monitoring dashboard
apiVersion: v1
kind: ConfigMap
metadata:
  name: compliance-dashboard
  namespace: monitoring
data:
  dashboard.json: |
    {
      "dashboard": {
        "title": "Security Compliance Dashboard",
        "panels": [
          {
            "title": "Failed Authentication Attempts",
            "type": "stat",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{status=\"401\"}[24h]))"
              }
            ]
          },
          {
            "title": "Unauthorized Access Attempts",
            "type": "stat",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{status=\"403\"}[24h]))"
              }
            ]
          },
          {
            "title": "Security Events",
            "type": "logs",
            "targets": [
              {
                "expr": "{namespace=\"truva\"} |= \"SECURITY_EVENT\""
              }
            ]
          }
        ]
      }
    }
```

## Security Checklist

### Pre-Deployment Security Checklist

- [ ] **Authentication and Authorization**
  - [ ] JWT tokens properly configured
  - [ ] RBAC policies implemented
  - [ ] Service accounts configured with minimal permissions
  - [ ] Multi-factor authentication enabled

- [ ] **Network Security**
  - [ ] Network policies implemented
  - [ ] TLS/SSL certificates configured
  - [ ] Ingress security headers set
  - [ ] Service mesh security enabled (if applicable)

- [ ] **Container Security**
  - [ ] Pod security standards enforced
  - [ ] Container images scanned for vulnerabilities
  - [ ] Non-root user configured
  - [ ] Read-only root filesystem enabled
  - [ ] Security contexts properly set

- [ ] **Data Protection**
  - [ ] Encryption at rest enabled
  - [ ] Encryption in transit configured
  - [ ] Sensitive data properly masked
  - [ ] Data retention policies implemented

- [ ] **Secrets Management**
  - [ ] Kubernetes secrets encrypted
  - [ ] External secrets manager integrated (if applicable)
  - [ ] Secret rotation procedures in place
  - [ ] No hardcoded secrets in code

- [ ] **Monitoring and Logging**
  - [ ] Security monitoring configured
  - [ ] Audit logging enabled
  - [ ] Security alerts configured
  - [ ] Log aggregation set up

- [ ] **Incident Response**
  - [ ] Incident response plan documented
  - [ ] Emergency procedures tested
  - [ ] Contact information updated
  - [ ] Backup and recovery procedures verified

### Runtime Security Checklist

- [ ] **Regular Security Tasks**
  - [ ] Security patches applied
  - [ ] Vulnerability scans performed
  - [ ] Access reviews conducted
  - [ ] Security metrics reviewed

- [ ] **Monitoring and Alerting**
  - [ ] Security alerts functioning
  - [ ] Log analysis performed
  - [ ] Anomaly detection active
  - [ ] Compliance monitoring in place

- [ ] **Incident Response**
  - [ ] Incident response procedures tested
  - [ ] Security team trained
  - [ ] Communication channels verified
  - [ ] Recovery procedures validated

### Post-Incident Security Checklist

- [ ] **Immediate Response**
  - [ ] Incident contained
  - [ ] Affected systems isolated
  - [ ] Evidence preserved
  - [ ] Stakeholders notified

- [ ] **Investigation and Recovery**
  - [ ] Root cause identified
  - [ ] Vulnerabilities patched
  - [ ] Systems restored
  - [ ] Security controls updated

- [ ] **Post-Incident Activities**
  - [ ] Incident report completed
  - [ ] Lessons learned documented
  - [ ] Procedures updated
  - [ ] Training conducted

## Security Contacts

- **Security Team**: security@truva.io
- **Incident Response**: incident@truva.io
- **Emergency Hotline**: +1-XXX-XXX-XXXX
- **Security Portal**: https://security.truva.io

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [SANS Security Policies](https://www.sans.org/information-security-policy/)

---

**Document Version**: 1.0  
**Last Updated**: 2024-12-19  
**Next Review**: 2025-03-19  
**Owner**: Security Team  
**Approved By**: CISO