# Production Deployment Guide

This guide provides comprehensive instructions for deploying and operating Truva in production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Infrastructure Requirements](#infrastructure-requirements)
- [Deployment Methods](#deployment-methods)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Monitoring and Observability](#monitoring-and-observability)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling](#scaling)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Kubernetes Cluster**: v1.20 or later
- **CPU**: Minimum 2 cores, Recommended 4+ cores
- **Memory**: Minimum 4GB RAM, Recommended 8GB+ RAM
- **Storage**: Minimum 20GB, Recommended 100GB+ for logs and metrics
- **Network**: Stable internet connection for image pulls and updates

### Required Tools

```bash
# Kubernetes CLI
kubectl version --client

# Helm (if using Helm deployment)
helm version

# Docker (for image management)
docker version

# Optional: Kustomize
kustomize version
```

### Access Requirements

- Kubernetes cluster admin access
- Container registry access (for custom images)
- DNS management access (for ingress configuration)
- Certificate management access (for TLS)

## Infrastructure Requirements

### Kubernetes Cluster

#### Minimum Cluster Configuration

```yaml
# Cluster specifications
nodes: 3
node_type: "Standard_D2s_v3" # Azure example
cpu_per_node: 2
memory_per_node: 8GB
storage_class: "managed-premium"
```

#### Required Kubernetes Features

- RBAC enabled
- Network policies support
- Persistent volume support
- Ingress controller
- DNS resolution
- Service mesh (optional but recommended)

### Storage Requirements

```yaml
# Storage classes needed
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: truva-storage
provisioner: kubernetes.io/azure-disk # Adjust for your cloud provider
parameters:
  storageaccounttype: Premium_LRS
  kind: Managed
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

### Network Configuration

```yaml
# Network policy example
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
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 6443
```

## Deployment Methods

### Method 1: Helm Deployment (Recommended)

#### 1. Add Helm Repository

```bash
# Add custom helm repository (if available)
helm repo add truva https://charts.truva.io
helm repo update
```

#### 2. Create Namespace

```bash
kubectl create namespace truva
kubectl label namespace truva name=truva
```

#### 3. Configure Values

```yaml
# values-production.yaml
replicaCount: 3

image:
  repository: truva/truva
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8080

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: truva.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: truva-tls
      hosts:
        - truva.yourdomain.com

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

persistence:
  enabled: true
  storageClass: "truva-storage"
  size: 50Gi

config:
  logLevel: "info"
  metricsEnabled: true
  tracingEnabled: true
  
security:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 2000
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    namespace: monitoring
```

#### 4. Deploy with Helm

```bash
# Install Truva
helm install truva truva/truva \
  --namespace truva \
  --values values-production.yaml \
  --wait --timeout 10m

# Verify deployment
helm status truva -n truva
kubectl get pods -n truva
```

### Method 2: Kustomize Deployment

#### 1. Prepare Kustomization

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: truva

resources:
  - base/

patchesStrategicMerge:
  - production-patches.yaml

images:
  - name: truva
    newTag: v1.0.0

configMapGenerator:
  - name: truva-config
    files:
      - config.yaml

secretGenerator:
  - name: truva-secrets
    files:
      - secrets.env
```

#### 2. Apply Kustomization

```bash
# Apply with kustomize
kubectl apply -k .

# Verify deployment
kubectl get all -n truva
```

### Method 3: Direct YAML Deployment

```bash
# Apply manifests directly
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

## Configuration

### Environment Variables

```yaml
# Production environment configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: truva-config
  namespace: truva
data:
  LOG_LEVEL: "info"
  METRICS_ENABLED: "true"
  TRACING_ENABLED: "true"
  KUBERNETES_NAMESPACE: "default"
  SERVER_PORT: "8080"
  UI_ENABLED: "true"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_REQUESTS: "100"
  RATE_LIMIT_WINDOW: "1m"
  SYNC_INTERVAL: "30s"
  LOG_AGGREGATION_ENABLED: "true"
  LOG_AGGREGATION_ENDPOINT: "http://signoz:4317"
```

### Secrets Management

```yaml
# Kubernetes secrets
apiVersion: v1
kind: Secret
metadata:
  name: truva-secrets
  namespace: truva
type: Opaque
data:
  # Base64 encoded values
  api-key: <base64-encoded-api-key>
  database-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-jwt-secret>
```

### Resource Limits

```yaml
# Resource configuration
resources:
  limits:
    cpu: "2"
    memory: "4Gi"
    ephemeral-storage: "10Gi"
  requests:
    cpu: "1"
    memory: "2Gi"
    ephemeral-storage: "5Gi"
```

## Security Considerations

### Pod Security Standards

```yaml
# Pod security context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 3000
  fsGroup: 2000
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### Network Security

```yaml
# Network policy for production
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
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 6443 # Kubernetes API
    - protocol: UDP
      port: 53   # DNS
```

### RBAC Configuration

```yaml
# Service account and RBAC
apiVersion: v1
kind: ServiceAccount
metadata:
  name: truva
  namespace: truva
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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: truva-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: truva-reader
subjects:
- kind: ServiceAccount
  name: truva
  namespace: truva
```

## Monitoring and Observability

### Prometheus Integration

```yaml
# ServiceMonitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: truva
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: truva
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Truva Production Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      }
    ]
  }
}
```

### Log Aggregation

```yaml
# Fluent Bit configuration for log collection
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf

    [INPUT]
        Name              tail
        Path              /var/log/containers/truva*.log
        Parser            docker
        Tag               truva.*
        Refresh_Interval  5

    [OUTPUT]
        Name  forward
        Match truva.*
        Host  signoz-otel-collector
        Port  24224
```

## Backup and Recovery

### Data Backup Strategy

```bash
#!/bin/bash
# backup-script.sh

NAMESPACE="truva"
BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup ConfigMaps
kubectl get configmaps -n $NAMESPACE -o yaml > $BACKUP_DIR/configmaps.yaml

# Backup Secrets (be careful with this)
kubectl get secrets -n $NAMESPACE -o yaml > $BACKUP_DIR/secrets.yaml

# Backup PersistentVolumeClaims
kubectl get pvc -n $NAMESPACE -o yaml > $BACKUP_DIR/pvc.yaml

# Backup application manifests
kubectl get deployment,service,ingress -n $NAMESPACE -o yaml > $BACKUP_DIR/manifests.yaml

echo "Backup completed: $BACKUP_DIR"
```

### Disaster Recovery Plan

1. **Immediate Response**
   - Assess the scope of the incident
   - Activate incident response team
   - Implement emergency procedures

2. **Recovery Steps**
   ```bash
   # Restore from backup
   kubectl apply -f $BACKUP_DIR/
   
   # Verify restoration
   kubectl get pods -n truva
   kubectl logs -n truva -l app=truva
   ```

3. **Post-Recovery**
   - Conduct post-incident review
   - Update documentation
   - Improve monitoring and alerting

## Scaling

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: truva-hpa
  namespace: truva
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: truva
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

### Vertical Pod Autoscaler

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: truva-vpa
  namespace: truva
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: truva
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: truva
      maxAllowed:
        cpu: 2
        memory: 4Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

## Maintenance

### Rolling Updates

```bash
# Update deployment image
kubectl set image deployment/truva truva=truva:v1.1.0 -n truva

# Monitor rollout
kubectl rollout status deployment/truva -n truva

# Rollback if needed
kubectl rollout undo deployment/truva -n truva
```

### Health Checks

```yaml
# Liveness and readiness probes
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

### Maintenance Windows

```bash
#!/bin/bash
# maintenance-window.sh

echo "Starting maintenance window..."

# Scale down to minimum replicas
kubectl scale deployment truva --replicas=1 -n truva

# Perform maintenance tasks
# - Update configurations
# - Apply patches
# - Database maintenance

# Scale back up
kubectl scale deployment truva --replicas=3 -n truva

echo "Maintenance window completed"
```

## Performance Optimization

### Resource Optimization

```yaml
# Optimized resource configuration
resources:
  limits:
    cpu: "1"
    memory: "2Gi"
    ephemeral-storage: "5Gi"
  requests:
    cpu: "500m"
    memory: "1Gi"
    ephemeral-storage: "2Gi"
```

### Caching Strategy

```yaml
# Redis cache configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-cache
  namespace: truva
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis-cache
  template:
    metadata:
      labels:
        app: redis-cache
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        resources:
          limits:
            cpu: 500m
            memory: 1Gi
          requests:
            cpu: 250m
            memory: 512Mi
```

## Troubleshooting

For detailed troubleshooting information, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).

### Quick Diagnostics

```bash
# Check pod status
kubectl get pods -n truva

# Check logs
kubectl logs -n truva -l app=truva --tail=100

# Check events
kubectl get events -n truva --sort-by='.lastTimestamp'

# Check resource usage
kubectl top pods -n truva
```

### Common Issues

1. **Pod CrashLoopBackOff**
   ```bash
   kubectl describe pod <pod-name> -n truva
   kubectl logs <pod-name> -n truva --previous
   ```

2. **Service Connectivity Issues**
   ```bash
   kubectl get svc -n truva
   kubectl get endpoints -n truva
   ```

3. **Ingress Issues**
   ```bash
   kubectl describe ingress -n truva
   kubectl get ingress -n truva
   ```

## Support and Contacts

- **Technical Support**: support@truva.io
- **Documentation**: https://docs.truva.io
- **Issue Tracking**: https://github.com/truva/truva/issues
- **Community**: https://community.truva.io

## Appendix

### Production Checklist

- [ ] Kubernetes cluster meets minimum requirements
- [ ] RBAC properly configured
- [ ] Network policies implemented
- [ ] Resource limits set
- [ ] Monitoring and alerting configured
- [ ] Backup strategy implemented
- [ ] Security scanning completed
- [ ] Load testing performed
- [ ] Disaster recovery plan tested
- [ ] Documentation updated

### Version Compatibility

| Truva Version | Kubernetes Version | Helm Version |
|---------------|-------------------|-------------|
| v1.0.x        | 1.20+             | 3.8+        |
| v1.1.x        | 1.21+             | 3.9+        |
| v1.2.x        | 1.22+             | 3.10+       |

### Resource Planning

| Environment | Nodes | CPU/Node | Memory/Node | Storage |
|-------------|-------|----------|-------------|----------|
| Development| 1     | 2 cores  | 4GB         | 50GB    |
| Staging    | 2     | 4 cores  | 8GB         | 100GB   |
| Production | 3+    | 8 cores  | 16GB        | 500GB+  |