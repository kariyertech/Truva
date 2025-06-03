# Troubleshooting Guide

This guide provides comprehensive troubleshooting information for Truva Kubernetes monitoring application.

## Table of Contents

- [General Troubleshooting](#general-troubleshooting)
- [Application Issues](#application-issues)
- [Kubernetes Issues](#kubernetes-issues)
- [Network Issues](#network-issues)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [Monitoring Issues](#monitoring-issues)
- [Log Analysis](#log-analysis)
- [Common Error Messages](#common-error-messages)
- [Diagnostic Tools](#diagnostic-tools)

## General Troubleshooting

### Initial Diagnosis Steps

1. **Check Pod Status**
   ```bash
   kubectl get pods -n truva
   kubectl describe pod <pod-name> -n truva
   ```

2. **Check Logs**
   ```bash
   kubectl logs -n truva -l app=truva --tail=100
   kubectl logs -n truva <pod-name> --previous
   ```

3. **Check Events**
   ```bash
   kubectl get events -n truva --sort-by='.lastTimestamp'
   ```

4. **Check Resource Usage**
   ```bash
   kubectl top pods -n truva
   kubectl top nodes
   ```

### Quick Health Check Script

```bash
#!/bin/bash
# health-check.sh

NAMESPACE="truva"
APP_LABEL="app=truva"

echo "=== Truva Health Check ==="
echo "Timestamp: $(date)"
echo

echo "1. Pod Status:"
kubectl get pods -n $NAMESPACE -l $APP_LABEL
echo

echo "2. Service Status:"
kubectl get svc -n $NAMESPACE
echo

echo "3. Recent Events:"
kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' | tail -10
echo

echo "4. Resource Usage:"
kubectl top pods -n $NAMESPACE 2>/dev/null || echo "Metrics server not available"
echo

echo "5. Application Health:"
POD_NAME=$(kubectl get pods -n $NAMESPACE -l $APP_LABEL -o jsonpath='{.items[0].metadata.name}')
if [ ! -z "$POD_NAME" ]; then
    kubectl exec -n $NAMESPACE $POD_NAME -- curl -s http://localhost:8080/health || echo "Health check failed"
else
    echo "No pods found"
fi
```

## Application Issues

### Pod CrashLoopBackOff

**Symptoms:**
- Pods continuously restarting
- Status shows `CrashLoopBackOff`
- Application not accessible

**Diagnosis:**
```bash
# Check pod description
kubectl describe pod <pod-name> -n truva

# Check current logs
kubectl logs <pod-name> -n truva

# Check previous container logs
kubectl logs <pod-name> -n truva --previous

# Check restart count
kubectl get pods -n truva
```

**Common Causes and Solutions:**

1. **Configuration Issues**
   ```bash
   # Check ConfigMap
   kubectl get configmap -n truva
   kubectl describe configmap truva-config -n truva
   
   # Verify environment variables
   kubectl exec -n truva <pod-name> -- env | grep TRUVA
   ```

2. **Resource Limits**
   ```bash
   # Check resource usage
   kubectl describe pod <pod-name> -n truva | grep -A 10 "Limits\|Requests"
   
   # Increase limits if needed
   kubectl patch deployment truva -n truva -p '{
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "truva",
             "resources": {
               "limits": {
                 "memory": "2Gi",
                 "cpu": "1000m"
               }
             }
           }]
         }
       }
     }
   }'
   ```

3. **Missing Dependencies**
   ```bash
   # Check if required services are running
   kubectl get svc -n truva
   kubectl get endpoints -n truva
   
   # Check Kubernetes API connectivity
   kubectl exec -n truva <pod-name> -- curl -k https://kubernetes.default.svc.cluster.local
   ```

### Application Not Starting

**Symptoms:**
- Pods stuck in `Pending` or `ContainerCreating` state
- Long startup times

**Diagnosis:**
```bash
# Check pod events
kubectl describe pod <pod-name> -n truva

# Check node resources
kubectl describe nodes

# Check image pull status
kubectl get events -n truva | grep "Failed to pull image"
```

**Solutions:**

1. **Image Pull Issues**
   ```bash
   # Check image exists
   docker pull truva:latest
   
   # Update image pull policy
   kubectl patch deployment truva -n truva -p '{
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "truva",
             "imagePullPolicy": "Always"
           }]
         }
       }
     }
   }'
   ```

2. **Resource Constraints**
   ```bash
   # Check node capacity
   kubectl describe nodes | grep -A 5 "Allocated resources"
   
   # Scale down other applications if needed
   kubectl scale deployment <other-app> --replicas=0 -n <namespace>
   ```

### Health Check Failures

**Symptoms:**
- Pods running but failing health checks
- Service endpoints not ready

**Diagnosis:**
```bash
# Check probe configuration
kubectl describe pod <pod-name> -n truva | grep -A 10 "Liveness\|Readiness"

# Test health endpoint manually
kubectl exec -n truva <pod-name> -- curl -v http://localhost:8080/health

# Check application logs for health check errors
kubectl logs <pod-name> -n truva | grep -i health
```

**Solutions:**

1. **Adjust Probe Timing**
   ```yaml
   # Update deployment with longer timeouts
   livenessProbe:
     httpGet:
       path: /health
       port: 8080
     initialDelaySeconds: 60  # Increased from 30
     periodSeconds: 10
     timeoutSeconds: 10       # Increased from 5
     failureThreshold: 5      # Increased from 3
   ```

2. **Fix Health Endpoint**
   ```bash
   # Check if health endpoint is responding
   kubectl port-forward -n truva <pod-name> 8080:8080 &
   curl http://localhost:8080/health
   ```

## Kubernetes Issues

### RBAC Permission Errors

**Symptoms:**
- "Forbidden" errors in logs
- Cannot access Kubernetes resources

**Diagnosis:**
```bash
# Check service account
kubectl get sa -n truva
kubectl describe sa truva -n truva

# Check role bindings
kubectl get rolebinding,clusterrolebinding -A | grep truva

# Test permissions
kubectl auth can-i get pods --as=system:serviceaccount:truva:truva
```

**Solutions:**

1. **Create Missing RBAC**
   ```yaml
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

### Storage Issues

**Symptoms:**
- PVC stuck in `Pending` state
- "No storage class" errors
- Volume mount failures

**Diagnosis:**
```bash
# Check PVC status
kubectl get pvc -n truva
kubectl describe pvc <pvc-name> -n truva

# Check storage classes
kubectl get storageclass

# Check persistent volumes
kubectl get pv
```

**Solutions:**

1. **Create Storage Class**
   ```yaml
   apiVersion: storage.k8s.io/v1
   kind: StorageClass
   metadata:
     name: truva-storage
   provisioner: kubernetes.io/aws-ebs  # Adjust for your provider
   parameters:
     type: gp2
   allowVolumeExpansion: true
   ```

2. **Fix PVC Configuration**
   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: truva-data
     namespace: truva
   spec:
     accessModes:
       - ReadWriteOnce
     storageClassName: truva-storage
     resources:
       requests:
         storage: 10Gi
   ```

## Network Issues

### Service Discovery Problems

**Symptoms:**
- Cannot connect to services
- DNS resolution failures
- Timeout errors

**Diagnosis:**
```bash
# Check service endpoints
kubectl get endpoints -n truva
kubectl describe svc truva -n truva

# Test DNS resolution
kubectl exec -n truva <pod-name> -- nslookup truva.truva.svc.cluster.local

# Test service connectivity
kubectl exec -n truva <pod-name> -- curl -v http://truva:8080/health
```

**Solutions:**

1. **Fix Service Configuration**
   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: truva
     namespace: truva
   spec:
     selector:
       app: truva  # Ensure this matches pod labels
     ports:
     - port: 8080
       targetPort: 8080
       protocol: TCP
   ```

2. **Check Network Policies**
   ```bash
   # List network policies
   kubectl get networkpolicy -n truva
   
   # Temporarily remove network policies for testing
   kubectl delete networkpolicy --all -n truva
   ```

### Ingress Issues

**Symptoms:**
- External access not working
- 404 or 502 errors
- SSL certificate issues

**Diagnosis:**
```bash
# Check ingress status
kubectl get ingress -n truva
kubectl describe ingress truva -n truva

# Check ingress controller
kubectl get pods -n ingress-nginx
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# Test backend connectivity
kubectl port-forward -n truva svc/truva 8080:8080
curl http://localhost:8080/health
```

**Solutions:**

1. **Fix Ingress Configuration**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: truva
     namespace: truva
     annotations:
       kubernetes.io/ingress.class: nginx
       nginx.ingress.kubernetes.io/rewrite-target: /
   spec:
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

2. **SSL Certificate Issues**
   ```bash
   # Check certificate status
   kubectl get certificate -n truva
   kubectl describe certificate truva-tls -n truva
   
   # Check cert-manager logs
   kubectl logs -n cert-manager -l app=cert-manager
   ```

## Performance Issues

### High CPU Usage

**Symptoms:**
- Pods consuming excessive CPU
- Slow response times
- CPU throttling

**Diagnosis:**
```bash
# Check CPU usage
kubectl top pods -n truva
kubectl top nodes

# Check CPU limits and requests
kubectl describe pod <pod-name> -n truva | grep -A 5 "Limits\|Requests"

# Monitor CPU over time
watch kubectl top pods -n truva
```

**Solutions:**

1. **Increase CPU Limits**
   ```bash
   kubectl patch deployment truva -n truva -p '{
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "truva",
             "resources": {
               "limits": {
                 "cpu": "2000m"
               },
               "requests": {
                 "cpu": "1000m"
               }
             }
           }]
         }
       }
     }
   }'
   ```

2. **Enable Horizontal Pod Autoscaler**
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
     minReplicas: 2
     maxReplicas: 10
     metrics:
     - type: Resource
       resource:
         name: cpu
         target:
           type: Utilization
           averageUtilization: 70
   ```

### Memory Issues

**Symptoms:**
- Out of Memory (OOM) kills
- Memory leaks
- Pods restarting due to memory limits

**Diagnosis:**
```bash
# Check memory usage
kubectl top pods -n truva

# Check for OOM kills
kubectl describe pod <pod-name> -n truva | grep -i "oom\|killed"

# Check memory limits
kubectl get pod <pod-name> -n truva -o jsonpath='{.spec.containers[0].resources}'
```

**Solutions:**

1. **Increase Memory Limits**
   ```bash
   kubectl patch deployment truva -n truva -p '{
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "truva",
             "resources": {
               "limits": {
                 "memory": "4Gi"
               },
               "requests": {
                 "memory": "2Gi"
               }
             }
           }]
         }
       }
     }
   }'
   ```

2. **Memory Profiling**
   ```bash
   # Enable memory profiling
   kubectl port-forward -n truva <pod-name> 6060:6060
   curl http://localhost:6060/debug/pprof/heap > heap.prof
   go tool pprof heap.prof
   ```

### Slow Response Times

**Symptoms:**
- High latency
- Timeouts
- Poor user experience

**Diagnosis:**
```bash
# Test response times
time curl http://truva.example.com/health

# Check application metrics
kubectl port-forward -n truva <pod-name> 8080:8080
curl http://localhost:8080/metrics | grep http_request_duration

# Check database connectivity
kubectl exec -n truva <pod-name> -- curl -v http://database:5432
```

**Solutions:**

1. **Add Caching**
   ```yaml
   # Deploy Redis cache
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: redis
     namespace: truva
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: redis
     template:
       metadata:
         labels:
           app: redis
       spec:
         containers:
         - name: redis
           image: redis:7-alpine
           ports:
           - containerPort: 6379
   ```

2. **Optimize Database Queries**
   ```bash
   # Enable query logging
   kubectl exec -n truva <pod-name> -- curl -X POST http://localhost:8080/debug/queries/enable
   
   # Review slow queries
   kubectl logs -n truva <pod-name> | grep "slow query"
   ```

## Security Issues

### Authentication Failures

**Symptoms:**
- 401 Unauthorized errors
- Authentication bypass attempts
- Invalid token errors

**Diagnosis:**
```bash
# Check authentication logs
kubectl logs -n truva -l app=truva | grep -i "auth\|401\|unauthorized"

# Test authentication endpoint
curl -v -H "Authorization: Bearer <token>" http://truva.example.com/api/pods

# Check JWT token validity
echo "<token>" | base64 -d | jq .
```

**Solutions:**

1. **Verify JWT Configuration**
   ```bash
   # Check JWT secret
   kubectl get secret truva-jwt -n truva -o jsonpath='{.data.secret}' | base64 -d
   
   # Update JWT secret if needed
   kubectl create secret generic truva-jwt --from-literal=secret=<new-secret> -n truva --dry-run=client -o yaml | kubectl apply -f -
   ```

2. **Check Token Expiration**
   ```bash
   # Decode JWT token
   echo "<jwt-payload>" | base64 -d | jq '.exp'
   
   # Compare with current time
   date +%s
   ```

### Authorization Issues

**Symptoms:**
- 403 Forbidden errors
- Access denied messages
- Role-based access failures

**Diagnosis:**
```bash
# Check user roles
kubectl get rolebinding,clusterrolebinding -A | grep <username>

# Test specific permissions
kubectl auth can-i get pods --as=<username>

# Check authorization logs
kubectl logs -n truva -l app=truva | grep -i "403\|forbidden\|denied"
```

**Solutions:**

1. **Update RBAC Rules**
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     namespace: truva
     name: truva-user
   rules:
   - apiGroups: [""]
     resources: ["pods"]
     verbs: ["get", "list"]
   ```

### Network Security Issues

**Symptoms:**
- Blocked connections
- Network policy violations
- Firewall issues

**Diagnosis:**
```bash
# Check network policies
kubectl get networkpolicy -n truva
kubectl describe networkpolicy <policy-name> -n truva

# Test connectivity
kubectl exec -n truva <pod-name> -- nc -zv <target-host> <port>

# Check iptables rules (on nodes)
sudo iptables -L | grep truva
```

**Solutions:**

1. **Update Network Policy**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: truva-allow-ingress
     namespace: truva
   spec:
     podSelector:
       matchLabels:
         app: truva
     policyTypes:
     - Ingress
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             name: ingress-nginx
       ports:
       - protocol: TCP
         port: 8080
   ```

## Monitoring Issues

### Metrics Not Available

**Symptoms:**
- Missing metrics in Prometheus
- Grafana dashboards empty
- Monitoring alerts not firing

**Diagnosis:**
```bash
# Check metrics endpoint
kubectl port-forward -n truva <pod-name> 8080:8080
curl http://localhost:8080/metrics

# Check ServiceMonitor
kubectl get servicemonitor -n monitoring
kubectl describe servicemonitor truva -n monitoring

# Check Prometheus targets
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Visit http://localhost:9090/targets
```

**Solutions:**

1. **Fix ServiceMonitor**
   ```yaml
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

2. **Enable Metrics in Application**
   ```bash
   # Check if metrics are enabled
   kubectl get configmap truva-config -n truva -o yaml | grep METRICS_ENABLED
   
   # Enable metrics if disabled
   kubectl patch configmap truva-config -n truva -p '{
     "data": {
       "METRICS_ENABLED": "true"
     }
   }'
   ```

### Log Aggregation Issues

**Symptoms:**
- Logs not appearing in centralized system
- Log shipping failures
- Missing log entries

**Diagnosis:**
```bash
# Check log shipping pods
kubectl get pods -n logging
kubectl logs -n logging -l app=fluent-bit

# Check log volume
kubectl exec -n truva <pod-name> -- ls -la /var/log/

# Test log endpoint
curl -X POST http://log-aggregator:9200/_bulk -H "Content-Type: application/json" -d '{"test": "log"}'
```

**Solutions:**

1. **Fix Fluent Bit Configuration**
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: fluent-bit-config
     namespace: logging
   data:
     fluent-bit.conf: |
       [INPUT]
           Name              tail
           Path              /var/log/containers/truva*.log
           Parser            docker
           Tag               truva.*
           Refresh_Interval  5
       
       [OUTPUT]
           Name  es
           Match truva.*
           Host  elasticsearch
           Port  9200
           Index truva-logs
   ```

## Log Analysis

### Common Log Patterns

1. **Application Startup**
   ```
   INFO  Starting Truva server on port 8080
   INFO  Kubernetes client initialized
   INFO  Metrics server started
   INFO  Server ready to accept connections
   ```

2. **Error Patterns**
   ```
   ERROR Failed to connect to Kubernetes API: connection refused
   ERROR Database connection failed: timeout
   ERROR Authentication failed for user: invalid token
   WARN  Rate limit exceeded for IP: 192.168.1.100
   ```

3. **Performance Issues**
   ```
   WARN  High memory usage: 85%
   WARN  Slow query detected: 2.5s
   ERROR Request timeout: /api/pods
   ```

### Log Analysis Commands

```bash
# Search for errors
kubectl logs -n truva -l app=truva | grep -i error

# Count error types
kubectl logs -n truva -l app=truva | grep ERROR | sort | uniq -c

# Monitor logs in real-time
kubectl logs -n truva -l app=truva -f

# Export logs for analysis
kubectl logs -n truva -l app=truva --since=1h > truva-logs.txt

# Search for specific patterns
kubectl logs -n truva -l app=truva | grep -E "(timeout|failed|error)" | tail -20
```

## Common Error Messages

### Application Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `connection refused` | Service not running | Check pod status and service configuration |
| `permission denied` | RBAC issues | Update service account permissions |
| `timeout` | Network or performance issues | Check network policies and resource limits |
| `out of memory` | Memory limit exceeded | Increase memory limits or optimize code |
| `image pull failed` | Image not found | Check image name and registry access |

### Kubernetes Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `CrashLoopBackOff` | Application failing to start | Check logs and configuration |
| `ImagePullBackOff` | Cannot pull container image | Check image name and registry credentials |
| `Pending` | Resource constraints | Check node capacity and resource requests |
| `FailedMount` | Volume mount issues | Check PVC and storage class |
| `NetworkPolicy` | Network access blocked | Update network policies |

## Diagnostic Tools

### Built-in Kubernetes Tools

```bash
# kubectl commands
kubectl get all -n truva
kubectl describe pod <pod-name> -n truva
kubectl logs <pod-name> -n truva
kubectl exec -n truva <pod-name> -- /bin/sh
kubectl port-forward -n truva <pod-name> 8080:8080

# Resource usage
kubectl top pods -n truva
kubectl top nodes

# Events and debugging
kubectl get events -n truva --sort-by='.lastTimestamp'
kubectl auth can-i get pods --as=system:serviceaccount:truva:truva
```

### External Tools

1. **k9s** - Terminal UI for Kubernetes
   ```bash
   k9s -n truva
   ```

2. **stern** - Multi-pod log tailing
   ```bash
   stern -n truva truva
   ```

3. **kubectx/kubens** - Context and namespace switching
   ```bash
   kubens truva
   kubectx production
   ```

4. **dive** - Docker image analysis
   ```bash
   dive truva:latest
   ```

### Custom Diagnostic Scripts

```bash
#!/bin/bash
# comprehensive-diag.sh

NAMESPACE="truva"
OUTPUT_DIR="./diagnostics-$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "Collecting Truva diagnostics..."

# Basic information
kubectl get all -n $NAMESPACE > $OUTPUT_DIR/resources.txt
kubectl describe pods -n $NAMESPACE > $OUTPUT_DIR/pod-descriptions.txt
kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' > $OUTPUT_DIR/events.txt

# Logs
for pod in $(kubectl get pods -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}'); do
    kubectl logs $pod -n $NAMESPACE > $OUTPUT_DIR/logs-$pod.txt
    kubectl logs $pod -n $NAMESPACE --previous > $OUTPUT_DIR/logs-$pod-previous.txt 2>/dev/null
done

# Configuration
kubectl get configmaps -n $NAMESPACE -o yaml > $OUTPUT_DIR/configmaps.yaml
kubectl get secrets -n $NAMESPACE -o yaml > $OUTPUT_DIR/secrets.yaml

# Network
kubectl get svc,endpoints,ingress -n $NAMESPACE > $OUTPUT_DIR/network.txt
kubectl get networkpolicy -n $NAMESPACE -o yaml > $OUTPUT_DIR/networkpolicies.yaml

# RBAC
kubectl get sa,role,rolebinding -n $NAMESPACE > $OUTPUT_DIR/rbac.txt

echo "Diagnostics collected in $OUTPUT_DIR"
```

## Emergency Procedures

### Application Down

1. **Immediate Response**
   ```bash
   # Check if pods are running
   kubectl get pods -n truva
   
   # Restart deployment if needed
   kubectl rollout restart deployment/truva -n truva
   
   # Scale up if needed
   kubectl scale deployment truva --replicas=3 -n truva
   ```

2. **Rollback if Recent Deployment**
   ```bash
   # Check rollout history
   kubectl rollout history deployment/truva -n truva
   
   # Rollback to previous version
   kubectl rollout undo deployment/truva -n truva
   ```

### Performance Degradation

1. **Quick Fixes**
   ```bash
   # Increase resources temporarily
   kubectl patch deployment truva -n truva -p '{
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "truva",
             "resources": {
               "limits": {
                 "cpu": "2000m",
                 "memory": "4Gi"
               }
             }
           }]
         }
       }
     }
   }'
   
   # Scale out
   kubectl scale deployment truva --replicas=5 -n truva
   ```

### Security Incident

1. **Immediate Isolation**
   ```bash
   # Block all ingress traffic
   kubectl patch networkpolicy truva-deny-all -n truva -p '{
     "spec": {
       "podSelector": {},
       "policyTypes": ["Ingress"]
     }
   }'
   
   # Scale down to minimum
   kubectl scale deployment truva --replicas=1 -n truva
   ```

2. **Investigation**
   ```bash
   # Collect evidence
   kubectl logs -n truva -l app=truva --since=1h > incident-logs.txt
   kubectl get events -n truva --sort-by='.lastTimestamp' > incident-events.txt
   ```

## Support Escalation

### When to Escalate

- Critical production issues affecting users
- Security incidents or breaches
- Data loss or corruption
- Persistent issues after following troubleshooting steps

### Information to Collect

1. **Environment Details**
   - Kubernetes version
   - Truva version
   - Cloud provider and region
   - Cluster configuration

2. **Issue Description**
   - Timeline of events
   - Error messages
   - Steps to reproduce
   - Impact assessment

3. **Diagnostic Data**
   - Pod logs
   - Events
   - Resource usage
   - Configuration files

### Contact Information

- **Emergency Support**: +1-XXX-XXX-XXXX
- **Email**: support@truva.io
- **Slack**: #truva-support
- **Ticket System**: https://support.truva.io

## Preventive Measures

### Regular Maintenance

1. **Weekly Tasks**
   - Review application logs
   - Check resource usage trends
   - Verify backup integrity
   - Update security patches

2. **Monthly Tasks**
   - Performance testing
   - Security scanning
   - Disaster recovery testing
   - Documentation updates

### Monitoring and Alerting

```yaml
# Example alert rules
groups:
- name: truva.rules
  rules:
  - alert: TruvaDown
    expr: up{job="truva"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Truva is down"
      
  - alert: TruvaHighCPU
    expr: rate(container_cpu_usage_seconds_total{pod=~"truva-.*"}[5m]) > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected"
```

### Best Practices

1. **Deployment**
   - Use rolling updates
   - Implement proper health checks
   - Set appropriate resource limits
   - Use multiple replicas

2. **Monitoring**
   - Monitor key metrics
   - Set up alerting
   - Regular log review
   - Performance baselines

3. **Security**
   - Regular security scans
   - Keep dependencies updated
   - Follow principle of least privilege
   - Network segmentation

This troubleshooting guide should help you diagnose and resolve most common issues with Truva. For issues not covered here, please refer to the support channels listed above.