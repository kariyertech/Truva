# Truva Architecture Documentation

## Overview

Truva is a Kubernetes development tool designed to streamline the development workflow by providing real-time file synchronization, process management, and log monitoring capabilities. The architecture follows a modular design with clear separation of concerns.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           Truva CLI                            │
├─────────────────────────────────────────────────────────────────┤
│  cmd/                                                           │
│  ├── main.go          (Entry Point)                            │
│  └── cli/             (CLI Commands & Validation)              │
│      ├── root.go                                                │
│      ├── up.go                                                  │
│      └── validation.go                                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Services                           │
├─────────────────────────────────────────────────────────────────┤
│  internal/                                                      │
│  ├── k8s/            (Kubernetes Operations)                   │
│  │   ├── client.go   (K8s API Client)                          │
│  │   ├── interfaces.go (Abstractions)                          │
│  │   ├── backup.go   (Deployment Backup)                       │
│  │   ├── modify.go   (Deployment Modification)                 │
│  │   └── restore.go  (Deployment Restoration)                  │
│  │                                                              │
│  ├── sync/           (File Synchronization)                    │
│  │   └── sync.go     (File Watching & Sync Logic)              │
│  │                                                              │
│  └── ui/             (Web Interface)                           │
│      ├── web.go      (HTTP Server & WebSocket)                 │
│      └── log_handler.go (Log Processing)                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Support Packages                          │
├─────────────────────────────────────────────────────────────────┤
│  pkg/                                                           │
│  ├── api/            (HTTP API Routes)                         │
│  ├── config/         (Configuration Management)                │
│  ├── context/        (Context & Lifecycle Management)          │
│  ├── health/         (Health Check Endpoints)                  │
│  ├── retry/          (Retry Logic & Circuit Breaker)           │
│  ├── cleanup/        (Resource Cleanup)                        │
│  └── utils/          (Utilities: Logging, File Watching)       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    External Dependencies                       │
├─────────────────────────────────────────────────────────────────┤
│  • Kubernetes API Server                                       │
│  • File System (Local Development Environment)                 │
│  • WebSocket Connections (Browser Clients)                     │
└─────────────────────────────────────────────────────────────────┘
```

## Component Interactions

### 1. File Synchronization Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ File System │───▶│ File Watcher│───▶│ Sync Engine │───▶│ K8s Pods    │
│ (Local)     │    │ (fsnotify)  │    │ (Debounced) │    │ (Remote)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
   File Changes    ──▶  Change Events  ──▶  Batch Sync   ──▶  Process Restart
```

### 2. Log Streaming Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ K8s Pods    │───▶│ Log Stream  │───▶│ WebSocket   │───▶│ Web Browser │
│ (Multiple)  │    │ Aggregator  │    │ Manager     │    │ (Client)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
   Pod Logs       ──▶  Log Processing ──▶  Real-time   ──▶  Live Display
   (Streaming)         (Filtering)         Broadcasting      (with Filtering)
```

### 3. Web Interface Data Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ HTTP Server │◄──▶│ WebSocket   │◄──▶│ Log Manager │
│ (Static)    │    │ Handler     │    │ (Dynamic)   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
   Web UI          Real-time Logs      Pod Discovery
   Templates       & Status Updates   & Management
```

## Core Components

### 1. CLI Layer (`cmd/`)
- **Entry Point**: `main.go` - Application bootstrap
- **Command Processing**: `cli/` - Cobra-based CLI with validation
- **Configuration**: Loads and validates user inputs

### 2. Kubernetes Integration (`internal/k8s/`)
- **Client Interface**: Abstracts Kubernetes API operations
- **Deployment Management**: Backup, modify, and restore deployments
- **Pod Operations**: File copying, process management, log streaming
- **Multi-container Support**: Container discovery and management

### 3. File Synchronization (`internal/sync/`)
- **File Watching**: Uses `fsnotify` for real-time file system monitoring
- **Debouncing**: Prevents excessive sync operations during rapid changes
- **Batch Processing**: Efficient handling of multiple file changes
- **Rate Limiting**: Prevents API overload with concurrent operations

### 4. Web Interface (`internal/ui/`)
- **HTTP Server**: Serves static content and API endpoints
- **WebSocket Management**: Real-time bidirectional communication
- **Log Aggregation**: Collects and streams logs from multiple pods
- **Connection Management**: Handles client connections and cleanup

### 5. Support Services (`pkg/`)
- **Configuration**: YAML-based configuration management
- **Health Checks**: Liveness and readiness endpoints
- **Retry Logic**: Exponential backoff and circuit breaker patterns
- **Context Management**: Graceful shutdown and resource cleanup
- **Logging**: Structured logging with configurable formats

## Data Flow Patterns

### 1. Synchronous Operations
- CLI command processing
- Configuration loading
- Kubernetes API calls (with retry)
- File system operations

### 2. Asynchronous Operations
- File system watching
- Log streaming
- WebSocket communication
- Background cleanup tasks

### 3. Event-Driven Architecture
- File change events trigger synchronization
- Pod state changes trigger UI updates
- WebSocket events drive real-time updates
- Context cancellation propagates shutdown signals

## Configuration Management

```yaml
# config.yaml structure
server:
  port: 8080
  host: "localhost"

logging:
  level: "info"
  format: "text"  # or "json"
  file: "truva.log"

kubernetes:
  config_path: "~/.kube/config"

ui:
  template_path: "./templates"

sync:
  debounce_duration: "500ms"
  batch_size: 10

monitoring:
  metrics_enabled: true
  health_check_enabled: true
```

## Security Considerations

### 1. Kubernetes Access
- Uses standard kubeconfig authentication
- Respects RBAC permissions
- No credential storage in application

### 2. Web Interface
- CORS configuration for development
- WebSocket origin validation
- No sensitive data in client-side code

### 3. File Operations
- Path validation to prevent directory traversal
- Temporary file cleanup
- Proper error handling for permission issues

## Performance Optimizations

### 1. File Synchronization
- Debounced file watching (500ms default)
- Batch processing of multiple changes
- Rate limiting for concurrent operations (5 max)

### 2. Log Streaming
- Buffered WebSocket connections (4KB buffers)
- Channel-based log aggregation (500 buffer size)
- Connection pooling and reuse

### 3. Memory Management
- Context-based cancellation
- Proper goroutine cleanup
- Resource pooling where applicable

## Error Handling Strategy

### 1. Retry Mechanisms
- Exponential backoff for Kubernetes API calls
- Circuit breaker pattern for failing operations
- Configurable retry limits and timeouts

### 2. Graceful Degradation
- Continue operation if some pods are unavailable
- Fallback to basic functionality if advanced features fail
- User notification of partial failures

### 3. Recovery Procedures
- Automatic reconnection for WebSocket clients
- Deployment restoration on critical failures
- State recovery after application restart

## Monitoring and Observability

### 1. Health Endpoints
- `/health` - Basic health check
- `/health/ready` - Readiness probe
- `/health/live` - Liveness probe

### 2. Logging
- Structured logging with configurable formats
- Request/response logging for API calls
- Performance metrics for critical operations

### 3. WebSocket Status
- Connection state monitoring
- Client count tracking
- Error rate monitoring

## Deployment Architecture

### Development Mode
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Developer   │───▶│ Truva CLI   │───▶│ K8s Cluster │
│ Machine     │    │ (Local)     │    │ (Dev/Test)  │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
   Local Files      File Sync &        Pod Updates &
   & Web Browser    Log Streaming     Process Restart
```

### Production Considerations
- Resource limits and requests
- Persistent configuration storage
- Log aggregation integration
- Monitoring and alerting setup

## Extension Points

### 1. Plugin Architecture
- Interface-based design allows for easy extension
- Custom sync strategies
- Additional log processors
- Custom health checks

### 2. Configuration Extensions
- Environment-specific configurations
- Custom deployment strategies
- Integration with CI/CD pipelines

### 3. UI Customization
- Template-based UI rendering
- Custom CSS and JavaScript
- Additional dashboard widgets

## Future Enhancements

### 1. Planned Features
- Multi-cluster support
- Advanced filtering and search
- Performance metrics dashboard
- Integration with popular IDEs

### 2. Scalability Improvements
- Horizontal scaling support
- Distributed log aggregation
- Caching layer for frequently accessed data

### 3. Developer Experience
- Auto-discovery of development environments
- Smart sync based on file types
- Integration with build tools
- Enhanced debugging capabilities