# Truva

Truva is a CLI tool designed for managing Kubernetes deployments and pods, with a built-in UI for monitoring logs in real time. The tool enables syncing files from the local machine to Kubernetes pods, restarting processes, and displaying logs of all pods dynamically in a web interface.

## Features

- **File Sync**: Sync local files to the target Kubernetes deployment or pod.
- **Process Restart**: Automatically restart processes in Kubernetes pods after file synchronization.
- **Dynamic Log Monitoring**: Monitor logs of each pod in real time through a web-based interface.
- **WebSocket Integration**: Logs are streamed in real time using WebSocket connections.
- **Multiple Pods Support**: Supports deployments with multiple pods, dynamically creating buttons to monitor each pod individually.

### Key Components:

- `cmd`: Contains the main application logic and the CLI commands.
- `internal/k8s`: Handles Kubernetes-related operations like backing up, modifying, and restoring deployments.
- `internal/sync`: Responsible for syncing files to the Kubernetes pods and restarting processes.
- `internal/ui`: Manages the web server and WebSocket logic for real-time log streaming.
- `pkg/api`: API routes for syncing and log management.
- `pkg/utils`: Utility functions such as file watching and logging.
- `templates/index.html`: The HTML file that powers the web interface for displaying pod logs.

## Getting Started

### Prerequisites

- Kubernetes cluster access
- `kubectl` command-line tool installed and configured
- YQ and JQ Tools

## Example Usage

```bash
go run main.go up --namespace <namespace> --targetType deployment --targetName <deployment-name> --localPath <path-to-local-files> --containerPath <container-path-in-pod>
```