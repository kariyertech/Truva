# Truva API Documentation

Truva provides a RESTful API and WebSocket interface for managing Kubernetes development workflows, including file synchronization, log streaming, and health monitoring.

## Base URL

- **Local Development**: `http://localhost:8080`
- **Production**: Configure via `config.yaml`

## Authentication

Currently, Truva does not implement authentication. This is suitable for local development environments. For production deployments, consider implementing authentication middleware.

## API Endpoints

### Synchronization

#### POST /api/sync

Modifies a Kubernetes deployment to enable file synchronization between your local development environment and running pods.

**Query Parameters:**
- `namespace` (required): Kubernetes namespace containing the deployment
- `deployment` (required): Name of the Kubernetes deployment to modify
- `local-path` (required): Local file system path to synchronize
- `container-path` (required): Container path where files should be synchronized

**Example Request:**
```bash
curl -X POST "http://localhost:8080/api/sync?namespace=default&deployment=my-app&local-path=/path/to/code&container-path=/app"
```

**Response:**
```json
{
  "message": "Deployment modified successfully"
}
```

**Error Responses:**
- `400 Bad Request`: Missing required query parameters
- `500 Internal Server Error`: Failed to modify deployment

### Logging

#### POST /api/logs

Accepts log data from applications and writes it to the application log file.

**Request Body:**
- Content-Type: `text/plain` or `application/json`
- For JSON format, include fields: `timestamp`, `level`, `message`, `source`

**Example Request:**
```bash
# Plain text
curl -X POST "http://localhost:8080/api/logs" \
  -H "Content-Type: text/plain" \
  -d "2024-12-19 10:30:00 INFO Application started successfully"

# JSON format
curl -X POST "http://localhost:8080/api/logs" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-12-19T10:30:00Z",
    "level": "INFO",
    "message": "Application started successfully",
    "source": "my-service"
  }'
```

**Response:**
- `204 No Content`: Logs written successfully
- `500 Internal Server Error`: Failed to write logs

### Health Monitoring

#### GET /health

Returns the overall health status of the application.

**Example Request:**
```bash
curl "http://localhost:8080/health"
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-12-19T10:30:00Z",
  "version": "1.0.0",
  "uptime": "2h30m45s",
  "checks": {
    "config": {
      "status": "ok",
      "message": "Configuration loaded successfully"
    },
    "kubernetes": {
      "status": "ok",
      "message": "Kubernetes API accessible"
    }
  }
}
```

#### GET /health/ready

Kubernetes readiness probe endpoint. Returns whether the application is ready to serve traffic.

#### GET /health/live

Kubernetes liveness probe endpoint. Returns whether the application is alive and functioning.

### WebSocket Endpoints

#### GET /ws

Establishes a WebSocket connection for real-time log streaming from Kubernetes pods.

**Connection Headers:**
```
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <key>
Sec-WebSocket-Version: 13
```

**Message Format:**
```json
{
  "type": "log",
  "data": {
    "timestamp": "2024-12-19T10:30:00Z",
    "level": "INFO",
    "message": "Application log message",
    "pod": "my-app-12345",
    "container": "app",
    "namespace": "default"
  },
  "timestamp": "2024-12-19T10:30:00Z"
}
```

**Message Types:**
- `log`: Log message from pods
- `status`: Connection status updates
- `error`: Error messages
- `ping`/`pong`: Heartbeat messages

#### GET /ws/status

Returns information about active WebSocket connections.

**Example Response:**
```json
{
  "active_connections": 3,
  "total_connections": 15,
  "uptime": "2h30m45s"
}
```

### Web Interface

#### GET /

Serves the main web interface for Truva, providing a user-friendly dashboard for monitoring logs and managing synchronization.

## Error Handling

All API endpoints return appropriate HTTP status codes:

- `200 OK`: Request successful
- `204 No Content`: Request successful, no content to return
- `400 Bad Request`: Invalid request parameters
- `500 Internal Server Error`: Server-side error
- `503 Service Unavailable`: Service temporarily unavailable

Error responses include descriptive messages in the response body.

## Rate Limiting

Currently, no rate limiting is implemented. For production use, consider implementing rate limiting middleware.

## CORS

CORS headers are configured to allow cross-origin requests. This can be customized in the configuration file.

## Configuration

API behavior can be configured via `config.yaml`:

```yaml
server:
  host: "localhost"
  port: 8080
  
monitoring:
  health_check_enabled: true
  
logging:
  level: "info"
  format: "json"  # or "text"
```

## OpenAPI Specification

A complete OpenAPI 3.0 specification is available at `docs/swagger.yaml`. You can use this with tools like:

- [Swagger UI](https://swagger.io/tools/swagger-ui/)
- [Redoc](https://redocly.github.io/redoc/)
- [Postman](https://www.postman.com/)

## Examples

### JavaScript WebSocket Client

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
  console.log('Connected to Truva WebSocket');
};

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  if (message.type === 'log') {
    console.log(`[${message.data.pod}] ${message.data.message}`);
  }
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
};
```

### Python API Client

```python
import requests
import json

# Sync files
response = requests.post('http://localhost:8080/api/sync', params={
    'namespace': 'default',
    'deployment': 'my-app',
    'local-path': '/path/to/code',
    'container-path': '/app'
})

if response.status_code == 200:
    print('Sync successful:', response.json())
else:
    print('Sync failed:', response.text)

# Submit logs
log_data = {
    'timestamp': '2024-12-19T10:30:00Z',
    'level': 'INFO',
    'message': 'Application started',
    'source': 'my-service'
}

response = requests.post('http://localhost:8080/api/logs',
                        json=log_data,
                        headers={'Content-Type': 'application/json'})

if response.status_code == 204:
    print('Log submitted successfully')
```

## Support

For issues and questions:
- GitHub Issues: [https://github.com/kariyertech/Truva/issues](https://github.com/kariyertech/Truva/issues)
- Documentation: [https://github.com/kariyertech/Truva/docs](https://github.com/kariyertech/Truva/docs)