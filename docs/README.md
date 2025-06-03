# Truva API Documentation

This directory contains comprehensive API documentation for Truva - Kubernetes Development Tool.

## Documentation Files

### 📋 [API.md](./API.md)
Complete API reference documentation including:
- Endpoint descriptions and usage examples
- Request/response formats
- Error handling
- Authentication (when implemented)
- Code examples in multiple languages

### 📊 [swagger.yaml](./swagger.yaml)
OpenAPI 3.0 specification file that provides:
- Machine-readable API specification
- Complete schema definitions
- Request/response examples
- Compatible with Swagger/OpenAPI tools

### 🌐 [swagger-ui.html](./swagger-ui.html)
Interactive API documentation interface that:
- Provides a web-based API explorer
- Allows testing API endpoints directly
- Renders the OpenAPI specification in a user-friendly format

## Accessing Documentation

When Truva is running, you can access the documentation at:

- **Interactive API Docs**: http://localhost:8080/docs/
- **OpenAPI Spec**: http://localhost:8080/docs/swagger.yaml
- **Markdown Docs**: http://localhost:8080/docs/api.md

## API Overview

Truva provides the following API categories:

### 🔄 Synchronization APIs
- `POST /api/sync` - File synchronization with Kubernetes deployments

### 📝 Logging APIs
- `POST /api/logs` - Submit application logs

### 🏥 Health Check APIs
- `GET /health` - Overall application health
- `GET /health/ready` - Readiness probe
- `GET /health/live` - Liveness probe

### 🔌 WebSocket APIs
- `GET /ws` - Real-time log streaming
- `GET /ws/status` - WebSocket connection status

### 🖥️ Web Interface
- `GET /` - Main web dashboard

## Quick Start

### 1. Start File Synchronization
```bash
curl -X POST "http://localhost:8080/api/sync?namespace=default&deployment=my-app&local-path=/path/to/code&container-path=/app"
```

### 2. Check Application Health
```bash
curl "http://localhost:8080/health"
```

### 3. Connect to Real-time Logs
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log(message);
};
```

## Development

### Updating Documentation

1. **API Changes**: Update `swagger.yaml` with new endpoints or modifications
2. **Examples**: Add new examples to `API.md`
3. **UI**: Modify `swagger-ui.html` for presentation changes

### Validation

Validate the OpenAPI specification:
```bash
# Using swagger-codegen
swagger-codegen validate -i docs/swagger.yaml

# Using online validator
curl -X POST "https://validator.swagger.io/validator/debug" \
  -H "Content-Type: application/json" \
  -d @docs/swagger.yaml
```

### Generating Client SDKs

Use the OpenAPI specification to generate client libraries:

```bash
# Generate JavaScript client
swagger-codegen generate -i docs/swagger.yaml -l javascript -o clients/javascript

# Generate Python client
swagger-codegen generate -i docs/swagger.yaml -l python -o clients/python

# Generate Go client
swagger-codegen generate -i docs/swagger.yaml -l go -o clients/go
```

## Tools and Integrations

### Recommended Tools

- **[Swagger Editor](https://editor.swagger.io/)** - Edit and validate OpenAPI specs
- **[Postman](https://www.postman.com/)** - Import OpenAPI spec for API testing
- **[Insomnia](https://insomnia.rest/)** - Alternative API testing tool
- **[Redoc](https://redocly.github.io/redoc/)** - Alternative documentation renderer

### IDE Extensions

- **VS Code**: OpenAPI (Swagger) Editor extension
- **IntelliJ**: OpenAPI Specifications plugin
- **Vim**: vim-swagger plugin

## Contributing

When contributing to the API:

1. Update the OpenAPI specification first
2. Ensure examples are working and up-to-date
3. Test the interactive documentation
4. Update any affected client code examples
5. Validate the specification before committing

## Support

For API-related questions:
- 📖 Check this documentation first
- 🐛 Report issues on GitHub
- 💬 Join our community discussions
- 📧 Contact the development team

---

**Note**: This documentation is automatically served by Truva when running. Access it at http://localhost:8080/docs/ for the best experience.