# Multi-stage Dockerfile for Truva Kubernetes Development Tool
# Stage 1: Build stage
FROM golang:1.23-alpine AS builder

# Install security updates and required packages
RUN apk update && apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create non-root user for build
RUN adduser -D -s /bin/sh -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o truva ./cmd/main.go

# Verify the binary
RUN file truva && ldd truva || true

# Stage 2: Runtime stage
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy the binary
COPY --from=builder /app/truva /truva

# Copy configuration files
COPY --from=builder /app/config.yaml /config.yaml
COPY --from=builder /app/templates/ /templates/

# Create necessary directories
USER 1001:1001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["./truva", "--health-check"]

# Expose port
EXPOSE 8080

# Set environment variables
ENV GIN_MODE=release
ENV TRUVA_ENV=production

# Run the application
ENTRYPOINT ["/truva"]
CMD ["up"]