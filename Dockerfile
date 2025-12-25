# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cerberus .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates wget

# Create non-root user
RUN addgroup -S cerberus && adduser -S cerberus -G cerberus

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/cerberus .

# Copy config and rules files
COPY --from=builder /app/config.yaml .
COPY --from=builder /app/rules.json .
COPY --from=builder /app/correlation_rules.json .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Change ownership
RUN chown -R cerberus:cerberus /app

# Switch to non-root user
USER cerberus

# Expose ports
EXPOSE 514/udp 515/tcp 8080 8081

# Health check - Uses readiness probe to verify ClickHouse and SQLite are accessible
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health/ready || exit 1

# Run the binary
CMD ["./cerberus"]