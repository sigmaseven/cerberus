# Production Deployment Runbook

## Overview

This runbook provides comprehensive instructions for deploying Cerberus SIEM in a production environment. It covers installation, configuration, security hardening, monitoring, backup procedures, and troubleshooting.

**Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Target Environment**: Production (Linux, Docker, Kubernetes)

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Security Hardening](#security-hardening)
5. [Monitoring Setup](#monitoring-setup)
6. [Backup Procedures](#backup-procedures)
7. [Troubleshooting](#troubleshooting)
8. [Operational Procedures](#operational-procedures)

---

## Prerequisites

### Hardware Requirements

**Minimum (Development/Testing)**:
- CPU: 2 cores
- RAM: 4 GB
- Disk: 50 GB SSD
- Network: 1 Gbps

**Recommended (Production)**:
- CPU: 4-8 cores
- RAM: 16-32 GB
- Disk: 500 GB+ SSD (with 10,000+ IOPS)
- Network: 10 Gbps

**High-Volume (10K+ EPS)**:
- CPU: 8-16 cores
- RAM: 32-64 GB
- Disk: 1 TB+ NVMe SSD (with 20,000+ IOPS)
- Network: 10 Gbps

### Software Requirements

**Required**:
- Operating System: Linux (Ubuntu 20.04+, RHEL 8+, or Alpine Linux)
- Go Runtime: 1.21+ (for binary deployment)
- SQLite: 3.35+ (included in binary)
- ClickHouse: 22.3+ (for event storage)
- Docker: 20.10+ (for containerized deployment)
- Kubernetes: 1.24+ (for Kubernetes deployment)

**Optional**:
- Redis: 6.0+ (for distributed rate limiting and caching)
- Prometheus: 2.30+ (for metrics collection)
- Grafana: 8.0+ (for visualization)

### Network Requirements

**Ports to Open**:
- `514/udp`, `514/tcp`: Syslog listener
- `515/tcp`, `515/udp`: CEF listener
- `8080/tcp`: JSON HTTP listener
- `8081/tcp`: API server and metrics endpoint

**Firewall Rules**:
- Ingress: Allow ports 514, 515, 8080, 8081 from trusted sources
- Egress: Allow HTTPS (443) for external webhooks, SMTP (587/465) for email
- Internal: Allow ClickHouse (9000), Redis (6379) on internal network only

### TLS Certificate Requirements

- Valid TLS certificate (X.509, PEM format)
- Private key (RSA 2048+ or ECDSA P-256+)
- Certificate chain (intermediate certificates)
- Recommended: Use Let's Encrypt or internal CA
- Expiry: Monitor certificate expiry (auto-renewal recommended)

---

## Installation

### Binary Installation

**Step 1: Download Binary**
```bash
# Download latest release
wget https://github.com/your-org/cerberus/releases/latest/cerberus-linux-amd64
chmod +x cerberus-linux-amd64
sudo mv cerberus-linux-amd64 /usr/local/bin/cerberus
```

**Step 2: Create Service User**
```bash
sudo useradd -r -s /bin/false cerberus
sudo mkdir -p /etc/cerberus /var/lib/cerberus /var/log/cerberus
sudo chown -R cerberus:cerberus /etc/cerberus /var/lib/cerberus /var/log/cerberus
```

**Step 3: Install Configuration**
```bash
sudo cp config.yaml /etc/cerberus/
sudo chown cerberus:cerberus /etc/cerberus/config.yaml
sudo chmod 600 /etc/cerberus/config.yaml
```

**Step 4: Create Systemd Service**
```bash
sudo tee /etc/systemd/system/cerberus.service > /dev/null <<EOF
[Unit]
Description=Cerberus SIEM
After=network.target clickhouse.service

[Service]
Type=simple
User=cerberus
Group=cerberus
WorkingDirectory=/var/lib/cerberus
ExecStart=/usr/local/bin/cerberus -config /etc/cerberus/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cerberus

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cerberus
sudo systemctl start cerberus
```

### Docker Deployment

**Step 1: Create Docker Compose File**
```bash
# Use provided docker-compose.yml or create custom
cp docker-compose.yml docker-compose.prod.yml
# Edit docker-compose.prod.yml for production settings
```

**Step 2: Configure Environment Variables**
```bash
# Create .env file
cat > .env <<EOF
CERBERUS_CLICKHOUSE_ADDR=clickhouse:9000
CERBERUS_CLICKHOUSE_DATABASE=cerberus
CERBERUS_CLICKHOUSE_USER=default
CERBERUS_CLICKHOUSE_PASSWORD=changeme_production_password
CERBERUS_AUTH_ENABLED=true
CERBERUS_AUTH_JWT_SECRET=changeme_strong_jwt_secret_64_chars_minimum
CERBERUS_API_TLS=true
CERBERUS_API_CERT_FILE=/etc/ssl/certs/cerberus.crt
CERBERUS_API_KEY_FILE=/etc/ssl/private/cerberus.key
EOF

chmod 600 .env
```

**Step 3: Start Services**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

**Step 4: Verify Deployment**
```bash
docker-compose -f docker-compose.prod.yml ps
docker-compose -f docker-compose.prod.yml logs -f cerberus
```

### Kubernetes Deployment

**Step 1: Create Namespace**
```bash
kubectl create namespace cerberus
```

**Step 2: Create Secrets**
```bash
kubectl create secret generic cerberus-secrets \
  --from-literal=jwt-secret='changeme_strong_jwt_secret_64_chars_minimum' \
  --from-literal=clickhouse-password='changeme_production_password' \
  --namespace=cerberus
```

**Step 3: Create ConfigMap**
```bash
kubectl create configmap cerberus-config \
  --from-file=config.yaml \
  --namespace=cerberus
```

**Step 4: Deploy**
```bash
kubectl apply -f k8s/deployment.yaml -n cerberus
kubectl apply -f k8s/service.yaml -n cerberus
```

**Step 5: Verify**
```bash
kubectl get pods -n cerberus
kubectl logs -f deployment/cerberus -n cerberus
```

### Database Initialization

**SQLite**:
- Automatically initialized on first run
- Database file: `data/cerberus.db`
- WAL files: `data/cerberus.db-wal`, `data/cerberus.db-shm`

**ClickHouse**:
```bash
# Connect to ClickHouse
clickhouse-client --host localhost --port 9000

# Create database
CREATE DATABASE IF NOT EXISTS cerberus;

# Schema is automatically created by Cerberus on first connection
```

**Initial Admin User**:
```bash
# Admin user is created automatically if auth is enabled
# Default credentials (CHANGE IMMEDIATELY):
# Username: admin
# Password: admin1234 (from config.yaml)

# Change password via API after first login
curl -X PUT http://localhost:8081/api/v1/users/admin \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewStrongPassword123!"}'
```

---

## Configuration

### Configuration File Reference

**Location**: `/etc/cerberus/config.yaml` (binary) or `/app/config.yaml` (Docker)

**Full Configuration**:
```yaml
# ClickHouse Configuration
clickhouse:
  addr: "localhost:9000"
  database: "cerberus"
  username: "default"
  password: "changeme_production_password"  # SECURITY: Use strong password
  tls: false  # SECURITY: Enable TLS in production
  max_pool_size: 100
  batch_size: 1000
  flush_interval: 5  # seconds

# Event Listeners
listeners:
  syslog:
    port: 514
    host: "0.0.0.0"
  cef:
    port: 515
    host: "0.0.0.0"
  json:
    port: 8080
    host: "0.0.0.0"
    tls: false  # SECURITY: Enable TLS in production

# API Configuration
api:
  version: "v1"
  port: 8081
  tls: true  # SECURITY: Enable TLS in production
  cert_file: "/etc/ssl/certs/cerberus.crt"
  key_file: "/etc/ssl/private/cerberus.key"
  trust_proxy: false
  trusted_proxy_networks: []  # SECURITY: Configure trusted proxy IPs

# Authentication Configuration
auth:
  enabled: true  # SECURITY: MUST be true in production
  username: "admin"
  password: "changeme_immediately"  # SECURITY: Change on first login
  jwt_secret: "changeme_strong_jwt_secret_64_chars_minimum"  # SECURITY: Use strong secret
  jwt_expiry: 24h
  bcrypt_cost: 10
  lockout_threshold: 5
  lockout_duration: 15m

# Security Configuration
security:
  regex_timeout: 100ms  # ReDoS protection timeout
  login_body_limit: 1024  # Maximum login request size (bytes)
  max_request_size: 10485760  # 10 MB
  password_policy:
    min_length: 8
    require_classes: 3  # Require 3 of 4 character classes
    max_history: 5
    expiration_days: 90
    warning_days: 7

# CORS Configuration
cors:
  enabled: true
  allowed_origins:  # SECURITY: Configure allowlist
    - "https://your-domain.com"
  allowed_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "PATCH"
    - "DELETE"
  allowed_headers:
    - "Authorization"
    - "Content-Type"
    - "X-CSRF-Token"
  allow_credentials: true

# Rate Limiting
api:
  rate_limit:
    requests_per_second: 100
    burst: 200
    max_auth_failures: 5
    global:
      limit: 1000
      window: 1s
      burst: 2000

# Storage Configuration
storage:
  deduplication: true
  dedup_cache_size: 10000
  dedup_eviction_size: 8000

# Retention Configuration
retention:
  events: 30  # days
  alerts: 90  # days

# ML Configuration
ml:
  enabled: true
  mode: "simple"
  model_path: "./data/ml_models"
  training_data_dir: "./data/ml_training"
  batch_size: 100
  threshold: 0.7
  update_interval: 60  # minutes
  feature_cache_size: 10000
  algorithms:
    - "zscore"
    - "iqr"
    - "isolation_forest"
  training_interval: 24  # hours
  retrain_threshold: 1000
  enable_drift_detection: true
  anomaly_threshold: 0.7
  min_training_samples: 100

# SOAR Configuration
soar:
  destructive_actions_enabled: false  # SECURITY: Enable only with approval workflow
  approval_required: true
  sandbox_enabled: true
```

### Environment Variable Overrides

All configuration can be overridden via environment variables using the format:
`CERBERUS_<SECTION>_<KEY>=value`

**Examples**:
```bash
export CERBERUS_CLICKHOUSE_ADDR=clickhouse:9000
export CERBERUS_AUTH_ENABLED=true
export CERBERUS_AUTH_JWT_SECRET=changeme_strong_jwt_secret_64_chars_minimum
export CERBERUS_API_TLS=true
export CERBERUS_API_CERT_FILE=/etc/ssl/certs/cerberus.crt
export CERBERUS_API_KEY_FILE=/etc/ssl/private/cerberus.key
```

### Secrets Management

**Option 1: Environment Variables** (Recommended for Docker/Kubernetes)
```bash
# Use secret management tools (HashiCorp Vault, AWS Secrets Manager, etc.)
# Inject secrets as environment variables at runtime
```

**Option 2: Secret Files**
```bash
# Store secrets in separate files with restricted permissions
echo "changeme_strong_jwt_secret_64_chars_minimum" > /etc/cerberus/jwt_secret
chmod 600 /etc/cerberus/jwt_secret
chown cerberus:cerberus /etc/cerberus/jwt_secret

# Reference in config.yaml
auth:
  jwt_secret_file: "/etc/cerberus/jwt_secret"
```

**Option 3: Key Management Service**
- Use AWS KMS, Azure Key Vault, or HashiCorp Vault
- Configure application to fetch secrets at startup
- Rotate secrets periodically (recommended: every 90 days)

### TLS Configuration

**Step 1: Obtain Certificate**
```bash
# Option A: Let's Encrypt (recommended)
sudo certbot certonly --standalone -d your-domain.com

# Option B: Internal CA
# Generate certificate signing request and submit to CA
```

**Step 2: Configure Certificates**
```yaml
api:
  tls: true
  cert_file: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
  key_file: "/etc/letsencrypt/live/your-domain.com/privkey.pem"

listeners:
  json:
    tls: true
    cert_file: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
    key_file: "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

**Step 3: Set Permissions**
```bash
sudo chown cerberus:cerberus /etc/letsencrypt/live/your-domain.com/*.pem
sudo chmod 600 /etc/letsencrypt/live/your-domain.com/privkey.pem
sudo chmod 644 /etc/letsencrypt/live/your-domain.com/fullchain.pem
```

**Step 4: Enable Auto-Renewal** (Let's Encrypt)
```bash
# Add to crontab
sudo crontab -e
# Add: 0 0 1 * * certbot renew --quiet && systemctl reload cerberus
```

---

## Security Hardening

### Authentication Hardening

**1. Enable Authentication**
```yaml
auth:
  enabled: true  # MUST be true in production
```

**2. Configure Strong JWT Secret**
```yaml
auth:
  jwt_secret: "changeme_strong_jwt_secret_64_chars_minimum"  # Minimum 32 characters, recommended 64+
```
```bash
# Generate strong JWT secret
openssl rand -hex 32
```

**3. Enable HTTPS/TLS**
```yaml
api:
  tls: true  # Disable HTTP, require HTTPS
  cert_file: "/etc/ssl/certs/cerberus.crt"
  key_file: "/etc/ssl/private/cerberus.key"
```

**4. Configure CORS Allowlist**
```yaml
cors:
  enabled: true
  allowed_origins:
    - "https://your-domain.com"  # SECURITY: Only allow trusted origins
    - "https://admin.your-domain.com"
  allow_credentials: true
```

**5. Set Up Rate Limiting**
```yaml
api:
  rate_limit:
    requests_per_second: 100  # Adjust based on load
    burst: 200
    max_auth_failures: 5  # Lockout after 5 failed attempts
    global:
      limit: 1000
      window: 1s
      burst: 2000
```

**6. Configure Password Policy**
```yaml
security:
  password_policy:
    min_length: 12  # SECURITY: Minimum 12 characters
    require_classes: 3  # Require 3 of 4 character classes (upper, lower, number, special)
    max_history: 5  # Prevent password reuse
    expiration_days: 90  # Force password change every 90 days
    warning_days: 7  # Warn 7 days before expiration
```

**7. Enable MFA for Admin Accounts**
```bash
# After login, enable MFA via API
curl -X POST http://localhost:8081/api/v1/auth/mfa/enable \
  -H "Authorization: Bearer $JWT_TOKEN"

# Verify MFA enrollment
curl -X POST http://localhost:8081/api/v1/auth/mfa/verify \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

**8. Review RBAC Role Assignments**
```bash
# List all users and roles
curl -X GET http://localhost:8081/api/v1/users \
  -H "Authorization: Bearer $JWT_TOKEN"

# Review role permissions
curl -X GET http://localhost:8081/api/v1/roles \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**9. Configure Session Timeout**
```yaml
auth:
  jwt_expiry: 8h  # SECURITY: Shorten from 24h for production (recommended: 4-8h)
```

**10. Enable Audit Logging**
```yaml
# Audit logging is enabled by default
# Logs are written to application logs (structured JSON)
# Ensure log aggregation is configured (see Monitoring section)
```

### Network Security

**1. Firewall Configuration**
```bash
# UFW example (Ubuntu)
sudo ufw allow from trusted_ip/32 to any port 514 proto udp
sudo ufw allow from trusted_ip/32 to any port 515 proto tcp
sudo ufw allow from trusted_ip/32 to any port 8080 proto tcp
sudo ufw allow from trusted_ip/32 to any port 8081 proto tcp
sudo ufw enable
```

**2. Disable Unnecessary Services**
```bash
# Ensure only required ports are exposed
# Use reverse proxy (nginx, traefik) for HTTPS termination
```

**3. IP Allowlisting**
```yaml
# Configure in config.yaml (if supported)
# Or use firewall rules
```

### Application Security

**1. Run as Non-Root User**
```bash
# Binary installation: Already configured (cerberus user)
# Docker: Already configured (USER cerberus in Dockerfile)
# Kubernetes: Use securityContext.runAsNonRoot: true
```

**2. File Permissions**
```bash
sudo chmod 600 /etc/cerberus/config.yaml
sudo chmod 600 /etc/cerberus/jwt_secret
sudo chown cerberus:cerberus /etc/cerberus/*
```

**3. Disable Debug Mode**
```yaml
# Ensure debug: false in production
logging:
  level: "info"  # Use "warn" or "error" in production
```

---

## Monitoring Setup

### Prometheus Configuration

**Step 1: Configure Prometheus Scraping**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cerberus'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

**Step 2: Start Prometheus**
```bash
docker run -d \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

### Grafana Dashboard

**Step 1: Import Dashboard**
```bash
# Download dashboard JSON (see docs/operations/grafana-dashboard.json)
# Import via Grafana UI: Dashboards → Import → Upload JSON
```

**Step 2: Key Metrics to Monitor**
- **Ingestion**: Events per second, ingestion latency, dropped events
- **API**: Request rate, response time (p50, p95, p99), error rate
- **Storage**: ClickHouse queries, SQLite operations, disk usage
- **System**: CPU usage, memory usage, goroutine count
- **Security**: Failed login attempts, rate limit violations, regex timeouts

### Alert Configuration

**Recommended Alerts**:
```yaml
# prometheus-alerts.yml
groups:
  - name: cerberus
    rules:
      # Ingestion rate drop
      - alert: CerberusIngestionRateDrop
        expr: rate(cerberus_events_ingested_total[5m]) < 1000
        for: 5m
        annotations:
          summary: "Ingestion rate dropped below threshold"

      # API error rate
      - alert: CerberusAPIErrorRate
        expr: rate(cerberus_api_requests_total{status=~"5.."}[5m]) > 0.01
        for: 5m
        annotations:
          summary: "High API error rate detected"

      # Disk usage
      - alert: CerberusDiskUsage
        expr: node_filesystem_avail_bytes{mountpoint="/var/lib/cerberus"} / node_filesystem_size_bytes{mountpoint="/var/lib/cerberus"} < 0.1
        for: 5m
        annotations:
          summary: "Disk usage above 90%"

      # Memory usage
      - alert: CerberusMemoryUsage
        expr: process_resident_memory_bytes / 1024 / 1024 / 1024 > 8
        for: 5m
        annotations:
          summary: "Memory usage above 8 GB"
```

**Step 3: Configure Alertmanager**
```bash
# Configure alertmanager to send alerts to email/Slack/PagerDuty
# See Prometheus Alertmanager documentation
```

### Health Check Monitoring

**Endpoint**: `http://localhost:8081/health`

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-08T12:00:00Z",
  "version": "1.0.0",
  "uptime": "24h30m15s"
}
```

**Monitoring**:
```bash
# Add to monitoring system
curl -f http://localhost:8081/health || alert("Cerberus health check failed")
```

### Log Aggregation

**Structured JSON Logs**:
```bash
# Logs are written to stdout/stderr in structured JSON format
# Use log aggregation tool (ELK, Loki, CloudWatch) to collect logs

# Example: Send logs to Loki
docker run -d \
  -v $(pwd)/promtail-config.yml:/etc/promtail/config.yml \
  grafana/promtail \
  -config.file=/etc/promtail/config.yml
```

---

## Backup Procedures

### SQLite Database Backup

**Method 1: Direct Copy (Recommended)**
```bash
# Stop Cerberus (or use WAL checkpoint)
sudo systemctl stop cerberus

# Copy database files
sudo cp /var/lib/cerberus/data/cerberus.db /backup/cerberus-$(date +%Y%m%d).db
sudo cp /var/lib/cerberus/data/cerberus.db-wal /backup/cerberus-$(date +%Y%m%d).db-wal 2>/dev/null || true
sudo cp /var/lib/cerberus/data/cerberus.db-shm /backup/cerberus-$(date +%Y%m%d).db-shm 2>/dev/null || true

# Restart Cerberus
sudo systemctl start cerberus
```

**Method 2: Online Backup (Using WAL)**
```bash
# Create checkpoint and backup
sqlite3 /var/lib/cerberus/data/cerberus.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 /var/lib/cerberus/data/cerberus.db ".backup /backup/cerberus-$(date +%Y%m%d).db"
```

**Automated Backup Script**:
```bash
#!/bin/bash
# /usr/local/bin/cerberus-backup.sh

BACKUP_DIR="/backup/cerberus"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Perform backup
sudo systemctl stop cerberus
sudo sqlite3 /var/lib/cerberus/data/cerberus.db ".backup $BACKUP_DIR/cerberus-$(date +%Y%m%d-%H%M%S).db"
sudo systemctl start cerberus

# Compress backup
gzip "$BACKUP_DIR/cerberus-$(date +%Y%m%d-%H%M%S).db"

# Cleanup old backups
find "$BACKUP_DIR" -name "cerberus-*.db.gz" -mtime +$RETENTION_DAYS -delete

# Add to crontab: 0 2 * * * /usr/local/bin/cerberus-backup.sh
```

### ClickHouse Backup

**Method 1: Native Backup**
```bash
# Create backup
clickhouse-client --query "BACKUP DATABASE cerberus TO Disk('backups', 'cerberus-$(date +%Y%m%d).zip')"
```

**Method 2: Table-Level Backup**
```bash
# Backup events table
clickhouse-client --query "SELECT * FROM cerberus.events" | gzip > /backup/events-$(date +%Y%m%d).csv.gz

# Backup alerts table
clickhouse-client --query "SELECT * FROM cerberus.alerts" | gzip > /backup/alerts-$(date +%Y%m%d).csv.gz
```

**Method 3: Snapshot Backup** (Docker)
```bash
# Stop ClickHouse
docker-compose stop clickhouse

# Create snapshot
docker run --rm \
  -v cerberus_clickhouse_data:/data \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/clickhouse-$(date +%Y%m%d).tar.gz -C /data .

# Start ClickHouse
docker-compose start clickhouse
```

### Configuration Backup

```bash
# Backup configuration files
sudo cp /etc/cerberus/config.yaml /backup/config-$(date +%Y%m%d).yaml
sudo cp /etc/cerberus/jwt_secret /backup/jwt_secret-$(date +%Y%m%d) 2>/dev/null || true
sudo cp /etc/cerberus/rules.json /backup/rules-$(date +%Y%m%d).json 2>/dev/null || true
```

### Rule/Action Backup via API

```bash
# Export rules
curl -X GET http://localhost:8081/api/v1/rules \
  -H "Authorization: Bearer $JWT_TOKEN" \
  > /backup/rules-$(date +%Y%m%d).json

# Export actions
curl -X GET http://localhost:8081/api/v1/actions \
  -H "Authorization: Bearer $JWT_TOKEN" \
  > /backup/actions-$(date +%Y%m%d).json

# Export correlation rules
curl -X GET http://localhost:8081/api/v1/correlation-rules \
  -H "Authorization: Bearer $JWT_TOKEN" \
  > /backup/correlation-rules-$(date +%Y%m%d).json
```

### Restore Procedures

**SQLite Restore**:
```bash
# Stop Cerberus
sudo systemctl stop cerberus

# Restore database
sudo cp /backup/cerberus-20250108.db /var/lib/cerberus/data/cerberus.db
sudo chown cerberus:cerberus /var/lib/cerberus/data/cerberus.db

# Start Cerberus
sudo systemctl start cerberus
```

**ClickHouse Restore**:
```bash
# Restore from backup
clickhouse-client --query "RESTORE DATABASE cerberus FROM Disk('backups', 'cerberus-20250108.zip')"
```

**Configuration Restore**:
```bash
sudo cp /backup/config-20250108.yaml /etc/cerberus/config.yaml
sudo systemctl restart cerberus
```

### Disaster Recovery Testing

**Quarterly Testing**:
1. Restore backup to test environment
2. Verify data integrity
3. Test application functionality
4. Document recovery time objective (RTO) and recovery point objective (RPO)

**RTO Target**: < 4 hours  
**RPO Target**: < 24 hours

---

## Troubleshooting

### Common Issues

**1. Service Won't Start**

**Symptoms**: `systemctl status cerberus` shows failed state

**Diagnosis**:
```bash
# Check logs
sudo journalctl -u cerberus -n 100

# Check configuration
sudo cerberus -config /etc/cerberus/config.yaml -validate

# Check file permissions
ls -la /etc/cerberus/
ls -la /var/lib/cerberus/
```

**Solutions**:
- Verify configuration file syntax (YAML parsing errors)
- Check file permissions (must be readable by cerberus user)
- Verify database directory exists and is writable
- Check ClickHouse connectivity

**2. High Memory Usage**

**Symptoms**: Process using >8GB RAM

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep cerberus
top -p $(pgrep cerberus)

# Check goroutine count
curl http://localhost:8081/metrics | grep go_goroutines

# Check cache sizes
curl http://localhost:8081/metrics | grep cerberus_cache
```

**Solutions**:
- Reduce cache sizes in configuration
- Increase `max_pool_size` for ClickHouse
- Review deduplication cache size
- Check for memory leaks (review recent code changes)

**3. High CPU Usage**

**Symptoms**: CPU usage >80% sustained

**Diagnosis**:
```bash
# Check CPU usage
top -p $(pgrep cerberus)

# Check regex timeout metrics
curl http://localhost:8081/metrics | grep regex_timeout

# Check event processing rate
curl http://localhost:8081/metrics | grep events_processed
```

**Solutions**:
- Review regex patterns (may be causing ReDoS)
- Increase regex timeout if legitimate patterns timing out
- Reduce event processing rate (add rate limiting)
- Scale horizontally (add more instances)

**4. ClickHouse Connection Errors**

**Symptoms**: "Failed to connect to ClickHouse" errors

**Diagnosis**:
```bash
# Test ClickHouse connectivity
clickhouse-client --host localhost --port 9000 --query "SELECT 1"

# Check ClickHouse logs
docker-compose logs clickhouse
# or
tail -f /var/log/clickhouse-server/clickhouse-server.log
```

**Solutions**:
- Verify ClickHouse is running
- Check network connectivity (firewall rules)
- Verify credentials in config.yaml
- Check ClickHouse disk space

**5. Slow Query Performance**

**Symptoms**: API queries taking >1s

**Diagnosis**:
```bash
# Check query metrics
curl http://localhost:8081/metrics | grep query_duration

# Enable query logging in ClickHouse
# Check ClickHouse slow query log
```

**Solutions**:
- Add indexes to ClickHouse tables
- Optimize CQL queries (avoid wildcards, use indexes)
- Increase ClickHouse resources (CPU, memory)
- Consider partitioning by date

### Log Locations

**Systemd (Binary Installation)**:
```bash
sudo journalctl -u cerberus -f
```

**Docker**:
```bash
docker-compose logs -f cerberus
```

**Kubernetes**:
```bash
kubectl logs -f deployment/cerberus -n cerberus
```

**Application Logs**:
- Format: Structured JSON
- Location: stdout/stderr (redirected to log aggregation)
- Level: Configured in `config.yaml` (default: info)

### Performance Tuning

**ClickHouse Optimizations**:
```sql
-- Add indexes
ALTER TABLE events ADD INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3;
ALTER TABLE events ADD INDEX idx_source source TYPE set(100) GRANULARITY 3;

-- Optimize table
OPTIMIZE TABLE events FINAL;
```

**SQLite Optimizations**:
```sql
-- PRAGMA settings (already configured in code)
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -10000;  -- 10 MB cache
PRAGMA mmap_size = 268435456;  -- 256 MB
```

**Application Tuning**:
```yaml
# Increase worker counts
engine:
  worker_count: 8  # Match CPU cores
  channel_buffer_size: 10000

# Increase batch sizes
clickhouse:
  batch_size: 2000  # Increase if memory allows
  flush_interval: 3  # seconds

# Adjust cache sizes
storage:
  dedup_cache_size: 20000  # Increase if memory allows
```

### Debug Mode Activation

**Temporary Debug Mode**:
```yaml
# config.yaml
logging:
  level: "debug"  # Enable debug logging
```

**Environment Variable**:
```bash
export CERBERUS_LOG_LEVEL=debug
```

**Warning**: Debug logging produces high volume - use only for troubleshooting, disable in production.

### Support Escalation Procedures

**1. Gather Diagnostics**:
```bash
# Collect system information
sudo systemctl status cerberus > diagnostics.txt
sudo journalctl -u cerberus -n 1000 >> diagnostics.txt
curl http://localhost:8081/health >> diagnostics.txt
curl http://localhost:8081/metrics >> diagnostics.txt

# Collect configuration (sanitize secrets)
sudo cat /etc/cerberus/config.yaml | sed 's/password:.*/password: [REDACTED]/' >> diagnostics.txt
```

**2. Contact Support**:
- Email: support@cerberus-siem.com
- Include: diagnostics.txt, error messages, reproduction steps

---

## Operational Procedures

### Start/Stop/Restart Procedures

**Systemd**:
```bash
# Start
sudo systemctl start cerberus

# Stop
sudo systemctl stop cerberus

# Restart
sudo systemctl restart cerberus

# Status
sudo systemctl status cerberus

# Enable on boot
sudo systemctl enable cerberus
```

**Docker**:
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# Status
docker-compose ps

# Logs
docker-compose logs -f cerberus
```

**Kubernetes**:
```bash
# Restart deployment
kubectl rollout restart deployment/cerberus -n cerberus

# Scale
kubectl scale deployment/cerberus --replicas=3 -n cerberus

# Status
kubectl get pods -n cerberus
```

### Rolling Updates/Upgrades

**Binary Installation**:
```bash
# 1. Backup current version
sudo cp /usr/local/bin/cerberus /usr/local/bin/cerberus.backup

# 2. Stop service
sudo systemctl stop cerberus

# 3. Install new binary
sudo cp cerberus-new /usr/local/bin/cerberus
sudo chmod +x /usr/local/bin/cerberus

# 4. Start service
sudo systemctl start cerberus

# 5. Verify
sudo systemctl status cerberus
curl http://localhost:8081/health

# 6. Rollback if needed
sudo systemctl stop cerberus
sudo cp /usr/local/bin/cerberus.backup /usr/local/bin/cerberus
sudo systemctl start cerberus
```

**Docker**:
```bash
# Pull new image
docker-compose pull

# Rolling update
docker-compose up -d --no-deps cerberus

# Verify
docker-compose ps
curl http://localhost:8081/health

# Rollback if needed
docker-compose pull cerberus:previous-version
docker-compose up -d --no-deps cerberus
```

**Kubernetes**:
```bash
# Update image
kubectl set image deployment/cerberus cerberus=cerberus:new-version -n cerberus

# Monitor rollout
kubectl rollout status deployment/cerberus -n cerberus

# Rollback if needed
kubectl rollout undo deployment/cerberus -n cerberus
```

### Database Migrations

**Automatic Migrations**:
- Migrations run automatically on startup
- Check migration logs for errors:
```bash
sudo journalctl -u cerberus | grep -i migration
```

**Manual Migration**:
```bash
# SQLite migrations are automatic
# ClickHouse schema changes require manual SQL execution
clickhouse-client --query "ALTER TABLE cerberus.events ADD COLUMN new_field String"
```

### Scaling Considerations

**Horizontal Scaling** (Multiple Instances):
- **Stateless**: API server is stateless (can scale horizontally)
- **Stateful**: Event ingestion can be scaled with load balancer
- **Database**: ClickHouse supports distributed tables
- **SQLite**: Single-instance (consider migration to PostgreSQL for multi-instance)

**Vertical Scaling** (Larger Instance):
- Increase CPU cores (improves concurrent processing)
- Increase RAM (larger caches, more concurrent connections)
- Use NVMe SSD (improves ClickHouse performance)

### Capacity Planning

**Event Storage**:
- Average event size: ~1 KB
- 10K EPS = 864 GB/day = 25.9 TB/month
- Plan for 3-6 months retention = 77-155 TB

**Alert Storage**:
- Average alert size: ~2 KB
- Estimate 1% alert rate = 100 alerts/sec = 17 GB/day = 510 GB/month
- Plan for 3-6 months retention = 1.5-3 TB

**Database Sizing**:
- SQLite: ~10 GB (users, rules, actions, investigations)
- ClickHouse: 100+ TB (events and alerts)

**Network Bandwidth**:
- 10K EPS × 1 KB = 10 MB/s ingress
- API traffic: ~1-5 MB/s (depends on usage)
- Total: ~15 MB/s = 120 Mbps

---

## Appendix

### Quick Reference

**Service Management**:
```bash
systemctl start|stop|restart|status cerberus
```

**Health Check**:
```bash
curl http://localhost:8081/health
```

**Metrics**:
```bash
curl http://localhost:8081/metrics
```

**Logs**:
```bash
journalctl -u cerberus -f
```

**Configuration**:
- Location: `/etc/cerberus/config.yaml`
- Validate: `cerberus -config /etc/cerberus/config.yaml -validate`

### Useful Commands

**Check Version**:
```bash
cerberus -version
```

**Database Size**:
```bash
du -sh /var/lib/cerberus/data/cerberus.db
```

**ClickHouse Table Sizes**:
```bash
clickhouse-client --query "SELECT table, formatReadableSize(sum(bytes)) FROM system.parts WHERE database='cerberus' GROUP BY table"
```

**Check Running Processes**:
```bash
ps aux | grep cerberus
```

**Check Network Connections**:
```bash
netstat -tlnp | grep cerberus
# or
ss -tlnp | grep cerberus
```

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Next Review**: 2025-04-XX


