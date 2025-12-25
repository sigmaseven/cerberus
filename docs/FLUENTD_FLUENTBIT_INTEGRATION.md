# Fluentd and Fluent Bit Integration Guide

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Field Mapping](#field-mapping)
5. [Deployment Scenarios](#deployment-scenarios)
6. [Security](#security)
7. [Troubleshooting](#troubleshooting)
8. [Performance Tuning](#performance-tuning)
9. [Examples](#examples)

---

## Overview

Cerberus now supports native ingestion from Fluentd and Fluent Bit log shippers via the Forward protocol. This integration enables:

- **Centralized Log Collection**: Collect logs from distributed systems
- **Kubernetes Integration**: Native support for container log collection
- **SIGMA Field Normalization**: Automatic mapping to SIGMA taxonomy
- **High Performance**: MessagePack binary protocol with compression
- **Security**: TLS encryption and shared key authentication
- **Reliability**: Acknowledgment-based guaranteed delivery

### Protocol Support

Cerberus implements the complete Fluentd Forward protocol:
- **Message Mode**: Single event transmission
- **Forward Mode**: Batch event transmission
- **PackedForward Mode**: Binary-packed batch transmission
- **CompressedPackedForward Mode**: Gzip-compressed batch transmission

---

## Quick Start

### Enable Fluentd/Fluent Bit Listeners

Edit `config.yaml`:

```yaml
listeners:
  fluentd:
    enabled: true
    port: 24224
    host: "0.0.0.0"
    worker_count: 8

  fluentbit:
    enabled: true
    port: 24225
    host: "0.0.0.0"
    worker_count: 8
    require_ack: true
```

Restart Cerberus:

```bash
./cerberus
```

### Configure Fluentd Client

Create `/etc/fluentd/fluent.conf`:

```
<source>
  @type tail
  path /var/log/syslog
  tag syslog.system
  <parse>
    @type syslog
  </parse>
</source>

<match **>
  @type forward
  <server>
    host cerberus.example.com
    port 24224
  </server>
</match>
```

Start Fluentd:

```bash
fluentd -c /etc/fluentd/fluent.conf
```

### Configure Fluent Bit Client

Create `/etc/fluent-bit/fluent-bit.conf`:

```
[INPUT]
    Name        tail
    Path        /var/log/syslog
    Tag         syslog.system

[OUTPUT]
    Name        forward
    Match       *
    Host        cerberus.example.com
    Port        24225
```

Start Fluent Bit:

```bash
fluent-bit -c /etc/fluent-bit/fluent-bit.conf
```

### Verify Ingestion

Check Cerberus logs:

```bash
tail -f cerberus.log | grep "Fluentd\|FluentBit"
```

Query events via API:

```bash
curl http://localhost:8080/api/v1/events?source=fluentd&limit=10
curl http://localhost:8080/api/v1/events?source=fluentbit&limit=10
```

---

## Configuration

### Cerberus Configuration Options

#### Fluentd Listener

```yaml
listeners:
  fluentd:
    enabled: true              # Enable Fluentd listener
    port: 24224                # Port (standard: 24224)
    host: "0.0.0.0"           # Bind address
    protocol: "tcp"            # Protocol: tcp or tls
    tls: false                 # Enable TLS
    cert_file: "server.crt"   # TLS certificate
    key_file: "server.key"    # TLS private key
    worker_count: 8            # Parallel parsing workers
    shared_key: ""             # Shared key for authentication
    require_ack: false         # Require acknowledgments
    chunk_size_limit: 8388608  # Max chunk size (8MB)
```

#### Fluent Bit Listener

```yaml
listeners:
  fluentbit:
    enabled: true              # Enable Fluent Bit listener
    port: 24225                # Port (use different from Fluentd)
    host: "0.0.0.0"           # Bind address
    protocol: "tcp"            # Protocol: tcp or tls
    tls: false                 # Enable TLS
    cert_file: "server.crt"   # TLS certificate
    key_file: "server.key"    # TLS private key
    worker_count: 8            # Parallel parsing workers
    shared_key: ""             # Shared key for authentication
    require_ack: true          # Require acknowledgments (recommended)
    chunk_size_limit: 8388608  # Max chunk size (8MB)
```

---

## Field Mapping

Cerberus automatically maps Fluentd/Fluent Bit fields to SIGMA standard taxonomy.

### Kubernetes Fields

| Source Field | SIGMA Field | Description |
|-------------|-------------|-------------|
| `kubernetes.pod_name` | `HostName` | Pod name |
| `kubernetes.namespace_name` | `k8s_namespace` | Kubernetes namespace |
| `kubernetes.container_name` | `Process.Name` | Container name |
| `kubernetes.container_id` | `k8s_container_id` | Container ID |
| `kubernetes.labels.app` | `k8s_labels.app` | App label |
| `log` | `Message` | Log message |

### Docker Fields

| Source Field | SIGMA Field | Description |
|-------------|-------------|-------------|
| `container_id` | `Process.ProcessId` | Container ID |
| `container_name` | `Process.Name` | Container name |
| `log` | `Message` | Log message |
| `source` | `docker_source` | Log source (stdout/stderr) |

### Syslog Fields

| Source Field | SIGMA Field | Description |
|-------------|-------------|-------------|
| `host` | `HostName` | Hostname |
| `ident` | `Process.Name` | Process name |
| `pid` | `Process.ProcessId` | Process ID |
| `message` | `Message` | Syslog message |
| `facility` | `syslog_facility` | Syslog facility |
| `severity` | `syslog_severity` | Syslog severity |

### Apache/Nginx Access Logs

| Source Field | SIGMA Field | Description |
|-------------|-------------|-------------|
| `host` / `remote_addr` | `SourceIP` | Client IP address |
| `user` / `remote_user` | `User.Name` | Authenticated user |
| `method` / `request_method` | `Network.Protocol` | HTTP method |
| `path` / `request_uri` | `http_path` | Request path |
| `code` / `status` | `http_status_code` | HTTP status code |

---

## Deployment Scenarios

### Scenario 1: Standalone Server

Deploy Fluentd on a single server to collect system logs:

```conf
<source>
  @type tail
  path /var/log/syslog
  tag syslog.system
  <parse>
    @type syslog
  </parse>
</source>

<match **>
  @type forward
  <server>
    host cerberus.example.com
    port 24224
  </server>
</match>
```

### Scenario 2: Docker Environment

Configure Docker to use Fluentd log driver:

Edit `/etc/docker/daemon.json`:

```json
{
  "log-driver": "fluentd",
  "log-opts": {
    "fluentd-address": "localhost:24225",
    "tag": "docker.{{.Name}}"
  }
}
```

Restart Docker:

```bash
sudo systemctl restart docker
```

### Scenario 3: Kubernetes Cluster

Deploy Fluent Bit as DaemonSet:

```bash
kubectl apply -f examples/kubernetes/fluent-bit-daemonset.yaml
```

This deploys Fluent Bit on every node to collect container logs.

### Scenario 4: Multi-Region

Deploy Fluentd aggregators in each region that forward to Cerberus:

```conf
# Regional Fluentd aggregator
<source>
  @type forward
  port 24224
</source>

<filter **>
  @type record_transformer
  <record>
    region us-east-1
  </record>
</filter>

<match **>
  @type forward
  <server>
    host cerberus-central.example.com
    port 24224
  </server>
</match>
```

---

## Security

### Enable TLS

#### Generate Certificates

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Generate client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

#### Configure Cerberus

```yaml
listeners:
  fluentd:
    enabled: true
    port: 24224
    tls: true
    cert_file: "server.crt"
    key_file: "server.key"
    shared_key: "your-secure-shared-key"
```

#### Configure Fluentd

```conf
<match **>
  @type forward
  <server>
    host cerberus.example.com
    port 24224
  </server>

  transport tls
  tls_cert_path /etc/fluentd/certs/ca.crt
  tls_client_cert_path /etc/fluentd/certs/client.crt
  tls_client_private_key_path /etc/fluentd/certs/client.key

  <security>
    self_hostname "#{Socket.gethostname}"
    shared_key your-secure-shared-key
  </security>
</match>
```

#### Configure Fluent Bit

```conf
[OUTPUT]
    Name        forward
    Match       *
    Host        cerberus.example.com
    Port        24224

    tls         On
    tls.verify  On
    tls.ca_file /etc/fluent-bit/certs/ca.crt
    tls.crt_file /etc/fluent-bit/certs/client.crt
    tls.key_file /etc/fluent-bit/certs/client.key

    Shared_Key  your-secure-shared-key
```

### Firewall Configuration

Open ports on Cerberus server:

```bash
# Fluentd
sudo ufw allow 24224/tcp

# Fluent Bit
sudo ufw allow 24225/tcp
```

---

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to Cerberus

**Solutions**:
1. Check if listener is enabled in `config.yaml`
2. Verify port is open: `nc -zv cerberus.example.com 24224`
3. Check firewall rules
4. Review Cerberus logs for errors

### Authentication Failures

**Problem**: HELO/PING/PONG authentication fails

**Solutions**:
1. Verify shared key matches on both sides
2. Check TLS certificate validity
3. Review Cerberus logs for authentication errors

### Events Not Appearing

**Problem**: Logs are sent but don't appear in Cerberus

**Solutions**:
1. Check parsing errors in Cerberus logs
2. Verify event source: `curl http://localhost:8080/api/v1/events?limit=10`
3. Check detection rules aren't dropping events
4. Verify buffer isn't full

### Performance Issues

**Problem**: High CPU/memory usage or slow ingestion

**Solutions**:
1. Increase `worker_count` in `config.yaml`
2. Enable compression in Fluentd/Fluent Bit
3. Increase buffer sizes
4. Use PackedForward mode for batching

---

## Performance Tuning

### Cerberus Configuration

```yaml
listeners:
  fluentd:
    worker_count: 16          # Increase for high throughput
    chunk_size_limit: 16777216 # 16MB for larger batches

engine:
  channel_buffer_size: 20000   # Increase buffer size
  rate_limit: 200000           # Increase rate limit

clickhouse:
  batch_size: 100000           # Larger batches
  flush_interval: 2            # Faster flushes
```

### Fluentd Configuration

```conf
<match **>
  @type forward
  <server>
    host cerberus.example.com
    port 24224
  </server>

  # Compress for network efficiency
  compress gzip

  # Large buffer for batch sending
  <buffer>
    @type file
    path /var/log/fluentd/buffer/cerberus
    flush_mode interval
    flush_interval 5s
    chunk_limit_size 10M
    total_limit_size 1G
    overflow_action block
  </buffer>
</match>
```

### Fluent Bit Configuration

```conf
[OUTPUT]
    Name        forward
    Match       *
    Host        cerberus.example.com
    Port        24225

    # Multiple workers for parallel sending
    Workers     4

    # Retry configuration
    Retry_Limit 10
```

### Expected Throughput

| Scenario | Events/Second | Notes |
|----------|--------------|-------|
| Single instance, TCP | 10,000-20,000 | Basic setup |
| Single instance, compressed | 30,000-50,000 | With gzip |
| Multiple workers | 50,000-100,000 | worker_count=16 |
| Kubernetes cluster | 100,000+ | Multiple Fluent Bit pods |

---

## Examples

### Example 1: Kubernetes Logs to Cerberus

Deploy the complete stack:

```bash
# Deploy Cerberus
kubectl apply -f examples/kubernetes/cerberus-deployment.yaml

# Deploy Fluent Bit DaemonSet
kubectl apply -f examples/kubernetes/fluent-bit-daemonset.yaml

# Verify deployment
kubectl get pods -n logging
kubectl get pods -n cerberus

# Check logs
kubectl logs -n cerberus deployment/cerberus
kubectl logs -n logging daemonset/fluent-bit

# Query events
kubectl port-forward -n cerberus svc/cerberus 8080:8080
curl http://localhost:8080/api/v1/events?source=fluentbit&limit=10
```

### Example 2: Docker Logs

Configure Docker to send logs:

```bash
# Configure Docker daemon
sudo tee /etc/docker/daemon.json <<EOF
{
  "log-driver": "fluentd",
  "log-opts": {
    "fluentd-address": "cerberus.example.com:24224",
    "tag": "docker.{{.Name}}"
  }
}
EOF

# Restart Docker
sudo systemctl restart docker

# Run a test container
docker run --rm alpine echo "Test log from Docker"

# Verify in Cerberus
curl http://cerberus.example.com:8080/api/v1/events?source=fluentd&limit=10
```

### Example 3: Web Server Logs

Configure Fluentd to parse Apache/Nginx logs:

```conf
# Use the provided example
cp examples/fluentd/webserver.conf /etc/fluentd/fluent.conf

# Start Fluentd
sudo systemctl start fluentd

# Generate test traffic
curl http://localhost/admin  # Should trigger security alert

# Check Cerberus for alerts
curl http://cerberus.example.com:8080/api/v1/alerts?limit=10
```

### Example 4: Integration Testing

Run the integration test suite:

```bash
# Install dependencies
pip install msgpack requests

# Run tests
python tests/test_fluentd_integration.py --host cerberus.example.com --test all

# Run with shell script
bash tests/test_fluentd_integration.sh
```

---

## Additional Resources

- [Fluentd Documentation](https://docs.fluentd.org/)
- [Fluent Bit Documentation](https://docs.fluentbit.io/)
- [SIGMA Specification](https://github.com/SigmaHQ/sigma)
- [Cerberus Architecture Guide](ARCHITECTURE.md)
- [Field Mapping Configuration](../config/fluentd_field_mappings.yaml)

---

## Support

For issues or questions:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review Cerberus logs: `tail -f cerberus.log`
3. Enable debug logging: Set `Log_Level debug` in Fluentd/Fluent Bit
4. Open an issue on GitHub

---

## License

This integration is part of Cerberus SIEM and follows the same license.
