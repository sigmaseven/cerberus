# Cerberus SIEM

Cerberus is a lightweight, high-performance Security Information and Event Management (SIEM) system built in Go. It ingests security events from various sources, applies detection rules, generates alerts, and orchestrates responses through configurable actions. Designed for scalability, Cerberus supports real-time event processing with built-in metrics, data retention, and disaster recovery features.

## Features

- **Multi-Protocol Ingestion**: Supports Syslog (TCP/UDP), CEF (TCP/UDP), and JSON (HTTP/UDP) event sources.
- **Advanced Rule-Based Detection**: JSON-configurable rules with logical operators, plus correlation rules for multi-event patterns.
- **Alert Management**: Automatic alert generation with acknowledge/dismiss functionality and severity levels.
- **Real-Time Dashboard**: Web-based UI for monitoring events, alerts, and system status with auto-refresh.
- **Orchestration & Response**: Execute actions like webhooks, Jira ticket creation, Slack notifications, and email alerts.
- **Data Retention & Recovery**: Configurable retention policies and event replay for disaster recovery.
- **Security**: Authentication, rate limiting, and secrets management.
- **Metrics & Monitoring**: Prometheus-compatible metrics for events, alerts, and performance.
- **Data Management**: Event deduplication, batching, dead-letter queues, and GDPR-compliant retention cleanup.
- **Scalability**: Concurrent processing with configurable workers and rate limiting.
- **Deployment Ready**: Docker and Kubernetes support for easy deployment.

## Installation

### Prerequisites

- Go 1.24 or later
- MongoDB (for event and alert storage)
- (Optional) Prometheus for metrics scraping

### Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/cerberus.git
   cd cerberus
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Build the binary:
   ```bash
   go build -o cerberus .
   ```

### Docker Build

```bash
docker build -t cerberus .
```

## Configuration

Cerberus uses a JSON configuration file (`config.json`) for settings. Place it in the working directory or specify via environment variables.

### Sample `config.json`

```json
{
  "mongodb": {
    "enabled": true,
    "uri": "mongodb://localhost:27017",
    "database": "cerberus"
  },
  "listeners": {
    "syslog": {
      "port": 514,
      "host": "0.0.0.0"
    },
    "cef": {
      "port": 515,
      "host": "0.0.0.0"
    },
    "json": {
      "port": 8080,
      "host": "0.0.0.0",
      "tls": false
    },
    "skip_on_error": false
  },
  "api": {
    "version": "v1",
    "port": 8081
  },
  "auth": {
    "enabled": false,
    "username": "admin",
    "password": "password"
  },
  "rules": {
    "file": "rules.json"
  },
  "correlation_rules": {
    "file": "correlation_rules.json"
  },
  "retention": {
    "events": 30,
    "alerts": 90
  }
}
```

### Environment Variables

Override config with `CERBERUS_` prefixed env vars, e.g., `CERBERUS_MONGODB_URI=mongodb://...`.

## Event Listener Setup and Configuration

Cerberus listens for events on configured ports. Each listener supports TCP and UDP for reliability.

### Syslog Listener

- **Protocol**: Syslog RFC 5424
- **Ports**: TCP/UDP on configured port (default 514)
- **Configuration**: Set `listeners.syslog.port` and `host`.
- **Usage**: Send Syslog messages to the port. Events are parsed and stored.

Example Syslog message:
```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
```

### CEF Listener

- **Protocol**: Common Event Format
- **Ports**: TCP/UDP on configured port (default 515)
- **Configuration**: Set `listeners.cef.port` and `host`.
- **Usage**: Send CEF-formatted events.

Example CEF message:
```
CEF:0|Test|Test|1.0|100|Test Event|10|src=192.168.1.1 suser=admin
```

### JSON Listener

- **Protocol**: JSON over HTTP POST or UDP
- **Ports**: HTTP on configured port (default 8080), UDP on same port
- **Configuration**: Set `listeners.json.port`, `host`, and `tls` (for HTTPS).
- **Usage**: POST JSON to `/api/v1/ingest/json` or send UDP packets.

Example JSON event:
```json
{
  "event_type": "user_login",
  "fields": {
    "status": "failure",
    "user": "testuser"
  }
}
```

### Listener Features

- **Rate Limiting**: 1000 EPS per listener.
- **Deduplication**: Prevents duplicate events based on hash.
- **Batching**: Inserts events in batches for performance.

## Detection Rule Setup and Configuration

Rules are defined in `rules.json` for single-event detection and `correlation_rules.json` for multi-event correlation patterns. All rules are validated against JSON schemas for security.

### Sample `rules.json`

```json
{
  "rules": [
    {
      "id": "failed_login",
      "name": "Failed User Login",
      "description": "Detects multiple failed login attempts",
      "severity": "Warning",
      "version": "1.0",
      "enabled": true,
      "conditions": [
        {
          "field": "event_type",
          "operator": "equals",
          "value": "user_login",
          "logic": "AND"
        },
        {
          "field": "fields.status",
          "operator": "equals",
          "value": "failure",
          "logic": "AND"
        }
      ],
      "actions": [
        {
          "type": "webhook",
          "config": {
            "url": "https://example.com/webhook"
          }
        }
      ]
    },
    {
      "id": "admin_access",
      "name": "Admin Access Detected",
      "description": "Alerts on admin user access",
      "severity": "Critical",
      "version": "1.0",
      "enabled": true,
      "conditions": [
        {
          "field": "fields.user",
          "operator": "contains",
          "value": "admin",
          "logic": "AND"
        }
      ],
      "actions": [
        {
          "type": "jira",
          "config": {
            "base_url": "https://your-jira.atlassian.net",
            "username": "user",
            "token": "token",
            "project": "SEC"
          }
        }
      ]
    }
  ]
}
```

### Rule Structure

- **id**: Unique identifier.
- **name/description**: Human-readable info.
- **severity**: Low, Medium, High, Critical.
- **enabled**: true/false.
- **conditions**: List of field-operator-value with logic (AND/OR).
- **actions**: List of actions to execute on match.

### Operators

- `equals`, `contains`, `not_equals`, `starts_with`, `greater_than`, `less_than`.

### Correlation Rules

Correlation rules detect patterns across multiple events within a time window. Defined in `correlation_rules.json`.

#### Sample `correlation_rules.json`

```json
{
  "rules": [
    {
      "id": "brute_force_attack",
      "name": "Brute Force Attack Detection",
      "description": "Detects multiple failed logins followed by a successful login",
      "severity": "High",
      "version": 1,
      "window": 300000000000,
      "sequence": ["user_login", "user_login", "user_login"],
      "conditions": [],
      "actions": [
        {
          "type": "webhook",
          "config": {
            "url": "https://example.com/alert"
          }
        }
      ]
    }
  ]
}
```

- **window**: Time window in nanoseconds (e.g., 300000000000 = 5 minutes)
- **sequence**: Ordered list of event types to match
- **conditions**: Optional additional conditions on the triggering event

### Adding Rules

1. Edit `rules.json` or `correlation_rules.json` (ensure they conform to their respective schemas).
2. Restart Cerberus to reload rules.
3. Use the web UI at `http://localhost:8081` to manage rules interactively.

## Orchestration Setup and Usage

Orchestration handles alert responses via actions.

### Supported Actions

- **Webhook**: POST alert JSON to a URL.
- **Jira**: Create tickets in Jira.
- **Slack**: Send messages to Slack channels.
- **Email**: Send email notifications.

### Action Configuration

Configure in `rules.json` under `actions`.

Example Webhook:
```yaml
actions:
  - type: "webhook"
    config:
      url: "https://webhook.site/..."
```

Example Jira:
```yaml
actions:
  - type: "jira"
    config:
      base_url: "https://your-jira.atlassian.net"
      username: "your-email"
      token: "api-token"
      project: "PROJECT_KEY"
```

Example Slack:
```yaml
actions:
  - type: "slack"
    config:
      webhook_url: "https://hooks.slack.com/services/..."
```

Example Email:
```yaml
actions:
  - type: "email"
    config:
      smtp_server: "smtp.gmail.com"
      port: 587
      username: "your-email@gmail.com"
      password: "app-password"
      from: "your-email@gmail.com"
      to: "alerts@company.com"
```

### Usage

Actions execute asynchronously on rule matches. Metrics track execution success.

## Running Cerberus

1. Ensure MongoDB is running (if using persistent storage).
2. Run the binary:
   ```bash
   ./cerberus
   ```
3. Access the web UI at `http://localhost:8081` (requires MongoDB enabled).
4. Health check: `curl http://localhost:8081/health`
5. Metrics: `curl http://localhost:8081/metrics` (if Prometheus enabled)

### Docker Run

```bash
docker run -p 514:514/udp -p 515:515/tcp -p 8080:8080 -p 8081:8081 -v $(pwd)/config.yaml:/app/config.yaml -v $(pwd)/rules.json:/app/rules.json -v $(pwd)/rules_schema.json:/app/rules_schema.json cerberus
```

### Docker Compose

For a complete setup with MongoDB:

```bash
docker-compose up -d
```

This starts Cerberus and MongoDB with proper networking.

### Kubernetes Deployment

Use `k8s/deployment.yaml` for K8s deployment.

## API Endpoints

**Note**: API server only starts when MongoDB is enabled in config.

- `GET /health`: Health status.
- `GET /api/events`: List events.
- `GET /api/alerts`: List alerts.
- `POST /api/alerts/{id}/acknowledge`: Acknowledge an alert.
- `POST /api/alerts/{id}/dismiss`: Dismiss an alert.
- `GET /api/rules`: List all detection rules.
- `POST /api/rules`: Create a new detection rule.
- `GET /api/rules/{id}`: Get a specific detection rule.
- `PUT /api/rules/{id}`: Update a detection rule.
- `DELETE /api/rules/{id}`: Delete a detection rule.
- `GET /api/correlation-rules`: List all correlation rules.
- `POST /api/correlation-rules`: Create a new correlation rule.
- `GET /api/correlation-rules/{id}`: Get a specific correlation rule.
- `PUT /api/correlation-rules/{id}`: Update a correlation rule.
- `DELETE /api/correlation-rules/{id}`: Delete a correlation rule.
- `GET /api/actions`: List all actions.
- `POST /api/actions`: Create a new action.
- `GET /api/actions/{id}`: Get a specific action.
- `PUT /api/actions/{id}`: Update an action.
- `DELETE /api/actions/{id}`: Delete an action.
- `GET /api/listeners`: Get current listener configuration.
- `GET /metrics`: Prometheus metrics.

## Monitoring

- **Metrics**: Events ingested, alerts generated, actions executed, processing duration.
- **Logs**: Zap-based logging.
- **Retention**: Configure cleanup in code (e.g., 30 days).

## Troubleshooting

- **API Not Starting**: Check that MongoDB is enabled in `config.json`. Cerberus will log a warning if the API server is not started due to disabled MongoDB.
- **Listener Issues**: Check ports are free and not blocked by firewall.
- **DB Errors**: Verify MongoDB connection string and that MongoDB is running.
- **Rule Not Matching**: Validate JSON syntax and fields against schema. Use the web UI to test rules.
- **Shutdown Hangs**: Ensure MongoDB is accessible; otherwise, the system runs in memory-only mode.

## Contributing

1. Fork the repo.
2. Create a feature branch.
3. Submit a PR.

## License

MIT License. See LICENSE file.