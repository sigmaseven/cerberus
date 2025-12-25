# Cerberus Test Data Tools

This directory contains tools for generating, seeding, and managing test data for the Cerberus SIEM application.

## Overview

- **eventgen/** - Event generator CLI tool for creating realistic security events
- **rulegen/** - Pre-built detection and correlation rule templates
- **seed/** - Database seeding tool for initial data population
- **scenarios/** - Attack scenario definitions (coming soon)
- **alertsim/** - Alert lifecycle simulator (coming soon)
- **api/** - API test client library (coming soon)

---

## ⚠️ Windows Defender Notice

**Event Generator Build Issue**: Windows Defender may flag the event generator binary as a threat because it contains security testing strings (e.g., "mimikatz", "powershell -enc", etc.). This is a **false positive** - the tool only *generates test data* with these strings, it doesn't execute anything malicious.

### Solutions:

#### Option 1: Add Exclusion for bin/ Directory (Recommended)

1. Open **Windows Security** (Windows key → search "Windows Security")
2. Click **Virus & threat protection**
3. Scroll down to **Virus & threat protection settings** → **Manage settings**
4. Scroll to **Exclusions** → **Add or remove exclusions**
5. Click **Add an exclusion** → **Folder**
6. Navigate to and select: `C:\Users\sigma\cerberus\bin\`
7. Retry building: `go build -o bin/eventgen.exe tools/eventgen/*.go`

#### Option 2: Temporary Disable During Build

1. Open **Windows Security**
2. Click **Virus & threat protection**
3. Under **Virus & threat protection settings** → **Manage settings**
4. Temporarily turn off **Real-time protection**
5. Build the tool: `go build -o bin/eventgen.exe tools/eventgen/*.go`
6. **Re-enable Real-time protection immediately**

#### Option 3: Use Seed Tool (Workaround)

The seed tool (`bin/seed.exe`) includes event generation capabilities and builds without issue:

```bash
# Seed tool works perfectly
./bin/seed.exe --all
```

For live event generation, consider:
- Using the API directly with JSON/Syslog/CEF
- Running event generator on Linux/macOS (no detection issues)
- Building with sanitized strings (remove security tool names)

### Why This Happens

Security tools often flag executables containing:
- Security tool names: `mimikatz`, `nc.exe`, `meterpreter`
- Attack command patterns: `powershell -enc`, reverse shells
- Penetration testing strings: common exploit payloads

This is **expected behavior** for security testing tools. The event generator is safe and only creates JSON/Syslog event data.

---

## Quick Start

### 1. Build the Tools

```bash
# From cerberus root directory

# Build event generator
go build -o bin/eventgen.exe tools/eventgen/*.go

# Build seed tool
go build -o bin/seed.exe tools/seed/main.go
```

### 2. Seed Database with Initial Data

```bash
# Seed everything (rules, events, alerts, actions)
./bin/seed.exe --all

# Seed just rules
./bin/seed.exe --rules

# Seed specific number of events and alerts
./bin/seed.exe --events 1000 --alerts 50

# Clear existing data and reseed
./bin/seed.exe --all --clear
```

### 3. Generate Events

```bash
# Generate single event and print to stdout
./bin/eventgen.exe --mode single --output stdout

# Generate event stream (10 events/sec for 60 seconds)
./bin/eventgen.exe --mode stream --rate 10 --duration 60

# Generate attack scenario
./bin/eventgen.exe --mode scenario --scenario brute_force

# Generate to file instead of API
./bin/eventgen.exe --mode stream --rate 5 --duration 30 --output file
```

---

## Event Generator (`eventgen`)

### Overview

The event generator creates realistic security events in multiple formats. It can generate individual events, continuous streams, or pre-defined attack scenarios.

### Usage

```bash
eventgen [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `single` | Generation mode: `single`, `stream`, `scenario` |
| `--scenario` | - | Scenario name: `brute_force`, `port_scan`, `data_exfil`, `mixed_attack` |
| `--rate` | `1` | Events per second (stream mode) |
| `--duration` | `10` | Duration in seconds (stream mode) |
| `--count` | `1` | Number of events (single mode) |
| `--output` | `api` | Output: `api`, `syslog`, `cef`, `json`, `file`, `stdout` |
| `--api-url` | `http://localhost:8080/api/v1/events` | API endpoint |
| `--syslog-addr` | `localhost:514` | Syslog listener address |
| `--cef-addr` | `localhost:515` | CEF listener address |
| `--json-addr` | `localhost:8888` | JSON listener address |
| `--target-ip` | `192.0.2.50` | Target IP for scenarios |
| `--external-ip` | `198.51.100.25` | External IP for scenarios |

### Event Types Generated

1. **Authentication Events** - Login attempts (success/failure)
2. **Network Events** - Network connections (internal/external)
3. **File Events** - File system access (sensitive/normal)
4. **Process Events** - Process creation (suspicious/benign)
5. **HTTP Events** - Web requests (normal/attack patterns)

### Attack Scenarios

#### Brute Force Attack
```bash
./bin/eventgen.exe --mode scenario --scenario brute_force --target-ip 10.0.1.100
```

Generates:
- 50 failed authentication attempts from same IP
- 1 successful login after failures
- Triggers: `failed_login_brute_force` and `brute_force_then_success` rules

#### Port Scan
```bash
./bin/eventgen.exe --mode scenario --scenario port_scan --target-ip 10.0.1.50
```

Generates:
- 20 connection attempts to different ports
- All connections from same source IP
- Triggers: `port_scan_detection` rule

#### Data Exfiltration
```bash
./bin/eventgen.exe --mode scenario --scenario data_exfil --external-ip 203.0.113.50
```

Generates:
- 10 large data transfers (100MB each)
- All to external IP address
- Triggers: `large_data_transfer` rule

#### Mixed Attack
```bash
./bin/eventgen.exe --mode scenario --scenario mixed_attack
```

Generates:
- Combination of brute force and port scan
- Simulates multi-stage attack
- Triggers multiple rules and correlations

### Output Methods

#### API (Default)
```bash
./bin/eventgen.exe --output api --api-url http://localhost:8080/api/v1/events
```

Sends events via HTTP POST to Cerberus API.

#### Syslog
```bash
./bin/eventgen.exe --output syslog --syslog-addr localhost:514
```

Sends events in Syslog format via UDP.

#### CEF (Common Event Format)
```bash
./bin/eventgen.exe --output cef --cef-addr localhost:515
```

Sends events in CEF format via UDP.

#### JSON Listener
```bash
./bin/eventgen.exe --output json --json-addr localhost:8888
```

Sends raw JSON events via TCP to JSON listener.

#### File
```bash
./bin/eventgen.exe --output file
```

Appends events to `events.json` file.

#### Stdout
```bash
./bin/eventgen.exe --output stdout
```

Prints events to console (useful for debugging).

### Examples

**Generate normal activity baseline:**
```bash
./bin/eventgen.exe --mode stream --rate 5 --duration 300
```

**High-volume load test:**
```bash
./bin/eventgen.exe --mode stream --rate 1000 --duration 60
```

**Generate 100 events to file:**
```bash
./bin/eventgen.exe --mode single --count 100 --output file
```

**Test detection pipeline:**
```bash
# Terminal 1: Start Cerberus
./cerberus.exe

# Terminal 2: Generate brute force attack
./bin/eventgen.exe --mode scenario --scenario brute_force

# Check UI or API for alerts
curl http://localhost:8080/api/v1/alerts
```

---

## Seed Tool (`seed`)

### Overview

The seed tool populates MongoDB with initial test data including rules, events, alerts, and actions.

### Usage

```bash
seed [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Seed all data types |
| `--events` | `0` | Number of events to seed |
| `--alerts` | `0` | Number of alerts to seed |
| `--rules` | `false` | Seed detection and correlation rules |
| `--actions` | `false` | Seed actions |
| `--clear` | `false` | Clear existing data before seeding |
| `--mongo-uri` | `mongodb://localhost:27017` | MongoDB URI |
| `--database` | `cerberus` | Database name |

### What Gets Seeded

#### Detection Rules (10 rules)
- Failed login brute force detection
- Successful login tracking
- Sensitive file access
- Port scan detection
- Large data transfer
- SQL injection attempts
- Privileged command execution
- Suspicious PowerShell
- RDP connections
- SMB connections

#### Correlation Rules (5 rules)
- Brute force → Successful login
- RDP → SMB (lateral movement)
- Port scan → Connection (reconnaissance to exploit)
- File access → Data transfer (data exfiltration)
- File access → Privilege escalation

#### Events
- Realistic event data spread over last 24 hours
- Multiple event types (auth, network, file, process, HTTP)
- Various severities and source IPs

#### Alerts
- Different alert statuses (new, acknowledged, investigating, resolved)
- Workflow data (acknowledgment, assignment, resolution)
- Status history tracking
- Various severities

#### Actions
- Email notification
- Webhook integration
- Slack notification

### Examples

**Seed everything:**
```bash
./bin/seed.exe --all
```

**Seed 1000 events and 100 alerts:**
```bash
./bin/seed.exe --events 1000 --alerts 100
```

**Fresh start (clear and reseed):**
```bash
./bin/seed.exe --all --clear
```

**Seed just rules:**
```bash
./bin/seed.exe --rules
```

**Custom MongoDB connection:**
```bash
./bin/seed.exe --all --mongo-uri mongodb://user:pass@remote:27017 --database cerberus_test
```

---

## Rule Templates (`rulegen/rules/`)

### Pre-built Rule Sets

#### Detection Rules: `detection_rules.json`

Contains 10 pre-configured detection rules covering:
- Authentication attacks
- Network anomalies
- File system access
- Process execution
- Web attacks

**Usage:**
```bash
# Rules are automatically loaded by seed tool
./bin/seed.exe --rules

# Or manually import via API
curl -X POST http://localhost:8080/api/v1/rules/import \
  -H "Content-Type: application/json" \
  -d @tools/rulegen/rules/detection_rules.json
```

#### Correlation Rules: `correlation_rules.json`

Contains 5 correlation rules for detecting:
- Credential compromise (brute force → success)
- Lateral movement (RDP → SMB)
- Attack progression (recon → exploit)
- Data exfiltration (file access → transfer)
- Privilege escalation chains

**Usage:**
```bash
# Import via seed tool
./bin/seed.exe --rules

# Or manually via API
curl -X POST http://localhost:8080/api/v1/correlation_rules/import \
  -H "Content-Type: application/json" \
  -d @tools/rulegen/rules/correlation_rules.json
```

---

## Testing Workflows

### End-to-End Detection Testing

```bash
# 1. Clear and seed fresh data
./bin/seed.exe --all --clear

# 2. Start Cerberus
./cerberus.exe

# 3. Generate attack scenario
./bin/eventgen.exe --mode scenario --scenario brute_force

# 4. Check for alerts (should see 2 alerts)
curl http://localhost:8080/api/v1/alerts | jq
# Expected: failed_login_brute_force + brute_force_then_success

# 5. Acknowledge alert via API
ALERT_ID=$(curl -s http://localhost:8080/api/v1/alerts | jq -r '.items[0].alert_id')
curl -X POST http://localhost:8080/api/v1/alerts/$ALERT_ID/status \
  -H "Content-Type: application/json" \
  -d '{"status":"acknowledged","user":"analyst1","note":"Investigating"}'
```

### Performance Testing

```bash
# 1. Start Cerberus with monitoring
./cerberus.exe

# 2. Generate high-volume event stream
./bin/eventgen.exe --mode stream --rate 1000 --duration 60

# 3. Monitor metrics
curl http://localhost:8080/api/v1/stats | jq

# 4. Check system resources
# - CPU usage should scale with event_worker_count
# - Memory should remain stable
# - No dropped events
```

### Correlation Rule Testing

```bash
# 1. Ensure correlation rules loaded
./bin/seed.exe --rules

# 2. Generate scenario that triggers correlation
./bin/eventgen.exe --mode scenario --scenario brute_force

# 3. Wait for correlation window (5 minutes)
# Events must occur within correlation time window

# 4. Check for correlated alert
curl http://localhost:8080/api/v1/alerts | jq '.items[] | select(.rule_id == "brute_force_then_success")'
```

---

## Troubleshooting

### Events Not Appearing

**Check Cerberus is running:**
```bash
curl http://localhost:8080/api/v1/health
```

**Verify listeners are active:**
```bash
netstat -an | grep 514  # Syslog
netstat -an | grep 515  # CEF
netstat -an | grep 8888 # JSON
```

**Check event generator output:**
```bash
# Use stdout to see what's being generated
./bin/eventgen.exe --mode single --output stdout
```

### Alerts Not Triggering

**Verify rules are loaded:**
```bash
curl http://localhost:8080/api/v1/rules | jq
```

**Check rule enabled status:**
```bash
curl http://localhost:8080/api/v1/rules | jq '.[] | select(.enabled == false)'
```

**Generate events that match rule conditions:**
```bash
# Use pre-built scenarios designed to trigger rules
./bin/eventgen.exe --mode scenario --scenario brute_force
```

**Check detection engine logs:**
```bash
# Look for rule evaluation messages in Cerberus output
```

### Seed Tool Errors

**MongoDB not accessible:**
```bash
# Test connection
mongo mongodb://localhost:27017

# Or with seed tool
./bin/seed.exe --mongo-uri mongodb://localhost:27017 --events 1
```

**Rule file not found:**
```bash
# Ensure running from cerberus root directory
cd /path/to/cerberus
./bin/seed.exe --rules
```

**Duplicate key errors:**
```bash
# Clear existing data first
./bin/seed.exe --all --clear
```

---

## Advanced Usage

### Custom Event Generation

Modify `tools/eventgen/generator.go` to add custom event types or fields:

```go
// Add custom event generator
func (g *EventGenerator) GenerateCustomEvent() Event {
    // Your custom logic here
}
```

### Custom Rule Templates

Create new rule files in `tools/rulegen/rules/`:

```bash
# Create custom rule set
cat > tools/rulegen/rules/custom_rules.json << 'EOF'
[
  {
    "id": "my_custom_rule",
    "name": "Custom Detection Rule",
    ...
  }
]
EOF

# Import manually
curl -X POST http://localhost:8080/api/v1/rules/import \
  -d @tools/rulegen/rules/custom_rules.json
```

### Programmatic Event Generation

Use the event generator as a library:

```go
package main

import "cerberus/tools/eventgen"

func main() {
    gen := eventgen.NewEventGenerator()

    // Generate specific event
    event := gen.GenerateAuthEvent(false)

    // Generate scenario
    events := gen.GenerateBruteForceScenario("10.0.1.100", 50)
}
```

---

## Roadmap

### Phase 2: Scenarios (Week 2)
- [ ] YAML-based scenario definitions
- [ ] Scenario runner tool
- [ ] More complex attack chains
- [ ] Scenario validation

### Phase 3: Alert Lifecycle (Week 3)
- [ ] Alert simulator tool
- [ ] Workflow automation
- [ ] Bulk operations testing
- [ ] API client library

### Phase 4: Performance (Week 4)
- [ ] Load testing scenarios
- [ ] Metrics collection
- [ ] Performance benchmarks
- [ ] Resource monitoring

### Phase 5: Advanced (Week 5)
- [ ] Threat intel integration tests
- [ ] Multi-tenant test data
- [ ] Chaos testing
- [ ] Automated regression tests

---

## Contributing

To add new test data generators or scenarios:

1. Create new tool in `tools/` directory
2. Follow existing patterns for CLI flags and output
3. Update this README with usage documentation
4. Add examples and testing workflows

---

## Support

For questions or issues:
- Check troubleshooting section above
- Review Cerberus logs for errors
- Create issue in GitHub repository

**Last Updated**: 2024-11-04
**Version**: 1.0
