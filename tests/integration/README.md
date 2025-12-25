# Integration Tests

This directory contains end-to-end integration tests for the Cerberus SIEM system.

## Overview

Integration tests verify complete workflows across multiple components:
- Event ingestion pipeline (syslog, CEF, JSON)
- Detection engine and alert generation
- Alert lifecycle management
- Search functionality (CQL queries)
- ML pipeline (feature extraction, training, prediction)
- SOAR playbook execution

## Prerequisites

### Docker
Integration tests use Testcontainers which requires Docker:
- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker must be running before executing tests

### Go Version
- Go 1.24.0 or later

### Testcontainers
The project uses `github.com/testcontainers/testcontainers-go` which is already included in `go.mod`.

## Running Tests

### Run All Integration Tests
```bash
go test ./tests/integration/... -v
```

### Run Specific Test
```bash
go test ./tests/integration/... -v -run TestEventPipeline_SyslogIngestion
```

### Run with Race Detector
```bash
go test ./tests/integration/... -race -v
```

### Run with Coverage
```bash
go test ./tests/integration/... -coverprofile=coverage.out -cover
go tool cover -html=coverage.out -o coverage.html
```

## Test Infrastructure

### Testcontainers
Tests use Testcontainers to spin up isolated Docker containers:
- **ClickHouse**: For event and alert storage
- **Miniredis**: In-memory Redis server for caching (no container needed)

### Test Helpers
- `helpers.go`: Testcontainers setup and infrastructure management
- `fixtures.go`: Test data generators (events, alerts, rules, etc.)

## Test Structure

### Event Pipeline Tests (`event_pipeline_test.go`)
- Syslog event ingestion → detection → alert generation
- CEF event ingestion
- JSON event ingestion via HTTP
- Concurrent event ingestion
- Malformed event handling (DLQ)
- Rule matching and non-matching scenarios

### Alert Lifecycle Tests (`alert_lifecycle_e2e_test.go`)
- Alert creation
- Status transitions (pending → acknowledged → investigating → resolved → closed)
- Alert assignment to analysts
- Investigation creation
- Alert deduplication
- Bulk operations (bulk assign, bulk close)

### Search Tests (`search_e2e_test.go`)
- CQL query parsing and validation
- Time range queries
- Pagination with large result sets

### ML Pipeline Tests (`ml_pipeline_e2e_test.go`)
- Feature extraction (content, network, temporal)
- Model training workflow
- Model persistence and loading

### SOAR Playbook Tests (`soar_playbook_e2e_test.go`)
- Playbook execution on alerts
- Conditional step execution
- Audit logging

## Cleanup and Isolation

### Automatic Cleanup
- Testcontainers automatically clean up containers after tests
- Test databases are created with unique names to prevent conflicts
- Redis is cleaned via `miniredis.FlushAll()` between tests

### Manual Cleanup
If tests are interrupted, containers may remain running:
```bash
# List running containers
docker ps

# Stop all testcontainers
docker stop $(docker ps -q --filter "ancestor=clickhouse/clickhouse-server:latest")
```

## Debugging

### Enable Verbose Logging
Tests use `zap.NewNop().Sugar()` by default. To enable logging:
```go
logger, _ := zap.NewDevelopment()
sugar := logger.Sugar()
```

### Check Container Logs
```bash
# Find container ID
docker ps

# View logs
docker logs <container-id>
```

### Test Timeout
Default test timeout is 120 seconds for container startup. Increase if needed:
```go
containerStartTimeout = 240 * time.Second
```

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run Integration Tests
  run: |
    go test ./tests/integration/... -v -race -coverprofile=coverage.out
```

### Test Execution Time
Full integration test suite typically runs in 5-10 minutes:
- Container startup: 30-60 seconds
- Individual tests: 1-5 seconds each
- Cleanup: Automatic

## Troubleshooting

### Container Startup Failures
- **Error**: "Failed to start ClickHouse container"
  - **Solution**: Ensure Docker is running and has sufficient resources (2GB RAM minimum)

### Port Conflicts
- **Error**: "Port already in use"
  - **Solution**: Testcontainers uses random ports, but if conflicts occur, check for existing ClickHouse containers

### Timeout Errors
- **Error**: "Container start timeout exceeded"
  - **Solution**: Increase `containerStartTimeout` or check Docker resource limits

### Test Data Conflicts
- **Error**: "Table already exists"
  - **Solution**: Tests use unique database names with timestamps. This shouldn't occur unless tests are run concurrently.

## Test Data

### Test Fixtures
All test data is generated programmatically using functions in `fixtures.go`:
- `GenerateTestEvent()`: Base event generator
- `GenerateSyslogEvent()`: Syslog-specific events
- `GenerateCEFEvent()`: CEF format events
- `GenerateJSONEvent()`: JSON format events
- `GenerateTestAlert()`: Alert generator
- `GenerateTestRule()`: Detection rule generator
- `GenerateFailedLoginEvents()`: Multiple failed login events (correlation testing)

### Test Isolation
Each test:
1. Sets up fresh test infrastructure (containers, databases)
2. Generates unique test data
3. Runs test scenario
4. Verifies results
5. Cleans up automatically via `defer`

## Coverage Goals

- Overall coverage: 80%+
- Critical paths: 90%+
- Integration workflows: 95%+

## Contributing

When adding new integration tests:
1. Use existing test infrastructure (`SetupTestInfrastructure`)
2. Create test fixtures in `fixtures.go` if needed
3. Follow existing test patterns
4. Ensure tests are isolated and can run independently
5. Clean up resources in `defer` blocks
6. Document new test scenarios in this README

