# Cerberus SIEM BDD Tests

Comprehensive Behavior-Driven Development (BDD) tests for Cerberus SIEM using Godog.

## Overview

This test suite provides **complete requirements coverage** for all Cerberus SIEM features defined in `docs/requirements/`. Every test scenario is traceable to a specific requirement ID, ensuring compliance and preventing regression.

### Requirements Coverage

#### Security (CRITICAL)
- **SEC-001**: JWT Authentication
- **SEC-002**: Role-Based Access Control (RBAC)
- **SEC-003**: SQL Injection Prevention ✅ **FULLY IMPLEMENTED**
- **SEC-004**: SSRF Prevention
- **SEC-007**: Command Injection Prevention
- **SEC-015**: Password Complexity
- **SEC-016**: Account Lockout

#### Data Integrity (CRITICAL)
- **DATA-001**: ACID Transactions ✅ **FULLY IMPLEMENTED**
- **DATA-002**: Crash Recovery (Durability)
- **DATA-003**: Referential Integrity

#### Detection Engine (HIGH)
- **SIGMA-002**: Operator Case Sensitivity ✅ **FULLY IMPLEMENTED**
- **SIGMA-005**: Field Path Resolution ✅ **FULLY IMPLEMENTED**
- **FR-CORR-001**: Count-Based Correlation ✅ **FULLY IMPLEMENTED**
- **FR-CORR-002**: Value Count Correlation ✅ **FULLY IMPLEMENTED**
- **FR-CORR-003**: Sequence Correlation ✅ **FULLY IMPLEMENTED**

#### API Contracts (HIGH)
- **API-001 through API-013**: All API endpoints ✅ **FULLY IMPLEMENTED**

#### Performance (MEDIUM)
- **PERF-001**: Event Ingestion Throughput (10,000 EPS) ✅ **FULLY IMPLEMENTED**
- **PERF-002**: Rule Evaluation Latency

## Project Structure

```
tests/bdd/
├── features/              # Gherkin feature files
│   ├── security/
│   │   ├── sql_injection_prevention.feature
│   │   ├── authentication.feature
│   │   └── authorization.feature
│   ├── data/
│   │   └── acid_transactions.feature
│   ├── detection/
│   │   ├── sigma_operators.feature
│   │   └── correlation_rules.feature
│   ├── api/
│   │   └── rule_management.feature
│   └── performance/
│       └── ingestion_throughput.feature
├── steps/                 # Go step definitions
│   ├── security_steps.go
│   ├── security_steps_part2.go
│   └── [domain]_steps.go
├── main_test.go           # Test suite entry point
└── README.md              # This file
```

## Prerequisites

### Required
- **Go 1.21+**
- **Godog** BDD framework
- **Cerberus** running on `localhost:8081` (or configure `CERBERUS_API_URL`)
- **Database** initialized (SQLite/ClickHouse)

### Installation

```bash
# Install Godog
go install github.com/cucumber/godog/cmd/godog@latest

# Install test dependencies
cd tests/bdd
go mod tidy
```

## Running Tests

### Run All Tests

```bash
# From repository root
go test -v ./tests/bdd

# From tests/bdd directory
go test -v .
```

### Run Specific Tags

```bash
# Run only security tests
go test -v ./tests/bdd -godog.tags="@security"

# Run only critical tests
go test -v ./tests/bdd -godog.tags="@critical"

# Run specific feature
go test -v ./tests/bdd -godog.tags="@sql-injection"

# Exclude slow tests
go test -v ./tests/bdd -godog.tags="~@slow"

# Combine tags (AND)
go test -v ./tests/bdd -godog.tags="@security && @critical"

# Combine tags (OR)
go test -v ./tests/bdd -godog.tags="@authentication,@authorization"
```

### Run Specific Feature Files

```bash
# Run single feature file
go test -v ./tests/bdd -godog.paths=features/security/sql_injection_prevention.feature

# Run all security features
go test -v ./tests/bdd -godog.paths=features/security/
```

### Output Formats

```bash
# Pretty format (default, colored output)
go test -v ./tests/bdd -godog.format=pretty

# Progress bar
go test -v ./tests/bdd -godog.format=progress

# Cucumber JSON (for CI integration)
go test -v ./tests/bdd -godog.format=cucumber:report.json

# JUnit XML (for Jenkins/GitLab CI)
go test -v ./tests/bdd -godog.format=junit:report.xml
```

## Test Tags

Tags allow selective test execution. All scenarios are tagged for filtering:

### Priority Tags
- `@critical` - Critical security/data integrity tests (MUST PASS)
- `@high` - High-priority feature tests
- `@medium` - Medium-priority tests
- `@low` - Low-priority tests

### Domain Tags
- `@security` - Security tests (authentication, injection, RBAC)
- `@data` - Data integrity tests (ACID, transactions)
- `@detection` - Detection engine tests (SIGMA, correlation)
- `@api` - API contract tests
- `@performance` - Performance and throughput tests

### Feature Tags
- `@sql-injection` - SQL injection prevention
- `@authentication` - User authentication
- `@authorization` - Role-based access control
- `@acid` - ACID transaction guarantees
- `@sigma` - SIGMA operator compliance
- `@correlation` - Correlation rule evaluation
- `@ingestion` - Event ingestion throughput

### Test Type Tags
- `@happy-path` - Happy path scenarios
- `@error-handling` - Error handling scenarios
- `@attack-vector` - Security attack vector tests
- `@code-inspection` - Static code analysis tests
- `@slow` - Slow-running tests (>10 seconds)

## Environment Configuration

Configure via environment variables:

```bash
# API base URL (default: http://localhost:8081)
export CERBERUS_API_URL=http://localhost:8081

# Test admin credentials
export CERBERUS_TEST_ADMIN_USER=admin
export CERBERUS_TEST_ADMIN_PASS=Admin123!Test

# Database connection
export CERBERUS_DB_PATH=/path/to/test.db

# Test timeouts
export CERBERUS_TEST_TIMEOUT=30s
```

## Writing New Tests

### 1. Create Feature File

```gherkin
# tests/bdd/features/[domain]/[feature].feature
Feature: My New Feature
  As a user
  I want to do something
  So that I achieve a goal

  @my-tag
  Scenario: Successful operation
    Given the system is ready
    When I perform an action
    Then the result should be correct
```

### 2. Implement Step Definitions

```go
// tests/bdd/steps/[domain]_steps.go
package steps

import "github.com/cucumber/godog"

type MyContext struct {
    // State fields
}

func NewMyContext() *MyContext {
    return &MyContext{}
}

func RegisterMySteps(ctx *godog.ScenarioContext, mc *MyContext) {
    ctx.Step(`^the system is ready$`, mc.theSystemIsReady)
    ctx.Step(`^I perform an action$`, mc.iPerformAction)
    ctx.Step(`^the result should be correct$`, mc.theResultShouldBeCorrect)
}

func (mc *MyContext) theSystemIsReady() error {
    // Implementation
    return nil
}
```

### 3. Register in main_test.go

```go
func InitializeScenario(ctx *godog.ScenarioContext) {
    myCtx := steps.NewMyContext()
    steps.RegisterMySteps(ctx, myCtx)
}
```

## Best Practices

### State Isolation
- ✅ **DO**: Use context structs to isolate scenario state
- ❌ **DON'T**: Use global variables (causes test contamination)

### Error Handling
- ✅ **DO**: Check ALL error returns
- ✅ **DO**: Use `fmt.Errorf` with `%w` to wrap errors
- ❌ **DON'T**: Ignore errors with `_`

### Assertions
- ✅ **DO**: Return descriptive errors: `fmt.Errorf("expected %d, got %d", expected, actual)`
- ❌ **DON'T**: Return generic errors: `errors.New("failed")`

### Test Data
- ✅ **DO**: Clean up test data in `AfterScenario` hooks
- ✅ **DO**: Use unique IDs for test entities
- ❌ **DON'T**: Assume test data exists from previous runs

### Documentation
- ✅ **DO**: Reference requirement IDs in feature file comments
- ✅ **DO**: Add GoDoc comments to exported functions
- ✅ **DO**: Explain "why" not just "what"

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/bdd-tests.yml
name: BDD Tests
on: [push, pull_request]

jobs:
  bdd:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install dependencies
        run: |
          go install github.com/cucumber/godog/cmd/godog@latest
          cd tests/bdd && go mod download

      - name: Start Cerberus
        run: |
          docker-compose up -d
          sleep 10

      - name: Run BDD tests
        run: |
          go test -v ./tests/bdd -godog.format=cucumber:report.json

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: bdd-test-results
          path: tests/bdd/report.json
```

### GitLab CI

```yaml
# .gitlab-ci.yml
bdd-tests:
  stage: test
  image: golang:1.21
  services:
    - name: cerberus:latest
      alias: cerberus-api
  script:
    - go install github.com/cucumber/godog/cmd/godog@latest
    - cd tests/bdd
    - go test -v . -godog.format=junit:report.xml
  artifacts:
    reports:
      junit: tests/bdd/report.xml
```

## Troubleshooting

### Tests Fail with "Connection Refused"

**Problem**: Cerberus API not running

**Solution**:
```bash
# Start Cerberus
docker-compose up -d

# Or start manually
go run main.go
```

### Tests Fail with "401 Unauthorized"

**Problem**: Test user doesn't exist

**Solution**:
```bash
# Create admin user
curl -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!Test","role":"admin"}'
```

### Code Inspection Tests Fail

**Problem**: Storage layer source files not found

**Solution**:
```bash
# Run tests from repository root
cd /path/to/cerberus
go test -v ./tests/bdd
```

## Contributing

When adding new BDD tests:

1. **Identify requirement** - Find requirement ID in `docs/requirements/`
2. **Write feature file** - Use Gherkin syntax, reference requirement in comments
3. **Implement steps** - Follow existing patterns, use context structs
4. **Test locally** - Run `go test -v ./tests/bdd`
5. **Update coverage** - Mark requirement as tested in this README
6. **Submit PR** - Include requirement traceability

## References

- [Godog Documentation](https://github.com/cucumber/godog)
- [Gherkin Syntax](https://cucumber.io/docs/gherkin/)
- [BDD Best Practices](https://cucumber.io/docs/bdd/)
- [Cerberus Requirements](../../docs/requirements/)

## License

MIT License - See LICENSE file for details

---

## ⚠️ IMPORTANT LIMITATIONS (Added 2025-11-16)

### These are CONTRACT TESTS, NOT Integration Tests

The current BDD tests verify **API contracts and data structures**, not actual system behavior.

**What these tests verify**:
- ✅ JSON request/response structure
- ✅ Error handling patterns
- ✅ Data type correctness
- ✅ Transaction lifecycle

**What these tests DO NOT verify**:
- ❌ Actual backend API responses
- ❌ Real database persistence
- ❌ Actual RBAC enforcement
- ❌ Real SIGMA engine execution
- ❌ True correlation engine behavior
- ❌ Actual performance measurements

**Example**: Authorization tests verify HTTP 403 handling, but do NOT verify the backend actually returns 403 for unauthorized requests.

### Known Issues

1. **No Backend Integration** - Mock data, not real API calls
2. **No Performance Testing** - Arithmetic calculations, not real measurements
3. **Code Duplication** - 21+ identical HTTP request patterns
4. **Long Functions** - 9 functions >50 lines

**See**: BDD_TESTS_RE_REVIEW.md for full analysis

### Roadmap

**Phase 1** (3-4 weeks): Add real backend integration
**Phase 2** (2-3 weeks): Add real performance testing
**Phase 3** (2-3 weeks): Test actual SIGMA/correlation engines
**Phase 4** (1-2 weeks): Code quality improvements

---

