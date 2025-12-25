# CI/CD Integration Guide

**Purpose:** Guide for CI/CD integration, GitHub Actions workflows, coverage reporting, and test execution strategies.

---

## Overview

Cerberus uses GitHub Actions for continuous integration. Tests run automatically on:
- **Pull requests:** All unit and integration tests
- **Push to main:** Full test suite with coverage upload
- **Scheduled (nightly):** Extended fuzzing and performance benchmarks

---

## Workflow Files

### Standard CI Pipeline (`.github/workflows/tests.yml`)

Runs on every pull request and push to main:

```yaml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
```

### Nightly Extended Tests (`.github/workflows/nightly-tests.yml`)

Runs extended fuzzing and performance benchmarks:

```yaml
name: Nightly Tests

on:
  schedule:
    - cron: '0 2 * * *' # 2 AM UTC daily
  workflow_dispatch: # Manual trigger

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      
      - name: Run fuzzing
        run: |
          go test -fuzz=./search/... -fuzztime=4h
          go test -fuzz=./ingest/... -fuzztime=4h
```

---

## Test Execution Strategies

### Parallel Execution

Tests run in parallel by default:

```yaml
- name: Run tests in parallel
  run: go test -p 8 -v ./...  # 8 parallel processes
```

### Test Caching

Cache Go modules and test cache:

```yaml
- uses: actions/cache@v3
  with:
    path: |
      ~/.cache/go-build
      ~/go/pkg/mod
    key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
```

### Integration Tests with Testcontainers

For tests requiring Docker containers:

```yaml
- name: Run integration tests
  run: go test -tags=integration ./tests/integration/...
  env:
    DOCKER_HOST: unix:///var/run/docker.sock
```

---

## Coverage Reporting

### Codecov Integration

Upload coverage to Codecov:

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.out
    flags: unittests
    name: codecov-umbrella
    fail_ci_if_error: false
```

### Coverage Threshold Checks

Fail CI if coverage drops:

```yaml
- name: Check coverage threshold
  run: |
    TOTAL=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "$TOTAL < 90.0" | bc -l) )); then
      echo "Coverage $TOTAL% below 90% threshold"
      exit 1
    fi
```

---

## Performance Benchmarking

### Benchmark Comparison

Compare benchmarks against baseline:

```yaml
- name: Run benchmarks
  run: go test -bench=. -benchmem -count=10 > benchmark.txt

- name: Compare with baseline
  run: benchstat baseline.txt benchmark.txt
```

---

## Troubleshooting

### Common CI Issues

**Tests timeout:**
- Increase timeout: `timeout-minutes: 30`

**Docker not available:**
- Use testcontainers-ryuk: `TESTCONTAINERS_RYUK_DISABLED=true`

**Race detector failures:**
- Review race detector output
- Fix data races before merging

---

**Last Updated:** 2025-11-20

