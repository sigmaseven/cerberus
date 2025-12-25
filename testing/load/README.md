# Load Testing Suite

## Overview

This directory contains comprehensive load testing tools for Cerberus SIEM to validate performance claims and identify bottlenecks.

## Test Scenarios

### 1. Ingestion Throughput Test
**Target**: 10,000 events per second sustained for 1 hour

**Command**:
```bash
go test -v -timeout 70m ./testing/load -run TestIngestionThroughput_10KEPS
```

**Metrics**:
- Events ingested per second
- Latency (p50, p95, p99)
- Dropped events
- Errors
- CPU/Memory usage

### 2. API Response Time Test
**Target**: <300ms p95 response time under 100 concurrent users, 1000 req/sec

**Command**:
```bash
go test -v -timeout 10m ./testing/load -run TestAPIResponseTimes
```

**Endpoints Tested**:
- GET /api/v1/rules
- GET /api/v1/alerts
- GET /api/v1/events
- POST /api/v1/events/search

### 3. CQL Query Performance Test
**Target**: <1s p95 query time with 1M events in ClickHouse

**Command**:
```bash
go test -v -timeout 30m ./testing/load -run TestCQLQueryPerformance
```

**Query Types**:
- Simple queries (field = "value")
- Complex queries (AND/OR combinations)
- Range queries
- Wildcard queries

### 4. Correlation Engine Performance Test
**Target**: <10ms p95 correlation evaluation with 1000 rules, 10K EPS

**Command**:
```bash
go test -v -timeout 10m ./testing/load -run TestCorrelationEnginePerformance
```

## Prerequisites

1. **Server Running**: Cerberus API server must be running on localhost:8080
2. **Test Data**: Pre-populate ClickHouse with test data (use event generator)
3. **Monitoring**: Prometheus and Grafana should be configured for metrics

## Setup

1. Install dependencies:
```bash
go mod tidy
```

2. Start Cerberus server:
```bash
go run main.go
```

3. Run load tests:
```bash
cd testing/load
go test -v -run TestIngestionThroughput_10KEPS
```

## Results

Test results are logged to stdout and can be redirected to a file:
```bash
go test -v -run TestIngestionThroughput_10KEPS 2>&1 | tee results.txt
```

## Continuous Integration

For CI/CD, use shorter test durations and lower loads:
```bash
go test -v -timeout 5m -short ./testing/load
```


