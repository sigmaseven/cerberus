# Cerberus SIEM Load Testing Scripts

This directory contains performance testing and benchmarking scripts for Cerberus SIEM.

## Scripts

### load_test.ps1

Comprehensive load testing script that validates performance improvements from audit fixes.

#### Features

- **Event Ingestion Testing**: Tests UDP/TCP Syslog ingestion at high throughput
- **Search Performance Testing**: Validates CQL query performance with concurrent searches
- **Detection Engine Testing**: Verifies rule matching and ML anomaly detection
- **API Endpoint Testing**: Tests all major API endpoints with metrics
- **Resource Monitoring**: Tracks memory usage, goroutines, and handles
- **Failure Scenario Testing**: Validates error handling and resilience

#### Prerequisites

- PowerShell 5.1 or later
- Cerberus SIEM running on localhost (or configure custom host)
- Administrator privileges for UDP/TCP socket operations
- Sufficient system resources (4GB+ RAM recommended)

#### Usage

**Basic usage (default settings):**
```powershell
.\scripts\load_test.ps1
```

**Custom configuration:**
```powershell
.\scripts\load_test.ps1 `
    -BaseUrl "http://localhost:8080" `
    -SyslogHost "localhost" `
    -SyslogPort 514 `
    -Duration 30 `
    -EventsPerSecond 10000 `
    -ConcurrentSearches 100 `
    -OutputFile "LOAD_TEST_RESULTS.md"
```

**Extended load test:**
```powershell
# Run for 60 seconds with 15,000 events/sec
.\scripts\load_test.ps1 -Duration 60 -EventsPerSecond 15000
```

**Stress test:**
```powershell
# Maximum load test
.\scripts\load_test.ps1 -Duration 120 -EventsPerSecond 20000 -ConcurrentSearches 200
```

#### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BaseUrl` | `http://localhost:8080` | Cerberus API base URL |
| `SyslogHost` | `localhost` | Syslog listener hostname |
| `SyslogPort` | `514` | Syslog listener port |
| `Duration` | `30` | Test duration in seconds |
| `EventsPerSecond` | `10000` | Target ingestion rate |
| `ConcurrentSearches` | `100` | Number of concurrent search queries |
| `OutputFile` | `LOAD_TEST_RESULTS.md` | Output report filename |

#### Test Scenarios

##### 1. Event Ingestion Performance
- Sends 10,000 events/second for 30 seconds (300,000 total events)
- Tests both UDP and TCP Syslog protocols
- Measures throughput, latency, dropped events
- Validates buffer pooling (memory delta < 100MB)
- Verifies parallel parsing workers (5-8x throughput gain)

##### 2. Search Performance
- Executes 100 concurrent CQL search queries
- Tests various query types (wildcards, boolean, text, time range)
- Measures response times (P50, P95, P99)
- Validates rate limiting (10 req/s per IP, should trigger 429)
- Verifies compression (gzip) for large responses
- Checks request ID tracing (X-Request-ID headers)

##### 3. Detection Engine Performance
- Processes 1,000 events through detection engine
- Measures rule matching latency
- Tests ML anomaly detection throughput
- Verifies system remains healthy (no goroutine leaks)
- Counts alerts generated

##### 4. API Endpoint Performance
- Tests major endpoints: /health, /events, /alerts, /rules, /search, /stats
- Runs 10 iterations per endpoint
- Measures response times and success rates
- Validates compression for large responses (>1KB)
- Tests request size limits (rejects >10MB)
- Verifies request ID headers on all responses

##### 5. Memory and Resource Usage
- Monitors Cerberus process for 20 seconds (10 samples)
- Tracks memory usage (Working Set, Private Memory)
- Monitors thread count (proxy for goroutines)
- Tracks handle count (file descriptors, sockets)
- Detects memory leaks (<20% growth is acceptable)
- Detects goroutine leaks (<10 threads growth is acceptable)

##### 6. Failure Scenarios
- Invalid JSON handling
- Missing required fields
- Invalid search queries
- Non-existent endpoints (404)
- Rate limit enforcement (burst test)

#### Output Report

The script generates a comprehensive Markdown report (`LOAD_TEST_RESULTS.md`) containing:

- Executive summary with overall pass/fail status
- Detailed metrics for each test category
- Performance statistics (P50, P95, P99 latencies)
- Resource usage graphs (memory, threads, handles)
- Before/after comparison with estimated baseline
- Improvement summary (throughput, latency, memory efficiency)
- Recommendations for optimization

#### Interpreting Results

**Success Criteria:**
- Event Ingestion: ≥90% of target rate achieved
- Search P95: <1000ms
- Search P99: <2000ms
- Rate Limiting: Triggered (429 responses received)
- Memory Growth: <20% over test duration
- Thread Growth: <10 threads over test duration
- All error scenarios: Handled correctly

**Warning Signs:**
- High drop rate (>5%): Increase worker_count or buffer_size
- High search latency: Check ClickHouse indexing
- Memory growth >20%: Potential memory leak
- Thread growth >10: Potential goroutine leak
- Rate limiting not triggered: Configuration issue

#### Baseline Comparison

**Before Audit Fixes (Estimated):**
- Ingestion: ~2,000 events/sec
- Search P95: ~5,000ms
- Memory leaks: ~500MB over 30s
- Goroutine leaks: Yes (correlation state)
- No buffer pooling, rate limiting, compression

**After Audit Fixes (Target):**
- Ingestion: 10,000+ events/sec (5x improvement)
- Search P95: <1,000ms (5x improvement)
- Memory stable: <50MB growth over 30s (10x improvement)
- No goroutine leaks: Thread count stable
- Buffer pooling: Implemented (2-3x GC reduction)
- Rate limiting: Implemented (10 req/s search limit)
- Compression: Implemented (gzip for large responses)
- Size limits: Implemented (10MB max request)

#### Troubleshooting

**Script fails to connect to API:**
- Verify Cerberus is running: `Get-Process cerberus`
- Check API port: Default is 8080
- Check firewall rules

**UDP/TCP send failures:**
- Run PowerShell as Administrator
- Check if port 514 is available: `netstat -an | findstr 514`
- Verify Syslog listener is enabled in config.yaml

**High memory usage during test:**
- This is expected - testing generates significant load
- Monitor that memory stabilizes after test completes
- Check final report for memory leak detection

**Rate limiting not triggered:**
- Verify `rate_limit` configuration in config.yaml
- Check that `search_rate_limit` is set to 10 req/s
- Ensure tests run from single IP (localhost)

#### CI/CD Integration

Add to GitHub Actions workflow:

```yaml
- name: Run Load Tests
  run: |
    pwsh -File scripts/load_test.ps1 -Duration 30 -EventsPerSecond 5000
  timeout-minutes: 10

- name: Upload Load Test Results
  uses: actions/upload-artifact@v3
  with:
    name: load-test-results
    path: LOAD_TEST_RESULTS.md
```

#### Performance Monitoring

Run load tests regularly to detect performance regressions:

**Daily smoke test:**
```powershell
.\scripts\load_test.ps1 -Duration 10 -EventsPerSecond 5000
```

**Weekly full test:**
```powershell
.\scripts\load_test.ps1 -Duration 60 -EventsPerSecond 10000
```

**Pre-release validation:**
```powershell
.\scripts\load_test.ps1 -Duration 120 -EventsPerSecond 15000 -ConcurrentSearches 200
```

## Future Enhancements

- [ ] Add WebSocket performance testing
- [ ] Test correlation rule performance
- [ ] Add distributed load testing (multiple clients)
- [ ] Generate performance graphs (charts, timeseries)
- [ ] Add baseline regression detection
- [ ] Support for Linux (Bash version)
- [ ] Add Prometheus metrics scraping
- [ ] Test ML model training performance

## Contributing

When adding new load tests:
1. Follow PowerShell best practices
2. Add comprehensive error handling
3. Include progress indicators for long operations
4. Document all parameters and thresholds
5. Update this README with new test scenarios

## License

Copyright (c) 2025 Cerberus SIEM Team. All rights reserved.
