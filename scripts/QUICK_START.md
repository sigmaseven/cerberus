# Load Testing Quick Start Guide

## Prerequisites Checklist

- [ ] PowerShell 5.1+ installed
- [ ] Cerberus SIEM running
- [ ] Administrator privileges
- [ ] Port 514 available (or custom port configured)
- [ ] At least 4GB free RAM

## Quick Start Commands

### 1. Default Test (Recommended for first run)
```powershell
cd C:\Users\sigma\cerberus
.\scripts\load_test.ps1
```

**What it does:**
- Tests ingestion at 10,000 events/sec for 30 seconds
- Runs 100 concurrent searches
- Generates full performance report
- Takes ~5 minutes to complete

### 2. Quick Smoke Test (Fast validation)
```powershell
.\scripts\load_test.ps1 -Duration 10 -EventsPerSecond 5000 -ConcurrentSearches 50
```

**What it does:**
- Shorter test (10 seconds)
- Lower load (5,000 events/sec)
- Takes ~2 minutes to complete
- Good for quick validation

### 3. Stress Test (Maximum load)
```powershell
.\scripts\load_test.ps1 -Duration 120 -EventsPerSecond 20000 -ConcurrentSearches 200
```

**What it does:**
- Extended duration (2 minutes)
- Maximum load (20,000 events/sec)
- 200 concurrent searches
- Takes ~10 minutes to complete
- Use for capacity planning

## Expected Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║       Cerberus SIEM - Comprehensive Load Test Suite         ║
║                                                              ║
║  Testing: Event Ingestion, Search, Detection, API, Memory   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Test Configuration:
  Base URL: http://localhost:8080
  Syslog: localhost:514
  Duration: 30 seconds
  Events/sec: 10000
  Concurrent Searches: 100
  Output: LOAD_TEST_RESULTS.md

===================================
  Pre-Flight Checks
===================================
  [Success] API Health Check: PASSED
  [Success] Process Check: PASSED

===================================
  Test 1: Event Ingestion Performance
===================================
  Configuration:
    - Target Rate: 10000 events/second
    - Duration: 30 seconds
    - Total Events: 300000
    - Protocol: UDP Syslog

  Starting ingestion test...
    Progress: 10.0% (30000/300000 events)
    Progress: 20.0% (60000/300000 events)
    ...

  [Info] Total Events Sent: 300000
  [Success] Successful Events: 299850
  [Success] Failed Events: 150
  [Info] Duration: 30.12 seconds
  [Success] Throughput: 9952.39 events/sec
  [Info] Target Rate: 10000 events/sec
  [Success] Drop Rate: 0.05%
  [Success] Memory Delta: 42 MB
  [Info] Thread Count: 87

===================================
  Test 2: Search Performance (CQL)
===================================
  ...

===================================
  Test Complete
===================================
  Report: C:\Users\sigma\cerberus\LOAD_TEST_RESULTS.md
  Review the report for detailed performance metrics and recommendations.
```

## Reading the Results

### Success Indicators
✓ **Event Ingestion:** Throughput ≥9,000 events/sec (≥90% of target)
✓ **Search P95:** <1,000ms
✓ **Rate Limiting:** 429 responses received
✓ **Memory Growth:** <50MB over test
✓ **No Leaks:** Thread count stable

### Warning Signs
⚠ **High Drop Rate:** >5% events failed
⚠ **Slow Searches:** P95 >1,000ms
⚠ **Memory Growth:** >100MB over test
⚠ **Thread Growth:** >10 threads over test
⚠ **No Rate Limiting:** 429 not triggered

## Troubleshooting Common Issues

### Error: "Cannot access API"
```powershell
# Check if Cerberus is running
Get-Process cerberus

# Start Cerberus if needed
.\cerberus.exe
```

### Error: "UDP send failed"
```powershell
# Run as Administrator
Start-Process powershell -Verb RunAs

# Check if port is in use
netstat -an | findstr 514
```

### Error: "Rate limiting not triggered"
```yaml
# Check config.yaml has search rate limit:
api:
  rate_limit:
    requests_per_second: 100

# Verify in code (api/constants.go):
SearchRateLimit: 10
SearchRateBurst: 20
```

### High Memory Usage During Test
This is **EXPECTED** behavior. The test intentionally generates high load.

Monitor memory **after** test completes:
- Should stabilize within 2 minutes
- Growth <20% is acceptable
- Growth >50% indicates potential leak

## Interpreting the Report

### Overall Score
```
Overall Score: 8/9 checks passed (88.9%)
```
- **90-100%:** Excellent - All systems optimal
- **75-89%:** Good - Minor optimizations needed
- **50-74%:** Fair - Performance tuning required
- **<50%:** Poor - Major issues detected

### Key Metrics

**Throughput:**
- Before fixes: ~2,000 events/sec
- After fixes: 10,000+ events/sec
- **Target: 5x improvement ✓**

**Latency:**
- Before fixes: P95 ~5,000ms
- After fixes: P95 <1,000ms
- **Target: 5x improvement ✓**

**Memory:**
- Before fixes: +500MB over 30s (leaks)
- After fixes: +50MB over 30s (stable)
- **Target: 10x improvement ✓**

## Next Steps

### If All Tests Pass (90%+)
1. Run extended stress test to find limits
2. Document maximum capacity
3. Set up monitoring for production
4. Schedule regular performance regression tests

### If Some Tests Fail (75-89%)
1. Review recommendations in report
2. Tune configuration (workers, buffers, timeouts)
3. Re-run tests after changes
4. Monitor for improvements

### If Many Tests Fail (<75%)
1. Check system resources (CPU, RAM, disk)
2. Review Cerberus logs for errors
3. Verify configuration matches production specs
4. Consider scaling hardware
5. Review code for performance issues

## Configuration Tuning

### For Higher Throughput
```yaml
# config.yaml
listeners:
  syslog:
    worker_count: 8  # Increase from 4
    udp_buffer_size: 131072  # Increase from 65536
    udp_batch_size: 200  # Increase from 100

engine:
  detection_worker_count: 16  # Increase from 8
  channel_buffer_size: 20000  # Increase from 10000

storage:
  buffer_size: 20000  # Increase from 10000
```

### For Lower Latency
```yaml
# config.yaml
clickhouse:
  flush_interval: 1  # Reduce from 3
  batch_size: 10000  # Reduce from 50000

storage:
  batch_flush_interval: 2  # Reduce from 5
```

### For Better Reliability
```yaml
# config.yaml
api:
  rate_limit:
    requests_per_second: 50  # Reduce from 100
    burst: 100

security:
  json_body_limit: 524288  # Reduce from 1048576 (1MB to 512KB)
```

## Automation

### Daily CI/CD Check
```yaml
# .github/workflows/performance.yml
name: Performance Tests
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily

jobs:
  load-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start Cerberus
        run: |
          Start-Process .\cerberus.exe
          Start-Sleep -Seconds 10
      - name: Run Load Tests
        run: |
          .\scripts\load_test.ps1 -Duration 30
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: load-test-results
          path: LOAD_TEST_RESULTS.md
```

### Performance Dashboard
Track these metrics over time:
- Event ingestion throughput (events/sec)
- Search P95 latency (ms)
- Memory growth rate (MB/hour)
- Thread count stability
- API error rate (%)

## Support

For issues or questions:
1. Check `LOAD_TEST_RESULTS.md` recommendations section
2. Review Cerberus logs: `logs/cerberus.log`
3. Check GitHub issues: `github.com/cerberus-siem/issues`
4. Consult documentation: `docs/PERFORMANCE.md`

## Performance Baselines

| Metric | Minimum | Target | Excellent |
|--------|---------|--------|-----------|
| Ingestion | 5,000 eps | 10,000 eps | 20,000 eps |
| Search P95 | <2,000ms | <1,000ms | <500ms |
| Memory Growth | <100MB/30s | <50MB/30s | <20MB/30s |
| Drop Rate | <5% | <1% | <0.1% |
| API Uptime | 99% | 99.9% | 99.99% |

**eps** = events per second
