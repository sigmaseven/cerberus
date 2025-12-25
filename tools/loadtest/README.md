# Cerberus Load Tester (Go Edition)

High-performance load testing tool for discovering maximum event ingestion throughput of Cerberus SIEM.

## Why Go?

This Go version replaces the PowerShell script for significantly better performance:
- **Compiled native code** vs interpreted PowerShell
- **Concurrent goroutines** for parallel UDP sending
- **Efficient UDP handling** with Go's net package
- **10-100x faster** event generation and transmission

## Features

- Progressive load testing with binary search or incremental strategies
- Concurrent UDP syslog event transmission
- Real-time progress monitoring
- Comprehensive markdown reports with performance analysis
- Health checks and system monitoring
- Configurable test parameters

## Building

```bash
cd tools/loadtest
go build -o loadtest.exe .
```

## Usage

### Basic Usage

```bash
# Binary search strategy (default)
./loadtest.exe

# Incremental strategy
./loadtest.exe -strategy incremental

# Custom parameters
./loadtest.exe -start 5000 -max 200000 -duration 20 -senders 200
```

### Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | `http://localhost:8080` | Base URL of Cerberus API |
| `-host` | `localhost` | Syslog listener host |
| `-port` | `514` | Syslog listener port |
| `-duration` | `15` | Duration for each test iteration (seconds) |
| `-start` | `1000` | Starting events per second rate |
| `-max` | `100000` | Maximum events per second to test |
| `-threshold` | `1.0` | Maximum acceptable drop rate (%) |
| `-strategy` | `binary` | Search strategy: `binary` or `incremental` |
| `-step` | `5000` | Step size for incremental strategy |
| `-output` | `MAX_THROUGHPUT_RESULTS.md` | Output file for results |
| `-senders` | `100` | Number of concurrent UDP senders |

### Examples

**Find maximum throughput with binary search:**
```bash
./loadtest.exe -strategy binary -duration 20 -senders 200
```

**Incremental search from 10k to 500k eps:**
```bash
./loadtest.exe -strategy incremental -start 10000 -max 500000 -step 10000
```

**High concurrency test:**
```bash
./loadtest.exe -senders 500 -max 1000000
```

## How It Works

### Binary Search Strategy
1. Tests the midpoint between min and max rates
2. If successful, searches higher rates
3. If failed, searches lower rates
4. Continues until convergence (typically 10-15 iterations)
5. Most efficient for finding exact maximum

### Incremental Strategy
1. Starts at the base rate
2. Increments by step size on success
3. Stops after 2 consecutive failures
4. Better for understanding performance curve

### Test Criteria

A test is considered **successful** if:
- Drop rate ≤ threshold (default 1%)
- API health check passes
- System remains stable

## Performance Comparison

| Tool | Events/sec | CPU Usage | Notes |
|------|------------|-----------|-------|
| PowerShell | ~5,000-10,000 | High | Bottlenecked by script overhead |
| Go | ~100,000+ | Low | Limited only by network/system |

The Go version can typically achieve **10-100x higher throughput** than PowerShell.

## Output

### Console Output
- Real-time progress updates
- Per-iteration results with metrics
- Final summary with recommendations

### Report File
Generates a comprehensive markdown report including:
- Executive summary with max sustainable rate
- Detailed iteration results table
- Performance analysis and statistics
- Scaling recommendations
- Production deployment guidance

## Tips for Maximum Performance

1. **Increase concurrent senders** for higher rates: `-senders 200` or more
2. **Use shorter test durations** for faster convergence: `-duration 10`
3. **Adjust start/max rates** based on your system capacity
4. **Run on same host** as Cerberus to eliminate network latency
5. **Close unnecessary applications** to reduce interference

## Example Run

```bash
$ ./loadtest.exe -start 10000 -max 200000 -senders 200

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    Cerberus SIEM - Maximum Throughput Discovery Test        ║
║                     (Go Edition)                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Test Configuration:
  Base URL: http://localhost:8080
  Syslog: localhost:514
  Strategy: binary
  Test Duration: 15 seconds per iteration
  Start Rate: 10000 eps
  Max Rate: 200000 eps
  Drop Rate Threshold: 1.0%
  Concurrent Senders: 200
  Output: MAX_THROUGHPUT_RESULTS.md

===================================
  Pre-Flight Checks
===================================
  [Success] API Health Check: PASSED

===================================
  Binary Search Strategy
===================================
  Starting binary search between 10000 and 200000 eps

===================================
  Iteration 1 - Testing 105000 eps
===================================
  Search Range: [10000 - 200000]

  Testing at rate: 105000 events/sec for 15s
    Progress: 33.3% - Current Rate: 104523 eps
    Progress: 66.7% - Current Rate: 104891 eps
    Progress: 100.0% - Current Rate: 105002 eps
  Waiting for event processing (10 seconds)...

  Results:
    Events Sent: 1575000/1575000
    Send Rate: 105002.34 eps (target: 105000)
    Drop Rate: 0.0012% [OK]
    Events Ingested: 1574981
    Ingestion Rate: 62999.24 eps
    System Health: Healthy [OK]
    Test Result: PASS [OK]

  [OK] Rate 105000 eps is sustainable - trying higher

...

===================================
  Test Complete
===================================

  Maximum Sustainable Rate: 156000 events/second
  Total Test Time: 12.5 minutes
  Total Iterations: 8

  Quick Summary:
  [OK] Max Rate: 156000 eps
  [OK] Drop Rate at Max: 0.8234%
  [OK] Recommended Production Rate: 109200 eps (70% of max)

  Report saved to: MAX_THROUGHPUT_RESULTS.md
```

## Troubleshooting

**No events being received:**
- Check Cerberus is running and listener is configured
- Verify syslog host/port with `-host` and `-port` flags
- Check firewall isn't blocking UDP port 514

**Tests failing immediately:**
- Lower the `-start` rate
- Check system resources (CPU, RAM, disk I/O)
- Review Cerberus logs for errors

**Inconsistent results:**
- Increase `-duration` for more stable measurements
- Close background applications
- Ensure system is idle during testing

## License

Part of Cerberus SIEM project.
