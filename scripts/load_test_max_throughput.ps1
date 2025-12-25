<#
.SYNOPSIS
    Progressive Load Testing Script to Find Maximum Event Ingestion Rate

.DESCRIPTION
    This script progressively increases load to discover the maximum sustainable
    event ingestion rate for Cerberus SIEM. It uses a binary search algorithm
    to efficiently find the breaking point where events start dropping.

.PARAMETER BaseUrl
    Base URL of the Cerberus API (default: http://localhost:8080)

.PARAMETER SyslogHost
    Syslog listener host (default: localhost)

.PARAMETER SyslogPort
    Syslog listener port (default: 514)

.PARAMETER TestDuration
    Duration for each load test iteration in seconds (default: 15)

.PARAMETER StartRate
    Starting events per second rate (default: 1000)

.PARAMETER MaxRate
    Maximum events per second to test (default: 100000)

.PARAMETER DropRateThreshold
    Maximum acceptable event drop rate percentage (default: 1.0)

.PARAMETER Strategy
    Search strategy: "binary" or "incremental" (default: binary)

.PARAMETER IncrementStep
    Step size for incremental strategy (default: 5000)

.PARAMETER OutputFile
    Output file for results (default: MAX_THROUGHPUT_RESULTS.md)

.EXAMPLE
    .\load_test_max_throughput.ps1 -Strategy binary -TestDuration 20

.EXAMPLE
    .\load_test_max_throughput.ps1 -Strategy incremental -IncrementStep 2000

.NOTES
    Author: Cerberus SIEM Team
    Version: 1.0.0
    This script will run multiple iterations and may take significant time
#>

param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$SyslogHost = "localhost",
    [int]$SyslogPort = 514,
    [int]$TestDuration = 15,
    [int]$StartRate = 1000,
    [int]$MaxRate = 100000,
    [double]$DropRateThreshold = 1.0,
    [ValidateSet("binary", "incremental")]
    [string]$Strategy = "binary",
    [int]$IncrementStep = 5000,
    [string]$OutputFile = "MAX_THROUGHPUT_RESULTS.md"
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Test Results Storage
$script:TestIterations = @()
$script:MaxSustainableRate = 0
$script:OptimalConfiguration = @{}

#region Helper Functions

function Write-TestHeader {
    param([string]$Title)
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$Test,
        [string]$Result,
        [string]$Status = "Info"
    )
    $color = switch ($Status) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }
    Write-Host "  [$Status] $Test`: $Result" -ForegroundColor $color
}

function Get-MemoryUsage {
    $process = Get-Process -Name cerberus -ErrorAction SilentlyContinue
    if ($process) {
        return @{
            WorkingSetMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
            PrivateMemoryMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            CPUPercent = $process.CPU
            Threads = $process.Threads.Count
            Handles = $process.HandleCount
        }
    }
    return $null
}

function Send-SyslogUDP {
    param(
        [string]$Message,
        [string]$TargetHost = "localhost",
        [int]$Port = 514
    )

    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
        $sent = $udpClient.Send($bytes, $bytes.Length, $TargetHost, $Port)
        $udpClient.Close()
        return $sent -eq $bytes.Length
    }
    catch {
        return $false
    }
}

function Generate-SyslogMessage {
    param([int]$Index)

    $timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    $hostnames = @("web-server-01", "db-server-02", "app-server-03", "mail-server-04")
    $processes = @("sshd", "apache2", "mysqld", "postfix", "kernel")
    $hostname = $hostnames[$Index % $hostnames.Count]
    $process = $processes[$Index % $processes.Count]
    $processId = Get-Random -Minimum 1000 -Maximum 9999

    $messages = @(
        "User authentication successful from 192.168.1.100",
        "Connection established from 10.0.0.50 port 22",
        "Database query executed in 45ms",
        "HTTP request GET /api/users completed with status 200",
        "Failed login attempt from 172.16.0.100",
        "System backup completed successfully",
        "Certificate renewal initiated",
        "Memory usage at 75%",
        "Disk I/O warning threshold exceeded",
        "Service restarted successfully"
    )

    $message = $messages[$Index % $messages.Count]

    return "<134>$timestamp $hostname ${process}[$processId]: $message"
}

function Test-ApiHealth {
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/health" -Method GET -TimeoutSec 5 -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Get-EventCount {
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/api/v1/stats" -Method GET -TimeoutSec 10 -ErrorAction Stop
        $stats = $response.Content | ConvertFrom-Json
        if ($stats.events_ingested) {
            return $stats.events_ingested
        }
        return 0
    }
    catch {
        return 0
    }
}

#endregion

#region Load Test Execution

function Test-LoadAtRate {
    param(
        [int]$EventsPerSecond,
        [int]$Duration
    )

    Write-Host "`n  Testing at rate: $EventsPerSecond events/sec for ${Duration}s" -ForegroundColor Yellow

    $totalEvents = $EventsPerSecond * $Duration
    $batchSize = [math]::Min(1000, $EventsPerSecond)
    $batchDelayMs = ($batchSize / $EventsPerSecond) * 1000

    # Capture initial state
    $initialMemory = Get-MemoryUsage
    $initialEventCount = Get-EventCount
    $testStartTime = Get-Date

    # Event counters
    $sentSuccessful = 0
    $sentFailed = 0

    # Send events
    for ($i = 0; $i -lt $totalEvents; $i += $batchSize) {
        $batchStartTime = Get-Date

        # Send batch
        for ($j = 0; $j -lt $batchSize -and ($i + $j) -lt $totalEvents; $j++) {
            $message = Generate-SyslogMessage -Index ($i + $j)
            if (Send-SyslogUDP -Message $message -TargetHost $SyslogHost -Port $SyslogPort) {
                $sentSuccessful++
            }
            else {
                $sentFailed++
            }
        }

        # Rate limiting
        $elapsed = ((Get-Date) - $batchStartTime).TotalMilliseconds
        if ($elapsed -lt $batchDelayMs) {
            Start-Sleep -Milliseconds ($batchDelayMs - $elapsed)
        }

        # Progress update every 10000 events
        if (($i % 10000) -eq 0 -and $i -gt 0) {
            $progress = [math]::Round(($i / $totalEvents) * 100, 1)
            $currentRate = [math]::Round($sentSuccessful / ((Get-Date) - $testStartTime).TotalSeconds, 0)
            Write-Host "    Progress: $progress% - Current Rate: $currentRate eps" -ForegroundColor Gray
        }
    }

    $testEndTime = Get-Date
    $actualDuration = ($testEndTime - $testStartTime).TotalSeconds

    # Wait for processing
    Write-Host "  Waiting for event processing (10 seconds)..." -ForegroundColor Gray
    Start-Sleep -Seconds 10

    # Capture final state
    $finalMemory = Get-MemoryUsage
    $finalEventCount = Get-EventCount

    # Calculate metrics
    $actualRate = [math]::Round($sentSuccessful / $actualDuration, 2)
    $dropRate = [math]::Round(($sentFailed / $totalEvents) * 100, 4)
    $eventsIngested = $finalEventCount - $initialEventCount
    $ingestionRate = if ($eventsIngested -gt 0) {
        [math]::Round($eventsIngested / ($actualDuration + 10), 2)
    } else {
        0
    }
    $memoryDelta = if ($finalMemory -and $initialMemory) {
        [math]::Round($finalMemory.WorkingSetMB - $initialMemory.WorkingSetMB, 2)
    } else {
        0
    }

    # System health check
    $healthCheck = Test-ApiHealth
    $memoryStable = [math]::Abs($memoryDelta) -lt 200  # Less than 200MB growth
    $systemHealthy = $healthCheck -and $memoryStable

    $result = @{
        TargetRate = $EventsPerSecond
        Duration = [math]::Round($actualDuration, 2)
        EventsSent = $sentSuccessful
        EventsFailed = $sentFailed
        SendRate = $actualRate
        DropRate = $dropRate
        EventsIngested = $eventsIngested
        IngestionRate = $ingestionRate
        MemoryDelta = $memoryDelta
        InitialMemory = if ($initialMemory) { $initialMemory.WorkingSetMB } else { 0 }
        FinalMemory = if ($finalMemory) { $finalMemory.WorkingSetMB } else { 0 }
        Threads = if ($finalMemory) { $finalMemory.Threads } else { 0 }
        SystemHealthy = $systemHealthy
        HealthCheck = $healthCheck
        MemoryStable = $memoryStable
        Success = ($dropRate -le $DropRateThreshold) -and $systemHealthy
        Timestamp = Get-Date
    }

    # Display results
    Write-Host "`n  Results:" -ForegroundColor White
    Write-TestResult "Events Sent" "$sentSuccessful/$totalEvents" "Info"
    Write-TestResult "Send Rate" "$actualRate eps (target: $EventsPerSecond)" $(if ($actualRate -ge ($EventsPerSecond * 0.95)) { "Success" } else { "Warning" })
    Write-TestResult "Drop Rate" "$dropRate%" $(if ($dropRate -le $DropRateThreshold) { "Success" } else { "Error" })
    Write-TestResult "Events Ingested" "$eventsIngested" "Info"
    Write-TestResult "Ingestion Rate" "$ingestionRate eps" "Info"
    Write-TestResult "Memory Delta" "$memoryDelta MB" $(if ($memoryStable) { "Success" } else { "Warning" })
    Write-TestResult "System Health" $(if ($systemHealthy) { "Healthy" } else { "Degraded" }) $(if ($systemHealthy) { "Success" } else { "Error" })
    Write-TestResult "Test Result" $(if ($result.Success) { "PASS" } else { "FAIL" }) $(if ($result.Success) { "Success" } else { "Error" })

    return $result
}

#endregion

#region Search Strategies

function Find-MaxThroughput-Binary {
    Write-TestHeader "Binary Search Strategy"
    Write-Host "  Starting binary search between $StartRate and $MaxRate eps"

    $low = $StartRate
    $high = $MaxRate
    $bestSuccessRate = 0
    $iterations = 0
    $maxIterations = 15  # Limit iterations to prevent excessive testing

    while ($low -le $high -and $iterations -lt $maxIterations) {
        $iterations++
        $testRate = [math]::Floor(($low + $high) / 2)

        Write-TestHeader "Iteration $iterations - Testing $testRate eps"
        Write-Host "  Search Range: [$low - $high]" -ForegroundColor Gray

        $result = Test-LoadAtRate -EventsPerSecond $testRate -Duration $TestDuration
        $script:TestIterations += $result

        if ($result.Success) {
            # Test passed - try higher rate
            $bestSuccessRate = $testRate
            $script:MaxSustainableRate = $testRate
            $script:OptimalConfiguration = $result

            Write-Host "`n  [OK] Rate $testRate eps is sustainable - trying higher" -ForegroundColor Green
            $low = $testRate + 1
        }
        else {
            # Test failed - try lower rate
            Write-Host "`n  [FAIL] Rate $testRate eps failed - trying lower" -ForegroundColor Red
            $high = $testRate - 1
        }

        # Small cooldown between tests
        if ($low -le $high) {
            Write-Host "`n  Cooldown period (15 seconds)..." -ForegroundColor Gray
            Start-Sleep -Seconds 15
        }
    }

    if ($bestSuccessRate -eq 0) {
        Write-Host "`n  [WARNING] No successful rate found! Starting rate may be too high." -ForegroundColor Yellow
    }

    return $bestSuccessRate
}

function Find-MaxThroughput-Incremental {
    Write-TestHeader "Incremental Strategy"
    Write-Host "  Starting at $StartRate eps, incrementing by $IncrementStep"

    $currentRate = $StartRate
    $lastSuccessRate = 0
    $consecutiveFailures = 0
    $maxConsecutiveFailures = 2

    while ($currentRate -le $MaxRate -and $consecutiveFailures -lt $maxConsecutiveFailures) {
        Write-TestHeader "Testing $currentRate eps"

        $result = Test-LoadAtRate -EventsPerSecond $currentRate -Duration $TestDuration
        $script:TestIterations += $result

        if ($result.Success) {
            # Test passed - increment and continue
            $lastSuccessRate = $currentRate
            $script:MaxSustainableRate = $currentRate
            $script:OptimalConfiguration = $result
            $consecutiveFailures = 0

            Write-Host "`n  [OK] Rate $currentRate eps is sustainable - incrementing" -ForegroundColor Green
            $currentRate += $IncrementStep
        }
        else {
            # Test failed - increment failure counter
            $consecutiveFailures++
            Write-Host "`n  [FAIL] Rate $currentRate eps failed (failure $consecutiveFailures/$maxConsecutiveFailures)" -ForegroundColor Red

            if ($consecutiveFailures -lt $maxConsecutiveFailures) {
                # Try one more time with smaller increment
                $currentRate = $lastSuccessRate + [math]::Floor($IncrementStep / 2)
            }
        }

        # Cooldown between tests
        if ($currentRate -le $MaxRate -and $consecutiveFailures -lt $maxConsecutiveFailures) {
            Write-Host "`n  Cooldown period (15 seconds)..." -ForegroundColor Gray
            Start-Sleep -Seconds 15
        }
    }

    if ($lastSuccessRate -eq 0) {
        Write-Host "`n  [WARNING] No successful rate found! Starting rate may be too high." -ForegroundColor Yellow
    }

    return $lastSuccessRate
}

#endregion

#region Report Generation

function Generate-Report {
    param([int]$MaxRate)

    Write-TestHeader "Generating Report"

    $reportPath = Join-Path $PSScriptRoot ".." $OutputFile

    $report = @"
# Cerberus SIEM - Maximum Throughput Test Results

**Test Date:** $(Get-Date)
**Base URL:** $BaseUrl
**Strategy:** $Strategy
**Test Duration per Iteration:** $TestDuration seconds
**Drop Rate Threshold:** $DropRateThreshold%

---

## Executive Summary

**Maximum Sustainable Event Ingestion Rate: $MaxRate events/second**

"@

    if ($MaxRate -gt 0) {
        $report += @"

This test discovered that Cerberus SIEM can sustainably ingest **$MaxRate events per second**
with less than $DropRateThreshold% event drop rate and stable system health.

### Optimal Configuration at Max Rate:
- **Events Sent:** $($script:OptimalConfiguration.EventsSent)
- **Send Rate:** $($script:OptimalConfiguration.SendRate) eps
- **Drop Rate:** $($script:OptimalConfiguration.DropRate)%
- **Events Ingested:** $($script:OptimalConfiguration.EventsIngested)
- **Ingestion Rate:** $($script:OptimalConfiguration.IngestionRate) eps
- **Memory Usage:** $($script:OptimalConfiguration.InitialMemory) MB → $($script:OptimalConfiguration.FinalMemory) MB (Δ $($script:OptimalConfiguration.MemoryDelta) MB)
- **Thread Count:** $($script:OptimalConfiguration.Threads)
- **System Health:** $(if ($script:OptimalConfiguration.SystemHealthy) { "Healthy [OK]" } else { "Degraded [FAIL]" })

"@
    }
    else {
        $report += @"

**WARNING:** No sustainable rate could be determined. All tested rates failed.
This may indicate:
- Starting rate is too high
- System resources are insufficient
- Configuration issues with Cerberus
- Network issues preventing event delivery

"@
    }

    $report += @"
---

## Test Iterations

A total of $($script:TestIterations.Count) test iterations were performed.

| Iteration | Target Rate | Send Rate | Drop Rate | Ingested | Ingestion Rate | Memory Δ | Result |
|-----------|-------------|-----------|-----------|----------|----------------|----------|--------|
"@

    for ($i = 0; $i -lt $script:TestIterations.Count; $i++) {
        $iter = $script:TestIterations[$i]
        $result = if ($iter.Success) { "[OK] PASS" } else { "[X] FAIL" }
        $report += "`n| $($i + 1) | $($iter.TargetRate) | $($iter.SendRate) | $($iter.DropRate)% | $($iter.EventsIngested) | $($iter.IngestionRate) | $($iter.MemoryDelta) MB | $result |"
    }

    $report += @"


---

## Performance Analysis

### Throughput Distribution

"@

    # Calculate statistics across all successful tests
    $successfulTests = $script:TestIterations | Where-Object { $_.Success }
    if ($successfulTests.Count -gt 0) {
        $avgSendRate = [math]::Round(($successfulTests | Measure-Object -Property SendRate -Average).Average, 2)
        $avgIngestionRate = [math]::Round(($successfulTests | Measure-Object -Property IngestionRate -Average).Average, 2)
        $avgDropRate = [math]::Round(($successfulTests | Measure-Object -Property DropRate -Average).Average, 4)
        $avgMemoryDelta = [math]::Round(($successfulTests | Measure-Object -Property MemoryDelta -Average).Average, 2)

        $report += @"
**Successful Tests:** $($successfulTests.Count)/$($script:TestIterations.Count)

**Average Metrics (Successful Tests):**
- Send Rate: $avgSendRate eps
- Ingestion Rate: $avgIngestionRate eps
- Drop Rate: $avgDropRate%
- Memory Delta: $avgMemoryDelta MB

"@
    }

    # Calculate statistics across all failed tests
    $failedTests = $script:TestIterations | Where-Object { -not $_.Success }
    if ($failedTests.Count -gt 0) {
        $avgFailedDropRate = [math]::Round(($failedTests | Measure-Object -Property DropRate -Average).Average, 4)
        $avgFailedMemoryDelta = [math]::Round(($failedTests | Measure-Object -Property MemoryDelta -Average).Average, 2)

        $report += @"
**Failed Tests:** $($failedTests.Count)/$($script:TestIterations.Count)

**Average Metrics (Failed Tests):**
- Drop Rate: $avgFailedDropRate%
- Memory Delta: $avgFailedMemoryDelta MB

### Failure Reasons:
"@

        foreach ($failed in $failedTests) {
            if ($failed.DropRate -gt $DropRateThreshold) {
                $report += "- Rate $($failed.TargetRate) eps: High drop rate ($($failed.DropRate)%)`n"
            }
            if (-not $failed.HealthCheck) {
                $report += "- Rate $($failed.TargetRate) eps: Health check failed`n"
            }
            if (-not $failed.MemoryStable) {
                $report += "- Rate $($failed.TargetRate) eps: Excessive memory growth ($($failed.MemoryDelta) MB)`n"
            }
        }
    }

    $report += @"


---

## Recommendations

"@

    if ($MaxRate -ge 50000) {
        $report += "- [OK] **Excellent Performance** - System can handle very high throughput ($MaxRate eps)`n"
    }
    elseif ($MaxRate -ge 20000) {
        $report += "- [OK] **Good Performance** - System can handle high throughput ($MaxRate eps)`n"
    }
    elseif ($MaxRate -ge 10000) {
        $report += "- [!] **Moderate Performance** - System can handle moderate throughput ($MaxRate eps)`n"
        $report += "- Consider: Increasing ClickHouse workers, optimizing batch sizes, adding more CPU/RAM`n"
    }
    elseif ($MaxRate -ge 5000) {
        $report += "- [!] **Limited Performance** - System struggling at moderate load ($MaxRate eps)`n"
        $report += "- Recommended: Review system resources, check for bottlenecks in detection rules`n"
    }
    else {
        $report += "- [X] **Poor Performance** - System cannot sustain high load ($MaxRate eps)`n"
        $report += "- Critical: Check ClickHouse configuration, increase resources, review detection engine`n"
    }

    if ($script:OptimalConfiguration.MemoryDelta -gt 100) {
        $report += "- [!] Memory growth detected ($($script:OptimalConfiguration.MemoryDelta) MB) - monitor for leaks`n"
    }

    # Resource recommendations
    $report += @"

### Scaling Recommendations:

**For Higher Throughput:**
1. Increase ClickHouse batch size (current default: 10000)
2. Add more event storage workers (current default: 8)
3. Scale ClickHouse horizontally (add more nodes)
4. Increase system resources (CPU, RAM)
5. Optimize detection rules (reduce complexity)

**For Better Stability:**
1. Enable event filtering to drop low-value events
2. Implement event sampling for high-volume sources
3. Monitor memory usage and tune GC settings
4. Review and optimize correlation rules

**Production Deployment:**
- Reserve 20-30% headroom: Target sustained rate of $([math]::Floor($MaxRate * 0.7)) eps
- Enable auto-scaling based on event queue depth
- Implement circuit breakers for downstream dependencies
- Set up comprehensive monitoring and alerting

---

## System Configuration

**Test Parameters:**
- Start Rate: $StartRate eps
- Max Rate: $MaxRate eps
- Test Duration: $TestDuration seconds
- Drop Rate Threshold: $DropRateThreshold%
- Strategy: $Strategy
- Increment Step: $IncrementStep eps (incremental only)

**Environment:**
- Syslog: $SyslogHost`:$SyslogPort
- Protocol: UDP
- Message Format: RFC 3164 Syslog

---

**Generated:** $(Get-Date)
**Test Script:** load_test_max_throughput.ps1
"@

    # Save report
    $report | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "  Report saved to: $reportPath" -ForegroundColor Green

    return $reportPath
}

#endregion

#region Main Execution

function Main {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    Cerberus SIEM - Maximum Throughput Discovery Test        ║
║                                                              ║
║   Progressive load testing to find maximum ingestion rate   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "`nTest Configuration:" -ForegroundColor White
    Write-Host "  Base URL: $BaseUrl"
    Write-Host "  Syslog: $SyslogHost`:$SyslogPort"
    Write-Host "  Strategy: $Strategy"
    Write-Host "  Test Duration: $TestDuration seconds per iteration"
    Write-Host "  Start Rate: $StartRate eps"
    Write-Host "  Max Rate: $MaxRate eps"
    Write-Host "  Drop Rate Threshold: $DropRateThreshold%"
    if ($Strategy -eq "incremental") {
        Write-Host "  Increment Step: $IncrementStep eps"
    }
    Write-Host "  Output: $OutputFile"

    # Pre-flight checks
    Write-Host "`n" -NoNewline
    Write-TestHeader "Pre-Flight Checks"

    if (-not (Test-ApiHealth)) {
        Write-TestResult "API Health Check" "FAILED - Is Cerberus running?" "Error"
        Write-Host "`nAborting tests - API is not accessible`n" -ForegroundColor Red
        exit 1
    }
    Write-TestResult "API Health Check" "PASSED" "Success"

    $process = Get-Process -Name cerberus -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-TestResult "Process Check" "WARNING - Cannot monitor process" "Warning"
    }
    else {
        Write-TestResult "Process Check" "PASSED" "Success"
        $memory = Get-MemoryUsage
        Write-Host "    Current Memory: $($memory.WorkingSetMB) MB, Threads: $($memory.Threads)" -ForegroundColor Gray
    }

    # Execute search strategy
    try {
        $testStartTime = Get-Date

        if ($Strategy -eq "binary") {
            $maxRate = Find-MaxThroughput-Binary
        }
        else {
            $maxRate = Find-MaxThroughput-Incremental
        }

        $testEndTime = Get-Date
        $totalTestTime = ($testEndTime - $testStartTime).TotalMinutes

        # Generate report
        Write-Host "`n" -NoNewline
        Write-TestHeader "Test Complete"

        Write-Host "`n  Maximum Sustainable Rate: $maxRate events/second" -ForegroundColor $(if ($maxRate -gt 0) { "Green" } else { "Red" })
        Write-Host "  Total Test Time: $([math]::Round($totalTestTime, 1)) minutes"
        Write-Host "  Total Iterations: $($script:TestIterations.Count)"

        $reportPath = Generate-Report -MaxRate $maxRate

        Write-Host "`n  Report: $reportPath" -ForegroundColor Green
        Write-Host "  Review the report for detailed analysis and recommendations.`n" -ForegroundColor White

        # Display quick summary
        if ($maxRate -gt 0) {
            Write-Host "  Quick Summary:" -ForegroundColor Cyan
            Write-Host "  [OK] Max Rate: $maxRate eps" -ForegroundColor Green
            Write-Host "  [OK] Drop Rate at Max: $($script:OptimalConfiguration.DropRate)%" -ForegroundColor Green
            Write-Host "  [OK] Memory Delta: $($script:OptimalConfiguration.MemoryDelta) MB" -ForegroundColor Green
            Write-Host "  [OK] Recommended Production Rate: $([math]::Floor($maxRate * 0.7)) eps (70% of max)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "`n[ERROR] Test execution failed: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }
}

# Run main function
Main

#endregion
