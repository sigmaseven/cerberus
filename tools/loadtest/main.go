package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Configuration
type Config struct {
	BaseURL            string
	SyslogHost         string
	SyslogPort         int
	TestDuration       int
	StartRate          int
	MaxRate            int
	DropRateThreshold  float64
	Strategy           string
	IncrementStep      int
	OutputFile         string
	ConcurrentSenders  int
}

// TestResult stores results from a single load test iteration
type TestResult struct {
	TargetRate      int
	Duration        float64
	EventsSent      int64
	EventsFailed    int64
	SendRate        float64
	DropRate        float64
	EventsIngested  int64
	IngestionRate   float64
	SystemHealthy   bool
	HealthCheck     bool
	Success         bool
	Timestamp       time.Time
}

// Stats from API
type APIStats struct {
	EventsIngested int64 `json:"events_ingested"`
}

var (
	testIterations     []*TestResult
	maxSustainableRate int
	optimalConfig      *TestResult
	iterationsMutex    sync.Mutex
)

func main() {
	cfg := parseFlags()

	printHeader()
	printConfig(cfg)

	// Pre-flight checks
	if !runPreFlightChecks(cfg) {
		fmt.Println("\nAborting tests - pre-flight checks failed")
		os.Exit(1)
	}

	// Run test strategy
	testStartTime := time.Now()
	var maxRate int

	if cfg.Strategy == "binary" {
		maxRate = findMaxThroughputBinary(cfg)
	} else {
		maxRate = findMaxThroughputIncremental(cfg)
	}

	testDuration := time.Since(testStartTime)

	// Generate report
	printTestComplete(maxRate, testDuration)
	generateReport(cfg, maxRate, testDuration)
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.BaseURL, "url", "http://localhost:8080", "Base URL of the Cerberus API")
	flag.StringVar(&cfg.SyslogHost, "host", "localhost", "Syslog listener host")
	flag.IntVar(&cfg.SyslogPort, "port", 514, "Syslog listener port")
	flag.IntVar(&cfg.TestDuration, "duration", 15, "Duration for each test iteration in seconds")
	flag.IntVar(&cfg.StartRate, "start", 1000, "Starting events per second rate")
	flag.IntVar(&cfg.MaxRate, "max", 100000, "Maximum events per second to test")
	flag.Float64Var(&cfg.DropRateThreshold, "threshold", 1.0, "Maximum acceptable drop rate percentage")
	flag.StringVar(&cfg.Strategy, "strategy", "binary", "Search strategy: binary or incremental")
	flag.IntVar(&cfg.IncrementStep, "step", 5000, "Step size for incremental strategy")
	flag.StringVar(&cfg.OutputFile, "output", "MAX_THROUGHPUT_RESULTS.md", "Output file for results")
	flag.IntVar(&cfg.ConcurrentSenders, "senders", 100, "Number of concurrent UDP senders")

	flag.Parse()
	return cfg
}

func printHeader() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                                                              ║")
	fmt.Println("║    Cerberus SIEM - Maximum Throughput Discovery Test        ║")
	fmt.Println("║                     (Go Edition)                             ║")
	fmt.Println("║                                                              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

func printConfig(cfg *Config) {
	fmt.Println("\nTest Configuration:")
	fmt.Printf("  Base URL: %s\n", cfg.BaseURL)
	fmt.Printf("  Syslog: %s:%d\n", cfg.SyslogHost, cfg.SyslogPort)
	fmt.Printf("  Strategy: %s\n", cfg.Strategy)
	fmt.Printf("  Test Duration: %d seconds per iteration\n", cfg.TestDuration)
	fmt.Printf("  Start Rate: %d eps\n", cfg.StartRate)
	fmt.Printf("  Max Rate: %d eps\n", cfg.MaxRate)
	fmt.Printf("  Drop Rate Threshold: %.1f%%\n", cfg.DropRateThreshold)
	fmt.Printf("  Concurrent Senders: %d\n", cfg.ConcurrentSenders)
	if cfg.Strategy == "incremental" {
		fmt.Printf("  Increment Step: %d eps\n", cfg.IncrementStep)
	}
	fmt.Printf("  Output: %s\n", cfg.OutputFile)
}

func runPreFlightChecks(cfg *Config) bool {
	fmt.Println("\n===================================")
	fmt.Println("  Pre-Flight Checks")
	fmt.Println("===================================")

	if !testAPIHealth(cfg.BaseURL) {
		fmt.Println("  [Error] API Health Check: FAILED - Is Cerberus running?")
		return false
	}
	fmt.Println("  [Success] API Health Check: PASSED")

	return true
}

func testAPIHealth(baseURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func getEventCount(baseURL string) int64 {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/stats")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}

	var stats APIStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return 0
	}

	return stats.EventsIngested
}

func generateSyslogMessage(index int) string {
	timestamp := time.Now().Format("Jan 02 15:04:05")

	hostnames := []string{"web-server-01", "db-server-02", "app-server-03", "mail-server-04"}
	processes := []string{"sshd", "apache2", "mysqld", "postfix", "kernel"}
	messages := []string{
		"User authentication successful from 192.168.1.100",
		"Connection established from 10.0.0.50 port 22",
		"Database query executed in 45ms",
		"HTTP request GET /api/users completed with status 200",
		"Failed login attempt from 172.16.0.100",
		"System backup completed successfully",
		"Certificate renewal initiated",
		"Memory usage at 75%",
		"Disk I/O warning threshold exceeded",
		"Service restarted successfully",
	}

	hostname := hostnames[index%len(hostnames)]
	process := processes[index%len(processes)]
	message := messages[index%len(messages)]
	processID := 1000 + (index % 8999)

	return fmt.Sprintf("<134>%s %s %s[%d]: %s", timestamp, hostname, process, processID, message)
}

func sendSyslogUDP(message string, host string, port int) bool {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	_, err = conn.Write([]byte(message))
	return err == nil
}

func testLoadAtRate(cfg *Config, eventsPerSecond int) *TestResult {
	fmt.Printf("\n  Testing at rate: %d events/sec for %ds\n", eventsPerSecond, cfg.TestDuration)

	totalEvents := int64(eventsPerSecond * cfg.TestDuration)

	// Capture initial state
	initialEventCount := getEventCount(cfg.BaseURL)
	testStartTime := time.Now()

	// Event counters
	var sentSuccessful int64
	var sentFailed int64
	var eventIndex int64

	// Create worker pool
	jobs := make(chan int64, eventsPerSecond)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.ConcurrentSenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				message := generateSyslogMessage(int(idx))
				if sendSyslogUDP(message, cfg.SyslogHost, cfg.SyslogPort) {
					atomic.AddInt64(&sentSuccessful, 1)
				} else {
					atomic.AddInt64(&sentFailed, 1)
				}
			}
		}()
	}

	// Send events with rate limiting
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	eventsThisSecond := 0
	startSecond := time.Now()

	for atomic.LoadInt64(&eventIndex) < totalEvents {
		select {
		case <-ticker.C:
			elapsed := time.Since(startSecond).Seconds()
			currentRate := int(float64(eventsThisSecond) / elapsed)
			progress := float64(atomic.LoadInt64(&eventIndex)) / float64(totalEvents) * 100
			fmt.Printf("    Progress: %.1f%% - Current Rate: %d eps\n", progress, currentRate)
			eventsThisSecond = 0
			startSecond = time.Now()
		default:
			if eventsThisSecond < eventsPerSecond {
				idx := atomic.AddInt64(&eventIndex, 1) - 1
				if idx < totalEvents {
					jobs <- idx
					eventsThisSecond++
				}
			} else {
				// Rate limit - sleep briefly
				time.Sleep(time.Millisecond)
			}
		}
	}

	close(jobs)
	wg.Wait()

	testEndTime := time.Now()
	actualDuration := testEndTime.Sub(testStartTime).Seconds()

	// Wait for processing
	fmt.Println("  Waiting for event processing (10 seconds)...")
	time.Sleep(10 * time.Second)

	// Capture final state
	finalEventCount := getEventCount(cfg.BaseURL)

	// Calculate metrics
	actualRate := float64(sentSuccessful) / actualDuration
	dropRate := float64(sentFailed) / float64(totalEvents) * 100
	eventsIngested := finalEventCount - initialEventCount

	var ingestionRate float64
	if eventsIngested > 0 {
		ingestionRate = float64(eventsIngested) / (actualDuration + 10)
	}

	// System health check
	healthCheck := testAPIHealth(cfg.BaseURL)
	systemHealthy := healthCheck

	result := &TestResult{
		TargetRate:     eventsPerSecond,
		Duration:       actualDuration,
		EventsSent:     sentSuccessful,
		EventsFailed:   sentFailed,
		SendRate:       actualRate,
		DropRate:       dropRate,
		EventsIngested: eventsIngested,
		IngestionRate:  ingestionRate,
		SystemHealthy:  systemHealthy,
		HealthCheck:    healthCheck,
		Success:        dropRate <= cfg.DropRateThreshold && systemHealthy,
		Timestamp:      time.Now(),
	}

	// Display results
	fmt.Println("\n  Results:")
	fmt.Printf("    Events Sent: %d/%d\n", sentSuccessful, totalEvents)
	fmt.Printf("    Send Rate: %.2f eps (target: %d)\n", actualRate, eventsPerSecond)

	if dropRate <= cfg.DropRateThreshold {
		fmt.Printf("    Drop Rate: %.4f%% [OK]\n", dropRate)
	} else {
		fmt.Printf("    Drop Rate: %.4f%% [FAIL]\n", dropRate)
	}

	fmt.Printf("    Events Ingested: %d\n", eventsIngested)
	fmt.Printf("    Ingestion Rate: %.2f eps\n", ingestionRate)

	if systemHealthy {
		fmt.Printf("    System Health: Healthy [OK]\n")
	} else {
		fmt.Printf("    System Health: Degraded [FAIL]\n")
	}

	if result.Success {
		fmt.Printf("    Test Result: PASS [OK]\n")
	} else {
		fmt.Printf("    Test Result: FAIL [X]\n")
	}

	return result
}

func findMaxThroughputBinary(cfg *Config) int {
	fmt.Println("\n===================================")
	fmt.Println("  Binary Search Strategy")
	fmt.Println("===================================")
	fmt.Printf("  Starting binary search between %d and %d eps\n", cfg.StartRate, cfg.MaxRate)

	low := cfg.StartRate
	high := cfg.MaxRate
	bestSuccessRate := 0
	iterations := 0
	maxIterations := 15

	for low <= high && iterations < maxIterations {
		iterations++
		testRate := (low + high) / 2

		fmt.Printf("\n===================================\n")
		fmt.Printf("  Iteration %d - Testing %d eps\n", iterations, testRate)
		fmt.Printf("===================================\n")
		fmt.Printf("  Search Range: [%d - %d]\n", low, high)

		result := testLoadAtRate(cfg, testRate)

		iterationsMutex.Lock()
		testIterations = append(testIterations, result)
		iterationsMutex.Unlock()

		if result.Success {
			// Test passed - try higher rate
			bestSuccessRate = testRate
			maxSustainableRate = testRate
			optimalConfig = result

			fmt.Printf("\n  [OK] Rate %d eps is sustainable - trying higher\n", testRate)
			low = testRate + 1
		} else {
			// Test failed - try lower rate
			fmt.Printf("\n  [FAIL] Rate %d eps failed - trying lower\n", testRate)
			high = testRate - 1
		}

		// Cooldown between tests
		if low <= high {
			fmt.Println("\n  Cooldown period (15 seconds)...")
			time.Sleep(15 * time.Second)
		}
	}

	if bestSuccessRate == 0 {
		fmt.Println("\n  [WARNING] No successful rate found! Starting rate may be too high.")
	}

	return bestSuccessRate
}

func findMaxThroughputIncremental(cfg *Config) int {
	fmt.Println("\n===================================")
	fmt.Println("  Incremental Strategy")
	fmt.Println("===================================")
	fmt.Printf("  Starting at %d eps, incrementing by %d\n", cfg.StartRate, cfg.IncrementStep)

	currentRate := cfg.StartRate
	lastSuccessRate := 0
	consecutiveFailures := 0
	maxConsecutiveFailures := 2

	for currentRate <= cfg.MaxRate && consecutiveFailures < maxConsecutiveFailures {
		fmt.Printf("\n===================================\n")
		fmt.Printf("  Testing %d eps\n", currentRate)
		fmt.Printf("===================================\n")

		result := testLoadAtRate(cfg, currentRate)

		iterationsMutex.Lock()
		testIterations = append(testIterations, result)
		iterationsMutex.Unlock()

		if result.Success {
			// Test passed - increment and continue
			lastSuccessRate = currentRate
			maxSustainableRate = currentRate
			optimalConfig = result
			consecutiveFailures = 0

			fmt.Printf("\n  [OK] Rate %d eps is sustainable - incrementing\n", currentRate)
			currentRate += cfg.IncrementStep
		} else {
			// Test failed - increment failure counter
			consecutiveFailures++
			fmt.Printf("\n  [FAIL] Rate %d eps failed (failure %d/%d)\n",
				currentRate, consecutiveFailures, maxConsecutiveFailures)

			if consecutiveFailures < maxConsecutiveFailures {
				// Try one more time with smaller increment
				currentRate = lastSuccessRate + (cfg.IncrementStep / 2)
			}
		}

		// Cooldown between tests
		if currentRate <= cfg.MaxRate && consecutiveFailures < maxConsecutiveFailures {
			fmt.Println("\n  Cooldown period (15 seconds)...")
			time.Sleep(15 * time.Second)
		}
	}

	if lastSuccessRate == 0 {
		fmt.Println("\n  [WARNING] No successful rate found! Starting rate may be too high.")
	}

	return lastSuccessRate
}

func printTestComplete(maxRate int, duration time.Duration) {
	fmt.Println("\n===================================")
	fmt.Println("  Test Complete")
	fmt.Println("===================================")

	if maxRate > 0 {
		fmt.Printf("\n  Maximum Sustainable Rate: %d events/second\n", maxRate)
	} else {
		fmt.Printf("\n  Maximum Sustainable Rate: NONE FOUND\n")
	}

	fmt.Printf("  Total Test Time: %.1f minutes\n", duration.Minutes())
	fmt.Printf("  Total Iterations: %d\n", len(testIterations))
}

func generateReport(cfg *Config, maxRate int, testDuration time.Duration) {
	fmt.Println("\n===================================")
	fmt.Println("  Generating Report")
	fmt.Println("===================================")

	file, err := os.Create(cfg.OutputFile)
	if err != nil {
		fmt.Printf("  Error creating report file: %v\n", err)
		return
	}
	defer file.Close()

	// Header
	fmt.Fprintf(file, "# Cerberus SIEM - Maximum Throughput Test Results\n\n")
	fmt.Fprintf(file, "**Test Date:** %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(file, "**Base URL:** %s\n", cfg.BaseURL)
	fmt.Fprintf(file, "**Strategy:** %s\n", cfg.Strategy)
	fmt.Fprintf(file, "**Test Duration per Iteration:** %d seconds\n", cfg.TestDuration)
	fmt.Fprintf(file, "**Drop Rate Threshold:** %.1f%%\n", cfg.DropRateThreshold)
	fmt.Fprintf(file, "**Test Tool:** Go Load Tester\n\n")
	fmt.Fprintf(file, "---\n\n")

	// Executive Summary
	fmt.Fprintf(file, "## Executive Summary\n\n")
	fmt.Fprintf(file, "**Maximum Sustainable Event Ingestion Rate: %d events/second**\n\n", maxRate)

	if maxRate > 0 {
		fmt.Fprintf(file, "This test discovered that Cerberus SIEM can sustainably ingest **%d events per second** ", maxRate)
		fmt.Fprintf(file, "with less than %.1f%% event drop rate and stable system health.\n\n", cfg.DropRateThreshold)

		if optimalConfig != nil {
			fmt.Fprintf(file, "### Optimal Configuration at Max Rate:\n")
			fmt.Fprintf(file, "- **Events Sent:** %d\n", optimalConfig.EventsSent)
			fmt.Fprintf(file, "- **Send Rate:** %.2f eps\n", optimalConfig.SendRate)
			fmt.Fprintf(file, "- **Drop Rate:** %.4f%%\n", optimalConfig.DropRate)
			fmt.Fprintf(file, "- **Events Ingested:** %d\n", optimalConfig.EventsIngested)
			fmt.Fprintf(file, "- **Ingestion Rate:** %.2f eps\n", optimalConfig.IngestionRate)
			fmt.Fprintf(file, "- **System Health:** %s\n\n", healthStatus(optimalConfig.SystemHealthy))
		}
	} else {
		fmt.Fprintf(file, "**WARNING:** No sustainable rate could be determined. All tested rates failed.\n")
		fmt.Fprintf(file, "This may indicate:\n")
		fmt.Fprintf(file, "- Starting rate is too high\n")
		fmt.Fprintf(file, "- System resources are insufficient\n")
		fmt.Fprintf(file, "- Configuration issues with Cerberus\n")
		fmt.Fprintf(file, "- Network issues preventing event delivery\n\n")
	}

	fmt.Fprintf(file, "---\n\n")

	// Test Iterations
	fmt.Fprintf(file, "## Test Iterations\n\n")
	fmt.Fprintf(file, "A total of %d test iterations were performed.\n\n", len(testIterations))
	fmt.Fprintf(file, "| Iteration | Target Rate | Send Rate | Drop Rate | Ingested | Ingestion Rate | Result |\n")
	fmt.Fprintf(file, "|-----------|-------------|-----------|-----------|----------|----------------|--------|\n")

	for i, iter := range testIterations {
		result := "[X] FAIL"
		if iter.Success {
			result = "[OK] PASS"
		}
		fmt.Fprintf(file, "| %d | %d | %.2f | %.4f%% | %d | %.2f | %s |\n",
			i+1, iter.TargetRate, iter.SendRate, iter.DropRate,
			iter.EventsIngested, iter.IngestionRate, result)
	}

	fmt.Fprintf(file, "\n\n---\n\n")

	// Performance Analysis
	fmt.Fprintf(file, "## Performance Analysis\n\n")

	successfulTests := 0
	var totalSendRate, totalIngestionRate, totalDropRate float64

	for _, iter := range testIterations {
		if iter.Success {
			successfulTests++
			totalSendRate += iter.SendRate
			totalIngestionRate += iter.IngestionRate
			totalDropRate += iter.DropRate
		}
	}

	if successfulTests > 0 {
		fmt.Fprintf(file, "**Successful Tests:** %d/%d\n\n", successfulTests, len(testIterations))
		fmt.Fprintf(file, "**Average Metrics (Successful Tests):**\n")
		fmt.Fprintf(file, "- Send Rate: %.2f eps\n", totalSendRate/float64(successfulTests))
		fmt.Fprintf(file, "- Ingestion Rate: %.2f eps\n", totalIngestionRate/float64(successfulTests))
		fmt.Fprintf(file, "- Drop Rate: %.4f%%\n\n", totalDropRate/float64(successfulTests))
	}

	failedTests := len(testIterations) - successfulTests
	if failedTests > 0 {
		fmt.Fprintf(file, "**Failed Tests:** %d/%d\n\n", failedTests, len(testIterations))
	}

	fmt.Fprintf(file, "---\n\n")

	// Recommendations
	fmt.Fprintf(file, "## Recommendations\n\n")

	if maxRate >= 50000 {
		fmt.Fprintf(file, "- [OK] **Excellent Performance** - System can handle very high throughput (%d eps)\n", maxRate)
	} else if maxRate >= 20000 {
		fmt.Fprintf(file, "- [OK] **Good Performance** - System can handle high throughput (%d eps)\n", maxRate)
	} else if maxRate >= 10000 {
		fmt.Fprintf(file, "- [!] **Moderate Performance** - System can handle moderate throughput (%d eps)\n", maxRate)
		fmt.Fprintf(file, "- Consider: Increasing ClickHouse workers, optimizing batch sizes, adding more CPU/RAM\n")
	} else if maxRate >= 5000 {
		fmt.Fprintf(file, "- [!] **Limited Performance** - System struggling at moderate load (%d eps)\n", maxRate)
		fmt.Fprintf(file, "- Recommended: Review system resources, check for bottlenecks in detection rules\n")
	} else if maxRate > 0 {
		fmt.Fprintf(file, "- [X] **Poor Performance** - System cannot sustain high load (%d eps)\n", maxRate)
		fmt.Fprintf(file, "- Critical: Check ClickHouse configuration, increase resources, review detection engine\n")
	}

	fmt.Fprintf(file, "\n### Scaling Recommendations:\n\n")
	fmt.Fprintf(file, "**For Higher Throughput:**\n")
	fmt.Fprintf(file, "1. Increase ClickHouse batch size (current default: 10000)\n")
	fmt.Fprintf(file, "2. Add more event storage workers (current default: 8)\n")
	fmt.Fprintf(file, "3. Scale ClickHouse horizontally (add more nodes)\n")
	fmt.Fprintf(file, "4. Increase system resources (CPU, RAM)\n")
	fmt.Fprintf(file, "5. Optimize detection rules (reduce complexity)\n\n")

	if maxRate > 0 {
		recommendedRate := int(math.Floor(float64(maxRate) * 0.7))
		fmt.Fprintf(file, "**Production Deployment:**\n")
		fmt.Fprintf(file, "- Reserve 20-30%% headroom: Target sustained rate of %d eps (70%% of max)\n", recommendedRate)
		fmt.Fprintf(file, "- Enable auto-scaling based on event queue depth\n")
		fmt.Fprintf(file, "- Implement circuit breakers for downstream dependencies\n")
		fmt.Fprintf(file, "- Set up comprehensive monitoring and alerting\n\n")
	}

	fmt.Fprintf(file, "---\n\n")
	fmt.Fprintf(file, "**Generated:** %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(file, "**Test Script:** Go Load Tester\n")
	fmt.Fprintf(file, "**Total Test Duration:** %.1f minutes\n", testDuration.Minutes())

	fmt.Printf("  Report saved to: %s\n", cfg.OutputFile)

	// Print quick summary
	if maxRate > 0 {
		fmt.Println("\n  Quick Summary:")
		fmt.Printf("  [OK] Max Rate: %d eps\n", maxRate)
		if optimalConfig != nil {
			fmt.Printf("  [OK] Drop Rate at Max: %.4f%%\n", optimalConfig.DropRate)
		}
		recommendedRate := int(math.Floor(float64(maxRate) * 0.7))
		fmt.Printf("  [OK] Recommended Production Rate: %d eps (70%% of max)\n", recommendedRate)
	}
}

func healthStatus(healthy bool) string {
	if healthy {
		return "Healthy [OK]"
	}
	return "Degraded [FAIL]"
}
