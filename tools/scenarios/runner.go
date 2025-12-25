package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Scenario struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Duration    string            `yaml:"duration"`
	Variables   map[string]string `yaml:",inline"` // Captures all other top-level fields
	Events      []EventDefinition `yaml:"events"`
	Expected    []ExpectedAlert   `yaml:"expected_alerts"`
	Validation  ValidationConfig  `yaml:"validation"`
}

type EventDefinition struct {
	Type      string                 `yaml:"type"`
	Count     int                    `yaml:"count"`
	Interval  string                 `yaml:"interval"`
	Delay     string                 `yaml:"delay"`
	PortRange []int                  `yaml:"port_range"`
	Fields    map[string]interface{} `yaml:"fields"`
}

type ExpectedAlert struct {
	RuleID   string `yaml:"rule_id"`
	Severity string `yaml:"severity"`
	MinCount int    `yaml:"min_count"`
}

type ValidationConfig struct {
	Timeout       string `yaml:"timeout"`
	CheckInterval string `yaml:"check_interval"`
}

type Event struct {
	EventID   string                 `json:"event_id"`
	EventType string                 `json:"event_type"`
	Timestamp string                 `json:"timestamp"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	Severity  string                 `json:"severity,omitempty"`
	Fields    map[string]interface{} `json:"fields"`
	RawData   string                 `json:"raw_data"`
}

type Alert struct {
	AlertID   string `json:"alert_id"`
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}

type AlertsResponse struct {
	Items []Alert `json:"items"`
	Total int     `json:"total"`
}

type Config struct {
	ScenarioFile string
	APIUrl       string
	Validate     bool
	DryRun       bool
}

func main() {
	cfg := parseFlags()

	// Load scenario
	scenario, err := loadScenario(cfg.ScenarioFile)
	if err != nil {
		fmt.Printf("Error loading scenario: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Scenario: %s ===\n", scenario.Name)
	fmt.Printf("Description: %s\n", scenario.Description)
	fmt.Println()

	// Dry run mode - just show what would be generated
	if cfg.DryRun {
		fmt.Println("DRY RUN MODE - No events will be sent")
		fmt.Printf("Would generate %d event sequences\n", len(scenario.Events))
		for i, evt := range scenario.Events {
			fmt.Printf("  %d. %s: %d events\n", i+1, evt.Type, evt.Count)
		}
		return
	}

	// Execute scenario
	fmt.Println("Executing scenario...")
	startTime := time.Now()

	if err := executeScenario(scenario, cfg.APIUrl); err != nil {
		fmt.Printf("Error executing scenario: %v\n", err)
		os.Exit(1)
	}

	executionTime := time.Since(startTime)
	fmt.Printf("\n✓ Scenario execution complete (took %s)\n\n", executionTime.Round(time.Second))

	// Validate expected alerts
	if cfg.Validate {
		fmt.Println("Validating expected alerts...")
		if err := validateAlerts(scenario, cfg.APIUrl); err != nil {
			fmt.Printf("❌ Validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ All expected alerts generated successfully!")
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ScenarioFile, "scenario", "", "Path to scenario YAML file (required)")
	flag.StringVar(&cfg.APIUrl, "api-url", "http://localhost:8080/api/v1", "Cerberus API base URL")
	flag.BoolVar(&cfg.Validate, "validate", true, "Validate expected alerts after execution")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Show what would be generated without sending events")

	flag.Parse()

	if cfg.ScenarioFile == "" {
		fmt.Println("Error: --scenario flag is required")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func loadScenario(filename string) (*Scenario, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var scenario Scenario
	if err := yaml.Unmarshal(data, &scenario); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &scenario, nil
}

func executeScenario(scenario *Scenario, apiURL string) error {
	totalEvents := 0

	for _, eventDef := range scenario.Events {
		// Handle delay before this event sequence
		if eventDef.Delay != "" {
			delay, err := time.ParseDuration(eventDef.Delay)
			if err != nil {
				return fmt.Errorf("invalid delay '%s': %w", eventDef.Delay, err)
			}
			fmt.Printf("Waiting %s before next event sequence...\n", delay)
			time.Sleep(delay)
		}

		// Determine interval between events
		var interval time.Duration
		if eventDef.Interval != "" {
			var err error
			interval, err = time.ParseDuration(eventDef.Interval)
			if err != nil {
				return fmt.Errorf("invalid interval '%s': %w", eventDef.Interval, err)
			}
		}

		// Generate and send events
		fmt.Printf("Generating %d %s events...\n", eventDef.Count, eventDef.Type)

		for i := 0; i < eventDef.Count; i++ {
			event := generateEvent(eventDef, scenario.Variables, i)
			if err := sendEvent(event, apiURL); err != nil {
				fmt.Printf("Warning: Failed to send event: %v\n", err)
			}
			totalEvents++

			// Wait interval between events (except for last one)
			if i < eventDef.Count-1 && interval > 0 {
				time.Sleep(interval)
			}
		}
	}

	fmt.Printf("Sent %d total events\n", totalEvents)
	return nil
}

func generateEvent(def EventDefinition, variables map[string]string, index int) Event {
	// Create a copy of fields and substitute variables
	fields := make(map[string]interface{})
	for k, v := range def.Fields {
		// Handle string substitution
		if strVal, ok := v.(string); ok {
			fields[k] = substituteVariables(strVal, variables)
		} else {
			fields[k] = v
		}
	}

	// Handle port range cycling
	if len(def.PortRange) > 0 {
		port := def.PortRange[index%len(def.PortRange)]
		fields["dest_port"] = port
	}

	// Extract event type and source IP
	eventType := def.Type
	if et, ok := fields["event_type"].(string); ok {
		eventType = et
	}

	sourceIP := ""
	if sip, ok := fields["source_ip"].(string); ok {
		sourceIP = sip
	}

	// Generate raw data summary
	rawData := fmt.Sprintf("%s event from %s", eventType, sourceIP)

	return Event{
		EventID:   uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SourceIP:  sourceIP,
		Fields:    fields,
		RawData:   rawData,
	}
}

func substituteVariables(value string, variables map[string]string) string {
	result := value
	for k, v := range variables {
		placeholder := fmt.Sprintf("${%s}", strings.ToUpper(k))
		result = strings.ReplaceAll(result, placeholder, v)
	}
	return result
}

func sendEvent(event Event, apiURL string) error {
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	resp, err := http.Post(apiURL+"/events", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func validateAlerts(scenario *Scenario, apiURL string) error {
	// Parse validation config
	timeout := 120 * time.Second
	if scenario.Validation.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(scenario.Validation.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}
	}

	checkInterval := 5 * time.Second
	if scenario.Validation.CheckInterval != "" {
		var err error
		checkInterval, err = time.ParseDuration(scenario.Validation.CheckInterval)
		if err != nil {
			return fmt.Errorf("invalid check interval: %w", err)
		}
	}

	fmt.Printf("Waiting up to %s for alerts (checking every %s)...\n", timeout, checkInterval)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	foundAlerts := make(map[string]int) // rule_id -> count

	for {
		select {
		case <-ctx.Done():
			return validateAlertCounts(scenario.Expected, foundAlerts)
		case <-ticker.C:
			// Fetch recent alerts
			alerts, err := fetchAlerts(apiURL)
			if err != nil {
				fmt.Printf("Warning: Failed to fetch alerts: %v\n", err)
				continue
			}

			// Count alerts by rule ID
			for _, alert := range alerts {
				foundAlerts[alert.RuleID]++
			}

			// Check if we have all expected alerts
			if hasAllExpectedAlerts(scenario.Expected, foundAlerts) {
				fmt.Println("✓ All expected alerts found!")
				return nil
			}

			fmt.Printf("Found %d alerts so far, waiting for more...\n", len(alerts))
		}
	}
}

func fetchAlerts(apiURL string) ([]Alert, error) {
	resp, err := http.Get(apiURL + "/alerts?limit=100")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var alertsResp AlertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&alertsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return alertsResp.Items, nil
}

func hasAllExpectedAlerts(expected []ExpectedAlert, found map[string]int) bool {
	for _, exp := range expected {
		if found[exp.RuleID] < exp.MinCount {
			return false
		}
	}
	return true
}

func validateAlertCounts(expected []ExpectedAlert, found map[string]int) error {
	fmt.Println("\n=== Validation Results ===")

	allValid := true
	for _, exp := range expected {
		count := found[exp.RuleID]
		status := "✓"
		if count < exp.MinCount {
			status = "❌"
			allValid = false
		}

		fmt.Printf("%s Rule: %s (expected: %d, found: %d)\n", status, exp.RuleID, exp.MinCount, count)
	}

	if !allValid {
		return fmt.Errorf("some expected alerts were not generated")
	}

	return nil
}
