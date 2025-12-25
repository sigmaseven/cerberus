package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	defaultAPIURL     = "http://localhost:8080/api/v1/events"
	defaultSyslogAddr = "localhost:514"
	defaultCEFAddr    = "localhost:515"
	defaultJSONAddr   = "localhost:8888"
)

type Config struct {
	Mode       string
	Scenario   string
	Rate       int
	Duration   int
	Count      int
	Output     string
	APIUrl     string
	SyslogAddr string
	CEFAddr    string
	JSONAddr   string
	TargetIP   string
	ExternalIP string
}

func main() {
	cfg := parseFlags()

	generator := NewEventGenerator()

	switch cfg.Mode {
	case "single":
		generateSingleEvent(generator, cfg)
	case "stream":
		generateStream(generator, cfg)
	case "scenario":
		generateScenario(generator, cfg)
	default:
		fmt.Printf("Unknown mode: %s\n", cfg.Mode)
		os.Exit(1)
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Mode, "mode", "single", "Generation mode: single, stream, scenario")
	flag.StringVar(&cfg.Scenario, "scenario", "", "Scenario name: brute_force, port_scan, data_exfil")
	flag.IntVar(&cfg.Rate, "rate", 1, "Events per second (for stream mode)")
	flag.IntVar(&cfg.Duration, "duration", 10, "Duration in seconds (for stream mode)")
	flag.IntVar(&cfg.Count, "count", 1, "Number of events to generate (for single mode)")
	flag.StringVar(&cfg.Output, "output", "api", "Output method: api, syslog, cef, json, file, stdout")
	flag.StringVar(&cfg.APIUrl, "api-url", defaultAPIURL, "API endpoint URL")
	flag.StringVar(&cfg.SyslogAddr, "syslog-addr", defaultSyslogAddr, "Syslog listener address")
	flag.StringVar(&cfg.CEFAddr, "cef-addr", defaultCEFAddr, "CEF listener address")
	flag.StringVar(&cfg.JSONAddr, "json-addr", defaultJSONAddr, "JSON listener address")
	flag.StringVar(&cfg.TargetIP, "target-ip", "192.0.2.50", "Target IP for scenarios")
	flag.StringVar(&cfg.ExternalIP, "external-ip", "198.51.100.25", "External IP for scenarios")

	flag.Parse()
	return cfg
}

func generateSingleEvent(gen *EventGenerator, cfg *Config) {
	for i := 0; i < cfg.Count; i++ {
		event := gen.GenerateAuthEvent(false)
		sendEvent(event, cfg)
		fmt.Printf("Generated event: %s\n", event.EventID)
	}
}

func generateStream(gen *EventGenerator, cfg *Config) {
	ticker := time.NewTicker(time.Second / time.Duration(cfg.Rate))
	defer ticker.Stop()

	timeout := time.After(time.Duration(cfg.Duration) * time.Second)
	count := 0

	fmt.Printf("Starting event stream: %d events/sec for %d seconds\n", cfg.Rate, cfg.Duration)

	for {
		select {
		case <-ticker.C:
			// Generate random event type
			event := generateRandomEvent(gen)
			sendEvent(event, cfg)
			count++
			if count%100 == 0 {
				fmt.Printf("Generated %d events...\n", count)
			}
		case <-timeout:
			fmt.Printf("Stream complete. Generated %d total events.\n", count)
			return
		}
	}
}

func generateScenario(gen *EventGenerator, cfg *Config) {
	var events []Event

	switch cfg.Scenario {
	case "brute_force":
		fmt.Println("Generating brute force attack scenario...")
		events = gen.GenerateBruteForceScenario(cfg.TargetIP, 50)
	case "port_scan":
		fmt.Println("Generating port scan scenario...")
		events = gen.GeneratePortScanScenario(cfg.TargetIP, "10.0.1.100", 20)
	case "data_exfil":
		fmt.Println("Generating data exfiltration scenario...")
		events = gen.GenerateDataExfiltrationScenario("10.0.1.50", cfg.ExternalIP)
	case "mixed_attack":
		fmt.Println("Generating mixed attack scenario...")
		// Combine multiple attack types
		events = append(events, gen.GenerateBruteForceScenario(cfg.TargetIP, 30)...)
		time.Sleep(2 * time.Second)
		events = append(events, gen.GeneratePortScanScenario(cfg.TargetIP, "10.0.1.100", 10)...)
	default:
		fmt.Printf("Unknown scenario: %s\n", cfg.Scenario)
		fmt.Println("Available scenarios: brute_force, port_scan, data_exfil, mixed_attack")
		return
	}

	fmt.Printf("Sending %d events for scenario '%s'...\n", len(events), cfg.Scenario)

	for i, event := range events {
		sendEvent(event, cfg)
		if i < len(events)-1 {
			time.Sleep(time.Second) // Delay between events
		}
	}

	fmt.Printf("Scenario complete. Sent %d events.\n", len(events))
}

func generateRandomEvent(gen *EventGenerator) Event {
	eventTypes := []string{"auth", "network", "file", "process", "http"}
	eventType := eventTypes[gen.rand.Intn(len(eventTypes))]

	switch eventType {
	case "auth":
		return gen.GenerateAuthEvent(gen.rand.Float32() < 0.1) // 10% failed
	case "network":
		return gen.GenerateNetworkEvent(gen.rand.Float32() < 0.3) // 30% external
	case "file":
		return gen.GenerateFileEvent(gen.rand.Float32() < 0.05) // 5% sensitive
	case "process":
		return gen.GenerateProcessEvent(gen.rand.Float32() < 0.1) // 10% suspicious
	case "http":
		return gen.GenerateHTTPEvent(gen.rand.Float32() < 0.05) // 5% suspicious
	default:
		return gen.GenerateAuthEvent(false)
	}
}

func sendEvent(event Event, cfg *Config) {
	switch cfg.Output {
	case "api":
		sendToAPI(event, cfg.APIUrl)
	case "syslog":
		sendToSyslog(event, cfg.SyslogAddr)
	case "cef":
		sendToCEF(event, cfg.CEFAddr)
	case "json":
		sendToJSONListener(event, cfg.JSONAddr)
	case "file":
		appendToFile(event, "events.json")
	case "stdout":
		printEvent(event)
	default:
		fmt.Printf("Unknown output method: %s\n", cfg.Output)
	}
}

func sendToAPI(event Event, apiURL string) {
	jsonData, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error sending to API: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("API error (status %d): %s\n", resp.StatusCode, string(body))
	}
}

func sendToSyslog(event Event, addr string) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("Error connecting to syslog: %v\n", err)
		return
	}
	defer func() { _ = conn.Close() }()

	// Format as syslog message
	priority := 134 // Local0, Info
	timestamp := time.Now().Format("Jan 2 15:04:05")
	hostname := "eventgen"
	message := event.RawData

	syslogMsg := fmt.Sprintf("<%d>%s %s %s: %s", priority, timestamp, hostname, event.EventType, message)
	_, err = conn.Write([]byte(syslogMsg))
	if err != nil {
		fmt.Printf("Error sending syslog: %v\n", err)
	}
}

func sendToCEF(event Event, addr string) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("Error connecting to CEF: %v\n", err)
		return
	}
	defer func() { _ = conn.Close() }()

	// Format as CEF message
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	cefMsg := fmt.Sprintf("CEF:0|EventGen|TestTool|1.0|%s|%s|5|src=%s msg=%s",
		event.EventType,
		event.EventType,
		event.SourceIP,
		event.RawData,
	)

	_, err = conn.Write([]byte(cefMsg))
	if err != nil {
		fmt.Printf("Error sending CEF: %v\n", err)
	}
}

func sendToJSONListener(event Event, addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Error connecting to JSON listener: %v\n", err)
		return
	}
	defer func() { _ = conn.Close() }()

	jsonData, err := json.Marshal(event.Fields)
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}

	_, err = conn.Write(append(jsonData, '\n'))
	if err != nil {
		fmt.Printf("Error sending to JSON listener: %v\n", err)
	}
}

func appendToFile(event Event, filename string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()

	jsonData, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}

	if _, err := f.Write(append(jsonData, '\n')); err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
	}
}

func printEvent(event Event) {
	jsonData, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
}
