package load

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"cerberus/core"
)

// EventGenerator generates synthetic SIEM events for load testing
// TASK 43.3: Synthetic event data generator
type EventGenerator struct {
	eventTypes   []string
	hosts        []string
	users        []string
	processes    []string
	ips          []string
	timestamp    time.Time
	eventCounter int64
}

// NewEventGenerator creates a new event generator with realistic SIEM data
func NewEventGenerator() *EventGenerator {
	return &EventGenerator{
		eventTypes: []string{
			"login", "logout", "file_access", "network_connection", "process_creation",
			"registry_modification", "dns_query", "http_request", "execution", "deletion",
		},
		hosts: []string{
			"WIN-SERVER-01", "WIN-WORKSTATION-01", "LINUX-SERVER-01", "LINUX-DESKTOP-01",
			"MAC-WORKSTATION-01", "WIN-SERVER-02", "LINUX-SERVER-02",
		},
		users: []string{
			"administrator", "john.doe", "jane.smith", "service_account", "guest",
			"admin", "user1", "user2", "testuser", "svc_sql",
		},
		processes: []string{
			"cmd.exe", "powershell.exe", "explorer.exe", "chrome.exe", "firefox.exe",
			"ssh", "bash", "python", "java", "node",
		},
		ips: []string{
			"192.168.1.10", "192.168.1.11", "192.168.1.20", "10.0.0.5", "10.0.0.10",
			"172.16.0.5", "8.8.8.8", "1.1.1.1", "203.0.113.5", "198.51.100.10",
		},
		timestamp:    time.Now(),
		eventCounter: 0,
	}
}

// GenerateEvent generates a random SIEM event for load testing
func (eg *EventGenerator) GenerateEvent() *core.Event {
	eg.eventCounter++
	timestamp := eg.timestamp.Add(time.Duration(eg.eventCounter) * time.Millisecond)

	eventType := eg.randomChoice(eg.eventTypes).(string)
	host := eg.randomChoice(eg.hosts).(string)
	user := eg.randomChoice(eg.users).(string)
	process := eg.randomChoice(eg.processes).(string)
	sourceIP := eg.randomChoice(eg.ips).(string)
	destIP := eg.randomChoice(eg.ips).(string)

	// Generate event-specific fields based on type
	fields := map[string]interface{}{
		"event_type":     eventType,
		"host":           host,
		"user":           user,
		"timestamp":      timestamp.Format(time.RFC3339),
		"source_ip":      sourceIP,
		"destination_ip": destIP,
		"process":        process,
		"log_source":     eg.determineLogSource(host),
	}

	// Add type-specific fields
	switch eventType {
	case "login":
		fields["login_result"] = eg.randomChoice([]string{"success", "failure"})
		fields["login_method"] = eg.randomChoice([]string{"password", "ssh_key", "kerberos"})
	case "file_access":
		fields["file_path"] = fmt.Sprintf("/home/%s/file_%d.txt", user, eg.randomInt(1, 1000))
		fields["access_type"] = eg.randomChoice([]string{"read", "write", "execute"})
	case "network_connection":
		fields["protocol"] = eg.randomChoice([]string{"tcp", "udp", "icmp"})
		fields["port"] = eg.randomInt(1, 65535)
		fields["bytes_sent"] = eg.randomInt(0, 1000000)
		fields["bytes_received"] = eg.randomInt(0, 1000000)
	case "process_creation":
		fields["parent_process"] = eg.randomChoice(eg.processes)
		fields["command_line"] = fmt.Sprintf("%s --arg=%d", process, eg.randomInt(1, 100))
	case "http_request":
		fields["method"] = eg.randomChoice([]string{"GET", "POST", "PUT", "DELETE"})
		fields["url"] = fmt.Sprintf("http://example.com/path/%d", eg.randomInt(1, 1000))
		fields["status_code"] = eg.randomChoice([]int{200, 201, 301, 404, 500})
		fields["user_agent"] = "Mozilla/5.0"
	case "dns_query":
		fields["query"] = fmt.Sprintf("example%d.com", eg.randomInt(1, 100))
		fields["query_type"] = eg.randomChoice([]string{"A", "AAAA", "MX", "TXT"})
		fields["response"] = destIP
	}

	// Generate event ID
	eventID := fmt.Sprintf("event-%d-%d", timestamp.Unix(), eg.eventCounter)

	// Generate raw message (JSON format)
	rawBytes, _ := json.Marshal(fields)

	return &core.Event{
		EventID:      eventID,
		Timestamp:    timestamp,
		IngestedAt:   time.Now(),
		Source:       host,
		SourceFormat: "json",
		SourceIP:     sourceIP,
		EventType:    eventType,
		Severity:     eg.randomChoice([]string{"info", "warning", "error", "critical"}).(string),
		RawData:      rawBytes, // json.Marshal returns []byte, directly usable as json.RawMessage
		Fields:       fields,
	}
}

// GenerateBatch generates a batch of events
func (eg *EventGenerator) GenerateBatch(count int) []*core.Event {
	events := make([]*core.Event, count)
	for i := 0; i < count; i++ {
		events[i] = eg.GenerateEvent()
	}
	return events
}

// Helper functions
func (eg *EventGenerator) randomChoice(choices interface{}) interface{} {
	switch v := choices.(type) {
	case []string:
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(v))))
		return v[n.Int64()]
	case []int:
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(v))))
		return v[n.Int64()]
	default:
		return nil
	}
}

func (eg *EventGenerator) randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

func (eg *EventGenerator) determineLogSource(host string) string {
	if host[:3] == "WIN" {
		return "windows"
	} else if host[:5] == "LINUX" {
		return "linux"
	} else if host[:3] == "MAC" {
		return "macos"
	}
	return "network"
}
