//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event represents a test event
type Event struct {
	Fields   map[string]interface{}
	Category string
	Product  string
	Service  string
}

func main() {
	fmt.Println("=== Targeted Alert Generator ===")
	fmt.Println("Generating events to trigger ~20 alerts and ~10 correlations\n")

	// Send individual alert-triggering events
	fmt.Println("[1/3] Generating individual alert events...")
	alertEvents := generateAlertEvents()
	successCount := sendEvents(alertEvents)
	fmt.Printf("    ✓ Sent %d individual alert events\n", successCount)

	// Brief pause for processing
	time.Sleep(500 * time.Millisecond)

	// Send correlation sequence events
	fmt.Println("\n[2/3] Generating correlation sequence events...")
	correlationEvents := generateCorrelationEvents()
	successCount = sendEvents(correlationEvents)
	fmt.Printf("    ✓ Sent %d correlation sequence events\n", successCount)

	// Brief pause for processing
	time.Sleep(500 * time.Millisecond)

	// Send more diverse alerts
	fmt.Println("\n[3/3] Generating additional diverse alerts...")
	diverseEvents := generateDiverseAlerts()
	successCount = sendEvents(diverseEvents)
	fmt.Printf("    ✓ Sent %d diverse alert events\n", successCount)

	fmt.Println("\n=== Generation Complete ===")
	fmt.Println("Check the dashboard at http://localhost:8080 to verify alerts and correlations")
}

func generateAlertEvents() []Event {
	events := []Event{}
	baseTime := time.Now()

	// 1. Forest Blizzard APT - File Creation (High severity)
	for i := 0; i < 3; i++ {
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": fmt.Sprintf("C:\\ProgramData\\Microsoft\\v%d\\prnms003.inf_test", i),
				"Image":          "C:\\Windows\\System32\\svchost.exe",
				"Computer":       fmt.Sprintf("WORKSTATION-%d", i+1),
				"User":           "SYSTEM",
				"EventTime":      baseTime.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 2. Forest Blizzard - execute.bat creation (High severity)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": fmt.Sprintf("C:\\ProgramData\\execute.bat"),
				"Image":          "C:\\Windows\\System32\\cmd.exe",
				"Computer":       fmt.Sprintf("SERVER-%d", i+1),
				"User":           "admin",
				"EventTime":      baseTime.Add(time.Duration(i+5) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 3. Suspicious Python path config (Medium severity - Linux)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "file_event",
			Product:  "linux",
			Service:  "auditd",
			Fields: map[string]interface{}{
				"TargetFilename": "/usr/lib/python3.9/sitecustomize.pth",
				"Image":          "/usr/bin/python3",
				"User":           "www-data",
				"EventTime":      baseTime.Add(time.Duration(i+10) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 4. Renamed Schtasks Execution (High severity)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "process_creation",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":         1,
				"Image":           "C:\\Windows\\Temp\\scheduler.exe",
				"OriginalFileName": "schtasks.exe",
				"CommandLine":     "/Create /SC DAILY /TN MyTask /TR calc.exe",
				"Computer":        fmt.Sprintf("WORKSTATION-%d", i+10),
				"User":            "attacker",
				"ParentImage":     "C:\\Windows\\System32\\cmd.exe",
				"EventTime":       baseTime.Add(time.Duration(i+15) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 5. Network Connection via Finger.exe (High severity)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "network_connection",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":         3,
				"Image":           "C:\\Windows\\System32\\finger.exe",
				"DestinationIp":   fmt.Sprintf("192.168.1.%d", 100+i),
				"DestinationPort": 79,
				"Computer":        fmt.Sprintf("WORKSTATION-%d", i+20),
				"User":            "user1",
				"EventTime":       baseTime.Add(time.Duration(i+20) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 6. DNS Query by Finger Utility (High severity)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "dns_query",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":    22,
				"Image":      "C:\\Windows\\System32\\finger.exe",
				"QueryName":  fmt.Sprintf("malicious%d.example.com", i),
				"Computer":   fmt.Sprintf("WORKSTATION-%d", i+25),
				"User":       "user2",
				"EventTime":  baseTime.Add(time.Duration(i+25) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// 7. Suspicious Node.js child process - React2Shell (High severity)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "process_creation",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c whoami",
				"ParentImage": "C:\\Program Files\\nodejs\\node.exe",
				"Computer":    fmt.Sprintf("DEV-WORKSTATION-%d", i+1),
				"User":        "developer",
				"EventTime":   baseTime.Add(time.Duration(i+30) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	return events
}

func generateCorrelationEvents() []Event {
	events := []Event{}
	baseTime := time.Now()

	// Correlation 1: Multi-Stage APT Forest Blizzard Attack Chain (3 sequences)
	// Sequence: file_creation -> process_creation -> registry
	for seq := 0; seq < 3; seq++ {
		seqTime := baseTime.Add(time.Duration(seq*10) * time.Minute)
		computer := fmt.Sprintf("TARGET-SERVER-%d", seq+1)

		// Step 1: File creation (Forest Blizzard file)
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": "C:\\ProgramData\\Intel\\v1\\prnms009.inf_malware",
				"Image":          "C:\\Windows\\System32\\svchost.exe",
				"Computer":       computer,
				"User":           "SYSTEM",
				"EventTime":      seqTime.Format(time.RFC3339),
			},
		})

		// Step 2: Process creation (schtasks with malicious pattern)
		events = append(events, Event{
			Category: "process_creation",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\schtasks.exe",
				"CommandLine": "schtasks.exe /Create /RU SYSTEM /TN \\Microsoft\\Windows\\WinSrv\\servtask /TR C:\\ProgramData\\servtask.bat",
				"Computer":    computer,
				"User":        "SYSTEM",
				"ParentImage": "C:\\Windows\\System32\\cmd.exe",
				"EventTime":   seqTime.Add(2 * time.Minute).Format(time.RFC3339),
			},
		})

		// Step 3: Registry modification (custom protocol handler)
		events = append(events, Event{
			Category: "registry_set",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":      13,
				"TargetObject": "HKCU\\Software\\Classes\\search-ms\\shell\\open\\command\\(Default)",
				"Details":      "C:\\Windows\\System32\\cmd.exe /c malware.bat",
				"Image":        "C:\\Windows\\System32\\reg.exe",
				"Computer":     computer,
				"User":         "admin",
				"EventTime":    seqTime.Add(5 * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// Correlation 2: SAP NetWeaver Webshell Deployment and Execution (2 sequences)
	for seq := 0; seq < 2; seq++ {
		seqTime := baseTime.Add(time.Duration((seq+3)*10) * time.Minute)
		computer := fmt.Sprintf("SAP-SERVER-%d", seq+1)

		// Step 1: Webshell creation
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": fmt.Sprintf("C:\\usr\\sap\\%s\\j2ee\\cluster\\apps\\sap.com\\irj\\servlet_jsp\\irj\\root\\shell%d.jsp", fmt.Sprintf("DEV%d", seq), seq),
				"Image":          "C:\\usr\\sap\\sapjvm_8\\jre\\bin\\java.exe",
				"Computer":       computer,
				"User":           "sapuser",
				"EventTime":      seqTime.Format(time.RFC3339),
			},
		})

		// Step 2: Suspicious child process from SAP
		events = append(events, Event{
			Category: "process_creation",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c whoami /all",
				"ParentImage": "C:\\usr\\sap\\sapjvm_8\\jre\\bin\\java.exe",
				"Computer":    computer,
				"User":        "sapuser",
				"EventTime":   seqTime.Add(3 * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// Correlation 3: SharePoint CVE-2025-53770 Exploitation Chain (2 sequences)
	for seq := 0; seq < 2; seq++ {
		seqTime := baseTime.Add(time.Duration((seq+5)*10) * time.Minute)
		computer := fmt.Sprintf("SP-SERVER-%d", seq+1)

		// Step 1: Suspicious file creation
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": fmt.Sprintf("C:\\inetpub\\wwwroot\\wss\\VirtualDirectories\\%d\\ToolShell.aspx", 80+seq),
				"Image":          "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
				"Computer":       computer,
				"User":           "IIS_IUSRS",
				"EventTime":      seqTime.Format(time.RFC3339),
			},
		})

		// Step 2: Web access (IIS logs)
		events = append(events, Event{
			Category: "webserver",
			Product:  "windows",
			Service:  "iis",
			Fields: map[string]interface{}{
				"cs-uri-stem":  "/_layouts/15/ToolShell.aspx",
				"cs-method":    "POST",
				"sc-status":    200,
				"cs-username":  "anonymous",
				"c-ip":         fmt.Sprintf("10.0.0.%d", 50+seq),
				"Computer":     computer,
				"EventTime":    seqTime.Add(2 * time.Minute).Format(time.RFC3339),
			},
		})

		// Step 3: Exploitation indicator (w3wp spawning cmd)
		events = append(events, Event{
			Category: "process_creation",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c powershell -enc base64encodedcommand",
				"ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
				"Computer":    computer,
				"User":        "IIS_IUSRS",
				"EventTime":   seqTime.Add(4 * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// Correlation 4: Commvault Multi-CVE Attack Pattern (2 sequences)
	for seq := 0; seq < 2; seq++ {
		seqTime := baseTime.Add(time.Duration((seq+7)*10) * time.Minute)

		// Step 1: Auth bypass attempt
		events = append(events, Event{
			Category: "webserver",
			Product:  "windows",
			Service:  "commvault",
			Fields: map[string]interface{}{
				"cs-uri-stem":    "/webconsole/api/QLogin",
				"cs-uri-query":   "username=..\\..\\admin",
				"cs-method":      "POST",
				"sc-status":      200,
				"c-ip":           fmt.Sprintf("192.168.10.%d", 100+seq),
				"Computer":       fmt.Sprintf("COMMVAULT-%d", seq+1),
				"EventTime":      seqTime.Format(time.RFC3339),
			},
		})

		// Step 2: Path traversal webshell drop
		events = append(events, Event{
			Category: "file_event",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":        11,
				"TargetFilename": fmt.Sprintf("C:\\Program Files\\Commvault\\ContentStore\\WebConsole\\..\\..\\webshell%d.aspx", seq),
				"Image":          "C:\\Program Files\\Commvault\\Base\\WebServer.exe",
				"Computer":       fmt.Sprintf("COMMVAULT-%d", seq+1),
				"User":           "SYSTEM",
				"EventTime":      seqTime.Add(5 * time.Minute).Format(time.RFC3339),
			},
		})
	}

	return events
}

func generateDiverseAlerts() []Event {
	events := []Event{}
	baseTime := time.Now()

	// AWS GuardDuty alerts (High)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "aws_cloudtrail",
			Product:  "aws",
			Service:  "cloudtrail",
			Fields: map[string]interface{}{
				"eventSource":  "guardduty.amazonaws.com",
				"eventName":    "DeleteDetector",
				"userIdentity": map[string]interface{}{
					"type":     "IAMUser",
					"userName": fmt.Sprintf("suspicious-user-%d", i),
				},
				"sourceIPAddress": fmt.Sprintf("203.0.113.%d", 10+i),
				"awsRegion":       "us-east-1",
				"EventTime":       baseTime.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// Potential Pass the Hash (High)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "authentication",
			Product:  "windows",
			Service:  "security",
			Fields: map[string]interface{}{
				"EventID":           4624,
				"LogonType":         3,
				"AuthenticationPackageName": "NTLM",
				"LmPackageName":     "NTLM V1",
				"TargetUserName":    fmt.Sprintf("admin%d", i),
				"WorkstationName":   fmt.Sprintf("UNKNOWN-%d", i),
				"IpAddress":         fmt.Sprintf("10.10.10.%d", 100+i),
				"Computer":          fmt.Sprintf("DC-%d", i+1),
				"EventTime":         baseTime.Add(time.Duration(i+5) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// Katz Stealer DNS Query (High)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "dns_query",
			Product:  "windows",
			Service:  "sysmon",
			Fields: map[string]interface{}{
				"EventID":   22,
				"QueryName": fmt.Sprintf("katz-stealer%d.ru", i),
				"Image":     "C:\\Windows\\System32\\svchost.exe",
				"Computer":  fmt.Sprintf("INFECTED-%d", i+1),
				"User":      "SYSTEM",
				"EventTime": baseTime.Add(time.Duration(i+10) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// GitHub Actions suspicious execution (Medium)
	for i := 0; i < 2; i++ {
		events = append(events, Event{
			Category: "process_creation",
			Product:  "linux",
			Service:  "auditd",
			Fields: map[string]interface{}{
				"Image":       "/actions-runner/bin/Runner.Listener",
				"CommandLine": "./run.sh",
				"User":        "runner",
				"Computer":    fmt.Sprintf("github-runner-%d", i+1),
				"EventTime":   baseTime.Add(time.Duration(i+15) * time.Minute).Format(time.RFC3339),
			},
		})
	}

	// EDR-Freeze via WerFaultSecure (Medium-High)
	events = append(events, Event{
		Category: "image_load",
		Product:  "windows",
		Service:  "sysmon",
		Fields: map[string]interface{}{
			"EventID":    7,
			"Image":      "C:\\Windows\\System32\\WerFaultSecure.exe",
			"ImageLoaded": "C:\\Windows\\System32\\dbgcore.dll",
			"Computer":   "ENDPOINT-001",
			"User":       "SYSTEM",
			"EventTime":  baseTime.Add(20 * time.Minute).Format(time.RFC3339),
		},
	})

	// Atomic MacOS Stealer (High)
	events = append(events, Event{
		Category: "file_event",
		Product:  "macos",
		Service:  "edr",
		Fields: map[string]interface{}{
			"TargetFilename": "/Users/victim/Library/LaunchAgents/com.apple.AMPDevices.plist",
			"Image":          "/usr/bin/osascript",
			"User":           "victim",
			"Computer":       "MACBOOK-PRO-1",
			"EventTime":      baseTime.Add(25 * time.Minute).Format(time.RFC3339),
		},
	})

	return events
}

func sendEvents(events []Event) int {
	successCount := 0
	client := &http.Client{Timeout: 10 * time.Second}
	listenerURL := "http://localhost:8081/api/v1/ingest/json"

	for _, event := range events {
		payload := map[string]interface{}{}
		for k, v := range event.Fields {
			payload[k] = v
		}

		// Add logsource metadata
		if event.Category != "" {
			payload["Category"] = event.Category
			payload["logsource_category"] = event.Category
		}
		if event.Product != "" {
			payload["product"] = event.Product
		}
		if event.Service != "" {
			payload["service"] = event.Service
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		resp, err := client.Post(listenerURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
		resp.Body.Close()

		// Small delay between events
		time.Sleep(50 * time.Millisecond)
	}

	return successCount
}
