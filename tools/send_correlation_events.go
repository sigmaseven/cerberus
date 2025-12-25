//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func main() {
	fmt.Println("Sending correlation trigger events...")
	client := &http.Client{Timeout: 10 * time.Second}
	listenerURL := "http://localhost:8081/api/v1/ingest/json"

	// Send Forest Blizzard Protocol Handler events (completes the correlation chain)
	for i := 1; i <= 5; i++ {
		event := map[string]interface{}{
			"EventID":            13,
			"Category":           "registry_set",
			"logsource_category": "registry_set",
			"product":            "windows",
			"service":            "sysmon",
			"TargetObject":       `HKLM\SOFTWARE\Classes\PROTOCOLS\Handler\rogue\CLSID`,
			"Details":            "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}",
			"Image":              `C:\Windows\System32\reg.exe`,
			"Computer":           fmt.Sprintf("TARGET-SERVER-%d", i),
			"User":               "admin",
			"EventTime":          time.Now().Format(time.RFC3339),
		}

		jsonData, _ := json.Marshal(event)
		resp, err := client.Post(listenerURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("Failed: %v\n", err)
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Printf("✓ Sent registry_set event for TARGET-SERVER-%d\n", i)
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	// Send additional events for other correlation chains

	// SAP NetWeaver correlation - more process events
	for i := 1; i <= 3; i++ {
		event := map[string]interface{}{
			"EventID":            1,
			"Category":           "process_creation",
			"logsource_category": "process_creation",
			"product":            "windows",
			"service":            "sysmon",
			"Image":              `C:\Windows\System32\cmd.exe`,
			"CommandLine":        "cmd.exe /c net user hacker Password123 /add",
			"ParentImage":        `C:\usr\sap\sapjvm_8\jre\bin\java.exe`,
			"Computer":           fmt.Sprintf("SAP-SERVER-%d", i),
			"User":               "sapuser",
			"EventTime":          time.Now().Format(time.RFC3339),
		}

		jsonData, _ := json.Marshal(event)
		resp, err := client.Post(listenerURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Printf("✓ Sent SAP child process event for SAP-SERVER-%d\n", i)
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	// More diverse alerts - Low severity
	diverseEvents := []map[string]interface{}{
		{
			"Category":           "process_creation",
			"logsource_category": "process_creation",
			"product":            "windows",
			"service":            "sysmon",
			"EventID":            1,
			"Image":              `C:\Windows\System32\PING.EXE`,
			"CommandLine":        "ping -n 100 192.168.1.1",
			"ParentImage":        `C:\Windows\System32\cmd.exe`,
			"Computer":           "WORKSTATION-50",
			"User":               "user",
		},
		{
			"Category":           "network_connection",
			"logsource_category": "network_connection",
			"product":            "windows",
			"service":            "sysmon",
			"EventID":            3,
			"Image":              `C:\Windows\System32\svchost.exe`,
			"DestinationIp":      "8.8.8.8",
			"DestinationPort":    443,
			"Computer":           "WORKSTATION-51",
			"User":               "SYSTEM",
		},
		// Critical - Create a ransomware file
		{
			"Category":           "file_event",
			"logsource_category": "file_event",
			"product":            "windows",
			"service":            "sysmon",
			"EventID":            11,
			"TargetFilename":     `C:\Users\Public\Documents\FunkLocker.exe`,
			"Image":              `C:\Windows\System32\cmd.exe`,
			"Computer":           "INFECTED-PC-1",
			"User":               "victim",
		},
	}

	for _, event := range diverseEvents {
		event["EventTime"] = time.Now().Format(time.RFC3339)
		jsonData, _ := json.Marshal(event)
		resp, err := client.Post(listenerURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Printf("✓ Sent diverse event\n")
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("\nDone! Check alerts at http://localhost:8080/api/v1/alerts")
}
