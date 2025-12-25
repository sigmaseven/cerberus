//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CorrelationRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Window      int64    `json:"window"`
	Sequence    []string `json:"sequence"`
}

func main() {
	fmt.Println("=== Creating Correlation Rules ===")

	correlations := []CorrelationRule{
		{
			Name:        "Web Attack Chain - Webshell to Command Execution",
			Description: "Detects webshell file creation followed by suspicious command execution from web server process",
			Severity:    "Critical",
			Window:      3600000000000, // 1 hour
			Sequence:    []string{"39f1f9f2-9636-45de-98f6-a4046aa8e4b9", "8202070f-edeb-4d31-a010-a26c72ac5600"},
		},
		{
			Name:        "SAP Exploitation Chain",
			Description: "Detects SAP NetWeaver webshell creation followed by shell process spawned from Java",
			Severity:    "Critical",
			Window:      1800000000000, // 30 min
			Sequence:    []string{"86a7c91f-98c3-4f14-a58d-d989421e1234", "dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0"},
		},
		{
			Name:        "PowerShell Attack Progression",
			Description: "Detects suspicious PowerShell parent followed by Base64 encoded execution",
			Severity:    "High",
			Window:      1800000000000,
			Sequence:    []string{"754ed792-634f-40ae-b3bc-e0448d33f695", "fb843269-508c-4b76-8b8d-88679db22ce7"},
		},
		{
			Name:        "Script Engine to PowerShell Chain",
			Description: "Detects script engine invoking PowerShell followed by suspicious parent process",
			Severity:    "High",
			Window:      1800000000000,
			Sequence:    []string{"95eadcb2-92e4-4ed1-9031-92547773a6db", "754ed792-634f-40ae-b3bc-e0448d33f695"},
		},
		{
			Name:        "APT Persistence Chain",
			Description: "Detects Forest Blizzard file creation followed by renamed schtasks for persistence",
			Severity:    "Critical",
			Window:      3600000000000,
			Sequence:    []string{"b92d1d19-f5c9-4ed6-bbd5-7476709dc389", "f91e51c9-f344-4b32-969b-0b6f6b8537d4"},
		},
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, corr := range correlations {
		jsonData, _ := json.Marshal(corr)
		resp, err := client.Post("http://localhost:8080/api/v1/correlation-rules", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("✗ Failed to create '%s': %v\n", corr.Name, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Printf("✓ Created: %s\n", corr.Name)
		} else {
			fmt.Printf("✗ Failed to create '%s': HTTP %d\n", corr.Name, resp.StatusCode)
		}
	}

	fmt.Println("\nDone!")
}
