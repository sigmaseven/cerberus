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
	fmt.Println("=== Generating ~20 Alerts ===")
	client := &http.Client{Timeout: 10 * time.Second}
	url := "http://localhost:8081/api/v1/ingest/json"

	events := []map[string]interface{}{
		// HIGH SEVERITY (10 alerts)

		// 1-2: Forest Blizzard APT - File Creation (High)
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\ProgramData\Microsoft\v1\prnms003.inf_test`,
			"Image": `C:\Windows\System32\svchost.exe`, "Computer": "SERVER-1", "User": "SYSTEM",
		},
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\ProgramData\execute.bat`,
			"Image": `C:\Windows\System32\cmd.exe`, "Computer": "SERVER-2", "User": "admin",
		},

		// 3-4: Renamed Schtasks Execution (High)
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\Temp\scheduler.exe`, "OriginalFileName": "schtasks.exe",
			"CommandLine": "/Create /SC DAILY /TN Task1", "Computer": "WS-10", "User": "attacker",
		},
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Temp\taskman.exe`, "OriginalFileName": "schtasks.exe",
			"CommandLine": "/Create /TN BadTask", "Computer": "WS-11", "User": "hacker",
		},

		// 5-6: DNS Query by Finger Utility (High)
		{
			"Category": "dns_query", "logsource_category": "dns_query",
			"product": "windows", "service": "sysmon", "EventID": 22,
			"Image": `C:\Windows\System32\finger.exe`, "QueryName": "evil.com",
			"Computer": "WS-20", "User": "user1",
		},
		{
			"Category": "dns_query", "logsource_category": "dns_query",
			"product": "windows", "service": "sysmon", "EventID": 22,
			"Image": `C:\Windows\System32\finger.exe`, "QueryName": "malware.net",
			"Computer": "WS-21", "User": "user2",
		},

		// 7-8: Suspicious Process By Web Server (High)
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\cmd.exe`, "CommandLine": "cmd /c whoami",
			"ParentImage": `C:\Windows\System32\inetsrv\w3wp.exe`,
			"Computer": "WEB-1", "User": "IIS_IUSRS",
		},
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\powershell.exe`, "CommandLine": "powershell -enc abc",
			"ParentImage": `C:\Windows\System32\inetsrv\w3wp.exe`,
			"Computer": "WEB-2", "User": "IIS_IUSRS",
		},

		// 9-10: Shell Process from Java (High - webshell indicator)
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\cmd.exe`, "CommandLine": "cmd /c net user",
			"ParentImage": `C:\usr\sap\sapjvm_8\jre\bin\java.exe`,
			"Computer": "SAP-1", "User": "sapuser",
		},
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\cmd.exe`, "CommandLine": "cmd /c ipconfig",
			"ParentImage": `C:\Program Files\Java\jre\bin\java.exe`,
			"Computer": "APP-1", "User": "appuser",
		},

		// MEDIUM SEVERITY (6 alerts)

		// 11-12: WerFaultSecure EDR-Freeze (Medium)
		{
			"Category": "image_load", "logsource_category": "image_load",
			"product": "windows", "service": "sysmon", "EventID": 7,
			"Image": `C:\Windows\System32\WerFaultSecure.exe`,
			"ImageLoaded": `C:\Windows\System32\dbgcore.dll`,
			"Computer": "EP-1", "User": "SYSTEM",
		},
		{
			"Category": "image_load", "logsource_category": "image_load",
			"product": "windows", "service": "sysmon", "EventID": 7,
			"Image": `C:\Windows\System32\WerFaultSecure.exe`,
			"ImageLoaded": `C:\Windows\System32\dbghelp.dll`,
			"Computer": "EP-2", "User": "SYSTEM",
		},

		// 13-14: SAP NetWeaver Webshell Creation (Medium)
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\usr\sap\DEV\j2ee\cluster\apps\sap.com\irj\servlet_jsp\irj\root\shell.jsp`,
			"Image": `C:\Program Files\SAP\java.exe`, "Computer": "SAP-SRV-1", "User": "sapuser",
		},
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\usr\sap\PRD\j2ee\cluster\apps\sap.com\irj\servlet_jsp\irj\root\cmd.jsp`,
			"Image": `C:\Program Files\SAP\java.exe`, "Computer": "SAP-SRV-2", "User": "sapuser",
		},

		// LOW/INFO SEVERITY (4 alerts - need rules that produce lower severity)

		// 15-16: Suspicious PowerShell Parent (varies)
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": "powershell Get-Process",
			"ParentImage": `C:\Windows\System32\mshta.exe`,
			"Computer": "WS-30", "User": "user",
		},
		{
			"Category": "process_creation", "logsource_category": "process_creation",
			"product": "windows", "service": "sysmon", "EventID": 1,
			"Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": "powershell -w hidden",
			"ParentImage": `C:\Windows\System32\wscript.exe`,
			"Computer": "WS-31", "User": "user",
		},

		// 17-18: Webshell file creation patterns
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\inetpub\wwwroot\uploads\shell.aspx`,
			"Image": `C:\Windows\System32\inetsrv\w3wp.exe`,
			"Computer": "WEB-3", "User": "IIS_IUSRS",
		},
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\inetpub\wwwroot\cmd.asp`,
			"Image": `C:\Windows\System32\inetsrv\w3wp.exe`,
			"Computer": "WEB-4", "User": "IIS_IUSRS",
		},

		// 19-20: FunkLocker ransomware file creation (Critical)
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\Users\Public\FunkLocker.exe`,
			"Image": `C:\Windows\System32\cmd.exe`,
			"Computer": "VICTIM-1", "User": "victim",
		},
		{
			"Category": "file_event", "logsource_category": "file_event",
			"product": "windows", "service": "sysmon", "EventID": 11,
			"TargetFilename": `C:\ProgramData\ransom_note.txt`,
			"Image": `C:\Windows\System32\notepad.exe`,
			"Computer": "VICTIM-2", "User": "victim",
		},
	}

	successCount := 0
	for i, event := range events {
		event["EventTime"] = time.Now().Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		jsonData, _ := json.Marshal(event)
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Printf("Sent %d events\n", successCount)
	fmt.Println("\nCheck http://localhost:8080 for alerts")
}
