# SIGMA Authentication/Login Event Examples

## Windows Event ID 4624 - Successful Logon

### Example 1: Interactive Logon (Type 2)

**Scenario**: User logs in at the console/keyboard

```json
{
  "EventID": "4624",
  "Computer": "WORKSTATION01",
  "EventTime": "2025-11-09T14:30:00Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",

  "User": "CORP\\alice",
  "TargetUserName": "alice",
  "TargetDomainName": "CORP",

  "LogonType": "2",
  "LogonId": "0x1A2B3C4D",
  "AuthenticationPackageName": "Negotiate",
  "LogonProcessName": "User32",
  "WorkstationName": "WORKSTATION01",
  "IpAddress": "-",
  "IpPort": "-",

  "Category": "authentication"
}
```

**curl command**:
```bash
curl -X POST http://localhost:8080/api/v1/ingest/json \
  -H "Content-Type: application/json" \
  -d '{
    "EventID": "4624",
    "Computer": "WORKSTATION01",
    "EventTime": "2025-11-09T14:30:00Z",
    "User": "CORP\\alice",
    "TargetUserName": "alice",
    "TargetDomainName": "CORP",
    "LogonType": "2",
    "AuthenticationPackageName": "Negotiate",
    "WorkstationName": "WORKSTATION01",
    "Category": "authentication"
  }'
```

---

### Example 2: Network Logon (Type 3)

**Scenario**: Remote access via SMB/file share

```json
{
  "EventID": "4624",
  "Computer": "FILESERVER01",
  "EventTime": "2025-11-09T14:35:00Z",
  "Channel": "Security",

  "User": "CORP\\bob",
  "TargetUserName": "bob",
  "TargetDomainName": "CORP",
  "SubjectUserName": "FILESERVER01$",
  "SubjectDomainName": "CORP",

  "LogonType": "3",
  "LogonId": "0x5F6E7D8C",
  "AuthenticationPackageName": "NTLM",
  "LogonProcessName": "NtLmSsp",
  "WorkstationName": "WORKSTATION02",
  "IpAddress": "192.168.1.50",
  "IpPort": "52341",

  "Category": "authentication"
}
```

**curl command**:
```bash
curl -X POST http://localhost:8080/api/v1/ingest/json \
  -H "Content-Type: application/json" \
  -d '{
    "EventID": "4624",
    "Computer": "FILESERVER01",
    "EventTime": "2025-11-09T14:35:00Z",
    "User": "CORP\\bob",
    "TargetUserName": "bob",
    "TargetDomainName": "CORP",
    "LogonType": "3",
    "AuthenticationPackageName": "NTLM",
    "WorkstationName": "WORKSTATION02",
    "IpAddress": "192.168.1.50",
    "IpPort": "52341",
    "Category": "authentication"
  }'
```

---

### Example 3: Remote Desktop Logon (Type 10)

**Scenario**: RDP connection

```json
{
  "EventID": "4624",
  "Computer": "TERMINAL-SERVER",
  "EventTime": "2025-11-09T14:40:00Z",
  "Channel": "Security",

  "User": "CORP\\charlie",
  "TargetUserName": "charlie",
  "TargetDomainName": "CORP",

  "LogonType": "10",
  "LogonId": "0xABCDEF01",
  "AuthenticationPackageName": "Negotiate",
  "LogonProcessName": "User32",
  "WorkstationName": "LAPTOP03",
  "IpAddress": "192.168.1.75",
  "IpPort": "54123",

  "Category": "authentication"
}
```

**curl command**:
```bash
curl -X POST http://localhost:8080/api/v1/ingest/json \
  -H "Content-Type: application/json" \
  -d '{
    "EventID": "4624",
    "Computer": "TERMINAL-SERVER",
    "EventTime": "2025-11-09T14:40:00Z",
    "User": "CORP\\charlie",
    "TargetUserName": "charlie",
    "TargetDomainName": "CORP",
    "LogonType": "10",
    "AuthenticationPackageName": "Negotiate",
    "WorkstationName": "LAPTOP03",
    "IpAddress": "192.168.1.75",
    "Category": "authentication"
  }'
```

---

### Example 4: Service Logon (Type 5)

**Scenario**: Service account logon

```json
{
  "EventID": "4624",
  "Computer": "APPSERVER01",
  "EventTime": "2025-11-09T14:45:00Z",
  "Channel": "Security",

  "User": "CORP\\svc_webapp",
  "TargetUserName": "svc_webapp",
  "TargetDomainName": "CORP",

  "LogonType": "5",
  "LogonId": "0x3E5",
  "AuthenticationPackageName": "Negotiate",
  "LogonProcessName": "Advapi",
  "WorkstationName": "-",
  "IpAddress": "-",

  "Category": "authentication"
}
```

---

## Windows Event ID 4625 - Failed Logon

### Example 5: Failed Login Attempt

**Scenario**: Wrong password / brute force attempt

```json
{
  "EventID": "4625",
  "Computer": "DC01",
  "EventTime": "2025-11-09T14:50:00Z",
  "Channel": "Security",

  "User": "CORP\\administrator",
  "TargetUserName": "administrator",
  "TargetDomainName": "CORP",
  "SubjectUserName": "-",
  "SubjectDomainName": "-",

  "LogonType": "3",
  "AuthenticationPackageName": "NTLM",
  "WorkstationName": "UNKNOWN",
  "IpAddress": "203.0.113.45",
  "IpPort": "0",
  "FailureReason": "Unknown user name or bad password",
  "Status": "0xC000006D",
  "SubStatus": "0xC000006A",

  "Category": "authentication"
}
```

**curl command**:
```bash
curl -X POST http://localhost:8080/api/v1/ingest/json \
  -H "Content-Type: application/json" \
  -d '{
    "EventID": "4625",
    "Computer": "DC01",
    "EventTime": "2025-11-09T14:50:00Z",
    "User": "CORP\\administrator",
    "TargetUserName": "administrator",
    "TargetDomainName": "CORP",
    "LogonType": "3",
    "AuthenticationPackageName": "NTLM",
    "IpAddress": "203.0.113.45",
    "FailureReason": "Unknown user name or bad password",
    "Status": "0xC000006D",
    "Category": "authentication"
  }'
```

---

## PowerShell Examples

### Submit Successful Login

```powershell
# Interactive Logon (Type 2)
$loginEvent = @{
    EventID = "4624"
    Computer = $env:COMPUTERNAME
    EventTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    User = "$env:USERDOMAIN\$env:USERNAME"
    TargetUserName = $env:USERNAME
    TargetDomainName = $env:USERDOMAIN
    LogonType = "2"
    AuthenticationPackageName = "Negotiate"
    LogonProcessName = "User32"
    WorkstationName = $env:COMPUTERNAME
    IpAddress = "-"
    Category = "authentication"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/v1/ingest/json" `
    -Method POST `
    -ContentType "application/json" `
    -Body $loginEvent

Write-Host "Login event submitted!" -ForegroundColor Green
```

### Submit Failed Login Attempt

```powershell
# Failed login from suspicious IP
$failedLogin = @{
    EventID = "4625"
    Computer = $env:COMPUTERNAME
    EventTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    User = "$env:USERDOMAIN\administrator"
    TargetUserName = "administrator"
    TargetDomainName = $env:USERDOMAIN
    LogonType = "3"
    AuthenticationPackageName = "NTLM"
    IpAddress = "203.0.113.50"
    FailureReason = "Unknown user name or bad password"
    Status = "0xC000006D"
    Category = "authentication"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/v1/ingest/json" `
    -Method POST `
    -ContentType "application/json" `
    -Body $failedLogin

Write-Host "Failed login event submitted!" -ForegroundColor Green
```

### Simulate Brute Force Attack

```powershell
# Simulate 5 failed login attempts
Write-Host "Simulating brute force attack..." -ForegroundColor Yellow

for ($i = 1; $i -le 5; $i++) {
    $failedAttempt = @{
        EventID = "4625"
        Computer = "DC01"
        EventTime = (Get-Date).AddSeconds($i).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        User = "CORP\administrator"
        TargetUserName = "administrator"
        TargetDomainName = "CORP"
        LogonType = "3"
        AuthenticationPackageName = "NTLM"
        IpAddress = "203.0.113.100"
        IpPort = (Get-Random -Minimum 50000 -Maximum 60000).ToString()
        FailureReason = "Unknown user name or bad password"
        Status = "0xC000006D"
        Category = "authentication"
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "http://localhost:8080/api/v1/ingest/json" `
        -Method POST `
        -ContentType "application/json" `
        -Body $failedAttempt

    Write-Host "  Attempt $i/5 submitted" -ForegroundColor Gray
    Start-Sleep -Milliseconds 500
}

Write-Host "Brute force simulation complete!" -ForegroundColor Green
```

---

## Python Example

### Submit Multiple Login Events

```python
import requests
import json
from datetime import datetime, timedelta

def submit_login_event(event_data):
    """Submit authentication event to Cerberus"""
    url = "http://localhost:8080/api/v1/ingest/json"
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, headers=headers, json=event_data, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

# Successful RDP login
rdp_login = {
    "EventID": "4624",
    "Computer": "TERMINAL-SERVER",
    "EventTime": datetime.utcnow().isoformat() + "Z",
    "User": "CORP\\alice",
    "TargetUserName": "alice",
    "TargetDomainName": "CORP",
    "LogonType": "10",
    "AuthenticationPackageName": "Negotiate",
    "WorkstationName": "LAPTOP01",
    "IpAddress": "192.168.1.50",
    "IpPort": "54123",
    "Category": "authentication"
}

# Failed SSH login attempt (Linux-style)
failed_ssh = {
    "EventID": "5",
    "Computer": "LINUX-SERVER01",
    "EventTime": (datetime.utcnow() + timedelta(seconds=1)).isoformat() + "Z",
    "User": "root",
    "TargetUserName": "root",
    "LogonType": "Network",
    "AuthenticationPackageName": "ssh",
    "IpAddress": "203.0.113.75",
    "FailureReason": "Invalid credentials",
    "Category": "authentication"
}

# Privileged account usage
admin_login = {
    "EventID": "4672",
    "Computer": "DC01",
    "EventTime": (datetime.utcnow() + timedelta(seconds=2)).isoformat() + "Z",
    "User": "CORP\\Administrator",
    "TargetUserName": "Administrator",
    "TargetDomainName": "CORP",
    "LogonType": "2",
    "PrivilegeList": "SeDebugPrivilege,SeTakeOwnershipPrivilege",
    "Category": "authentication"
}

# Submit all events
events = [
    ("RDP Login", rdp_login),
    ("Failed SSH", failed_ssh),
    ("Admin Login", admin_login)
]

for name, event in events:
    if submit_login_event(event):
        print(f"✓ {name} submitted successfully")
    else:
        print(f"✗ {name} failed")
```

---

## Complete SIGMA Authentication Field Reference

### Core Fields
- `EventID` - Event identifier
  - `4624` - Successful logon
  - `4625` - Failed logon
  - `4634` - Logoff
  - `4647` - User initiated logoff
  - `4648` - Logon using explicit credentials
  - `4672` - Special privileges assigned to new logon

### User Identity Fields
- `User` - Full user identity (DOMAIN\username)
- `TargetUserName` - Target account name
- `TargetDomainName` - Target domain name
- `SubjectUserName` - Subject/initiating user
- `SubjectDomainName` - Subject domain

### Logon Details
- `LogonType` - Type of logon:
  - `2` - Interactive (console)
  - `3` - Network (SMB, RPC)
  - `4` - Batch
  - `5` - Service
  - `7` - Unlock
  - `8` - NetworkCleartext (IIS)
  - `9` - NewCredentials (RunAs)
  - `10` - RemoteInteractive (RDP)
  - `11` - CachedInteractive

- `LogonId` - Logon session identifier
- `AuthenticationPackageName` - Auth protocol
  - `Negotiate` - Kerberos or NTLM
  - `Kerberos` - Kerberos
  - `NTLM` - NTLM
  - `CredSSP` - Credential Security Support Provider

- `LogonProcessName` - Logon process
  - `User32` - Interactive logon
  - `Advapi` - Service logon
  - `NtLmSsp` - NTLM authentication

### Network Information
- `WorkstationName` - Source computer name
- `IpAddress` - Source IP address
- `IpPort` - Source port number

### Failure Information (4625 events)
- `FailureReason` - Reason for failure
- `Status` - NTSTATUS error code
- `SubStatus` - Sub-status code

### Privilege Information
- `PrivilegeList` - Assigned privileges

---

## CQL Queries for Authentication Events

### Find All Successful Logins
```cql
EventID = "4624" AND Category = "authentication"
```

### Find Failed Login Attempts
```cql
EventID = "4625" AND Category = "authentication"
```

### Find RDP Logins
```cql
EventID = "4624" AND LogonType = "10"
```

### Find Network Logins
```cql
EventID = "4624" AND LogonType = "3"
```

### Find Logins from Specific User
```cql
TargetUserName = "administrator" AND Category = "authentication"
```

### Find Failed Logins from External IPs
```cql
EventID = "4625" AND IpAddress startswith "203.0.113"
```

### Find NTLM Authentication
```cql
AuthenticationPackageName = "NTLM" AND Category = "authentication"
```

### Detect Brute Force (Multiple Failed Logins)
```cql
EventID = "4625" AND IpAddress exists
```
*(Then use correlation rules to detect 5+ failures from same IP)*

---

## Complete Test Script

Save as `test_authentication.ps1`:

```powershell
# Test Authentication Events with SIGMA Fields

$events = @(
    # Successful console login
    @{
        EventID = "4624"
        Computer = $env:COMPUTERNAME
        EventTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        User = "$env:USERDOMAIN\$env:USERNAME"
        TargetUserName = $env:USERNAME
        TargetDomainName = $env:USERDOMAIN
        LogonType = "2"
        AuthenticationPackageName = "Negotiate"
        Category = "authentication"
    },

    # Network login
    @{
        EventID = "4624"
        Computer = "FILESERVER01"
        EventTime = (Get-Date).AddSeconds(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        User = "$env:USERDOMAIN\$env:USERNAME"
        TargetUserName = $env:USERNAME
        LogonType = "3"
        AuthenticationPackageName = "NTLM"
        IpAddress = "192.168.1.100"
        Category = "authentication"
    },

    # RDP login
    @{
        EventID = "4624"
        Computer = "TERMINAL-SERVER"
        EventTime = (Get-Date).AddSeconds(2).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        User = "$env:USERDOMAIN\$env:USERNAME"
        TargetUserName = $env:USERNAME
        LogonType = "10"
        IpAddress = "192.168.1.50"
        Category = "authentication"
    },

    # Failed login
    @{
        EventID = "4625"
        Computer = "DC01"
        EventTime = (Get-Date).AddSeconds(3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        TargetUserName = "administrator"
        LogonType = "3"
        IpAddress = "203.0.113.100"
        FailureReason = "Unknown user name or bad password"
        Category = "authentication"
    }
)

foreach ($event in $events) {
    $json = $event | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:8080/api/v1/ingest/json" `
        -Method POST `
        -ContentType "application/json" `
        -Body $json
    Write-Host "✓ Event $($event.EventID) submitted" -ForegroundColor Green
    Start-Sleep -Milliseconds 200
}

Write-Host "`nQuery the events:" -ForegroundColor Cyan
Write-Host 'Category = "authentication"' -ForegroundColor White
```

---

**Status**: Ready to Use
**Category**: `authentication`
**Compatible Events**: 4624, 4625, 4634, 4647, 4648, 4672
