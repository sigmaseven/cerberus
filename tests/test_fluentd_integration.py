#!/usr/bin/env python3
"""
Integration test script for Cerberus Fluentd/Fluent Bit listener.
Tests the Forward protocol implementation with various message types.

Requirements:
    pip install msgpack requests
"""

import msgpack
import socket
import time
import sys
import argparse
import requests
from typing import Dict, Any, List

class FluentdForwardTester:
    """Test client for Fluentd Forward protocol"""

    def __init__(self, host: str = "localhost", port: int = 24224):
        self.host = host
        self.port = port

    def send_message_mode(self, tag: str, timestamp: int, record: Dict[str, Any]) -> bool:
        """
        Send a Message mode message: [tag, time, record]
        """
        try:
            data = [tag, timestamp, record]
            packed = msgpack.packb(data)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            sock.sendall(packed)
            sock.close()

            print(f"✓ Sent Message mode: tag={tag}, timestamp={timestamp}")
            return True
        except Exception as e:
            print(f"✗ Failed to send Message mode: {e}")
            return False

    def send_forward_mode(self, tag: str, entries: List[tuple]) -> bool:
        """
        Send a Forward mode message: [tag, [[time, record], [time, record], ...]]
        """
        try:
            entry_list = [[ts, rec] for ts, rec in entries]
            data = [tag, entry_list]
            packed = msgpack.packb(data)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            sock.sendall(packed)
            sock.close()

            print(f"✓ Sent Forward mode: tag={tag}, entries={len(entries)}")
            return True
        except Exception as e:
            print(f"✗ Failed to send Forward mode: {e}")
            return False

    def send_packed_forward_mode(self, tag: str, entries: List[tuple]) -> bool:
        """
        Send a PackedForward mode message: [tag, binary]
        """
        try:
            # Pack entries as msgpack binary
            entry_list = [[ts, rec] for ts, rec in entries]
            packed_entries = msgpack.packb(entry_list)

            # Create Forward message with binary
            data = [tag, packed_entries]
            packed = msgpack.packb(data)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            sock.sendall(packed)
            sock.close()

            print(f"✓ Sent PackedForward mode: tag={tag}, entries={len(entries)}")
            return True
        except Exception as e:
            print(f"✗ Failed to send PackedForward mode: {e}")
            return False

    def send_kubernetes_log(self, pod_name: str, namespace: str, container: str, message: str) -> bool:
        """
        Send a Kubernetes-style log with proper field mappings
        """
        tag = f"kubernetes.var.log.containers.{pod_name}"
        timestamp = int(time.time())
        record = {
            "log": message,
            "stream": "stdout",
            "kubernetes": {
                "pod_name": pod_name,
                "namespace_name": namespace,
                "container_name": container,
                "container_id": f"docker://abc{int(time.time())}",
                "labels": {
                    "app": "test-app",
                    "version": "1.0.0"
                }
            }
        }
        return self.send_message_mode(tag, timestamp, record)

    def send_docker_log(self, container_name: str, container_id: str, message: str) -> bool:
        """
        Send a Docker-style log with proper field mappings
        """
        tag = "docker.container"
        timestamp = int(time.time())
        record = {
            "log": message,
            "container_name": container_name,
            "container_id": container_id,
            "source": "stdout"
        }
        return self.send_message_mode(tag, timestamp, record)

    def send_syslog_message(self, hostname: str, program: str, pid: int, message: str, severity: int = 6) -> bool:
        """
        Send a Syslog-style message with proper field mappings
        """
        tag = "syslog.system"
        timestamp = int(time.time())
        record = {
            "message": message,
            "host": hostname,
            "ident": program,
            "pid": pid,
            "facility": 1,
            "severity": severity
        }
        return self.send_message_mode(tag, timestamp, record)

    def send_apache_access_log(self, remote_addr: str, user: str, method: str, path: str, status: int) -> bool:
        """
        Send an Apache access log with proper field mappings
        """
        tag = "apache.access"
        timestamp = int(time.time())
        record = {
            "host": remote_addr,
            "user": user,
            "method": method,
            "path": path,
            "code": str(status),
            "size": 1024,
            "referer": "https://example.com",
            "agent": "Mozilla/5.0"
        }
        return self.send_message_mode(tag, timestamp, record)

    def send_nginx_access_log(self, remote_addr: str, user: str, method: str, uri: str, status: int) -> bool:
        """
        Send an Nginx access log with proper field mappings
        """
        tag = "nginx.access"
        timestamp = int(time.time())
        record = {
            "remote_addr": remote_addr,
            "remote_user": user,
            "request_method": method,
            "request_uri": uri,
            "status": str(status),
            "body_bytes_sent": 512,
            "http_referer": "https://example.com",
            "http_user_agent": "curl/7.68.0"
        }
        return self.send_message_mode(tag, timestamp, record)

    def send_batch_logs(self, count: int = 100) -> bool:
        """
        Send a batch of logs using Forward mode
        """
        tag = "app.batch"
        entries = []
        timestamp = int(time.time())

        for i in range(count):
            entries.append((
                timestamp + i,
                {
                    "message": f"Batch log message {i+1}",
                    "level": "info",
                    "sequence": i
                }
            ))

        return self.send_forward_mode(tag, entries)

def verify_events_received(api_url: str, expected_count: int, timeout: int = 10) -> bool:
    """
    Verify that events were received by querying the Cerberus API
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{api_url}/api/v1/events?limit=1000")
            if response.status_code == 200:
                data = response.json()
                event_count = data.get("total", 0)

                if event_count >= expected_count:
                    print(f"✓ Verified: {event_count} events received (expected >= {expected_count})")
                    return True
                else:
                    print(f"  Waiting... {event_count}/{expected_count} events received")
                    time.sleep(1)
            else:
                print(f"  API returned status {response.status_code}")
                time.sleep(1)
        except Exception as e:
            print(f"  API request failed: {e}")
            time.sleep(1)

    print(f"✗ Timeout: Expected at least {expected_count} events")
    return False

def run_basic_tests(tester: FluentdForwardTester):
    """Run basic protocol tests"""
    print("\n=== Basic Protocol Tests ===")

    # Test 1: Message mode
    print("\n1. Testing Message mode...")
    success = tester.send_message_mode(
        tag="test.app",
        timestamp=int(time.time()),
        record={"message": "Hello from Message mode", "level": "info"}
    )
    time.sleep(0.5)

    # Test 2: Forward mode
    print("\n2. Testing Forward mode (batch)...")
    entries = [
        (int(time.time()), {"message": "Log 1", "level": "info"}),
        (int(time.time()) + 1, {"message": "Log 2", "level": "warn"}),
        (int(time.time()) + 2, {"message": "Log 3", "level": "error"}),
    ]
    success = tester.send_forward_mode("test.batch", entries)
    time.sleep(0.5)

    # Test 3: PackedForward mode
    print("\n3. Testing PackedForward mode...")
    entries = [
        (int(time.time()), {"message": "Packed log 1"}),
        (int(time.time()) + 1, {"message": "Packed log 2"}),
    ]
    success = tester.send_packed_forward_mode("test.packed", entries)
    time.sleep(0.5)

def run_field_mapping_tests(tester: FluentdForwardTester):
    """Run field mapping tests"""
    print("\n=== Field Mapping Tests ===")

    # Test 1: Kubernetes logs
    print("\n1. Testing Kubernetes log format...")
    tester.send_kubernetes_log(
        pod_name="test-pod-abc123",
        namespace="production",
        container="nginx",
        message="GET /api/users HTTP/1.1 200"
    )
    time.sleep(0.5)

    # Test 2: Docker logs
    print("\n2. Testing Docker log format...")
    tester.send_docker_log(
        container_name="app-container",
        container_id="abc123def456",
        message="Application started successfully"
    )
    time.sleep(0.5)

    # Test 3: Syslog messages
    print("\n3. Testing Syslog format...")
    tester.send_syslog_message(
        hostname="server1.example.com",
        program="sshd",
        pid=12345,
        message="Accepted publickey for admin from 192.168.1.100"
    )
    time.sleep(0.5)

    # Test 4: Apache access logs
    print("\n4. Testing Apache access log format...")
    tester.send_apache_access_log(
        remote_addr="192.168.1.100",
        user="admin",
        method="GET",
        path="/api/users",
        status=200
    )
    time.sleep(0.5)

    # Test 5: Nginx access logs
    print("\n5. Testing Nginx access log format...")
    tester.send_nginx_access_log(
        remote_addr="192.168.1.200",
        user="user123",
        method="POST",
        uri="/api/login",
        status=201
    )
    time.sleep(0.5)

def run_performance_tests(tester: FluentdForwardTester):
    """Run performance tests"""
    print("\n=== Performance Tests ===")

    # Test 1: Batch throughput
    print("\n1. Testing batch throughput (100 messages)...")
    start = time.time()
    tester.send_batch_logs(100)
    elapsed = time.time() - start
    print(f"  Sent 100 messages in {elapsed:.2f}s ({100/elapsed:.0f} msg/s)")

    # Test 2: Sustained load
    print("\n2. Testing sustained load (500 messages)...")
    start = time.time()
    for i in range(5):
        tester.send_batch_logs(100)
        time.sleep(0.1)
    elapsed = time.time() - start
    print(f"  Sent 500 messages in {elapsed:.2f}s ({500/elapsed:.0f} msg/s)")

def main():
    parser = argparse.ArgumentParser(description="Test Cerberus Fluentd/Fluent Bit integration")
    parser.add_argument("--host", default="localhost", help="Cerberus host (default: localhost)")
    parser.add_argument("--port", type=int, default=24224, help="Fluentd port (default: 24224)")
    parser.add_argument("--api-port", type=int, default=8080, help="API port (default: 8080)")
    parser.add_argument("--skip-verification", action="store_true", help="Skip event verification")
    parser.add_argument("--test", choices=["basic", "mapping", "performance", "all"], default="all",
                        help="Test suite to run (default: all)")

    args = parser.parse_args()

    print(f"Cerberus Fluentd Integration Test")
    print(f"==================================")
    print(f"Target: {args.host}:{args.port}")
    print(f"API: http://{args.host}:{args.api_port}")

    tester = FluentdForwardTester(args.host, args.port)
    api_url = f"http://{args.host}:{args.api_port}"

    # Run selected tests
    if args.test in ["basic", "all"]:
        run_basic_tests(tester)

    if args.test in ["mapping", "all"]:
        run_field_mapping_tests(tester)

    if args.test in ["performance", "all"]:
        run_performance_tests(tester)

    # Verify events were received
    if not args.skip_verification:
        print("\n=== Verification ===")
        print("\nWaiting 3 seconds for events to be processed...")
        time.sleep(3)

        verify_events_received(api_url, expected_count=1, timeout=10)

    print("\n=== Test Complete ===")
    print("Check the Cerberus API for detailed event information:")
    print(f"  curl {api_url}/api/v1/events?limit=10")
    print(f"  curl {api_url}/api/v1/events?source=fluentd")

if __name__ == "__main__":
    main()
