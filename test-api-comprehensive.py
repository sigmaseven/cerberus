#!/usr/bin/env python3
"""
Comprehensive API Test Suite for Cerberus SIEM
Automatically tests all endpoints from Swagger specification
"""

import requests
import json
import sys
import time
from typing import Dict, List, Tuple

BASE_URL = "http://localhost:8081"

# Test counters
tests_run = 0
tests_passed = 0
tests_failed = 0
test_results = []

# Sample data for creating resources
SAMPLE_RULE = {
    "id": "test_rule_auto",
    "name": "Test Rule",
    "description": "Test detection rule created by automated test",
    "severity": "Medium",
    "version": 1,
    "enabled": True,
    "conditions": [
        {
            "field": "event_type",
            "operator": "equals",
            "value": "test_event",
            "logic": "AND"
        }
    ],
    "actions": []
}

SAMPLE_ACTION = {
    "id": "test_action_auto",
    "type": "webhook",
    "config": {
        "url": "https://example.com/webhook",
        "method": "POST"
    }
}

SAMPLE_CORRELATION_RULE = {
    "id": "test_correlation_auto",
    "name": "Test Correlation Rule",
    "description": "Test correlation rule",
    "severity": "High",
    "version": 1,
    "window": 300000000000,
    "conditions": [
        {
            "field": "event_type",
            "operator": "equals",
            "value": "login",
            "logic": "AND"
        }
    ],
    "sequence": ["login", "login", "login"],
    "actions": []
}

def print_header(text):
    """Print formatted section header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def print_result(test_name, passed, details=""):
    """Print and record test result"""
    global tests_run, tests_passed, tests_failed
    tests_run += 1

    status = "PASS" if passed else "FAIL"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"

    print(f"{color}[{tests_run}] {status}{reset} - {test_name}")
    if details:
        print(f"    {details}")

    if passed:
        tests_passed += 1
    else:
        tests_failed += 1

    test_results.append({
        "name": test_name,
        "status": "PASS" if passed else "FAIL",
        "details": details
    })

def test_get(path, expected_type="any"):
    """Test GET endpoint"""
    test_name = f"GET {path}"
    try:
        response = requests.get(f"{BASE_URL}{path}")
        time.sleep(0.1)

        if response.status_code == 200:
            data = response.json()

            if expected_type == "array":
                if isinstance(data, list):
                    print_result(test_name, True, f"Returns array with {len(data)} items")
                    return data
                else:
                    print_result(test_name, False, f"Expected array, got {type(data).__name__}")
                    return None
            elif expected_type == "object":
                if isinstance(data, dict):
                    print_result(test_name, True, "Returns object")
                    return data
                else:
                    print_result(test_name, False, f"Expected object, got {type(data).__name__}")
                    return None
            else:
                print_result(test_name, True, f"HTTP {response.status_code}")
                return data
        else:
            print_result(test_name, False, f"HTTP {response.status_code}")
            return None

    except Exception as e:
        print_result(test_name, False, str(e))
        return None

def test_post(path, data, expected_status=201):
    """Test POST endpoint"""
    test_name = f"POST {path}"
    try:
        response = requests.post(
            f"{BASE_URL}{path}",
            json=data,
            headers={"Content-Type": "application/json"}
        )
        time.sleep(0.1)

        if response.status_code == expected_status:
            print_result(test_name, True, f"HTTP {response.status_code}")
            try:
                return response.json()
            except:
                return response.text
        else:
            print_result(test_name, False, f"Expected {expected_status}, got HTTP {response.status_code}: {response.text}")
            return None

    except Exception as e:
        print_result(test_name, False, str(e))
        return None

def test_put(path, data):
    """Test PUT endpoint"""
    test_name = f"PUT {path}"
    try:
        response = requests.put(
            f"{BASE_URL}{path}",
            json=data,
            headers={"Content-Type": "application/json"}
        )
        time.sleep(0.1)

        if response.status_code == 200:
            print_result(test_name, True, f"HTTP {response.status_code}")
            try:
                return response.json()
            except:
                return response.text
        else:
            print_result(test_name, False, f"HTTP {response.status_code}: {response.text}")
            return None

    except Exception as e:
        print_result(test_name, False, str(e))
        return None

def test_delete(path, expected_status=200):
    """Test DELETE endpoint"""
    test_name = f"DELETE {path}"
    try:
        response = requests.delete(f"{BASE_URL}{path}")
        time.sleep(0.1)

        if response.status_code == expected_status:
            print_result(test_name, True, f"HTTP {response.status_code}")
            return True
        else:
            print_result(test_name, False, f"Expected {expected_status}, got HTTP {response.status_code}")
            return False

    except Exception as e:
        print_result(test_name, False, str(e))
        return False

def main():
    """Run comprehensive API test suite"""

    print("\033[96m")
    print("="*60)
    print("  Cerberus SIEM API Comprehensive Test Suite")
    print("="*60)
    print(f"\033[0m")
    print(f"Base URL: {BASE_URL}")
    print()

    # ========================================================================
    # Phase 1: Test all GET endpoints
    # ========================================================================
    print_header("Phase 1: Testing GET Endpoints")

    test_get("/health", "object")
    test_get("/api/events", "array")
    test_get("/api/alerts", "array")
    test_get("/api/rules", "array")
    test_get("/api/actions", "array")
    test_get("/api/correlation-rules", "array")
    test_get("/api/listeners", "object")
    test_get("/api/dashboard", "object")
    test_get("/api/dashboard/chart", "array")

    # ========================================================================
    # Phase 2: Test Rules CRUD
    # ========================================================================
    print_header("Phase 2: Testing Rules CRUD Operations")

    # Create rule
    created_rule = test_post("/api/rules", SAMPLE_RULE, 201)
    rule_id = created_rule.get("id") if created_rule else None

    if rule_id:
        # Get specific rule
        test_get(f"/api/rules/{rule_id}", "object")

        # Update rule
        updated_rule = SAMPLE_RULE.copy()
        updated_rule["name"] = "Updated Test Rule"
        updated_rule["severity"] = "High"
        test_put(f"/api/rules/{rule_id}", updated_rule)

        # Verify update
        test_get(f"/api/rules/{rule_id}", "object")

    # List all rules
    test_get("/api/rules", "array")

    # ========================================================================
    # Phase 3: Test Actions CRUD
    # ========================================================================
    print_header("Phase 3: Testing Actions CRUD Operations")

    created_action = test_post("/api/actions", SAMPLE_ACTION, 201)
    action_id = created_action.get("id") if created_action else None

    if action_id:
        test_get(f"/api/actions/{action_id}", "object")

        # Update action
        updated_action = SAMPLE_ACTION.copy()
        updated_action["type"] = "email"
        updated_action["config"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "from": "alerts@example.com",
            "to": "admin@example.com"
        }
        test_put(f"/api/actions/{action_id}", updated_action)

    test_get("/api/actions", "array")

    # ========================================================================
    # Phase 4: Test Correlation Rules CRUD
    # ========================================================================
    print_header("Phase 4: Testing Correlation Rules CRUD Operations")

    created_correlation = test_post("/api/correlation-rules", SAMPLE_CORRELATION_RULE, 201)
    correlation_id = created_correlation.get("id") if created_correlation else None

    if correlation_id:
        test_get(f"/api/correlation-rules/{correlation_id}", "object")

        # Update correlation rule
        updated_correlation = SAMPLE_CORRELATION_RULE.copy()
        updated_correlation["severity"] = "Critical"
        test_put(f"/api/correlation-rules/{correlation_id}", updated_correlation)

    test_get("/api/correlation-rules", "array")

    # ========================================================================
    # Phase 5: Test Alert Operations
    # ========================================================================
    print_header("Phase 5: Testing Alert Operations")

    # Test with fake ID (should return 404, which is acceptable)
    test_post("/api/alerts/fake-alert-id/acknowledge", {}, expected_status=404)
    test_post("/api/alerts/fake-alert-id/dismiss", {}, expected_status=404)

    # ========================================================================
    # Phase 6: Test Error Handling
    # ========================================================================
    print_header("Phase 6: Testing Error Handling")

    # Test 404 for non-existent resource
    response = requests.get(f"{BASE_URL}/api/rules/nonexistent-rule-id")
    time.sleep(0.1)
    if response.status_code == 404:
        print_result("GET /api/rules/{nonexistent}", True, "Correctly returns 404")
    else:
        print_result("GET /api/rules/{nonexistent}", False, f"Expected 404, got {response.status_code}")

    # Test invalid JSON
    response = requests.post(
        f"{BASE_URL}/api/rules",
        data="{invalid json",
        headers={"Content-Type": "application/json"}
    )
    time.sleep(0.1)
    if response.status_code == 400:
        print_result("POST /api/rules (invalid JSON)", True, "Correctly returns 400")
    else:
        print_result("POST /api/rules (invalid JSON)", False, f"Expected 400, got {response.status_code}")

    # ========================================================================
    # Phase 7: Cleanup
    # ========================================================================
    print_header("Phase 7: Cleanup Test Resources")

    if rule_id:
        test_delete(f"/api/rules/{rule_id}")
    if action_id:
        test_delete(f"/api/actions/{action_id}")
    if correlation_id:
        test_delete(f"/api/correlation-rules/{correlation_id}")

    # Verify deletions
    if rule_id:
        response = requests.get(f"{BASE_URL}/api/rules/{rule_id}")
        time.sleep(0.1)
        if response.status_code == 404:
            print_result("Verify rule deletion", True, "Rule successfully deleted")
        else:
            print_result("Verify rule deletion", False, "Rule still exists")

    # ========================================================================
    # Summary
    # ========================================================================
    print("\n" + "="*60)
    print("  Test Summary")
    print("="*60)
    print(f"Total Tests:    {tests_run}")
    print(f"\033[92mPassed:         {tests_passed}\033[0m")
    if tests_failed > 0:
        print(f"\033[91mFailed:         {tests_failed}\033[0m")
    else:
        print(f"\033[92mFailed:         {tests_failed}\033[0m")

    success_rate = (tests_passed / tests_run * 100) if tests_run > 0 else 0
    print(f"Success Rate:   {success_rate:.1f}%")
    print("="*60)

    # Exit with failure code if any tests failed
    sys.exit(1 if tests_failed > 0 else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        sys.exit(1)
