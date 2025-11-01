# API Testing Guide

## Overview

This document describes the comprehensive API testing suite created for Cerberus SIEM. All tests are automatically generated from the Swagger/OpenAPI specification.

## Test Suites Available

### 1. Python Comprehensive Test Suite (Recommended)
**File:** `test-api-comprehensive.py`

**Features:**
- ✓ Automatically tests all endpoints from Swagger spec
- ✓ Full CRUD testing (Create, Read, Update, Delete)
- ✓ Response type validation (arrays vs objects)
- ✓ Error handling tests (404, 400, etc.)
- ✓ Dynamic ID handling (extracts IDs from responses)
- ✓ Automatic cleanup after tests
- ✓ Color-coded output
- ✓ Detailed test reports

**Requirements:**
```bash
pip install requests
```

**Usage:**
```bash
python test-api-comprehensive.py
```

**What it tests:**
- Phase 1: All GET endpoints (9 endpoints)
- Phase 2: Rules CRUD (Create, Read, Update, Delete)
- Phase 3: Actions CRUD
- Phase 4: Correlation Rules CRUD
- Phase 5: Alert operations (acknowledge, dismiss)
- Phase 6: Error handling (404, 400 status codes)
- Phase 7: Cleanup and verification

**Sample Output:**
```
============================================================
  Cerberus SIEM API Comprehensive Test Suite
============================================================
Base URL: http://localhost:8081

============================================================
  Phase 1: Testing GET Endpoints
============================================================
✓ [1] PASS - GET /health
    Returns object
✓ [2] PASS - GET /api/events
    Returns array with 0 items
✓ [3] PASS - GET /api/alerts
    Returns array with 0 items
...

============================================================
  Test Summary
============================================================
Total Tests:    32
Passed:         32
Failed:         0
Success Rate:   100.0%
```

---

### 2. Bash Test Suite
**File:** `test-api-suite.sh`

**Features:**
- Unix/Linux/Mac compatible
- Color-coded output
- Full CRUD testing
- Sample data included in script

**Usage:**
```bash
chmod +x test-api-suite.sh
./test-api-suite.sh
```

**Optional:** Specify custom base URL
```bash
./test-api-suite.sh http://production-server:8081
```

---

### 3. Windows Batch Test Suite
**File:** `test-api-suite.bat`

**Features:**
- Native Windows batch script
- No external dependencies
- Creates temporary JSON files for test data
- Automatic cleanup

**Usage:**
```cmd
test-api-suite.bat
```

---

## What Gets Tested

### GET Endpoints (Read Operations)
All collection and resource endpoints:

| Endpoint | Expected Type | Description |
|----------|--------------|-------------|
| `/health` | Object | Health check |
| `/api/events` | Array | List all events |
| `/api/alerts` | Array | List all alerts |
| `/api/rules` | Array | List all rules |
| `/api/actions` | Array | List all actions |
| `/api/correlation-rules` | Array | List correlation rules |
| `/api/listeners` | Object | Listener status |
| `/api/dashboard` | Object | Dashboard stats |
| `/api/dashboard/chart` | Array | Historical chart data |

### POST Endpoints (Create Operations)

**Create Rule:**
```bash
POST /api/rules
Content-Type: application/json

{
  "id": "test_rule_001",
  "name": "Test Rule",
  "description": "Test detection rule",
  "severity": "Medium",
  "version": 1,
  "enabled": true,
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
```

**Expected Response:** `201 Created`
```json
{
  "id": "c6654fb3-5341-486d-9d8d-85d40378adfe",
  "name": "Test Rule",
  ...
}
```

**Create Action:**
```bash
POST /api/actions
Content-Type: application/json

{
  "id": "test_action_001",
  "type": "webhook",
  "config": {
    "url": "https://example.com/webhook"
  }
}
```

**Create Correlation Rule:**
```bash
POST /api/correlation-rules
Content-Type: application/json

{
  "id": "test_correlation_001",
  "name": "Test Correlation",
  "severity": "High",
  "window": 300000000000,
  "sequence": ["login", "login", "login"],
  ...
}
```

### PUT Endpoints (Update Operations)

**Update Rule:**
```bash
PUT /api/rules/{id}
Content-Type: application/json

{
  "name": "Updated Rule Name",
  "severity": "High",
  ...
}
```

**Expected Response:** `200 OK`

### DELETE Endpoints

**Delete Rule:**
```bash
DELETE /api/rules/{id}
```

**Expected Response:** `200 OK`
```json
{
  "status": "deleted"
}
```

### Special Operations

**Acknowledge Alert:**
```bash
POST /api/alerts/{id}/acknowledge
```

**Dismiss Alert:**
```bash
POST /api/alerts/{id}/dismiss
```

---

## Response Validation

The test suites validate:

### ✓ HTTP Status Codes
- `200 OK` - Successful GET, PUT, DELETE
- `201 Created` - Successful POST
- `400 Bad Request` - Invalid JSON
- `404 Not Found` - Resource doesn't exist
- `503 Service Unavailable` - Storage not available

### ✓ Response Types
- **Arrays** - Must be `[]` when empty, NOT `null`
- **Objects** - Must be `{}` structure
- **Primitives** - Strings, numbers, booleans

### ✓ Response Structure
Validates against Swagger schema definitions:
- `core.Rule` - Rule objects
- `core.Action` - Action objects
- `core.Alert` - Alert objects
- `core.Event` - Event objects
- `core.CorrelationRule` - Correlation rule objects

---

## Manual Testing Examples

### Test GET Endpoint
```bash
curl http://localhost:8081/api/rules
```

**Expected (empty):**
```json
[]
```

**Expected (with data):**
```json
[
  {
    "id": "rule-123",
    "name": "Failed Login Detection",
    "severity": "Warning",
    ...
  }
]
```

### Test POST Endpoint
```bash
curl -X POST http://localhost:8081/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my_rule",
    "name": "My Rule",
    "description": "Test",
    "severity": "Low",
    "version": 1,
    "enabled": true,
    "conditions": [],
    "actions": []
  }'
```

### Test PUT Endpoint
```bash
curl -X PUT http://localhost:8081/api/rules/{id} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name",
    ...
  }'
```

### Test DELETE Endpoint
```bash
curl -X DELETE http://localhost:8081/api/rules/{id}
```

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: API Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start Cerberus
        run: |
          ./cerberus &
          sleep 5
      - name: Run API Tests
        run: python test-api-comprehensive.py
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    stages {
        stage('API Tests') {
            steps {
                sh './cerberus &'
                sh 'sleep 5'
                sh 'python test-api-comprehensive.py'
            }
        }
    }
}
```

---

## Troubleshooting

### Server Not Running
```
Error: Connection refused
```
**Solution:** Start Cerberus first:
```bash
./cerberus.exe
```

### Wrong Port
```
Error: Connection refused (port 8081)
```
**Solution:** Check `config.yaml` for correct API port

### Authentication Required
If you've enabled auth in config.yaml, add credentials:

**Python:**
```python
response = requests.get(
    f"{BASE_URL}/api/rules",
    auth=('admin', 'password')
)
```

**Curl:**
```bash
curl -u admin:password http://localhost:8081/api/rules
```

**Bash script:**
```bash
curl -u admin:password -X GET "$BASE_URL/api/rules"
```

---

## Test Data Management

### Sample Rule Data
```json
{
  "id": "test_rule_001",
  "name": "Test Rule",
  "description": "Automated test rule",
  "severity": "Medium",
  "version": 1,
  "enabled": true,
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
```

### Sample Action Data
```json
{
  "id": "test_action_001",
  "type": "webhook",
  "config": {
    "url": "https://example.com/webhook",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer token123"
    }
  }
}
```

### Sample Correlation Rule Data
```json
{
  "id": "test_correlation_001",
  "name": "Brute Force Detection",
  "description": "Detects multiple failed logins",
  "severity": "High",
  "version": 1,
  "window": 300000000000,
  "conditions": [
    {
      "field": "fields.status",
      "operator": "equals",
      "value": "failure",
      "logic": "AND"
    }
  ],
  "sequence": ["login", "login", "login"],
  "actions": []
}
```

---

## Best Practices

### 1. Run Tests Before Commits
```bash
# Before committing code
python test-api-comprehensive.py
git commit -m "Your changes"
```

### 2. Test Against Clean Database
```bash
# Clear test data
mongo cerberus --eval "db.rules.deleteMany({id: /^test_/})"
```

### 3. Use Meaningful Test IDs
```json
{
  "id": "test_rule_failed_login_detection",
  ...
}
```

### 4. Always Cleanup After Tests
The automated suites handle this, but for manual tests:
```bash
curl -X DELETE http://localhost:8081/api/rules/test_rule_001
curl -X DELETE http://localhost:8081/api/actions/test_action_001
```

---

## Test Coverage

| Category | Covered | Total | %age |
|----------|---------|-------|------|
| GET Endpoints | 9 | 9 | 100% |
| POST Endpoints | 6 | 6 | 100% |
| PUT Endpoints | 3 | 3 | 100% |
| DELETE Endpoints | 3 | 3 | 100% |
| Error Cases | 2 | 2 | 100% |
| **Total** | **23** | **23** | **100%** |

---

## Summary

You now have three comprehensive test suites that:

✓ **Automatically test all API endpoints** from the Swagger specification
✓ **Validate responses** against expected types and status codes
✓ **Test full CRUD operations** for all resources
✓ **Handle dynamic IDs** returned by the API
✓ **Verify error handling** (404, 400 responses)
✓ **Clean up test data** automatically
✓ **Provide detailed reporting** with pass/fail counts
✓ **Support CI/CD integration** for automated testing

Choose the test suite that works best for your environment:
- **Python** - Most feature-rich, best for CI/CD
- **Bash** - Great for Unix/Linux environments
- **Batch** - Native Windows support

All test suites are automatically generated from your Swagger/OpenAPI specification, ensuring they stay in sync with your API documentation!
