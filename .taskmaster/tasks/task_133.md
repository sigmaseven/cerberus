# Task ID: 133

**Title:** Fix IPv6 Address Formatting Vulnerability in SMTP Action

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Replace string concatenation with net.JoinHostPort() for IPv6-safe address formatting in detect/actions.go:853

**Details:**

**BLOCKING SECURITY ISSUE**

Location: `detect/actions.go:853`

Problem: Current implementation uses `fmt.Sprintf("%s:%d", host, port)` which fails with IPv6 addresses and creates potential SSRF bypass.

Implementation:
1. Import `net` and `strconv` packages if not already present
2. Replace line 853:
   ```go
   // WRONG
   conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", smtpServer, port))
   
   // CORRECT
   conn, err := dialer.Dial("tcp", net.JoinHostPort(smtpServer, strconv.Itoa(port)))
   ```
3. Review all other address formatting in the file for similar issues
4. Check webhook and HTTP action handlers for same pattern

Security Impact:
- Prevents IPv6 SSRF protection bypass
- Ensures proper connection handling in IPv6 environments
- Fixes service availability issues

Files to modify:
- `detect/actions.go` (primary fix)
- Review other action handlers for similar patterns

**Test Strategy:**

1. Unit test: Create test with IPv6 SMTP server address (e.g., [::1]:25)
2. Verify connection string format is correct for both IPv4 and IPv6
3. Test SSRF protection still works with IPv6 addresses
4. Integration test: Send test email via IPv6-enabled SMTP server
5. Verify no regression in IPv4 connectivity
6. Run existing action tests to ensure no breakage

## Subtasks

### 133.1. Import required packages and locate target code

**Status:** pending  
**Dependencies:** None  

Verify net and strconv package imports exist in detect/actions.go, and locate the exact vulnerable code at line 853

**Details:**

Open detect/actions.go and check if 'net' and 'strconv' packages are already imported. If not, add them to the import block. Locate line 853 containing 'fmt.Sprintf("%s:%d", smtpServer, port)' pattern. Document the current exact code structure for precise replacement.

### 133.2. Replace vulnerable address formatting with net.JoinHostPort()

**Status:** pending  
**Dependencies:** 133.1  

Replace the string concatenation pattern at line 853 with IPv6-safe net.JoinHostPort() implementation

**Details:**

Replace 'fmt.Sprintf("%s:%d", smtpServer, port)' with 'net.JoinHostPort(smtpServer, strconv.Itoa(port))' at line 853. Ensure the port variable is converted to string using strconv.Itoa(). Verify the replacement maintains the same functional behavior while adding IPv6 safety.

### 133.3. Audit actions.go for similar vulnerable patterns

**Status:** pending  
**Dependencies:** 133.2  

Search detect/actions.go for all other instances of string-based address formatting that could have the same IPv6 vulnerability

**Details:**

Search for patterns like 'fmt.Sprintf("%s:%d"', string concatenation with '+', or any manual host:port formatting in webhook handlers, HTTP action handlers, and other network connection code. Document all findings and apply the same net.JoinHostPort() fix pattern to each occurrence.

### 133.4. Create comprehensive IPv4/IPv6 unit tests

**Status:** pending  
**Dependencies:** 133.3  

Write unit tests verifying correct address formatting for both IPv4 and IPv6 SMTP server addresses

**Details:**

Create test cases in detect/actions_test.go covering: (1) IPv4 address (e.g., '192.168.1.1:25'), (2) IPv6 address (e.g., '[::1]:25', '[2001:db8::1]:587'), (3) hostname with port, (4) verify SSRF protection still functions with IPv6 addresses. Test that net.JoinHostPort correctly formats both IPv4 and IPv6 addresses with proper bracket notation.

### 133.5. Run integration tests and verify no regressions

**Status:** pending  
**Dependencies:** 133.4  

Execute full test suite to ensure the fix doesn't break existing functionality and all SMTP/webhook/HTTP actions work correctly

**Details:**

Run 'go test ./detect/...' to execute all detector tests including the new IPv6 tests. Verify existing IPv4 SMTP tests still pass. Check that SSRF protection mechanisms work with both IPv4 and IPv6 addresses. Review test coverage to ensure the fixed code paths are adequately tested. Document any failures and fix them before marking task complete.
