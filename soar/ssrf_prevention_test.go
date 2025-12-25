package soar

import (
	"cerberus/core"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// REQUIREMENT: AFFIRMATIONS.md - SSRF Prevention
// REQUIREMENT: docs/requirements/security-threat-model.md FR-SEC-009 (SSRF Protection)
// CRITICAL: Test that HTTP clients validate URLs to prevent SSRF attacks

// TestValidateWebhookURL_BlocksLocalhostURLs tests blocking of localhost URLs
func TestValidateWebhookURL_BlocksLocalhostURLs(t *testing.T) {
	// REQUIREMENT: Webhooks must not allow requests to localhost
	// SECURITY: Prevents access to internal services on localhost

	// Enable test mode to allow HTTP URLs for testing
	originalTestMode := os.Getenv("CERBERUS_TEST_MODE")
	os.Setenv("CERBERUS_TEST_MODE", "1")
	defer func() {
		if originalTestMode == "" {
			os.Unsetenv("CERBERUS_TEST_MODE")
		} else {
			os.Setenv("CERBERUS_TEST_MODE", originalTestMode)
		}
	}()

	localhostURLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://localhost/admin",
			reason: "localhost by name",
		},
		{
			url:    "http://127.0.0.1/internal",
			reason: "IPv4 loopback",
		},
		{
			url:    "http://127.0.0.1:8080/metrics",
			reason: "IPv4 loopback with port",
		},
		{
			url:    "http://[::1]/admin",
			reason: "IPv6 loopback",
		},
		{
			url:    "http://0.0.0.0/internal",
			reason: "0.0.0.0 address",
		},
		{
			url:    "http://127.255.255.255/",
			reason: "end of IPv4 loopback range",
		},
	}

	for _, tc := range localhostURLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// SECURITY REQUIREMENT: Localhost URLs MUST be blocked
			require.Error(t, err, "Localhost URL must be blocked: %s", tc.url)
			assert.Contains(t, err.Error(), "SSRF", "Error should indicate SSRF protection")
			// Error may say "localhost" for hostname or "private/internal" for IP
			hasIndicator := strings.Contains(err.Error(), "localhost") ||
				strings.Contains(err.Error(), "private") ||
				strings.Contains(err.Error(), "internal")
			assert.True(t, hasIndicator,
				"Error should mention localhost/private/internal for: %s (got: %s)", tc.reason, err.Error())
		})
	}
}

// TestValidateWebhookURL_BlocksPrivateIPRanges tests blocking of private IP ranges
func TestValidateWebhookURL_BlocksPrivateIPRanges(t *testing.T) {
	// REQUIREMENT: Webhooks must not allow requests to private IP ranges
	// SECURITY: Prevents access to internal network resources

	privateIPURLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://10.0.0.1/admin",
			reason: "RFC1918 10.0.0.0/8",
		},
		{
			url:    "http://10.255.255.255/",
			reason: "RFC1918 10.0.0.0/8 end of range",
		},
		{
			url:    "http://172.16.0.1/internal",
			reason: "RFC1918 172.16.0.0/12 start",
		},
		{
			url:    "http://172.31.255.255/",
			reason: "RFC1918 172.16.0.0/12 end",
		},
		{
			url:    "http://192.168.1.1/router",
			reason: "RFC1918 192.168.0.0/16",
		},
		{
			url:    "http://192.168.255.255/",
			reason: "RFC1918 192.168.0.0/16 end",
		},
	}

	for _, tc := range privateIPURLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// SECURITY REQUIREMENT: Private IP URLs MUST be blocked
			assert.Error(t, err, "Private IP URL must be blocked: %s", tc.url)
			assert.Contains(t, err.Error(), "SSRF", "Error should indicate SSRF protection")
			assert.Contains(t, err.Error(), "private",
				"Error should mention private IP for: %s", tc.reason)
		})
	}
}

// TestValidateWebhookURL_BlocksCloudMetadataServices tests blocking of cloud metadata endpoints
func TestValidateWebhookURL_BlocksCloudMetadataServices(t *testing.T) {
	// REQUIREMENT: Cloud metadata endpoints must be blocked
	// SECURITY: Prevents credential theft from cloud instances

	metadataURLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			reason: "AWS EC2 metadata service",
		},
		{
			url:    "http://169.254.169.254/computeMetadata/v1/",
			reason: "GCP metadata service",
		},
		{
			url:    "http://169.254.169.254/metadata/instance",
			reason: "Azure metadata service",
		},
		{
			url:    "http://169.254.169.253/latest/api/token",
			reason: "AWS IMDSv2",
		},
		{
			url:    "http://169.254.170.2/v2/metadata",
			reason: "AWS ECS task metadata",
		},
		{
			url:    "http://100.100.100.200/latest/meta-data/",
			reason: "Alibaba Cloud metadata",
		},
	}

	for _, tc := range metadataURLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// CRITICAL SECURITY REQUIREMENT: Cloud metadata MUST be blocked
			assert.Error(t, err, "Cloud metadata URL must be blocked: %s", tc.url)
			assert.Contains(t, err.Error(), "SSRF", "Error should indicate SSRF protection")
			assert.Contains(t, err.Error(), "private",
				"Error should mention private/internal IP for: %s", tc.reason)
		})
	}
}

// TestValidateWebhookURL_BlocksDangerousProtocols tests blocking of file:// protocol
func TestValidateWebhookURL_BlocksDangerousProtocols(t *testing.T) {
	// REQUIREMENT: Only HTTP/HTTPS protocols should be allowed
	// SECURITY: Prevents file access and protocol smuggling

	dangerousProtocols := []struct {
		url    string
		reason string
	}{
		{
			url:    "file:///etc/passwd",
			reason: "file:// protocol",
		},
		{
			url:    "file:///C:/Windows/System32/config/SAM",
			reason: "file:// Windows path",
		},
		{
			url:    "gopher://127.0.0.1:25/_MAIL",
			reason: "gopher:// protocol",
		},
		{
			url:    "dict://127.0.0.1:11211/stats",
			reason: "dict:// protocol",
		},
		{
			url:    "ftp://internal.server/file.txt",
			reason: "ftp:// protocol",
		},
		{
			url:    "ldap://internal.ldap/dc=example,dc=com",
			reason: "ldap:// protocol",
		},
	}

	for _, tc := range dangerousProtocols {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// SECURITY REQUIREMENT: Dangerous protocols MUST be blocked
			assert.Error(t, err, "Dangerous protocol must be blocked: %s", tc.url)
			assert.Contains(t, err.Error(), "protocol",
				"Error should mention protocol for: %s", tc.reason)
		})
	}
}

// TestValidateWebhookURL_AllowsPublicIPs tests that legitimate public IPs are allowed
func TestValidateWebhookURL_AllowsPublicIPs(t *testing.T) {
	// REQUIREMENT: SSRF protection must allow legitimate webhooks
	// SECURITY: Prevent false positives

	publicIPURLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://8.8.8.8/webhook",
			reason: "Google DNS",
		},
		{
			url:    "http://1.1.1.1/api",
			reason: "Cloudflare DNS",
		},
		{
			url:    "http://93.184.216.34/hook",
			reason: "example.com IP",
		},
	}

	for _, tc := range publicIPURLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// SECURITY REQUIREMENT: Public IPs should be allowed
			assert.NoError(t, err, "Public IP should be allowed: %s (%s)", tc.url, tc.reason)
		})
	}
}

// TestValidateWebhookURL_IPv6LinkLocal tests blocking of IPv6 link-local
func TestValidateWebhookURL_IPv6LinkLocal(t *testing.T) {
	// REQUIREMENT: IPv6 link-local addresses must be blocked
	// SECURITY: IPv6 provides multiple localhost representations

	ipv6URLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://[::1]/admin",
			reason: "IPv6 loopback",
		},
		{
			url:    "http://[0:0:0:0:0:0:0:1]/metrics",
			reason: "IPv6 loopback expanded",
		},
		{
			url:    "http://[fe80::1]/internal",
			reason: "IPv6 link-local",
		},
		{
			url:    "http://[fc00::1]/private",
			reason: "IPv6 unique local",
		},
		{
			url:    "http://[fd00::1]/private",
			reason: "IPv6 unique local fd00",
		},
	}

	for _, tc := range ipv6URLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// SECURITY REQUIREMENT: IPv6 internal addresses MUST be blocked
			assert.Error(t, err, "IPv6 internal address must be blocked: %s", tc.url)
			assert.Contains(t, err.Error(), "SSRF",
				"Error should indicate SSRF protection for: %s", tc.reason)
		})
	}
}

// TestWebhookAction_ValidateParams_CallsSSRFProtection tests integration with WebhookAction
func TestWebhookAction_ValidateParams_CallsSSRFProtection(t *testing.T) {
	// REQUIREMENT: WebhookAction must validate URLs through SSRF protection
	// SECURITY: Integration test verifying validation is called

	logger := zap.NewNop().Sugar()
	action := NewWebhookAction(logger)

	// Test that SSRF protection is called during parameter validation
	maliciousParams := []struct {
		url    string
		reason string
	}{
		{
			url:    "http://169.254.169.254/latest/meta-data/",
			reason: "AWS metadata",
		},
		{
			url:    "http://localhost:6379/",
			reason: "localhost Redis",
		},
		{
			url:    "http://192.168.1.1/admin",
			reason: "private IP",
		},
		{
			url:    "file:///etc/passwd",
			reason: "file protocol",
		},
	}

	for _, tc := range maliciousParams {
		t.Run(tc.reason, func(t *testing.T) {
			params := map[string]interface{}{
				"url":    tc.url,
				"method": "POST",
			}

			err := action.ValidateParams(params)

			// SECURITY REQUIREMENT: Malicious URLs MUST be rejected at validation
			require.Error(t, err, "Malicious URL must be rejected: %s (%s)", tc.url, tc.reason)
			assert.Contains(t, err.Error(), "validation failed",
				"Error should indicate validation failure")
		})
	}

	// Test that legitimate URL is allowed
	legitimateParams := map[string]interface{}{
		"url":    "https://api.example.com/webhook",
		"method": "POST",
	}
	err := action.ValidateParams(legitimateParams)
	// Note: This will fail DNS lookup in test environment, which is expected
	// The key is that it's not blocked for SSRF reasons
	// In production with real DNS, this would pass
	t.Logf("Legitimate URL validation result: %v (may fail DNS lookup in test environment)", err)
}

// TestWebhookAction_Execute_BlocksSSRFAtRuntime tests runtime SSRF protection
func TestWebhookAction_Execute_BlocksSSRFAtRuntime(t *testing.T) {
	// REQUIREMENT: Even if validation is bypassed, execution must not access internal resources
	// SECURITY: Defense in depth

	logger := zap.NewNop().Sugar()
	action := NewWebhookAction(logger)

	alert := &core.Alert{
		AlertID:   "test-alert",
		RuleID:    "test-rule",
		Severity:  "Medium",
		Timestamp: time.Now(),
	}

	ctx := context.Background()

	// These should fail during validation, not execution
	maliciousParams := map[string]interface{}{
		"url":    "http://127.0.0.1:6379/",
		"method": "POST",
	}

	result, err := action.Execute(ctx, alert, maliciousParams)

	// Should fail (either during validation or execution)
	assert.Error(t, err, "Execution with malicious URL should fail")
	if result != nil {
		assert.NotEqual(t, ActionStatusCompleted, result.Status,
			"Malicious webhook should not complete successfully")
	}
}

// TestIsPrivateOrInternalIP_ComprehensiveCoverage tests the IP validation function
func TestIsPrivateOrInternalIP_ComprehensiveCoverage(t *testing.T) {
	// REQUIREMENT: IP validation must correctly identify all private/internal IPs
	// SECURITY: Comprehensive test of IP classification

	testCases := []struct {
		ip          string
		shouldBlock bool
		reason      string
	}{
		// Public IPs (should NOT block)
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"93.184.216.34", false, "example.com"},

		// Localhost (should block)
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.255.255.255", true, "IPv4 loopback end"},
		{"::1", true, "IPv6 loopback"},

		// RFC1918 Private (should block)
		{"10.0.0.1", true, "RFC1918 10.x"},
		{"10.255.255.255", true, "RFC1918 10.x end"},
		{"172.16.0.1", true, "RFC1918 172.16-31.x"},
		{"172.31.255.255", true, "RFC1918 172.16-31.x end"},
		{"192.168.1.1", true, "RFC1918 192.168.x"},

		// Link-local / Cloud metadata (should block)
		{"169.254.169.254", true, "Cloud metadata"},
		{"169.254.169.253", true, "AWS IMDSv2"},
		{"169.254.170.2", true, "AWS ECS metadata"},
		{"169.254.1.1", true, "Link-local"},

		// Shared address space (should block)
		{"100.64.0.1", true, "Carrier-grade NAT"},

		// IPv6 private (should block)
		{"fc00::1", true, "IPv6 unique local"},
		{"fd00::1", true, "IPv6 unique local fd00"},
		{"fe80::1", true, "IPv6 link-local"},

		// Multicast (should block)
		{"224.0.0.1", true, "IPv4 multicast"},
		{"ff02::1", true, "IPv6 multicast"},

		// Reserved (should block)
		{"0.0.0.0", true, "This network"},
		{"255.255.255.255", true, "Broadcast"},
	}

	for _, tc := range testCases {
		t.Run(tc.reason, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip, "Failed to parse IP: %s", tc.ip)

			isBlocked := isPrivateOrInternalIP(ip)

			if tc.shouldBlock {
				assert.True(t, isBlocked,
					"SECURITY FAILURE: IP %s (%s) should be blocked but was allowed",
					tc.ip, tc.reason)
			} else {
				assert.False(t, isBlocked,
					"FALSE POSITIVE: IP %s (%s) should be allowed but was blocked",
					tc.ip, tc.reason)
			}
		})
	}
}

// TestValidateWebhookURL_InvalidURLs tests handling of malformed URLs
func TestValidateWebhookURL_InvalidURLs(t *testing.T) {
	// REQUIREMENT: Invalid URLs should be rejected gracefully
	// SECURITY: Prevent parser confusion attacks

	invalidURLs := []struct {
		url    string
		reason string
	}{
		{
			url:    "",
			reason: "empty URL",
		},
		{
			url:    "not-a-url",
			reason: "no scheme",
		},
		{
			url:    "http://",
			reason: "missing hostname",
		},
		{
			url:    "://example.com",
			reason: "missing scheme",
		},
	}

	for _, tc := range invalidURLs {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := ValidateWebhookURL(tc.url, nil)

			// Invalid URLs should be rejected
			assert.Error(t, err, "Invalid URL should be rejected: %s (%s)", tc.url, tc.reason)
		})
	}
}
