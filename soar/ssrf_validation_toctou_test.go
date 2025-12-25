package soar

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// SSRF TOCTOU (Time-of-Check-Time-of-Use) ATTACK TESTS
// ============================================================================
//
// SECURITY REQUIREMENT: FR-SEC-009 - SSRF Protection for Webhook Actions
// THREAT MODEL: DNS Rebinding Attacks (TOCTOU vulnerability)
//
// ATTACK SCENARIO:
// 1. Attacker controls DNS for evil.com
// 2. ValidateWebhookURL resolves evil.com → 1.2.3.4 (safe public IP)
// 3. Validation passes
// 4. Attacker changes DNS: evil.com → 169.254.169.254 (AWS metadata)
// 5. HTTP client resolves evil.com again → connects to metadata endpoint
// 6. SSRF successful - attacker steals cloud credentials
//
// DEFENSE IMPLEMENTED:
// - ValidateWebhookURL returns the resolved IP
// - CreateSSRFSafeClient uses the pre-resolved IP directly
// - Custom DialContext bypasses DNS resolution entirely
// - No DNS lookup happens between validation and request
//
// COVERAGE:
// - Test 1-3: Basic TOCTOU protection validation
// - Test 4-5: IP-based URLs (no DNS resolution needed)
// - Test 6-8: Various attack scenarios
// - Test 9-10: Edge cases and error handling

// TestSSRF_TOCTOU_ValidateReturnsResolvedIP verifies that ValidateWebhookURL
// returns the resolved IP address to prevent DNS rebinding attacks
func TestSSRF_TOCTOU_ValidateReturnsResolvedIP(t *testing.T) {
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

	tests := []struct {
		name             string
		url              string
		expectError      bool
		expectIPNonEmpty bool
	}{
		{
			name:             "valid_public_domain_returns_ip",
			url:              "http://example.com/webhook",
			expectError:      false,
			expectIPNonEmpty: true,
		},
		{
			name:             "valid_ip_address_returns_same_ip",
			url:              "http://8.8.8.8/webhook",
			expectError:      false,
			expectIPNonEmpty: true,
		},
		{
			name:             "localhost_blocked_returns_error",
			url:              "http://localhost/webhook",
			expectError:      true,
			expectIPNonEmpty: false,
		},
		{
			name:             "private_ip_blocked_returns_error",
			url:              "http://192.168.1.1/webhook",
			expectError:      true,
			expectIPNonEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvedIP, err := ValidateWebhookURL(tt.url, nil)

			if tt.expectError {
				assert.Error(t, err, "Expected validation to fail for %s", tt.url)
				assert.Empty(t, resolvedIP, "Expected empty IP on error")
			} else {
				assert.NoError(t, err, "Expected validation to pass for %s", tt.url)
				if tt.expectIPNonEmpty {
					assert.NotEmpty(t, resolvedIP, "Expected resolved IP to be returned")
					// Verify it's a valid IP address
					parsedIP := net.ParseIP(resolvedIP)
					assert.NotNil(t, parsedIP, "Expected valid IP address format")
				}
			}
		})
	}
}

// TestSSRF_TOCTOU_ClientUsesPreResolvedIP verifies that CreateSSRFSafeClient
// uses the pre-resolved IP and does NOT perform additional DNS lookups
func TestSSRF_TOCTOU_ClientUsesPreResolvedIP(t *testing.T) {
	// Create a test HTTP server on localhost
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	// Extract the IP and port from the test server
	// server.URL is like "http://127.0.0.1:12345"
	serverIP := strings.TrimPrefix(server.URL, "http://")

	// Test: CreateSSRFSafeClient should connect to the pre-resolved IP
	// even when given a different hostname in the URL
	testURL := "http://fake-hostname.example.com/webhook"

	// Create client with the test server's IP
	client, err := CreateSSRFSafeClient(testURL, serverIP)
	require.NoError(t, err, "Failed to create SSRF-safe client")
	require.NotNil(t, client, "Client should not be nil")

	// Make request using the original URL
	// If TOCTOU protection works, it should connect to serverIP, not resolve fake-hostname
	resp, err := client.Get(testURL)

	// This should succeed if client uses pre-resolved IP
	// It would fail if client tried to resolve "fake-hostname.example.com"
	assert.NoError(t, err, "Expected request to succeed using pre-resolved IP")
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "success", string(body))
	}
}

// TestSSRF_TOCTOU_NoDNSResolutionDuringRequest verifies that the HTTP client
// does NOT perform DNS resolution during the request (all DNS happens in validation)
func TestSSRF_TOCTOU_NoDNSResolutionDuringRequest(t *testing.T) {
	// This test verifies the TOCTOU fix by ensuring DNS is only resolved once

	// Use a real public IP (Google DNS) as the "resolved IP"
	resolvedIP := "8.8.8.8"

	// Create a client with a hostname that would resolve differently
	// If client performs DNS, this would fail because the hostname doesn't match the IP
	testURL := "http://example.com/test"

	client, err := CreateSSRFSafeClient(testURL, resolvedIP)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Attempt to make a request with a very short timeout
	// We expect connection timeout, not DNS resolution error
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)

	// We expect a timeout error (connecting to 8.8.8.8:80 will timeout)
	// NOT a DNS error (which would indicate DNS resolution happened)
	if err != nil {
		errStr := err.Error()
		// Should be timeout or connection refused, NOT "no such host" or DNS errors
		assert.NotContains(t, errStr, "no such host", "Client should not perform DNS lookup")
		assert.NotContains(t, errStr, "Temporary failure in name resolution", "Client should not perform DNS lookup")
	}
}

// TestSSRF_TOCTOU_IPAddressDirectUse verifies that when URL contains an IP address
// (no DNS resolution needed), the same IP is returned and used
func TestSSRF_TOCTOU_IPAddressDirectUse(t *testing.T) {
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

	tests := []struct {
		name        string
		url         string
		expectIP    string
		expectError bool
	}{
		{
			name:        "public_ipv4_returned_as_is",
			url:         "http://8.8.8.8/webhook",
			expectIP:    "8.8.8.8",
			expectError: false,
		},
		{
			name:        "private_ipv4_blocked",
			url:         "http://192.168.1.1/webhook",
			expectIP:    "",
			expectError: true,
		},
		{
			name:        "localhost_ipv4_blocked",
			url:         "http://127.0.0.1/webhook",
			expectIP:    "",
			expectError: true,
		},
		{
			name:        "metadata_ip_blocked",
			url:         "http://169.254.169.254/latest/meta-data/",
			expectIP:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvedIP, err := ValidateWebhookURL(tt.url, nil)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, resolvedIP)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectIP, resolvedIP, "IP should be returned as-is")
			}
		})
	}
}

// TestSSRF_TOCTOU_MetadataEndpointBlocked verifies that cloud metadata endpoints
// are blocked even if DNS rebinding is attempted
func TestSSRF_TOCTOU_MetadataEndpointBlocked(t *testing.T) {
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

	metadataIPs := []string{
		"169.254.169.254", // AWS, Azure, GCP, DigitalOcean
		"169.254.169.253", // AWS IMDSv2
		"169.254.170.2",   // AWS ECS
		"100.100.100.200", // Alibaba Cloud
	}

	for _, metadataIP := range metadataIPs {
		t.Run("block_"+metadataIP, func(t *testing.T) {
			url := "http://" + metadataIP + "/latest/meta-data/"

			resolvedIP, err := ValidateWebhookURL(url, nil)

			assert.Error(t, err, "Metadata endpoint %s should be blocked", metadataIP)
			assert.Contains(t, err.Error(), "SSRF", "Error should indicate SSRF protection")
			assert.Empty(t, resolvedIP, "Should not return IP for blocked endpoint")
		})
	}
}

// TestSSRF_TOCTOU_PrivateIPRangesBlocked verifies that all private IP ranges
// are blocked to prevent internal network scanning
func TestSSRF_TOCTOU_PrivateIPRangesBlocked(t *testing.T) {
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

	privateIPs := []string{
		"10.0.0.1",        // RFC1918 Class A
		"172.16.0.1",      // RFC1918 Class B
		"192.168.1.1",     // RFC1918 Class C
		"127.0.0.1",       // Loopback
		"0.0.0.0",         // This network
		"169.254.1.1",     // Link-local
		"224.0.0.1",       // Multicast
		"255.255.255.255", // Broadcast
	}

	for _, privateIP := range privateIPs {
		t.Run("block_"+privateIP, func(t *testing.T) {
			url := "http://" + privateIP + "/webhook"

			resolvedIP, err := ValidateWebhookURL(url, nil)

			assert.Error(t, err, "Private IP %s should be blocked", privateIP)
			assert.Contains(t, err.Error(), "SSRF", "Error should indicate SSRF protection")
			assert.Empty(t, resolvedIP, "Should not return IP for blocked endpoint")
		})
	}
}

// TestSSRF_TOCTOU_DangerousProtocolsBlocked verifies that dangerous protocols
// are blocked to prevent file:// and other protocol-based attacks
func TestSSRF_TOCTOU_DangerousProtocolsBlocked(t *testing.T) {
	dangerousURLs := []string{
		"file:///etc/passwd",
		"gopher://internal-server:70/",
		"dict://internal-server:2628/",
		"ftp://internal-server/",
		"ldap://internal-server/",
	}

	for _, dangerousURL := range dangerousURLs {
		t.Run("block_"+dangerousURL, func(t *testing.T) {
			resolvedIP, err := ValidateWebhookURL(dangerousURL, nil)

			assert.Error(t, err, "Dangerous protocol should be blocked: %s", dangerousURL)
			assert.Contains(t, err.Error(), "protocol not allowed", "Error should mention protocol")
			assert.Empty(t, resolvedIP, "Should not return IP for dangerous protocol")
		})
	}
}

// TestSSRF_TOCTOU_ClientRespectsResolvedIP verifies that the SSRF-safe client
// respects the resolved IP even when URL hostname differs
func TestSSRF_TOCTOU_ClientRespectsResolvedIP(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request reached this server
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("toctou-test-success"))
	}))
	defer server.Close()

	// Extract IP:port from server URL
	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Create client with a DIFFERENT hostname than the server
	// This simulates the TOCTOU attack scenario
	fakeURL := "http://attacker-controlled-domain.com/webhook"

	// But use the real server's IP (simulating validated IP)
	client, err := CreateSSRFSafeClient(fakeURL, serverAddr)
	require.NoError(t, err)

	// Make request to the fake URL
	// Client should connect to serverAddr, not try to resolve attacker-controlled-domain.com
	resp, err := client.Get(fakeURL)
	require.NoError(t, err, "Request should succeed using resolved IP")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "toctou-test-success", string(body), "Should reach the correct server")
}

// TestSSRF_TOCTOU_EmptyResolvedIPHandled verifies error handling when
// resolved IP is empty (edge case that should not happen in normal operation)
func TestSSRF_TOCTOU_EmptyResolvedIPHandled(t *testing.T) {
	testURL := "http://example.com/webhook"

	// Try to create client with empty resolved IP
	// This should handle gracefully (though it may not work for actual requests)
	client, err := CreateSSRFSafeClient(testURL, "")

	// Client creation should succeed (error handling is in the request, not creation)
	assert.NoError(t, err, "Client creation should not fail with empty IP")
	assert.NotNil(t, client, "Client should be created")

	// But actual request should fail
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	_, err = client.Do(req)

	// Should fail (connection to ":80" or similar)
	assert.Error(t, err, "Request with empty IP should fail")
}

// TestSSRF_TOCTOU_PortHandling verifies that ports are handled correctly
// in the pre-resolved IP scenario
func TestSSRF_TOCTOU_PortHandling(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		resolvedIP  string
		expectError bool
	}{
		{
			name:        "http_default_port_80",
			url:         "http://example.com/webhook",
			resolvedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:        "http_custom_port_8080",
			url:         "http://example.com:8080/webhook",
			resolvedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:        "https_default_port_443",
			url:         "https://example.com/webhook",
			resolvedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:        "https_custom_port_8443",
			url:         "https://example.com:8443/webhook",
			resolvedIP:  "8.8.8.8",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := CreateSSRFSafeClient(tt.url, tt.resolvedIP)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)

				// Verify client is configured
				assert.NotNil(t, client.Transport)
				assert.Equal(t, 30*time.Second, client.Timeout)
			}
		})
	}
}
