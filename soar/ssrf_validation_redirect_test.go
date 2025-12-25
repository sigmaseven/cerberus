package soar

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// SSRF REDIRECT BYPASS ATTACK TESTS
// ============================================================================
//
// SECURITY REQUIREMENT: FR-SEC-009 - SSRF Protection for Webhook Actions
// THREAT MODEL: HTTP Redirect-based SSRF Bypass
//
// ATTACK SCENARIO:
// 1. Attacker submits webhook URL: https://attacker.com/redirect
// 2. ValidateWebhookURL checks attacker.com → public IP (safe)
// 3. Validation passes
// 4. HTTP GET to https://attacker.com/redirect
// 5. Server returns: 302 Found, Location: http://169.254.169.254/latest/meta-data/
// 6. Go's http.Client follows redirect (default behavior)
// 7. SSRF successful - attacker steals cloud credentials
//
// DEFENSE IMPLEMENTED:
// - CreateSSRFSafeClient blocks ALL HTTP redirects
// - CheckRedirect returns http.ErrUseLastResponse
// - Defense-in-depth: Both Transport and Client have CheckRedirect
// - Client receives 302 but does NOT follow it
//
// COVERAGE:
// - Test 1-2: Basic redirect blocking
// - Test 3-4: Redirect to dangerous targets
// - Test 5-6: Multiple redirect chains
// - Test 7-8: Edge cases

// TestSSRF_Redirect_BasicRedirectBlocked verifies that HTTP redirects
// are blocked by the SSRF-safe client
func TestSSRF_Redirect_BasicRedirectBlocked(t *testing.T) {
	// Create a test server that returns a redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			// Return 302 redirect to /target
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		// Target endpoint
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target-reached"))
	}))
	defer server.Close()

	// Extract server IP
	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Create SSRF-safe client
	client, err := CreateSSRFSafeClient(server.URL+"/redirect", serverAddr)
	require.NoError(t, err)

	// Make request to redirect URL
	resp, err := client.Get(server.URL + "/redirect")
	require.NoError(t, err)
	defer resp.Body.Close()

	// SECURITY ASSERTION: Client should receive 302, NOT follow redirect
	assert.Equal(t, http.StatusFound, resp.StatusCode, "Should receive redirect status, not follow it")

	// Verify redirect was NOT followed
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	assert.NotContains(t, bodyStr, "target-reached", "Should NOT follow redirect to target")

	// Verify Location header is present (but not followed)
	location := resp.Header.Get("Location")
	assert.NotEmpty(t, location, "Location header should be present")
}

// TestSSRF_Redirect_RedirectToMetadataBlocked verifies that redirects
// to cloud metadata endpoints are blocked
func TestSSRF_Redirect_RedirectToMetadataBlocked(t *testing.T) {
	metadataEndpoints := []string{
		"http://169.254.169.254/latest/meta-data/",                        // AWS
		"http://metadata.google.internal/",                                // GCP
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
	}

	for _, metadataURL := range metadataEndpoints {
		t.Run("block_redirect_to_"+metadataURL, func(t *testing.T) {
			// Create server that redirects to metadata endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Redirect to metadata endpoint
				http.Redirect(w, r, metadataURL, http.StatusFound)
			}))
			defer server.Close()

			serverAddr := strings.TrimPrefix(server.URL, "http://")

			// Create SSRF-safe client
			client, err := CreateSSRFSafeClient(server.URL, serverAddr)
			require.NoError(t, err)

			// Make request
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// SECURITY ASSERTION: Should receive 302, NOT follow redirect
			assert.Equal(t, http.StatusFound, resp.StatusCode, "Should not follow redirect to metadata")

			// Verify redirect was not followed by checking we got the redirect HTML response
			// NOT the actual metadata JSON response
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// If redirect was followed, we'd get JSON metadata (containing "ami-id", "instanceId", etc.)
			// Since redirect was blocked, we get HTML redirect page containing "Found" or "Moved"
			assert.Contains(t, bodyStr, "Found", "Should receive redirect HTML, not metadata response")

			// Verify we didn't get actual metadata JSON responses
			assert.NotContains(t, bodyStr, "\"ami-id\"", "Should not reach AWS metadata JSON")
			assert.NotContains(t, bodyStr, "\"instanceId\"", "Should not reach Azure metadata JSON")
			assert.NotContains(t, bodyStr, "\"projectId\"", "Should not reach GCP metadata JSON")
		})
	}
}

// TestSSRF_Redirect_RedirectToPrivateIPBlocked verifies that redirects
// to private IP addresses are blocked
func TestSSRF_Redirect_RedirectToPrivateIPBlocked(t *testing.T) {
	privateTargets := []string{
		"http://192.168.1.1/admin",
		"http://10.0.0.1/internal",
		"http://172.16.0.1/secret",
		"http://127.0.0.1:6379/", // Redis
		"http://localhost:8080/", // Internal service
	}

	for _, privateTarget := range privateTargets {
		t.Run("block_redirect_to_"+privateTarget, func(t *testing.T) {
			// Create server that redirects to private IP
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, privateTarget, http.StatusMovedPermanently)
			}))
			defer server.Close()

			serverAddr := strings.TrimPrefix(server.URL, "http://")

			// Create SSRF-safe client
			client, err := CreateSSRFSafeClient(server.URL, serverAddr)
			require.NoError(t, err)

			// Make request
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// SECURITY ASSERTION: Should receive 301, NOT follow redirect
			assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode, "Should not follow redirect to private IP")
		})
	}
}

// TestSSRF_Redirect_MultipleRedirectChainBlocked verifies that even
// multi-hop redirect chains are blocked at the first redirect
func TestSSRF_Redirect_MultipleRedirectChainBlocked(t *testing.T) {
	// Create server with multi-hop redirect chain:
	// /start → /middle → /target
	redirectCount := 0
	targetReached := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			redirectCount++
			http.Redirect(w, r, "/middle", http.StatusFound)
		case "/middle":
			redirectCount++
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			targetReached = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("target-reached"))
		}
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Create SSRF-safe client
	client, err := CreateSSRFSafeClient(server.URL+"/start", serverAddr)
	require.NoError(t, err)

	// Make request to start of redirect chain
	resp, err := client.Get(server.URL + "/start")
	require.NoError(t, err)
	defer resp.Body.Close()

	// SECURITY ASSERTION: Should stop at first redirect
	assert.Equal(t, http.StatusFound, resp.StatusCode, "Should receive first redirect")
	assert.Equal(t, 1, redirectCount, "Should only process first redirect, not follow chain")
	assert.False(t, targetReached, "Should NOT reach final target")

	// Verify response body doesn't contain target
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "target-reached", "Should not follow redirect chain")
}

// TestSSRF_Redirect_RedirectStatus307and308Blocked verifies that
// all redirect status codes are blocked (301, 302, 303, 307, 308)
func TestSSRF_Redirect_RedirectStatus307and308Blocked(t *testing.T) {
	redirectStatuses := []struct {
		code int
		name string
	}{
		{http.StatusMovedPermanently, "301_Moved_Permanently"},
		{http.StatusFound, "302_Found"},
		{http.StatusSeeOther, "303_See_Other"},
		{http.StatusTemporaryRedirect, "307_Temporary_Redirect"},
		{http.StatusPermanentRedirect, "308_Permanent_Redirect"},
	}

	for _, redirect := range redirectStatuses {
		t.Run("block_"+redirect.name, func(t *testing.T) {
			// Create server that returns specific redirect code
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/target")
				w.WriteHeader(redirect.code)
			}))
			defer server.Close()

			serverAddr := strings.TrimPrefix(server.URL, "http://")

			// Create SSRF-safe client
			client, err := CreateSSRFSafeClient(server.URL, serverAddr)
			require.NoError(t, err)

			// Make request
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// SECURITY ASSERTION: Should receive redirect status, NOT follow
			assert.Equal(t, redirect.code, resp.StatusCode, "Should receive %d, not follow it", redirect.code)
		})
	}
}

// TestSSRF_Redirect_RedirectViaLocationHeaderBlocked verifies that
// redirects specified via Location header are blocked
func TestSSRF_Redirect_RedirectViaLocationHeaderBlocked(t *testing.T) {
	dangerousLocations := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:6379/",
		"http://192.168.1.1/admin",
		"file:///etc/passwd",
	}

	for _, location := range dangerousLocations {
		t.Run("block_location_"+location, func(t *testing.T) {
			// Create server that sets Location header to dangerous URL
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
				_, _ = w.Write([]byte("redirecting"))
			}))
			defer server.Close()

			serverAddr := strings.TrimPrefix(server.URL, "http://")

			// Create SSRF-safe client
			client, err := CreateSSRFSafeClient(server.URL, serverAddr)
			require.NoError(t, err)

			// Make request
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// SECURITY ASSERTION: Should receive 302, NOT follow Location
			assert.Equal(t, http.StatusFound, resp.StatusCode)

			// Verify Location header is present but not followed
			receivedLocation := resp.Header.Get("Location")
			assert.Equal(t, location, receivedLocation, "Location header should be preserved")

			// Verify we didn't follow the redirect
			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), "redirecting", "Should receive redirect response, not target")
		})
	}
}

// TestSSRF_Redirect_HTTPSRedirectToHTTPBlocked verifies that
// redirects from HTTPS to HTTP (protocol downgrade) are blocked
func TestSSRF_Redirect_HTTPSRedirectToHTTPBlocked(t *testing.T) {
	// Note: This test uses HTTP server (not HTTPS) to simulate the concept
	// In production, HTTPS server would redirect to HTTP, attempting downgrade

	// Create server that attempts protocol downgrade redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate HTTPS → HTTP redirect (protocol downgrade)
		http.Redirect(w, r, "http://attacker.com/steal-credentials", http.StatusFound)
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Create SSRF-safe client
	client, err := CreateSSRFSafeClient(server.URL, serverAddr)
	require.NoError(t, err)

	// Make request
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// SECURITY ASSERTION: Should receive redirect, NOT follow it
	assert.Equal(t, http.StatusFound, resp.StatusCode, "Should not follow protocol downgrade redirect")

	// Verify Location header points to HTTP
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "http://", "Location should contain HTTP URL")
	assert.NotContains(t, location, "https://", "Should not have been upgraded")
}

// TestSSRF_Redirect_JavaScriptRedirectNotFollowed verifies that
// HTML/JavaScript-based redirects are not followed (only HTTP redirects matter)
func TestSSRF_Redirect_JavaScriptRedirectNotFollowed(t *testing.T) {
	// Create server that returns HTML with JavaScript redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
			<html>
			<head>
				<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">
			</head>
			<body>
				<script>window.location='http://localhost:6379/';</script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Create SSRF-safe client
	client, err := CreateSSRFSafeClient(server.URL, serverAddr)
	require.NoError(t, err)

	// Make request
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// SECURITY ASSERTION: Should receive 200 OK (HTML content)
	// HTTP client doesn't execute JavaScript or meta refresh
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify we received the HTML content (not a redirect)
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "window.location", "Should receive HTML content")
	assert.Contains(t, bodyStr, "meta http-equiv", "Should receive HTML content")

	// This is safe because HTTP clients don't execute JavaScript
	// The dangerous URLs are in HTML, not HTTP redirects
}

// TestSSRF_Redirect_DefenseInDepth verifies that Client.CheckRedirect
// is configured to block all redirects
func TestSSRF_Redirect_DefenseInDepth(t *testing.T) {
	testURL := "http://example.com/webhook"
	resolvedIP := "8.8.8.8"

	client, err := CreateSSRFSafeClient(testURL, resolvedIP)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify Client.CheckRedirect is set
	assert.NotNil(t, client.CheckRedirect, "Client.CheckRedirect should be set for redirect blocking")

	// Verify Transport is configured
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.NotNil(t, transport.DialContext, "Transport.DialContext should be set for TOCTOU protection")

	// Test that CheckRedirect actually blocks redirects
	// Create a dummy request to test the function
	req, _ := http.NewRequest("GET", testURL, nil)
	err = client.CheckRedirect(req, []*http.Request{})

	// Should return http.ErrUseLastResponse
	assert.Equal(t, http.ErrUseLastResponse, err, "CheckRedirect should return ErrUseLastResponse")
}
