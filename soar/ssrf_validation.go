package soar

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SECURITY REQUIREMENTS:
// FR-SEC-009: SSRF Protection for Webhook Actions
// OWASP ASVS V5.3.8: Server Side Request Forgery (SSRF) Protection
// THREAT MODEL: Prevents attackers from using webhooks to:
// - Steal cloud metadata (AWS/GCP/Azure credentials)
// - Scan internal networks
// - Access localhost services
// - Bypass firewall restrictions
//
// DEFENSE STRATEGY:
// 1. Block dangerous protocols (file://, gopher://, dict://)
// 2. Block localhost addresses (127.0.0.1, ::1, localhost)
// 3. Block private IP ranges (RFC1918)
// 4. Block cloud metadata endpoints
// 5. Block link-local addresses
// 6. Perform DNS resolution and validate ALL resolved IPs

// ValidateWebhookURL validates a webhook URL to prevent SSRF attacks
// SECURITY: Must be called before making any HTTP request to webhook URL
//
// Requirements:
// - MUST block file:// and other dangerous protocols
// - MUST block localhost (127.0.0.1, ::1, localhost)
// - MUST block private IP ranges (10.x, 192.168.x, 172.16-31.x)
// - MUST block cloud metadata endpoints (169.254.169.254)
// - MUST resolve DNS and validate ALL resolved IPs
// - TASK 33.3: HTTPS-only enforcement (HTTP not allowed in production)
// - TASK 33.5: Allowlist enforcement (if allowlist is non-empty)
//
// Attack Examples Prevented:
// - "http://169.254.169.254/latest/meta-data/" - AWS metadata
// - "http://localhost:6379/" - Redis on localhost
// - "http://192.168.1.1/admin" - Internal router
// - "file:///etc/passwd" - Local file access
// - "http://evil.com@127.0.0.1/" - URL confusion
//
// TOCTOU PROTECTION: Returns the resolved IP address to prevent DNS rebinding attacks
// The caller MUST use this IP when making the HTTP request via CreateSSRFSafeClient
//
// Parameters:
//   - rawURL: The webhook URL to validate
//   - allowlist: Optional allowlist of allowed domains/IPs. If nil or empty, allowlist check is skipped.
//     Supports wildcards: *.example.com matches api.example.com, webhook.example.com
//
// Returns:
//   - resolvedIP: The validated IP address to use for the HTTP request (empty if URL uses IP directly)
//   - error: nil if URL is safe, error if URL is blocked
func ValidateWebhookURL(rawURL string, allowlist []string) (string, error) {
	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// SECURITY: Block dangerous protocols
	// TASK 33.3: Enforce HTTPS-only (HTTP not allowed for security)
	// Only https:// is allowed for webhooks (unless in test mode)
	scheme := strings.ToLower(u.Scheme)
	testMode := os.Getenv("CERBERUS_TEST_MODE") == "1"
	if testMode {
		// Test mode allows both http:// and https:// for testing
		if scheme != "http" && scheme != "https" {
			return "", fmt.Errorf("SSRF: protocol not allowed: %s (only http and https permitted in test mode)", u.Scheme)
		}
	} else {
		// Production mode: HTTPS only
		if scheme != "https" {
			return "", fmt.Errorf("SSRF: protocol not allowed: %s (only https permitted)", u.Scheme)
		}
	}

	// Extract hostname for validation
	hostname := u.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("SSRF: missing hostname in URL")
	}

	hostnameL := strings.ToLower(hostname)

	// TASK 33.5: Allowlist enforcement (check BEFORE DNS resolution for fail-fast)
	// If allowlist is configured and non-empty, validate URL against allowlist
	if len(allowlist) > 0 {
		allowed := isInAllowlist(hostname, hostnameL, allowlist)
		if !allowed {
			return "", fmt.Errorf("SSRF: webhook URL hostname %s is not in allowlist", hostname)
		}
	}

	// SECURITY: Block localhost by hostname
	// Attackers use various forms: localhost, LOCALHOST, LocalHost
	if hostnameL == "localhost" {
		return "", fmt.Errorf("SSRF: localhost not allowed")
	}

	// SECURITY: Check for IP address in hostname
	ip := net.ParseIP(hostname)
	if ip != nil {
		// Hostname is an IP address - validate it directly
		if isPrivateOrInternalIP(ip) {
			return "", fmt.Errorf("SSRF: private/internal IP not allowed: %s", hostname)
		}
		// Return the IP as-is (already validated)
		return ip.String(), nil
	}

	// Hostname is a domain - need to resolve and check all IPs
	// This prevents DNS rebinding attacks where:
	// 1. Domain initially resolves to public IP (passes validation)
	// 2. Attacker changes DNS to resolve to internal IP
	// 3. Application connects to internal IP
	//
	// DEFENSE: We resolve DNS HERE and validate ALL resolved IPs
	// TOCTOU PROTECTION: We return the first valid IP to use directly
	// TASK 33.2: Add DNS timeout to prevent DNS query DoS attacks
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// DNS resolution with timeout
	var ips []net.IP
	var lookupErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		ips, lookupErr = net.LookupIP(hostname)
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("SSRF: DNS lookup timeout for %s (exceeded 5 seconds)", hostname)
	case <-done:
		// DNS lookup completed
	}

	if lookupErr != nil {
		// DNS lookup failed - could be:
		// - Invalid domain
		// - Network issue
		// - DNS server blocking
		// For security, we FAIL CLOSED (deny by default)
		return "", fmt.Errorf("SSRF: DNS lookup failed for %s: %w (domain may not exist)", hostname, lookupErr)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("SSRF: no IP addresses resolved for domain %s", hostname)
	}

	// SECURITY: Validate ALL resolved IPs
	// A single malicious IP in the set makes the domain unsafe
	var firstValidIP string
	for _, resolvedIP := range ips {
		if isPrivateOrInternalIP(resolvedIP) {
			return "", fmt.Errorf("SSRF: domain %s resolves to private/internal IP: %s", hostname, resolvedIP)
		}
		// Store the first valid IP to return
		if firstValidIP == "" {
			firstValidIP = resolvedIP.String()
		}
	}

	// TOCTOU PROTECTION: Return the resolved IP address
	// The caller MUST use this IP to prevent DNS rebinding between validation and request
	return firstValidIP, nil
}

// isPrivateOrInternalIP checks if an IP address is private, internal, or otherwise blocked
// SECURITY: Comprehensive check covering all internal IP ranges
//
// Blocks:
// - Loopback: 127.0.0.0/8, ::1
// - Private (RFC1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
// - Link-local: 169.254.0.0/16 (includes AWS/GCP/Azure metadata)
// - Shared address space: 100.64.0.0/10
// - IPv6 unique local: fc00::/7
// - IPv6 link-local: fe80::/10
// - Multicast: 224.0.0.0/4, ff00::/8
// - Reserved: 240.0.0.0/4, 0.0.0.0/8
// - Broadcast: 255.255.255.255
//
// Returns: true if IP should be blocked, false if safe (public)
func isPrivateOrInternalIP(ip net.IP) bool {
	// Normalize IPv6-mapped IPv4 addresses to IPv4
	// SECURITY: net.ParseIP may return IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
	// We convert these to IPv4 for correct CIDR matching
	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4 // Use IPv4 representation for CIDR matching
	}

	// Cloud metadata endpoints - CRITICAL to block
	// These provide full cloud credentials to attackers
	cloudMetadata := []string{
		"169.254.169.254", // AWS EC2, GCP, Azure, DigitalOcean
		"169.254.169.253", // AWS IMDSv2
		"169.254.170.2",   // AWS ECS
		"100.100.100.200", // Alibaba Cloud
	}
	for _, metadata := range cloudMetadata {
		if ip.String() == metadata {
			return true
		}
	}

	// First, check IPv4-specific ranges if we have an IPv4 address
	if ipv4 != nil {
		ipv4Ranges := []string{
			"127.0.0.0/8",     // IPv4 Loopback
			"10.0.0.0/8",      // IPv4 Private Networks (RFC1918)
			"172.16.0.0/12",   // IPv4 Private Networks (RFC1918)
			"192.168.0.0/16",  // IPv4 Private Networks (RFC1918)
			"169.254.0.0/16",  // IPv4 Link-Local
			"100.64.0.0/10",   // IPv4 Shared Address Space
			"192.0.0.0/24",    // IPv4 IETF Protocol Assignments
			"192.0.2.0/24",    // IPv4 Documentation (TEST-NET)
			"198.51.100.0/24", // IPv4 Documentation (TEST-NET)
			"203.0.113.0/24",  // IPv4 Documentation (TEST-NET)
			"198.18.0.0/15",   // IPv4 Benchmarking
			"240.0.0.0/4",     // IPv4 Reserved
			"0.0.0.0/8",       // IPv4 Reserved
			"224.0.0.0/4",     // IPv4 Multicast
		}
		for _, cidr := range ipv4Ranges {
			_, subnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if subnet.Contains(ipv4) {
				return true
			}
		}
		// IPv4 addresses are fully checked above - skip IPv6 checks
		return false
	}

	// Check IPv6-specific ranges (for non-IPv4 addresses)
	// This catches pure IPv6 addresses and IPv6-mapped IPv4 addresses in ::ffff:x.x.x.x format
	ipv6Ranges := []string{
		"::1/128",       // IPv6 Loopback
		"fe80::/10",     // IPv6 Link-Local
		"fc00::/7",      // IPv6 Unique Local Addresses (private)
		"ff00::/8",      // IPv6 Multicast
		"::ffff:0:0/96", // IPv4-mapped IPv6 addresses
	}
	for _, cidr := range ipv6Ranges {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		// Use original IP to detect IPv6-mapped format (::ffff:x.x.x.x)
		if subnet.Contains(ip) {
			return true
		}
	}

	// Special case: IPv4 broadcast
	if ip.String() == "255.255.255.255" {
		return true
	}

	// Special case: IPv4 "this network"
	if ip.String() == "0.0.0.0" {
		return true
	}

	return false
}

// CreateSSRFSafeClient creates an HTTP client that prevents SSRF attacks via TOCTOU DNS rebinding
// SECURITY: This function implements defense-in-depth against DNS rebinding attacks
//
// TOCTOU VULNERABILITY EXPLAINED:
// 1. ValidateWebhookURL() resolves evil.com → 1.2.3.4 (safe) - validation passes
// 2. Attacker changes DNS: evil.com → 169.254.169.254 (AWS metadata)
// 3. http.Client resolves evil.com again → 169.254.169.254 - SSRF successful!
//
// DEFENSE STRATEGY:
// 1. Use pre-resolved IP from ValidateWebhookURL (performed during validation)
// 2. Custom DialContext forces HTTP client to connect to validated IP
// 3. Block ALL redirects to prevent redirect-based SSRF bypass
// 4. Enforce TLS 1.2+ for HTTPS connections
// 5. Set reasonable timeouts to prevent resource exhaustion
//
// PARAMETERS:
//   - targetURL: The original URL (with hostname) for TLS SNI and Host header
//   - resolvedIP: The validated IP address from ValidateWebhookURL
//
// RETURNS:
//   - *http.Client: SSRF-safe HTTP client configured to use the pre-resolved IP
//   - error: nil on success, error if URL parsing fails
//
// USAGE EXAMPLE:
//
//	resolvedIP, err := ValidateWebhookURL("https://api.example.com/webhook")
//	if err != nil {
//	    return err
//	}
//	client, err := CreateSSRFSafeClient("https://api.example.com/webhook", resolvedIP)
//	if err != nil {
//	    return err
//	}
//	resp, err := client.Get("https://api.example.com/webhook")
//
// SECURITY NOTES:
//   - MUST use resolvedIP from ValidateWebhookURL (not a fresh DNS lookup)
//   - Blocks ALL HTTP redirects (even to safe domains)
//   - TLS verification uses original hostname for SNI/certificate validation
//   - Enforces TLS 1.2+ minimum version
//   - Uses 30-second timeout to prevent slowloris-style resource exhaustion
func CreateSSRFSafeClient(targetURL string, resolvedIP string) (*http.Client, error) {
	// Parse the target URL to extract scheme, hostname, and port
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Extract the original hostname for TLS SNI
	originalHostname := parsedURL.Hostname()

	// Determine the port
	defaultPort := "80"
	if parsedURL.Scheme == "https" {
		defaultPort = "443"
	}
	port := parsedURL.Port()
	if port == "" {
		port = defaultPort
	}

	// Create custom dialer that uses the pre-resolved IP
	// SECURITY: This prevents DNS rebinding by bypassing DNS resolution entirely
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// DualStack enables both IPv4 and IPv6
		DualStack: true,
	}

	// Create custom transport with SSRF protections
	transport := &http.Transport{
		// TOCTOU PROTECTION: Use pre-resolved IP instead of DNS lookup
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Determine which address to use for connection
			// If resolvedIP already contains a port (e.g., "127.0.0.1:8080" from httptest),
			// use it as-is to preserve the complete address
			var dialAddr string
			if strings.Contains(resolvedIP, ":") {
				// resolvedIP includes port (e.g., "127.0.0.1:8080")
				// Verify it's valid by parsing it
				h, p, err := net.SplitHostPort(resolvedIP)
				if err == nil {
					// Valid host:port format, use it directly
					dialAddr = net.JoinHostPort(h, p)
				} else {
					// Parse failed, fallback to treating resolvedIP as just the host
					_, addrPort, portErr := net.SplitHostPort(addr)
					if portErr != nil {
						addrPort = port
					}
					dialAddr = net.JoinHostPort(resolvedIP, addrPort)
				}
			} else {
				// resolvedIP is just an IP address, need to add port
				_, addrPort, err := net.SplitHostPort(addr)
				if err != nil {
					// No port in addr, use default port
					addrPort = port
				}
				dialAddr = net.JoinHostPort(resolvedIP, addrPort)
			}

			// Use our pre-validated IP address for the connection
			// This prevents DNS resolution while using the correct address
			return dialer.DialContext(ctx, network, dialAddr)
		},

		// TLS configuration for HTTPS connections
		TLSClientConfig: &tls.Config{
			// Enforce TLS 1.2+ (TLS 1.0/1.1 are deprecated)
			MinVersion: tls.VersionTLS12,
			// ServerName for SNI (Server Name Indication)
			// IMPORTANT: Use original hostname, not IP, for certificate validation
			ServerName: originalHostname,
		},

		// Timeouts to prevent resource exhaustion
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		// Connection pool settings
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,

		// Disable HTTP/2 for simplicity and security
		// HTTP/2 has additional attack surface (HPACK bombs, etc.)
		ForceAttemptHTTP2: false,
	}

	// Create the SSRF-safe HTTP client
	client := &http.Client{
		Transport: transport,
		// Overall request timeout (includes all redirects, retries, etc.)
		Timeout: 30 * time.Second,
		// Redundant redirect blocking (defense-in-depth)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

// isInAllowlist checks if a hostname matches any entry in the allowlist
// TASK 33.5: Allowlist enforcement with wildcard support
//
// Supports:
// - Exact domain matching: "example.com" matches "example.com"
// - Wildcard matching: "*.example.com" matches "api.example.com", "webhook.example.com"
// - Subdomain matching: "*.example.com" matches "sub.api.example.com"
// - IP address matching (exact match)
// - CIDR matching for IP addresses
//
// Returns: true if hostname matches allowlist, false otherwise
func isInAllowlist(hostname, hostnameLower string, allowlist []string) bool {
	for _, entry := range allowlist {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}

		// Exact match
		if entry == hostnameLower {
			return true
		}

		// Wildcard matching: *.example.com
		if strings.HasPrefix(entry, "*.") {
			domain := entry[2:] // Remove "*." prefix
			// Check if hostname ends with the domain (e.g., api.example.com ends with .example.com)
			if strings.HasSuffix(hostnameLower, "."+domain) || hostnameLower == domain {
				return true
			}
		}

		// Subdomain matching: *.example.com should match sub.api.example.com
		if strings.Contains(entry, "*") {
			// Convert wildcard to regex-like matching
			parts := strings.Split(entry, "*")
			if len(parts) == 2 {
				prefix := strings.ToLower(parts[0])
				suffix := strings.ToLower(parts[1])
				if strings.HasPrefix(hostnameLower, prefix) && strings.HasSuffix(hostnameLower, suffix) {
					return true
				}
			}
		}

		// IP address or CIDR matching
		ip := net.ParseIP(hostname)
		if ip != nil {
			// Check if entry is exact IP match
			if entry == hostname {
				return true
			}
			// Check if entry is CIDR that contains the IP
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// isCloudMetadataEndpoint checks if a hostname is a known cloud metadata service
// SECURITY: Cloud metadata services provide full credentials to attackers
//
// Blocked domains:
// - metadata.google.internal (GCP)
// - metadata.google.com (GCP alternative)
// - 169.254.169.254 (AWS, Azure, DigitalOcean)
//
// Returns: true if hostname is cloud metadata, false otherwise
//
//lint:ignore U1000 Security helper reserved for future cloud metadata SSRF protection enhancement
func isCloudMetadataEndpoint(hostname string) bool {
	hostnameL := strings.ToLower(hostname)

	cloudMetadataDomains := []string{
		"metadata.google.internal",
		"metadata.google.com",
		"metadata",
	}

	for _, domain := range cloudMetadataDomains {
		if hostnameL == domain {
			return true
		}
	}

	return false
}
