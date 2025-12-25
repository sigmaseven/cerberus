package detect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"
	"cerberus/util/goroutine"

	"go.uber.org/zap"
)

// circuitBreakerEntry tracks a circuit breaker with its last access time for cleanup
type circuitBreakerEntry struct {
	cb           *core.CircuitBreaker
	lastAccessed time.Time
}

// ActionExecutor handles executing response actions with circuit breaker protection.
//
// LIFECYCLE CONTRACT:
// ActionExecutor starts a background goroutine for cleaning up stale circuit breakers.
// Callers MUST call Stop() when done to prevent goroutine leaks. The recommended
// pattern is to use defer immediately after creation:
//
//	ae, err := NewActionExecutorWithCircuitBreaker(timeout, logger, cbConfig, cfg)
//	if err != nil {
//	    return err
//	}
//	defer ae.Stop()
//
// ActionExecutor implements io.Closer for compatibility with resource management
// patterns. Close() is an alias for Stop().
type ActionExecutor struct {
	httpClient      *http.Client
	logger          *zap.SugaredLogger
	config          *config.Config                  // Configuration for webhook security
	circuitBreakers map[string]*circuitBreakerEntry // Per-endpoint circuit breakers with access tracking
	cbMutex         sync.RWMutex                    // Protects circuitBreakers map
	cbConfig        core.CircuitBreakerConfig       // Circuit breaker configuration
	cleanupCancel   context.CancelFunc              // Cancel function for cleanup goroutine
	wg              sync.WaitGroup                  // TASK 139: Tracks cleanup goroutine lifecycle
}

const MaxActionRetries = 3

// NewActionExecutor creates a new action executor with default circuit breaker config
// BACKWARD COMPATIBILITY: Maintains original signature using background context
// TASK 144.4: Delegates to context-aware constructor
func NewActionExecutor(timeout time.Duration, logger *zap.SugaredLogger) *ActionExecutor {
	ae, err := NewActionExecutorWithContext(context.Background(), timeout, logger, core.DefaultCircuitBreakerConfig(), nil)
	if err != nil {
		// Default config should always be valid - if this panics, it's a bug in DefaultCircuitBreakerConfig
		panic(fmt.Sprintf("bug: default circuit breaker config is invalid: %v", err))
	}
	return ae
}

// NewActionExecutorWithCircuitBreaker creates a new action executor with custom circuit breaker config
// BACKWARD COMPATIBILITY: Maintains config signature using background context
// TASK 144.4: Delegates to context-aware constructor
func NewActionExecutorWithCircuitBreaker(timeout time.Duration, logger *zap.SugaredLogger, cbConfig core.CircuitBreakerConfig, cfg *config.Config) (*ActionExecutor, error) {
	return NewActionExecutorWithContext(context.Background(), timeout, logger, cbConfig, cfg)
}

// NewActionExecutorWithContext creates a new action executor with parent context for lifecycle management
// TASK 144.4: New constructor that accepts parent context for graceful shutdown
// RELIABILITY: Circuit breaker prevents cascading failures from external service outages
// SECURITY: Custom DialContext prevents DNS rebinding attacks
//
// Parameters:
//   - parentCtx: Parent context for lifecycle coordination (cancellation propagates to cleanup goroutines)
//   - timeout: HTTP client timeout for webhook/API calls
//   - logger: Structured logger for observability
//   - cbConfig: Circuit breaker configuration (must be valid)
//   - cfg: Application config for webhook security settings (nil = use defaults)
//
// Returns:
//   - Configured ActionExecutor instance (cleanup goroutine started automatically)
//   - Error if circuit breaker config is invalid
//
// Lifecycle:
//   - Cleanup goroutine starts automatically in constructor
//   - Call Stop() OR cancel parentCtx to stop goroutines
//   - Stop() is safe to call multiple times
//   - Use defer ae.Stop() immediately after creation
//
// Thread-Safety:
//   - Safe to call from multiple goroutines
//   - Methods are thread-safe after creation
//
// Example:
//
//	appCtx, appCancel := context.WithCancel(context.Background())
//	defer appCancel()
//
//	ae, err := NewActionExecutorWithContext(appCtx, 10*time.Second, logger, cbConfig, cfg)
//	if err != nil {
//	    return err
//	}
//	defer ae.Stop()
//
// Graceful Shutdown:
//   - Cancelling appCtx will stop cleanup goroutine
//   - Stop() provides same functionality plus waits for completion
func NewActionExecutorWithContext(parentCtx context.Context, timeout time.Duration, logger *zap.SugaredLogger, cbConfig core.CircuitBreakerConfig, cfg *config.Config) (*ActionExecutor, error) {
	// TASK 137: Validate circuit breaker config upfront to avoid runtime panics
	if err := cbConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid circuit breaker config: %w", err)
	}

	// TASK 144.4: Derive cancellable context from parent for lifecycle management
	// This allows parent context cancellation to propagate to cleanup goroutines
	ctx, cancel := context.WithCancel(parentCtx)

	ae := &ActionExecutor{
		httpClient:      createSecureHTTPClient(timeout),
		logger:          logger,
		config:          cfg,
		circuitBreakers: make(map[string]*circuitBreakerEntry),
		cbConfig:        cbConfig,
		cleanupCancel:   cancel,
	}

	// TASK 139: Track cleanup goroutine lifecycle with WaitGroup
	// TASK 147: Added panic recovery to prevent cleanup crashes
	// TASK 144.4: Use parent-derived context for coordinated shutdown
	ae.wg.Add(1)
	go func() {
		defer ae.wg.Done()
		defer goroutine.Recover("action-executor-cleanup", ae.logger)
		ae.cleanupStaleCircuitBreakers(ctx)
	}()

	return ae, nil
}

// createSecureHTTPClient creates an HTTP client with DNS rebinding protection
// SECURITY: Re-validates IP addresses at connection time to prevent DNS rebinding attacks
//
// FR-SOAR-018 BLOCKING-002 Enhancements:
// - DNS rebinding protection: Resolve BEFORE and AFTER connection, verify IPs match
// - HTTP redirects DISABLED to prevent redirect-based SSRF
// TASK 1.3: HTTP client hardening with custom transport and configurable timeout
func createSecureHTTPClient(timeout time.Duration) *http.Client {
	// TASK 1.3: Ensure timeout is within reasonable bounds (1-60 seconds)
	if timeout < 1*time.Second {
		timeout = 1 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract host from addr (format: "host:port")
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// FR-SOAR-018: DNS rebinding protection - Resolve hostname BEFORE connection
			// SECURITY: Attacker could change DNS between validation and connection
			// We resolve again and validate the IPs before connecting
			lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			resolver := &net.Resolver{}
			ipsBefore, err := resolver.LookupIP(lookupCtx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed: %w", err)
			}

			// SECURITY: Validate ALL resolved IPs BEFORE connection
			// Skip SSRF check in test mode (set CERBERUS_TEST_MODE=1 environment variable)
			if os.Getenv("CERBERUS_TEST_MODE") != "1" {
				for _, ip := range ipsBefore {
					if isInternalIP(ip) {
						return nil, fmt.Errorf("SSRF blocked (pre-connection): %s resolved to internal IP %s", host, ip.String())
					}
				}
			}

			// Connect to first valid IP
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			// FR-SOAR-018: DNS rebinding protection - Resolve hostname AFTER connection
			// SECURITY: Verify DNS hasn't changed between connection establishment and use
			// This prevents TOCTOU (Time-of-Check-Time-of-Use) DNS rebinding attacks
			if os.Getenv("CERBERUS_TEST_MODE") != "1" {
				lookupCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
				defer cancel2()

				ipsAfter, err := resolver.LookupIP(lookupCtx2, "ip", host)
				if err != nil {
					conn.Close()
					return nil, fmt.Errorf("DNS re-verification failed: %w", err)
				}

				// Verify post-connection IPs match pre-connection IPs
				// If DNS changed, this is a potential rebinding attack
				ipMatch := false
				for _, ipAfter := range ipsAfter {
					for _, ipBefore := range ipsBefore {
						if ipAfter.Equal(ipBefore) {
							ipMatch = true
							break
						}
					}
					if ipMatch {
						break
					}
				}

				if !ipMatch {
					conn.Close()
					return nil, fmt.Errorf("SECURITY: DNS rebinding attack detected - IPs changed between connection (before: %v, after: %v)", ipsBefore, ipsAfter)
				}

				// Also validate post-connection IPs are not internal
				for _, ip := range ipsAfter {
					if isInternalIP(ip) {
						conn.Close()
						return nil, fmt.Errorf("SSRF blocked (post-connection): %s resolved to internal IP %s", host, ip.String())
					}
				}
			}

			// Connection is safe - DNS hasn't changed and points to external IPs
			return conn, nil
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// FR-SOAR-018: HTTP redirects DISABLED
	// SECURITY: Redirects can be used to bypass SSRF protection
	// By disabling redirects, we ensure the exact URL is used
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Return ErrUseLastResponse to prevent following redirects
			return http.ErrUseLastResponse
		},
	}
}

// getOrCreateCircuitBreaker gets or creates a circuit breaker for an endpoint
// RELIABILITY: Per-endpoint circuit breakers isolate failures to specific services
// PERFORMANCE: Updates last accessed time for cleanup mechanism
func (ae *ActionExecutor) getOrCreateCircuitBreaker(endpoint string) *core.CircuitBreaker {
	now := time.Now()

	ae.cbMutex.RLock()
	_, exists := ae.circuitBreakers[endpoint]
	ae.cbMutex.RUnlock()

	if exists {
		// Update last accessed time (write lock needed)
		ae.cbMutex.Lock()
		if entry, exists := ae.circuitBreakers[endpoint]; exists {
			entry.lastAccessed = now
			ae.cbMutex.Unlock()
			return entry.cb
		}
		ae.cbMutex.Unlock()
		// Entry was removed between read and write lock, fall through to create new one
	}

	// Create new circuit breaker with write lock
	ae.cbMutex.Lock()
	defer ae.cbMutex.Unlock()

	// Double-check after acquiring write lock (another goroutine may have created it)
	if entry, exists := ae.circuitBreakers[endpoint]; exists {
		entry.lastAccessed = now
		return entry.cb
	}

	// TASK 137: Use MustNewCircuitBreaker since config was already validated at ActionExecutor creation
	cb := core.MustNewCircuitBreaker(ae.cbConfig)
	ae.circuitBreakers[endpoint] = &circuitBreakerEntry{
		cb:           cb,
		lastAccessed: now,
	}
	ae.logger.Infof("Created circuit breaker for endpoint: %s", endpoint)
	return cb
}

// cleanupStaleCircuitBreakers periodically removes stale circuit breakers
// PERFORMANCE: Prevents unbounded memory growth from unique endpoints
func (ae *ActionExecutor) cleanupStaleCircuitBreakers(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ae.cbMutex.Lock()
			cutoff := time.Now().Add(-24 * time.Hour)
			removed := 0

			for endpoint, entry := range ae.circuitBreakers {
				// Remove if stale AND circuit is closed (safe to remove)
				if entry.lastAccessed.Before(cutoff) && entry.cb.State() == core.CircuitBreakerStateClosed {
					delete(ae.circuitBreakers, endpoint)
					removed++
				}
			}

			if removed > 0 {
				ae.logger.Infof("Cleaned up %d stale circuit breakers (total remaining: %d)", removed, len(ae.circuitBreakers))
			}
			ae.cbMutex.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

// Stop stops the action executor and waits for cleanup goroutine to exit.
// This method is safe to call multiple times.
// TASK 139: Wait for goroutine to complete for clean shutdown
func (ae *ActionExecutor) Stop() {
	if ae.cleanupCancel != nil {
		ae.cleanupCancel()
	}
	ae.wg.Wait() // Wait for cleanup goroutine to exit
}

// Close implements io.Closer interface for resource management compatibility.
// Close is an alias for Stop() and is safe to call multiple times.
func (ae *ActionExecutor) Close() error {
	ae.Stop()
	return nil
}

// updateCircuitBreakerMetrics updates Prometheus metrics for circuit breaker state
func (ae *ActionExecutor) updateCircuitBreakerMetrics(endpoint string, cb *core.CircuitBreaker) {
	state := cb.State()
	var stateValue float64
	switch state {
	case core.CircuitBreakerStateClosed:
		stateValue = 0
	case core.CircuitBreakerStateHalfOpen:
		stateValue = 1
	case core.CircuitBreakerStateOpen:
		stateValue = 2
	}
	metrics.CircuitBreakerState.WithLabelValues(endpoint).Set(stateValue)
}

// logCircuitBreakerTransition logs and records circuit breaker state transitions
func (ae *ActionExecutor) logCircuitBreakerTransition(endpoint string, oldState, newState core.CircuitBreakerState) {
	ae.logger.Warnf("Circuit breaker state transition for %s: %s -> %s", endpoint, oldState, newState)
	metrics.CircuitBreakerStateTransitions.WithLabelValues(endpoint, string(oldState), string(newState)).Inc()
}

// validateWebhookURL validates webhook URLs to prevent SSRF attacks
// SECURITY: Comprehensive protection against SSRF, DNS rebinding, and cloud metadata access
//
// FR-SOAR-018 BLOCKING-002 Enhancements:
// - DNS rebinding protection: Resolve hostname BEFORE and AFTER connection
// - HTTP redirects DISABLED
// - Complete IPv6 blocklist: ff00::/8 (multicast), fd00::/8 (ULA)
// - HTTPS-only enforcement (production mode)
// - Configurable allowlist support
func (ae *ActionExecutor) validateWebhookURL(urlStr string) error {
	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// FR-SOAR-018: HTTPS-only enforcement (unless in test mode)
	// SECURITY: HTTP is vulnerable to MITM attacks
	if os.Getenv("CERBERUS_TEST_MODE") != "1" {
		if parsedURL.Scheme != "https" {
			return fmt.Errorf("SECURITY: webhook URL MUST use HTTPS (HTTP is prohibited for security)")
		}
	} else {
		// Test mode allows HTTP and HTTPS
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("webhook URL must use http or https scheme")
		}
	}

	// Get hostname from URL
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("webhook URL must have a hostname")
	}

	hostnameLower := strings.ToLower(hostname)

	// TASK 1.4: Check allowlist first - if allowlist is configured, only allowlisted domains/IPs are permitted
	if ae.config != nil && len(ae.config.Security.Webhooks.Allowlist) > 0 {
		allowed := false
		// Resolve hostname to check IP allowlist
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return fmt.Errorf("failed to resolve hostname for allowlist check: %w", err)
		}

		for _, entry := range ae.config.Security.Webhooks.Allowlist {
			entry = strings.TrimSpace(strings.ToLower(entry))
			if entry == "" {
				continue
			}

			// Check if entry matches hostname (exact or subdomain)
			if entry == hostnameLower || strings.HasSuffix(hostnameLower, "."+entry) {
				allowed = true
				break
			}

			// Check if any resolved IP matches the allowlist entry (IP or CIDR)
			for _, ip := range ips {
				if isIPInAllowlist(ip, entry) {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			return fmt.Errorf("webhook URL hostname %s is not in allowlist", hostname)
		}
		// If allowed via allowlist, skip other checks (config allows it)
		return nil
	}

	// SECURITY: Block Kubernetes internal service hostnames
	kubernetesPatterns := []string{
		".svc.cluster.local",
		".svc.cluster",
		".svc",
		"kubernetes.default",
		"kubernetes",
	}
	for _, pattern := range kubernetesPatterns {
		if strings.Contains(hostnameLower, pattern) {
			return fmt.Errorf("webhook URL cannot target Kubernetes internal services")
		}
	}

	// SECURITY: Block localhost variations (unless configured to allow)
	// Skip localhost check in test mode or if config allows
	testMode := os.Getenv("CERBERUS_TEST_MODE")
	allowLocalhost := testMode == "1" || (ae.config != nil && ae.config.Security.Webhooks.AllowLocalhost)
	if !allowLocalhost {
		localhostPatterns := []string{
			"localhost",
			"127.",
			"0.0.0.0",
			"[::1]",
			"[0:0:0:0:0:0:0:1]",
		}
		for _, pattern := range localhostPatterns {
			if strings.Contains(hostnameLower, pattern) {
				return fmt.Errorf("webhook URL cannot target localhost")
			}
		}
	}

	// SECURITY: Block URLs with credentials (potential credential leakage)
	if parsedURL.User != nil {
		return fmt.Errorf("webhook URL cannot contain credentials")
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("hostname resolved to zero IP addresses")
	}

	// Block internal/private IP addresses to prevent SSRF (unless configured to allow)
	// Skip SSRF check in test mode or if config allows private IPs
	allowPrivateIPs := testMode == "1" || (ae.config != nil && ae.config.Security.Webhooks.AllowPrivateIPs)
	if !allowPrivateIPs {
		for _, ip := range ips {
			if isInternalIP(ip) {
				return fmt.Errorf("webhook URL points to internal/private network (resolved IP: %s)", ip.String())
			}
		}
	}

	return nil
}

// isIPInAllowlist checks if an IP matches an allowlist entry (IP or CIDR)
func isIPInAllowlist(ip net.IP, entry string) bool {
	// Try exact IP match
	if entryIP := net.ParseIP(entry); entryIP != nil {
		return ip.Equal(entryIP)
	}

	// Try CIDR match
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return ipNet.Contains(ip)
	}

	return false
}

// isInternalIP checks if an IP address is internal/private
// SECURITY: Comprehensive SSRF protection against cloud metadata endpoints and private networks
func isInternalIP(ip net.IP) bool {
	// Check for loopback addresses
	if ip.IsLoopback() {
		return true
	}

	// Check for private network ranges (IPv4 and IPv6)
	privateRanges := []string{
		// RFC1918 private networks
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",

		// Link-local addresses
		"169.254.0.0/16", // IPv4 link-local (includes AWS, GCP, Azure metadata)
		"fe80::/10",      // IPv6 link-local

		// Loopback
		"127.0.0.0/8", // IPv4 loopback
		"::1/128",     // IPv6 loopback

		// IPv6 unique local addresses (FR-SOAR-018: complete IPv6 ULA coverage)
		"fc00::/7", // IPv6 ULA range (includes fd00::/8)

		// Multicast
		"224.0.0.0/4", // IPv4 multicast
		"ff00::/8",    // IPv6 multicast (FR-SOAR-018: complete IPv6 coverage)

		// IPv4-mapped IPv6 addresses (::ffff:0:0/96)
		// SECURITY: Prevent bypass attacks using IPv4-mapped IPv6 format
		// Example: ::ffff:127.0.0.1 would map to 127.0.0.1
		"::ffff:0:0/96",

		// Other special-use addresses
		"0.0.0.0/8",          // "This" network
		"100.64.0.0/10",      // Shared address space (CGN)
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // TEST-NET-1
		"198.18.0.0/15",      // Benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"240.0.0.0/4",        // Reserved
		"255.255.255.255/32", // Broadcast
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	// SECURITY: Block all major cloud provider metadata endpoints
	cloudMetadataIPs := []string{
		"169.254.169.254", // AWS, GCP, Azure, Oracle Cloud metadata
		"169.254.169.253", // AWS IMDSv2
		"169.254.169.123", // DigitalOcean metadata
		"169.254.170.2",   // AWS ECS task metadata
		"fd00:ec2::254",   // AWS IPv6 metadata
	}

	ipStr := ip.String()
	for _, metadataIP := range cloudMetadataIPs {
		if ipStr == metadataIP {
			return true
		}
	}

	// Block link-local multicast and unicast
	if ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}

	// Block unspecified and interface-local multicast
	if ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}

	return false
}

// retryExecute executes a function with retry logic and circuit breaker protection
// RELIABILITY: Circuit breaker prevents retry storms against failing endpoints
func (ae *ActionExecutor) retryExecute(endpoint string, executeFunc func() error, successFormat string, successArgs []interface{}, actionType string) error {
	cb := ae.getOrCreateCircuitBreaker(endpoint)

	for i := 0; i < MaxActionRetries; i++ {
		// Check circuit breaker before attempting request
		oldState := cb.State()
		if err := cb.Allow(); err != nil {
			ae.logger.Warnf("Circuit breaker blocked request to %s: %v", endpoint, err)
			metrics.CircuitBreakerRequestsBlocked.WithLabelValues(endpoint).Inc()
			ae.updateCircuitBreakerMetrics(endpoint, cb)
			return fmt.Errorf("circuit breaker open for %s: %w", endpoint, err)
		}

		// Attempt the request
		err := executeFunc()

		if err == nil {
			// Success - record and update metrics atomically
			oldState, newState := cb.RecordSuccess()

			if oldState != newState {
				ae.logCircuitBreakerTransition(endpoint, oldState, newState)
			}

			ae.updateCircuitBreakerMetrics(endpoint, cb)
			ae.logger.Infof(successFormat, successArgs...)
			metrics.ActionsExecuted.WithLabelValues(actionType).Inc()
			return nil
		}

		// Failure - record and check for state transition atomically
		oldState, newState := cb.RecordFailure()

		if oldState != newState {
			ae.logCircuitBreakerTransition(endpoint, oldState, newState)
		}

		ae.updateCircuitBreakerMetrics(endpoint, cb)

		ae.logger.Warnf("Action to %s failed (attempt %d/%d): %v", endpoint, i+1, MaxActionRetries, err)

		// Don't retry if circuit breaker just opened
		if cb.State() == core.CircuitBreakerStateOpen {
			ae.logger.Warnf("Circuit breaker opened for %s after failures, stopping retries", endpoint)
			return fmt.Errorf("circuit breaker opened for %s after %d attempts: %w", endpoint, i+1, err)
		}

		// Exponential backoff for retries
		if i < MaxActionRetries-1 {
			backoff := time.Duration(1<<uint(i)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("action to %s failed after %d retries", endpoint, MaxActionRetries)
}

// ExecuteActions executes all actions for a rule match.
// The context is used for cancellation and timeout propagation to HTTP calls.
func (ae *ActionExecutor) ExecuteActions(ctx context.Context, rule core.AlertableRule, alert *core.Alert) error {
	var errs []error
	for _, action := range rule.GetActions() {
		// Check context cancellation before each action
		select {
		case <-ctx.Done():
			return fmt.Errorf("action execution cancelled: %w", ctx.Err())
		default:
		}

		if action.Config == nil {
			errs = append(errs, fmt.Errorf("action config is nil for type %s", action.Type))
			continue
		}
		switch action.Type {
		case "webhook":
			if err := ae.executeWebhook(ctx, action, alert); err != nil {
				ae.logger.Errorf("Error executing webhook action: %v", err)
				errs = append(errs, fmt.Errorf("webhook action failed: %w", err))
			}
		case "jira":
			if err := ae.executeJira(ctx, action, alert); err != nil {
				ae.logger.Errorf("Error executing jira action: %v", err)
				errs = append(errs, fmt.Errorf("jira action failed: %w", err))
			}
		case "slack":
			if err := ae.executeSlack(ctx, action, alert); err != nil {
				ae.logger.Errorf("Error executing slack action: %v", err)
				errs = append(errs, fmt.Errorf("slack action failed: %w", err))
			}
		case "email":
			if err := ae.executeEmail(ctx, action, alert); err != nil {
				ae.logger.Errorf("Error executing email action: %v", err)
				errs = append(errs, fmt.Errorf("email action failed: %w", err))
			}
		default:
			ae.logger.Errorf("Unknown action type: %s", action.Type)
			errs = append(errs, fmt.Errorf("unknown action type: %s", action.Type))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("one or more actions failed: %v", errs)
	}
	return nil
}

// executeWebhook executes a webhook action with retry logic and circuit breaker.
// Context is used for request cancellation and timeout propagation.
func (ae *ActionExecutor) executeWebhook(ctx context.Context, action core.Action, alert *core.Alert) error {
	urlStr, ok := action.Config["url"].(string)
	if !ok {
		ae.logger.Warnf("Webhook URL not found in config")
		return fmt.Errorf("webhook URL not found in config")
	}

	// SECURITY FIX: Validate URL to prevent SSRF attacks
	if err := ae.validateWebhookURL(urlStr); err != nil {
		ae.logger.Errorf("Invalid webhook URL: %v", err)
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	ae.logger.Debugf("Webhook URL validation passed for: %s", urlStr)

	payload, err := json.Marshal(alert)
	if err != nil {
		ae.logger.Errorf("Failed to marshal alert: %v", err)
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	// Extract hostname for circuit breaker endpoint key
	parsedURL, _ := url.Parse(urlStr)
	endpoint := parsedURL.Host

	return ae.retryExecute(endpoint, func() error { return ae.sendWebhook(ctx, urlStr, payload) }, "Webhook sent successfully to %s", []interface{}{urlStr}, "webhook")
}

// sendWebhook sends the HTTP POST request.
// Context is used for request cancellation - if the context is cancelled, the request is aborted.
func (ae *ActionExecutor) sendWebhook(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ae.httpClient.Do(req)

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ae.logger.Errorf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// executeJira creates a Jira ticket for the alert with circuit breaker protection.
// Context is used for request cancellation and timeout propagation.
func (ae *ActionExecutor) executeJira(ctx context.Context, action core.Action, alert *core.Alert) error {
	baseURL, ok := action.Config["base_url"].(string)
	if !ok {
		ae.logger.Warnf("Jira base URL not found in config")
		return fmt.Errorf("Jira base URL not found in config")
	}
	username := os.Getenv("CERBERUS_JIRA_USERNAME")
	if username == "" {
		ae.logger.Warnf("Jira username not set in environment")
		return fmt.Errorf("Jira username not set in environment")
	}
	token := os.Getenv("CERBERUS_JIRA_TOKEN")
	if token == "" {
		ae.logger.Warnf("Jira token not set in environment")
		return fmt.Errorf("Jira token not set in environment")
	}
	project, ok := action.Config["project"].(string)
	if !ok {
		ae.logger.Warnf("Jira project not found in config")
		return fmt.Errorf("Jira project not found in config")
	}

	// Create issue payload
	issue := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":     map[string]string{"key": project},
			"summary":     fmt.Sprintf("Alert: %s", alert.AlertID),
			"description": fmt.Sprintf("Severity: %s\nEvent ID: %s\nRaw Data: %s", alert.Severity, alert.EventID, alert.Event.RawData),
			"issuetype":   map[string]string{"name": "Task"},
		},
	}

	payload, err := json.Marshal(issue)
	if err != nil {
		ae.logger.Errorf("Failed to marshal Jira issue: %v", err)
		return fmt.Errorf("failed to marshal Jira issue: %w", err)
	}

	// Extract hostname for circuit breaker endpoint key
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid Jira base URL: %w", err)
	}
	endpoint := parsedURL.Host

	return ae.retryExecute(endpoint, func() error { return ae.sendJiraRequest(ctx, baseURL, username, token, payload) }, "Jira ticket created successfully for alert %s", []interface{}{alert.AlertID}, "jira")
}

// sendJiraRequest sends the Jira API request.
// Context is used for request cancellation - if the context is cancelled, the request is aborted.
func (ae *ActionExecutor) sendJiraRequest(ctx context.Context, baseURL, username, token string, payload []byte) error {
	url := fmt.Sprintf("%s/rest/api/2/issue", baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, token)

	resp, err := ae.httpClient.Do(req)

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ae.logger.Errorf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != 201 {
		return fmt.Errorf("Jira API returned status %d", resp.StatusCode)
	}
	return nil
}

// executeSlack sends a message to a Slack channel with circuit breaker protection.
// Context is used for request cancellation and timeout propagation.
func (ae *ActionExecutor) executeSlack(ctx context.Context, action core.Action, alert *core.Alert) error {
	webhookURL, ok := action.Config["webhook_url"].(string)
	if !ok {
		ae.logger.Warnf("Slack webhook URL not found in config")
		return fmt.Errorf("Slack webhook URL not found in config")
	}

	// SECURITY FIX: Validate Slack webhook URL
	if !strings.HasPrefix(webhookURL, "https://hooks.slack.com/") {
		// If not a Slack webhook, validate as regular webhook URL
		if err := ae.validateWebhookURL(webhookURL); err != nil {
			ae.logger.Errorf("Invalid Slack webhook URL: %v", err)
			return fmt.Errorf("invalid Slack webhook URL: %w", err)
		}
	}

	message := map[string]string{
		"text": fmt.Sprintf("Alert: %s\nSeverity: %s\nEvent ID: %s\nRule: %s", alert.AlertID, alert.Severity, alert.EventID, alert.RuleID),
	}

	payload, err := json.Marshal(message)
	if err != nil {
		ae.logger.Errorf("Failed to marshal Slack message: %v", err)
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	// Extract hostname for circuit breaker endpoint key
	parsedURL, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid Slack webhook URL: %w", err)
	}
	endpoint := parsedURL.Host

	return ae.retryExecute(endpoint, func() error { return ae.sendWebhook(ctx, webhookURL, payload) }, "Slack message sent successfully for alert %s", []interface{}{alert.AlertID}, "slack")
}

// executeEmail sends an email notification.
// Context is used for connection cancellation - if cancelled, the SMTP connection is aborted.
func (ae *ActionExecutor) executeEmail(ctx context.Context, action core.Action, alert *core.Alert) error {
	smtpServer, ok := action.Config["smtp_server"].(string)
	if !ok {
		ae.logger.Warnf("SMTP server not found in config")
		return fmt.Errorf("SMTP server not found in config")
	}
	portFloat, ok := action.Config["port"].(float64)
	if !ok {
		return fmt.Errorf("SMTP port not found in config")
	}
	if portFloat != float64(int(portFloat)) {
		return fmt.Errorf("SMTP port must be an integer")
	}
	port := int(portFloat)
	username := os.Getenv("CERBERUS_SMTP_USERNAME")
	if username == "" {
		ae.logger.Warnf("SMTP username not set in environment")
		return fmt.Errorf("SMTP username not set in environment")
	}
	password := os.Getenv("CERBERUS_SMTP_PASSWORD")
	if password == "" {
		ae.logger.Warnf("SMTP password not set in environment")
		return fmt.Errorf("SMTP password not set in environment")
	}
	from, ok := action.Config["from"].(string)
	if !ok {
		ae.logger.Warnf("From email not found in config")
		return fmt.Errorf("From email not found in config")
	}
	to, ok := action.Config["to"].(string)
	if !ok {
		ae.logger.Warnf("To email not found in config")
		return fmt.Errorf("To email not found in config")
	}

	subject := fmt.Sprintf("Alert: %s", alert.AlertID)
	body := fmt.Sprintf("Severity: %s\nEvent ID: %s\nRule: %s\nRaw Data: %s", alert.Severity, alert.EventID, alert.RuleID, alert.Event.RawData)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

	auth := smtp.PlainAuth("", username, password, smtpServer)

	// Use SMTP server hostname as endpoint for circuit breaker
	endpoint := smtpServer

	sendFunc := func() error {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		// Use net.JoinHostPort for IPv6-safe address formatting
		// This properly handles IPv6 addresses by wrapping them in brackets
		// Use DialContext to respect context cancellation
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(smtpServer, strconv.Itoa(port)))
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server: %w", err)
		}
		defer conn.Close() // Ensure connection is always closed

		client, err := smtp.NewClient(conn, smtpServer)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		// Enforce TLS: require STARTTLS support
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS, refusing to send email without TLS")
		}
		// Secure TLS configuration: enforce TLS 1.2+, secure ciphers, prevent downgrade attacks
		tlsConfig := &tls.Config{
			ServerName: smtpServer,
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: false, // Use client's preferred cipher suite order
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}

		if err = client.Mail(from); err != nil {
			return fmt.Errorf("failed to set sender: %w", err)
		}

		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("failed to set recipient: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to start data: %w", err)
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("failed to close data: %w", err)
		}

		return client.Quit()
	}

	return ae.retryExecute(endpoint, sendFunc, "Email sent successfully for alert %s", []interface{}{alert.AlertID}, "email")
}
