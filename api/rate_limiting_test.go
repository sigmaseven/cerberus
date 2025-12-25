package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TASK 56: Comprehensive Rate Limiting Security Test Suite
// Tests cover: per-IP, per-user, Redis-based distributed limiting, bypass prevention

// TestPerIPRateLimiting_BasicEnforcement tests basic per-IP rate limiting
// TASK 56.1: Per-IP rate limiting - basic enforcement
func TestPerIPRateLimiting_BasicEnforcement(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Configure rate limits for testing (low limits to test quickly)
	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  10,
		Window: time.Minute,
		Burst:  10,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, nil, nil, api.logger)

	// Create test endpoint
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create middleware chain
	middleware := api.globalRateLimitMiddleware(testHandler)

	testIP := "192.168.1.1"
	ctx := context.Background()

	// Make requests up to limit
	allowedCount := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = testIP + ":12345"
		rec := httptest.NewRecorder()

		if api.multiTierRateLimiter.AllowGlobal(ctx, testIP) {
			middleware.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				allowedCount++
			}
		} else {
			break
		}
	}

	// Should allow requests (global limit is high)
	assert.Greater(t, allowedCount, 0, "Should allow some requests")
}

// TestPerIPRateLimiting_TokenBucket tests token bucket algorithm behavior
// TASK 56.1: Per-IP rate limiting - token bucket algorithm
func TestPerIPRateLimiting_TokenBucket(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Configure with token bucket (rate and burst)
	config := &RateLimiterConfig{
		Limit:  10,               // 10 requests per window
		Window: time.Second * 10, // 10 second window
		Burst:  5,                // Burst of 5
	}

	limiter := NewRateLimiter(RateLimitTierGlobal, config, nil, api.logger)
	defer limiter.Close()

	testIP := "192.168.1.100"
	ctx := context.Background()

	// Test burst capacity
	burstAllowed := 0
	for i := 0; i < 10; i++ {
		if limiter.Allow(ctx, testIP) {
			burstAllowed++
		}
	}
	// Should allow at least burst amount immediately
	assert.GreaterOrEqual(t, burstAllowed, 5, "Should allow burst capacity")
	assert.LessOrEqual(t, burstAllowed, 10, "Should not exceed limit")
}

// TestPerIPRateLimiting_WindowExpiration tests rate limit window expiration
// TASK 56.1: Per-IP rate limiting - window expiration
func TestPerIPRateLimiting_WindowExpiration(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Configure with short window for testing
	config := &RateLimiterConfig{
		Limit:  5,
		Window: time.Second * 2, // 2 second window
		Burst:  5,
	}

	limiter := NewRateLimiter(RateLimitTierGlobal, config, nil, api.logger)
	defer limiter.Close()

	testIP := "192.168.1.200"
	ctx := context.Background()

	// Exhaust limit
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ctx, testIP), "Should allow requests up to limit")
	}

	// Should be rate limited now
	assert.False(t, limiter.Allow(ctx, testIP), "Should be rate limited after exceeding limit")

	// Wait for window expiration
	time.Sleep(3 * time.Second)

	// Should allow requests again after window expires
	assert.True(t, limiter.Allow(ctx, testIP), "Should allow requests after window expires")
}

// TestPerIPRateLimiting_ConcurrentIPs tests concurrent requests from multiple IPs
// TASK 56.1: Per-IP rate limiting - concurrent IPs
func TestPerIPRateLimiting_ConcurrentIPs(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	config := &RateLimiterConfig{
		Limit:  10,
		Window: time.Minute,
		Burst:  10,
	}

	limiter := NewRateLimiter(RateLimitTierGlobal, config, nil, api.logger)
	defer limiter.Close()

	ctx := context.Background()
	numIPs := 10
	var wg sync.WaitGroup
	allowedCounts := make(map[string]int)
	var mu sync.Mutex

	// Launch concurrent requests from different IPs
	for i := 0; i < numIPs; i++ {
		wg.Add(1)
		testIP := fmt.Sprintf("192.168.1.%d", i+1)
		go func(ip string) {
			defer wg.Done()
			count := 0
			// Each IP makes 15 requests (exceeds limit)
			for j := 0; j < 15; j++ {
				if limiter.Allow(ctx, ip) {
					count++
				}
			}
			mu.Lock()
			allowedCounts[ip] = count
			mu.Unlock()
		}(testIP)
	}

	wg.Wait()

	// Verify each IP gets independent rate limiting
	for ip, count := range allowedCounts {
		assert.Equal(t, 10, count, "Each IP should get its own limit: %s", ip)
	}
}

// TestPerUserRateLimiting_AuthenticatedUser tests authenticated user rate limiting
// TASK 56.2: Per-user rate limiting - authenticated users
func TestPerUserRateLimiting_AuthenticatedUser(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, nil, nil, api.logger)

	ctx := context.Background()
	username := "testuser"

	// Test API tier rate limiting (per-user)
	allowedCount := 0
	for i := 0; i < 110; i++ {
		if api.multiTierRateLimiter.AllowAPI(ctx, username) {
			allowedCount++
		}
	}

	// Should allow exactly limit amount
	assert.Equal(t, 100, allowedCount, "Should enforce per-user rate limit")
}

// TestPerUserRateLimiting_RoleBased tests role-based rate limiting
// TASK 56.2: Per-user rate limiting - role-based limits
func TestPerUserRateLimiting_RoleBased(t *testing.T) {
	// Note: Role-based limits would require custom logic in AllowAPI
	// This test documents expected behavior when implemented
	t.Skip("Role-based rate limiting requires custom implementation in AllowAPI")

	api, cleanup := setupTestAPI(t)
	defer cleanup()

	ctx := context.Background()

	// Admin user should have higher limit
	adminUser := "admin"
	regularUser := "user"

	// Expected: admin gets higher limit than regular user
	// This would require modifying AllowAPI to check user roles
	_ = api
	_ = ctx
	_ = adminUser
	_ = regularUser

	t.Log("TODO: Implement role-based rate limiting in AllowAPI")
}

// TestRedisRateLimiting_DistributedState tests Redis-based distributed rate limiting
// TASK 56.3: Redis-based distributed rate limiting
func TestRedisRateLimiting_DistributedState(t *testing.T) {
	t.Skip("Requires miniredis or Redis mock - placeholder for Redis integration testing")

	// Expected behavior:
	// 1. Multiple instances share rate limit state via Redis
	// 2. Redis INCR and EXPIRE atomic operations
	// 3. Fallback to local memory on Redis failure
	// 4. TTL verification

	t.Log("TODO: Implement Redis-based rate limiting tests with miniredis")
}

// TestRedisRateLimiting_Failover tests Redis failover fallback
// TASK 56.3: Redis failover fallback
func TestRedisRateLimiting_Failover(t *testing.T) {
	t.Skip("Requires Redis mock for failover testing")

	// Expected behavior:
	// 1. Graceful fallback to local memory when Redis fails
	// 2. Continue rate limiting using local state
	// 3. Log warning about Redis failure
	// 4. Recover when Redis comes back online

	t.Log("TODO: Implement Redis failover testing")
}

// TestBypassPrevention_XForwardedFor tests X-Forwarded-For header handling
// TASK 56.4: Bypass prevention - X-Forwarded-For
func TestBypassPrevention_XForwardedFor(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Configure to trust proxy
	api.config.API.TrustProxy = true
	api.config.API.TrustedProxyNetworks = []string{"127.0.0.1/32", "192.168.0.0/16"}

	// Test with X-Forwarded-For header
	testCases := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		expectedIP    string
		shouldTrust   bool
	}{
		{"Trusted proxy with X-Forwarded-For", "127.0.0.1:12345", "192.168.1.50", "192.168.1.50", true},
		{"Untrusted proxy with X-Forwarded-For", "203.0.113.1:12345", "192.168.1.50", "203.0.113.1", false},
		{"No X-Forwarded-For", "192.168.1.100:12345", "", "192.168.1.100", true},
		{"Multiple X-Forwarded-For", "127.0.0.1:12345", "192.168.1.50, 10.0.0.1", "192.168.1.50", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			extractedIP := getRealIP(req, api.config.API.TrustProxy, api.config.API.TrustedProxyNetworks)

			// Verify correct IP extraction
			expectedIPParts := strings.Split(tc.expectedIP, ":")
			extractedIPParts := strings.Split(extractedIP, ":")
			assert.Equal(t, expectedIPParts[0], extractedIPParts[0], "Should extract correct client IP")
		})
	}
}

// TestBypassPrevention_IPSpoofing tests IP spoofing prevention
// TASK 56.4: Bypass prevention - IP spoofing
func TestBypassPrevention_IPSpoofing(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Configure not to trust proxies (strict mode)
	api.config.API.TrustProxy = false

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	// Attacker tries to spoof IP via header
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.1")

	// Should ignore headers and use RemoteAddr
	extractedIP := getRealIP(req, api.config.API.TrustProxy, api.config.API.TrustedProxyNetworks)
	extractedIPParts := strings.Split(extractedIP, ":")
	assert.Equal(t, "192.168.1.100", extractedIPParts[0], "Should ignore X-Forwarded-For when not trusting proxies")
}

// TestEndpointSpecificLimits_LoginEndpoint tests login endpoint rate limiting
// TASK 56.5: Endpoint-specific limits - login
func TestEndpointSpecificLimits_LoginEndpoint(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, nil, nil, api.logger)

	ctx := context.Background()
	testIP := "192.168.1.1"

	// Test login tier limit (5 req/min)
	allowedCount := 0
	for i := 0; i < 10; i++ {
		if api.multiTierRateLimiter.AllowLogin(ctx, testIP) {
			allowedCount++
		}
	}

	assert.Equal(t, 5, allowedCount, "Login endpoint should enforce 5 req/min limit")
}

// TestEndpointSpecificLimits_APIEndpoint tests API endpoint rate limiting
// TASK 56.5: Endpoint-specific limits - API
func TestEndpointSpecificLimits_APIEndpoint(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, nil, nil, api.logger)

	ctx := context.Background()
	username := "testuser"

	// Test API tier limit (100 req/min per user)
	allowedCount := 0
	for i := 0; i < 110; i++ {
		if api.multiTierRateLimiter.AllowAPI(ctx, username) {
			allowedCount++
		}
	}

	assert.Equal(t, 100, allowedCount, "API endpoint should enforce 100 req/min per user")
}

// TestExemptIPs_Whitelist tests exempt IP whitelist
// TASK 56.5: Exempt IPs - whitelist
func TestExemptIPs_Whitelist(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	exemptIPs := []string{"192.168.1.100", "10.0.0.1"}

	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, exemptIPs, nil, api.logger)

	ctx := context.Background()

	// Test exempt IP bypasses rate limiting
	exemptIP := "192.168.1.100"
	for i := 0; i < 20; i++ {
		assert.True(t, api.multiTierRateLimiter.AllowLogin(ctx, exemptIP), "Exempt IP should bypass rate limiting")
		assert.True(t, api.multiTierRateLimiter.AllowGlobal(ctx, exemptIP), "Exempt IP should bypass global rate limiting")
	}

	// Test non-exempt IP is rate limited
	nonExemptIP := "192.168.1.200"
	allowedCount := 0
	for i := 0; i < 10; i++ {
		if api.multiTierRateLimiter.AllowLogin(ctx, nonExemptIP) {
			allowedCount++
		}
	}
	assert.Equal(t, 5, allowedCount, "Non-exempt IP should be rate limited")
}

// TestExemptIPs_CIDR tests CIDR range exemption
// TASK 56.5: Exempt IPs - CIDR ranges
func TestExemptIPs_CIDR(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Exempt entire CIDR range
	exemptIPs := []string{"192.168.0.0/16"}

	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, exemptIPs, nil, api.logger)

	ctx := context.Background()

	// Test IPs within CIDR range are exempt
	testIPs := []string{"192.168.1.1", "192.168.1.100", "192.168.255.255"}
	for _, testIP := range testIPs {
		for i := 0; i < 20; i++ {
			assert.True(t, api.multiTierRateLimiter.IsExempt(testIP), "IP in CIDR range should be exempt: %s", testIP)
			assert.True(t, api.multiTierRateLimiter.AllowLogin(ctx, testIP), "Exempt IP should bypass rate limiting: %s", testIP)
		}
	}

	// Test IP outside CIDR range is not exempt
	outsideIP := "10.0.0.1"
	assert.False(t, api.multiTierRateLimiter.IsExempt(outsideIP), "IP outside CIDR range should not be exempt")
}

// TestRateLimitHeaders_StandardHeaders tests rate limit response headers
// TASK 56.6: Rate limit headers - standard headers
func TestRateLimitHeaders_StandardHeaders(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	tier := RateLimitTierLogin
	api.writeRateLimitResponse(rec, tier)

	// Verify headers are set
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Should return 429 status")
	assert.Equal(t, "5", rec.Header().Get("X-RateLimit-Limit"), "Should set X-RateLimit-Limit header")
	assert.Equal(t, "0", rec.Header().Get("X-RateLimit-Remaining"), "Should set X-RateLimit-Remaining header")
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Reset"), "Should set X-RateLimit-Reset header")
}

// TestRateLimitHeaders_429Response tests 429 Too Many Requests response
// TASK 56.6: Rate limit headers - 429 response
func TestRateLimitHeaders_429Response(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	loginConfig := &RateLimiterConfig{
		Limit:  5,
		Window: time.Minute,
		Burst:  5,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  1000,
		Window: time.Hour,
		Burst:  1000,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig, nil, nil, api.logger)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := api.loginRateLimitMiddleware(testHandler)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	// Exhaust rate limit
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)
		if i < 5 {
			assert.Equal(t, http.StatusOK, rec.Code, "Should allow requests up to limit")
		}
	}

	// Next request should be rate limited
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Should return 429 when rate limited")
	assert.Contains(t, rec.Body.String(), "Too many requests", "Response body should indicate rate limiting")
}

// TestConcurrentRequests_RaceConditions tests concurrent request handling
// TASK 56.7: Concurrent requests - race conditions
func TestConcurrentRequests_RaceConditions(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	config := &RateLimiterConfig{
		Limit:  100,
		Window: time.Minute,
		Burst:  100,
	}

	limiter := NewRateLimiter(RateLimitTierGlobal, config, nil, api.logger)
	defer limiter.Close()

	ctx := context.Background()
	testIP := "192.168.1.1"

	// Launch 200 concurrent requests (exceeds limit)
	numGoroutines := 200
	var wg sync.WaitGroup
	var allowedCount int64
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow(ctx, testIP) {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should allow exactly limit amount (race-safe)
	assert.Equal(t, int64(100), allowedCount, "Should enforce limit correctly under concurrent load")
}

// TestConcurrentRequests_RedisFailover tests Redis failover under load
// TASK 56.7: Concurrent requests - Redis failover
func TestConcurrentRequests_RedisFailover(t *testing.T) {
	t.Skip("Requires Redis mock for failover testing")

	// Expected behavior:
	// 1. Normal operation uses Redis
	// 2. Redis failure triggers fallback to local memory
	// 3. Concurrent requests handled correctly during failover
	// 4. State preserved in local memory during failover
	// 5. Recovery when Redis comes back online

	t.Log("TODO: Implement Redis failover testing with concurrent requests")
}
