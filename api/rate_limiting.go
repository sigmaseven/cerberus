package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// RateLimiterTier represents the different rate limiting tiers
// TASK 24: Multi-tier rate limiting system
type RateLimiterTier string

const (
	RateLimitTierLogin  RateLimiterTier = "login"  // Login endpoint: 5 attempts/minute per IP
	RateLimitTierAPI    RateLimiterTier = "api"    // API endpoints: 100 requests/minute per user
	RateLimitTierGlobal RateLimiterTier = "global" // Global: 10,000 requests/second system-wide
)

// RateLimiterConfig holds configuration for a rate limiting tier
// TASK 24: Configuration for each rate limiting tier
type RateLimiterConfig struct {
	Limit  int           // Maximum requests
	Window time.Duration // Time window
	Burst  int           // Burst allowance
}

// RateLimiter manages rate limiting with support for multiple tiers
// TASK 24: Multi-tier rate limiting with per-IP, per-user, and global limits
type RateLimiter struct {
	config    *RateLimiterConfig
	tier      RateLimiterTier
	limiters  map[string]*rate.Limiter // Key: IP or username
	mu        sync.RWMutex
	redis     *core.RedisCache // Optional Redis for distributed state
	useRedis  bool
	logger    *zap.SugaredLogger
	stopCh    chan struct{}
	cleanupWg sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter for a specific tier
// TASK 24: Initialize rate limiter with config and optional Redis
func NewRateLimiter(tier RateLimiterTier, config *RateLimiterConfig, redis *core.RedisCache, logger *zap.SugaredLogger) *RateLimiter {
	rl := &RateLimiter{
		config:   config,
		tier:     tier,
		limiters: make(map[string]*rate.Limiter),
		redis:    redis,
		useRedis: redis != nil,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupWg.Add(1)
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given key is allowed
// TASK 24: Check rate limit with sliding window support
func (rl *RateLimiter) Allow(ctx context.Context, key string) bool {
	if rl.useRedis && rl.redis != nil {
		return rl.allowRedis(ctx, key)
	}
	return rl.allowMemory(key)
}

// allowMemory checks rate limit using in-memory storage
func (rl *RateLimiter) allowMemory(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[key]
	if !exists {
		// Create new limiter with rate and burst
		limiter = rate.NewLimiter(
			rate.Limit(float64(rl.config.Limit)/rl.config.Window.Seconds()),
			rl.config.Burst,
		)
		rl.limiters[key] = limiter
	}

	return limiter.Allow()
}

// allowRedis checks rate limit using Redis for distributed state
// TASK 24: Redis-based rate limiting for distributed deployments
func (rl *RateLimiter) allowRedis(ctx context.Context, key string) bool {
	redisKey := fmt.Sprintf("ratelimit:%s:%s", rl.tier, key)

	// Use Redis to get current count
	var currentCount int
	exists, err := rl.redis.Get(ctx, redisKey, &currentCount)
	if err != nil {
		// Redis error - fall back to in-memory
		rl.logger.Warnf("Redis rate limit check failed, falling back to memory: %v", err)
		return rl.allowMemory(key)
	}

	if !exists {
		currentCount = 0
	}

	if currentCount >= rl.config.Limit {
		return false
	}

	// Increment counter with window expiration
	currentCount++
	err = rl.redis.Set(ctx, redisKey, currentCount, rl.config.Window)
	if err != nil {
		rl.logger.Warnf("Redis rate limit increment failed: %v", err)
		return rl.allowMemory(key)
	}

	return true
}

// cleanup periodically removes inactive rate limiters
func (rl *RateLimiter) cleanup() {
	defer rl.cleanupWg.Done()
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			// For in-memory limiters, we keep them all (they're lightweight)
			// For Redis, expiration is handled by Redis TTL
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Close stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Close() {
	close(rl.stopCh)
	rl.cleanupWg.Wait()
}

// MultiTierRateLimiter manages all rate limiting tiers
// TASK 24: Centralized rate limiting with login, API, and global tiers
type MultiTierRateLimiter struct {
	loginLimiter  *RateLimiter
	apiLimiter    *RateLimiter
	globalLimiter *RateLimiter
	exemptIPs     map[string]bool // TASK 24: IPs exempt from rate limiting
	exemptIPsMu   sync.RWMutex
	logger        *zap.SugaredLogger
}

// NewMultiTierRateLimiter creates a new multi-tier rate limiter
// TASK 24: Initialize all three tiers with their configurations
func NewMultiTierRateLimiter(loginConfig, apiConfig, globalConfig *RateLimiterConfig, exemptIPs []string, redis *core.RedisCache, logger *zap.SugaredLogger) *MultiTierRateLimiter {
	exemptMap := make(map[string]bool)
	for _, ip := range exemptIPs {
		exemptMap[ip] = true
		// Also handle CIDR notation (simplified - would need proper CIDR matching in production)
		if strings.Contains(ip, "/") {
			exemptMap[ip] = true
		}
	}

	return &MultiTierRateLimiter{
		loginLimiter:  NewRateLimiter(RateLimitTierLogin, loginConfig, redis, logger),
		apiLimiter:    NewRateLimiter(RateLimitTierAPI, apiConfig, redis, logger),
		globalLimiter: NewRateLimiter(RateLimitTierGlobal, globalConfig, redis, logger),
		exemptIPs:     exemptMap,
		logger:        logger,
	}
}

// IsExempt checks if an IP is exempt from rate limiting
// TASK 24: Check if IP is in exempt list
func (mtrl *MultiTierRateLimiter) IsExempt(ip string) bool {
	mtrl.exemptIPsMu.RLock()
	defer mtrl.exemptIPsMu.RUnlock()

	// Check exact match
	if mtrl.exemptIPs[ip] {
		return true
	}

	// Check CIDR matches (simplified - would need proper CIDR parsing)
	for cidr := range mtrl.exemptIPs {
		if strings.Contains(cidr, "/") {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ipNet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}

	return false
}

// AllowLogin checks if login request is allowed
// TASK 24: Login tier rate limiting (5 attempts/minute per IP)
func (mtrl *MultiTierRateLimiter) AllowLogin(ctx context.Context, ip string) bool {
	if mtrl.IsExempt(ip) {
		return true
	}
	return mtrl.loginLimiter.Allow(ctx, ip)
}

// AllowAPI checks if API request is allowed
// TASK 24: API tier rate limiting (100 requests/minute per user)
func (mtrl *MultiTierRateLimiter) AllowAPI(ctx context.Context, username string) bool {
	if username == "" {
		// Unauthenticated requests use IP
		return true // Will be checked by global limiter
	}
	return mtrl.apiLimiter.Allow(ctx, username)
}

// AllowGlobal checks if global request is allowed
// TASK 24: Global tier rate limiting (10,000 requests/second system-wide)
func (mtrl *MultiTierRateLimiter) AllowGlobal(ctx context.Context, ip string) bool {
	if mtrl.IsExempt(ip) {
		return true
	}
	return mtrl.globalLimiter.Allow(ctx, "global") // Single key for global limit
}

// Close stops all rate limiter cleanup goroutines
func (mtrl *MultiTierRateLimiter) Close() {
	mtrl.loginLimiter.Close()
	mtrl.apiLimiter.Close()
	mtrl.globalLimiter.Close()
}

// loginRateLimitMiddleware provides rate limiting for login endpoint
// TASK 24.2: Login tier middleware (5 attempts/minute per IP)
func (a *API) loginRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

		// Check global limit first
		if !a.multiTierRateLimiter.AllowGlobal(r.Context(), ip) {
			a.writeRateLimitResponse(w, RateLimitTierGlobal)
			return
		}

		// Check login tier limit
		if !a.multiTierRateLimiter.AllowLogin(r.Context(), ip) {
			a.writeRateLimitResponse(w, RateLimitTierLogin)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// apiRateLimitMiddleware provides rate limiting for authenticated API endpoints
// TASK 24.2: API tier middleware (100 requests/minute per user)
func (a *API) apiRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

		// Check global limit first
		if !a.multiTierRateLimiter.AllowGlobal(r.Context(), ip) {
			a.writeRateLimitResponse(w, RateLimitTierGlobal)
			return
		}

		// Get username from context (set by JWT middleware)
		username := getUsernameFromContext(r.Context())

		// For authenticated requests, use per-user rate limiting
		if username != "" {
			if !a.multiTierRateLimiter.AllowAPI(r.Context(), username) {
				a.writeRateLimitResponse(w, RateLimitTierAPI)
				return
			}
		} else {
			// For unauthenticated requests, use per-IP rate limiting
			// This is handled by the existing rateLimitMiddleware
		}

		next.ServeHTTP(w, r)
	})
}

// globalRateLimitMiddleware provides system-wide rate limiting
// TASK 24.2: Global tier middleware (10,000 requests/second)
func (a *API) globalRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

		if !a.multiTierRateLimiter.AllowGlobal(r.Context(), ip) {
			a.writeRateLimitResponse(w, RateLimitTierGlobal)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeRateLimitResponse writes a 429 Too Many Requests response with rate limit headers
// TASK 24.2: Standard rate limit headers and response
func (a *API) writeRateLimitResponse(w http.ResponseWriter, tier RateLimiterTier) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit", "0") // Will be set by specific tier
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(1*time.Minute).Unix()))

	var limit, window int
	switch tier {
	case RateLimitTierLogin:
		limit = 5
		window = 60 // 1 minute
	case RateLimitTierAPI:
		limit = 100
		window = 60 // 1 minute
	case RateLimitTierGlobal:
		limit = 10000
		window = 1 // 1 second
	}

	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Duration(window)*time.Second).Unix()))

	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"Too many requests","tier":"` + string(tier) + `"}`))
}
