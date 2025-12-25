package api

import (
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// rateLimitMiddleware provides rate limiting per IP
func (a *API) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.rateLimitersMu.Lock()
		entry, exists := a.rateLimiters[ip]
		if !exists {
			entry = &rateLimiterEntry{
				limiter:  rate.NewLimiter(rate.Limit(a.config.API.RateLimit.RequestsPerSecond), a.config.API.RateLimit.Burst),
				lastSeen: time.Now(),
			}
			a.rateLimiters[ip] = entry
		} else {
			entry.lastSeen = time.Now()
		}
		// Capture limiter reference while holding lock to prevent race condition
		limiter := entry.limiter
		a.rateLimitersMu.Unlock()

		// Use captured reference (safe from race with cleanup goroutine)
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanupRateLimiters periodically removes inactive rate limiters and auth failures to prevent memory leaks
func (a *API) cleanupRateLimiters() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.rateLimitersMu.Lock()
			for ip, entry := range a.rateLimiters {
				if time.Since(entry.lastSeen) > 1*time.Hour {
					delete(a.rateLimiters, ip)
				}
			}
			a.rateLimitersMu.Unlock()

			// SECURITY FIX: This cleanup is now handled in auth.go with the AuthManager
			// to prevent race conditions with the order tracking slices
			// The authManager handles its own cleanup via cleanupAuthFailures()
		case <-a.stopCh:
			return
		}
	}
}

// corsMiddleware adds CORS headers
func (a *API) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// SECURITY FIX: Only set CORS headers if origin is explicitly allowed
		// This prevents wildcard CORS attacks and ensures strict origin checking
		originAllowed := false
		for _, allowed := range a.config.API.AllowedOrigins {
			if origin == allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				originAllowed = true
				break
			}
		}

		// Only set other CORS headers if origin was explicitly allowed
		if originAllowed {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Add HSTS if TLS is enabled
		if a.config.API.TLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
