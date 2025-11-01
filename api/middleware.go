package api

import (
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// rateLimitMiddleware provides rate limiting per IP
func (a *API) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy)
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

			a.authFailuresMu.Lock()
			for ip, entry := range a.authFailures {
				if time.Since(entry.lastFail) > 1*time.Hour {
					delete(a.authFailures, ip)
				}
			}
			a.authFailuresMu.Unlock()
		case <-a.stopCh:
			return
		}
	}
}

// corsMiddleware adds CORS headers
func (a *API) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		for _, allowed := range a.config.API.AllowedOrigins {
			if origin == allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

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

// basicAuthMiddleware provides basic authentication with rate limiting for failed attempts
func (a *API) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r, a.config.API.TrustProxy)

		// Check if IP is blocked due to too many failures
		a.authFailuresMu.Lock()
		entry, exists := a.authFailures[ip]
		if exists && entry.count >= 5 && time.Since(entry.lastFail) < 10*time.Minute {
			a.authFailuresMu.Unlock()
			a.logger.Errorf("Too many failed auth attempts from IP: %s", ip)
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		a.authFailuresMu.Unlock()

		username, password, ok := r.BasicAuth()
		if !ok || username != a.config.Auth.Username || bcrypt.CompareHashAndPassword([]byte(a.config.Auth.HashedPassword), []byte(password)) != nil {
			// Increment failure count
			a.authFailuresMu.Lock()
			if !exists {
				a.authFailures[ip] = &authFailureEntry{count: 1, lastFail: time.Now()}
			} else {
				entry.count++
				entry.lastFail = time.Now()
			}
			a.authFailuresMu.Unlock()

			a.logger.Errorf("Failed authentication attempt from IP: %s", ip)
			w.Header().Set("WWW-Authenticate", `Basic realm="Cerberus API"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// On success, reset failure count
		a.authFailuresMu.Lock()
		delete(a.authFailures, ip)
		a.authFailuresMu.Unlock()

		next.ServeHTTP(w, r)
	})
}
