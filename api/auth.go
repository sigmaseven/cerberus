package api

import (
	"net/http"
	"strings"
)

type Middleware func(http.Handler) http.Handler

// TASK 138: Removed unused basicAuthMiddleware (replaced by JWT authentication)

// jwtAuthMiddleware provides JWT authentication
func (a *API) jwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FIXED: Skip authentication entirely when auth is disabled
		if !a.config.Auth.Enabled {
			// Auth is disabled, allow all requests through with anonymous context
			ctx := WithUsername(r.Context(), "anonymous")
			ctx = WithRoles(ctx, []string{"admin"}) // Grant full access when auth is disabled
			r = r.WithContext(ctx)
			r.Header.Set("X-Username", "anonymous")
			next.ServeHTTP(w, r)
			return
		}

		var tokenString string

		// First, try to get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// If no Authorization header, try to get token from httpOnly cookie
			cookie, err := r.Cookie("auth_token")
			if err != nil {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}
			tokenString = cookie.Value
		}

		// Validate the token
		claims, err := a.validateJWT(tokenString, a.config)
		if err != nil {
			a.logger.Errorf("Invalid JWT token: %s", sanitizeLogMessage(err.Error()))
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add user information to request context for authorization
		ctx := WithUsername(r.Context(), claims.Username)
		ctx = WithRoles(ctx, claims.Roles)
		r = r.WithContext(ctx)

		// Also set headers for backward compatibility
		r.Header.Set("X-Username", claims.Username)

		next.ServeHTTP(w, r)
	})
}

// TASK 138: Removed unused requireRole function (RBAC now uses middleware_rbac.go)

// TASK 138: Removed unused updateAuthFailureOrder and updateAccountFailureOrder functions
// (were helpers for removed basicAuthMiddleware)
