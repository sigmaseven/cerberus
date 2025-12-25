package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// RBACMiddleware is an enhanced middleware that automatically determines required permissions
// from the request method and path using the permission registry
// TASK 31.3: RBAC middleware with JWT extraction and automatic permission checking
func (a *API) RBACMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SECURITY: Skip permission checks only when auth is completely disabled
		if !a.config.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Extract JWT token from Authorization header or cookie
		// TASK 31.3: Extract JWT token from Authorization header
		tokenString := extractTokenFromRequest(r)
		if tokenString == "" {
			a.logger.Warnf("RBAC: No JWT token found in request to %s %s", r.Method, r.URL.Path)
			writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
			return
		}

		// Validate JWT and extract claims
		// TASK 31.3: Validate JWT and extract claims including user role
		claims, err := a.validateJWT(tokenString, a.config)
		if err != nil {
			a.logger.Warnf("RBAC: Invalid JWT token: %v", err)
			writeError(w, http.StatusUnauthorized, "Invalid or expired token", nil, a.logger)
			return
		}

		// Get required permission for current endpoint
		// TASK 31.3: Get required permission for current endpoint using method and path
		requiredPerm, err := GetRequiredPermission(r.Method, r.URL.Path)
		if err != nil {
			// Endpoint not in registry - allow if authenticated (for backward compatibility)
			// This allows endpoints without explicit permission mapping to still work
			// but they should be added to PermissionRegistry for security
			a.logger.Debugf("RBAC: No permission mapping for %s %s, allowing authenticated access", r.Method, r.URL.Path)
			ctx := WithUsername(r.Context(), claims.Username)
			if len(claims.Roles) > 0 {
				ctx = WithRole(ctx, claims.Roles[0])
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Retrieve user's role from storage
		// TASK 31.3: Retrieve Role object for user's role name
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		user, role, err := a.userStorage.GetUserWithRole(ctx, claims.Username)
		if err != nil {
			a.logger.Errorf("RBAC: Failed to get user %s with role: %v", claims.Username, err)
			writeError(w, http.StatusInternalServerError, "Permission check failed", err, a.logger)
			return
		}

		// Check if user is active
		if !user.Active {
			a.logger.Warnf("RBAC: Inactive user %s attempted to access resource", claims.Username)
			a.auditPermissionDenial(r, claims.Username, requiredPerm, "user_inactive")
			writeError(w, http.StatusForbidden, "User account is inactive", nil, a.logger)
			return
		}

		// Check if user has a role assigned
		if role == nil {
			a.logger.Warnf("RBAC: User %s has no role assigned", claims.Username)
			a.auditPermissionDenial(r, claims.Username, requiredPerm, "no_role_assigned")
			writeError(w, http.StatusForbidden, "No role assigned to user", nil, a.logger)
			return
		}

		// Check permission
		// TASK 31.3: Call CheckPermission to validate access
		if !CheckPermission(role, requiredPerm) {
			a.logger.Warnf("RBAC: User %s (role: %s) lacks permission: %s for %s %s",
				claims.Username, role.Name, requiredPerm, r.Method, r.URL.Path)
			a.auditPermissionDenial(r, claims.Username, requiredPerm, "insufficient_permissions")
			writeError(w, http.StatusForbidden, "Insufficient permissions", nil, a.logger)
			return
		}

		// TASK 31.3: Context propagation of user info to downstream handlers
		ctx = WithUsername(r.Context(), claims.Username)
		ctx = WithRole(ctx, role.Name)
		ctx = WithPermissions(ctx, role.Permissions)

		// Permission granted - proceed with request
		a.logger.Debugf("RBAC: User %s (role: %s) granted permission: %s for %s %s",
			claims.Username, role.Name, requiredPerm, r.Method, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractTokenFromRequest extracts JWT token from Authorization header or cookie
// TASK 31.3: Extract JWT token from Authorization header
func extractTokenFromRequest(r *http.Request) string {
	// Try Authorization header first (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Fallback to cookie (for browser-based authentication)
	cookie, err := r.Cookie("auth_token")
	if err == nil && cookie != nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}
