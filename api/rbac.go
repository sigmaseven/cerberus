package api

import (
	"context"
	"net/http"
	"time"

	"cerberus/storage"
)

// RequirePermission creates middleware that checks if the authenticated user has the required permission
// This is the core RBAC enforcement mechanism - all protected endpoints must use this middleware
//
// SECURITY DESIGN:
// - Default deny: Returns 403 if user lacks permission
// - Server-side only: Never trust client-side permission checks
// - Audit logging: All denials are logged for security monitoring
// - Performance: Permission lookup is done via JWT claims to avoid DB queries
func (a *API) RequirePermission(permission storage.Permission) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// SECURITY: Skip permission checks only when auth is completely disabled
			if !a.config.Auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Get username from context (set by JWT middleware)
			username := getUsernameFromContext(r.Context())
			if username == "" {
				a.logger.Warnf("RBAC: No username in context for permission check: %s", permission)
				a.auditPermissionDenial(r, "", permission, "no_username_in_context")
				writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
				return
			}

			// Get user's role and check permissions
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()

			user, role, err := a.userStorage.GetUserWithRole(ctx, username)
			if err != nil {
				a.logger.Errorf("RBAC: Failed to get user %s with role: %v", username, err)
				a.auditPermissionDenial(r, username, permission, "user_lookup_failed")
				writeError(w, http.StatusInternalServerError, "Permission check failed", err, a.logger)
				return
			}

			// Check if user is active
			if !user.Active {
				a.logger.Warnf("RBAC: Inactive user %s attempted to access resource requiring %s", username, permission)
				a.auditPermissionDenial(r, username, permission, "user_inactive")
				writeError(w, http.StatusForbidden, "User account is inactive", nil, a.logger)
				return
			}

			// Check if user has a role assigned
			if role == nil {
				a.logger.Warnf("RBAC: User %s has no role assigned, denying permission: %s", username, permission)
				a.auditPermissionDenial(r, username, permission, "no_role_assigned")
				writeError(w, http.StatusForbidden, "No role assigned to user", nil, a.logger)
				return
			}

			// Check if role has the required permission
			// TASK 31.2: Use CheckPermission function for validation (supports wildcards)
			if !CheckPermission(role, permission) {
				a.logger.Warnf("RBAC: User %s (role: %s) lacks permission: %s", username, role.Name, permission)
				a.auditPermissionDenial(r, username, permission, "insufficient_permissions")
				writeError(w, http.StatusForbidden, "Insufficient permissions", nil, a.logger)
				return
			}

			// AUDIT: Successful permission check (only log at debug level to avoid log spam)
			a.logger.Debugf("RBAC: User %s (role: %s) granted permission: %s", username, role.Name, permission)

			// Permission granted - proceed with request
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates middleware that checks if user has ANY of the specified permissions
// Useful for endpoints that can be accessed by multiple role levels
func (a *API) RequireAnyPermission(permissions ...storage.Permission) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// SECURITY: Skip permission checks only when auth is completely disabled
			if !a.config.Auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			username := getUsernameFromContext(r.Context())
			if username == "" {
				a.logger.Warnf("RBAC: No username in context for permission check (any of): %v", permissions)
				writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()

			user, role, err := a.userStorage.GetUserWithRole(ctx, username)
			if err != nil {
				a.logger.Errorf("RBAC: Failed to get user %s with role: %v", username, err)
				writeError(w, http.StatusInternalServerError, "Permission check failed", err, a.logger)
				return
			}

			if !user.Active {
				a.logger.Warnf("RBAC: Inactive user %s attempted to access resource", username)
				writeError(w, http.StatusForbidden, "User account is inactive", nil, a.logger)
				return
			}

			if role == nil {
				a.logger.Warnf("RBAC: User %s has no role assigned", username)
				writeError(w, http.StatusForbidden, "No role assigned to user", nil, a.logger)
				return
			}

			// If no permissions specified, just require authentication (any authenticated user)
			if len(permissions) == 0 {
				a.logger.Debugf("RBAC: User %s (role: %s) authenticated, no specific permissions required", username, role.Name)
				next.ServeHTTP(w, r)
				return
			}

			// Check if role has ANY of the required permissions
			// TASK 31.2: Use CheckPermission function for validation (supports wildcards)
			for _, perm := range permissions {
				if CheckPermission(role, perm) {
					a.logger.Debugf("RBAC: User %s (role: %s) granted permission: %s", username, role.Name, perm)
					next.ServeHTTP(w, r)
					return
				}
			}

			// None of the permissions matched
			a.logger.Warnf("RBAC: User %s (role: %s) lacks any of the required permissions: %v", username, role.Name, permissions)
			a.auditPermissionDenial(r, username, permissions[0], "insufficient_permissions")
			writeError(w, http.StatusForbidden, "Insufficient permissions", nil, a.logger)
		})
	}
}

// RequireAllPermissions creates middleware that checks if user has ALL of the specified permissions
// Useful for highly privileged operations
func (a *API) RequireAllPermissions(permissions ...storage.Permission) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// SECURITY: Skip permission checks only when auth is completely disabled
			if !a.config.Auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			username := getUsernameFromContext(r.Context())
			if username == "" {
				a.logger.Warnf("RBAC: No username in context for permission check (all of): %v", permissions)
				writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()

			user, role, err := a.userStorage.GetUserWithRole(ctx, username)
			if err != nil {
				a.logger.Errorf("RBAC: Failed to get user %s with role: %v", username, err)
				writeError(w, http.StatusInternalServerError, "Permission check failed", err, a.logger)
				return
			}

			if !user.Active {
				a.logger.Warnf("RBAC: Inactive user %s attempted to access resource", username)
				writeError(w, http.StatusForbidden, "User account is inactive", nil, a.logger)
				return
			}

			if role == nil {
				a.logger.Warnf("RBAC: User %s has no role assigned", username)
				writeError(w, http.StatusForbidden, "No role assigned to user", nil, a.logger)
				return
			}

			// Check if role has ALL of the required permissions
			// TASK 31.2: Use CheckPermission function for validation (supports wildcards)
			for _, perm := range permissions {
				if !CheckPermission(role, perm) {
					a.logger.Warnf("RBAC: User %s (role: %s) lacks required permission: %s", username, role.Name, perm)
					a.auditPermissionDenial(r, username, perm, "insufficient_permissions")
					writeError(w, http.StatusForbidden, "Insufficient permissions", nil, a.logger)
					return
				}
			}

			a.logger.Debugf("RBAC: User %s (role: %s) has all required permissions", username, role.Name)
			next.ServeHTTP(w, r)
		})
	}
}

// getUsernameFromContext extracts the username from the request context
// This is set by the JWT middleware during authentication
func getUsernameFromContext(ctx context.Context) string {
	username, _ := GetUsername(ctx)
	return username
}

// auditPermissionDenial logs a permission denial for security monitoring
func (a *API) auditPermissionDenial(r *http.Request, username string, permission storage.Permission, reason string) {
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Permission denied",
		"action", "permission_check",
		"outcome", "denied",
		"username", username,
		"permission", permission,
		"reason", reason,
		"source_ip", ip,
		"path", r.URL.Path,
		"method", r.Method,
		"timestamp", time.Now().UTC())
}
