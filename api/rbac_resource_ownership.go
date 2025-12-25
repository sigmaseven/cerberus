package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"cerberus/core"
)

// CanAccessResource checks if a user can access a specific resource based on ownership and role
// TASK 23.3: Resource ownership validation functions
// SECURITY: Users can only modify their own resources unless they have admin privileges
func (a *API) CanAccessResource(ctx context.Context, userID string, userRole string, resource interface{}) bool {
	// Admin role can access any resource
	if IsAdmin(userRole) {
		return true
	}

	// Type assertion to check resource type
	switch res := resource.(type) {
	case *core.Investigation:
		return CanAccessInvestigation(userID, userRole, res)
	case *core.Alert:
		return CanAccessAlert(userID, userRole, res)
	default:
		// Unknown resource type - deny access by default
		a.logger.Warnf("Unknown resource type in CanAccessResource: %T", resource)
		return false
	}
}

// CanAccessInvestigation checks if a user can access an investigation
// TASK 23.3: Users can only modify their own investigations unless admin
func CanAccessInvestigation(userID string, userRole string, investigation *core.Investigation) bool {
	// Admin can access any investigation
	if IsAdmin(userRole) {
		return true
	}

	// Users can access investigations they created
	if investigation.CreatedBy == userID {
		return true
	}

	// Users can access investigations assigned to them
	if investigation.AssigneeID == userID {
		return true
	}

	// Analyst role can view all investigations but only modify assigned ones
	// For now, we check if user can modify (if it's assigned to them)
	// Read access would be separate (implemented via permission checks)
	return false
}

// CanAccessAlert checks if a user can access an alert
// TASK 23.3: Analysts can view all alerts but only modify assigned ones
func CanAccessAlert(userID string, userRole string, alert *core.Alert) bool {
	// Admin can access any alert
	if IsAdmin(userRole) {
		return true
	}

	// Analysts can view all alerts, but for modification:
	// - Can modify alerts assigned to them
	// - Can modify unassigned alerts (to assign them)
	if alert.AssignedTo == "" || alert.AssignedTo == userID {
		return true
	}

	// Cannot modify alerts assigned to other users
	return false
}

// IsResourceOwner checks if a user owns a resource
// TASK 23.3: Helper function to determine ownership
func IsResourceOwner(userID string, resourceOwnerID string) bool {
	if resourceOwnerID == "" {
		return false
	}
	return userID == resourceOwnerID
}

// IsAdmin checks if a role is admin
// TASK 23.3: Helper function to determine admin role
func IsAdmin(roleName string) bool {
	return roleName == "admin" || roleName == "administrator"
}

// RequireResourceOwnership creates middleware that checks resource ownership before allowing modification
// TASK 23.3: Resource ownership middleware for investigations, alerts, etc.
func (a *API) RequireResourceOwnership(resourceType string, getResource func(r *http.Request) (interface{}, error)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip ownership checks when auth is disabled
			if !a.config.Auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Get username from context
			username := getUsernameFromContext(r.Context())
			if username == "" {
				a.auditPermissionDenial(r, "", "", "no_username_in_context")
				writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
				return
			}

			// Get user's role
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()

			user, role, err := a.userStorage.GetUserWithRole(ctx, username)
			if err != nil {
				a.logger.Errorf("RBAC: Failed to get user %s with role: %v", username, err)
				a.auditPermissionDenial(r, username, "", "user_lookup_failed")
				writeError(w, http.StatusInternalServerError, "Permission check failed", err, a.logger)
				return
			}

			if !user.Active {
				a.logger.Warnf("RBAC: Inactive user %s attempted to access resource", username)
				writeError(w, http.StatusForbidden, "User account is inactive", nil, a.logger)
				return
			}

			userRole := "viewer" // default role
			if role != nil {
				userRole = role.Name
			}

			// Get the resource
			resource, err := getResource(r)
			if err != nil {
				a.logger.Errorf("RBAC: Failed to get resource for ownership check: %v", err)
				writeError(w, http.StatusNotFound, "Resource not found", err, a.logger)
				return
			}

			// Check resource access
			if !a.CanAccessResource(ctx, username, userRole, resource) {
				a.logger.Warnf("RBAC: User %s (role: %s) attempted to access resource they don't own: %s", username, userRole, resourceType)
				a.auditPermissionDenial(r, username, "", fmt.Sprintf("resource_ownership_denied:%s", resourceType))
				writeError(w, http.StatusForbidden, "Access denied: you don't have permission to modify this resource", nil, a.logger)
				return
			}

			// Resource access granted
			a.logger.Debugf("RBAC: User %s (role: %s) granted access to %s resource", username, userRole, resourceType)
			next.ServeHTTP(w, r)
		})
	}
}
