package api

import (
	"fmt"
	"strings"

	"cerberus/storage"
)

// PermissionRegistry maps HTTP method and path patterns to required permissions
// TASK 31.2: Endpoint-to-permission mapping registry
var PermissionRegistry = map[string]map[string]storage.Permission{
	"GET": {
		"/api/v1/events":                              storage.PermReadEvents,
		"/api/v1/events/search":                       storage.PermReadEvents,
		"/api/v1/events/search/validate":              storage.PermReadEvents,
		"/api/v1/events/search/fields":                storage.PermReadEvents,
		"/api/v1/events/search/operators":             storage.PermReadEvents,
		"/api/v1/alerts":                              storage.PermReadAlerts,
		"/api/v1/alerts/{id}":                         storage.PermReadAlerts,
		"/api/v1/rules":                               storage.PermReadRules,
		"/api/v1/rules/{id}":                          storage.PermReadRules,
		"/api/v1/actions":                             storage.PermReadActions,
		"/api/v1/actions/{id}":                        storage.PermReadActions,
		"/api/v1/correlation-rules":                   storage.PermReadRules,
		"/api/v1/correlation-rules/{id}":              storage.PermReadRules,
		"/api/v1/investigations":                      storage.PermReadAlerts,
		"/api/v1/investigations/{id}":                 storage.PermReadAlerts,
		"/api/v1/investigations/statistics":           storage.PermReadAlerts,
		"/api/v1/investigations/{id}/timeline":        storage.PermReadAlerts,
		"/api/v1/listeners":                           storage.PermReadListeners,
		"/api/v1/dashboard":                           storage.PermReadEvents,
		"/api/v1/dashboard/chart":                     storage.PermReadEvents,
		"/api/v1/mitre/coverage":                      storage.PermReadRules,
		"/api/v1/mitre/coverage/matrix":               storage.PermReadRules,
		"/api/v1/mitre/coverage/data-sources":         storage.PermReadRules,
		"/api/v1/mitre/techniques/{id}/subtechniques": storage.PermReadRules,
		"/api/v1/mitre/data-sources":                  storage.PermReadRules,
		"/api/v1/saved-searches":                      storage.PermReadEvents,
		"/api/v1/saved-searches/{id}":                 storage.PermReadEvents,
		"/api/v1/ml/status":                           storage.PermReadEvents,
		"/api/v1/ml/health":                           storage.PermReadEvents,
		"/api/v1/ml/performance":                      storage.PermReadEvents,
		"/api/v1/ml/config":                           storage.PermReadEvents,
		"/api/v1/users":                               storage.PermReadUsers,
		"/api/v1/users/{username}":                    storage.PermReadUsers,
		"/api/v1/users/me":                            storage.PermReadUsers, // Any authenticated user
		"/api/v1/roles":                               storage.PermReadUsers,
		"/api/v1/roles/{id}":                          storage.PermReadUsers,
		"/api/v1/dlq":                                 storage.PermReadEvents,
		"/api/v1/dlq/{id}":                            storage.PermReadEvents,
		// IOC lifecycle endpoints
		"/api/v1/iocs":                                storage.PermReadIOCs,
		"/api/v1/iocs/stats":                          storage.PermReadIOCs,
		"/api/v1/iocs/{id}":                           storage.PermReadIOCs,
		"/api/v1/iocs/{id}/matches":                   storage.PermReadIOCs,
		// Threat hunt endpoints
		"/api/v1/hunts":                               storage.PermReadHunts,
		"/api/v1/hunts/{id}":                          storage.PermReadHunts,
		"/api/v1/hunts/{id}/matches":                  storage.PermReadHunts,
	},
	"POST": {
		"/api/v1/rules":                      storage.PermWriteRules,
		"/api/v1/actions":                    storage.PermWriteActions,
		"/api/v1/correlation-rules":          storage.PermWriteRules,
		"/api/v1/investigations":             storage.PermReadAlerts, // Creating investigation requires read access
		"/api/v1/investigations/{id}/notes":  storage.PermReadAlerts,
		"/api/v1/investigations/{id}/alerts": storage.PermReadAlerts,
		"/api/v1/alerts/{id}/acknowledge":    storage.PermAcknowledgeAlerts, // TASK 31: Alert acknowledge requires specific permission
		"/api/v1/alerts/{id}/dismiss":        storage.PermReadAlerts,
		"/api/v1/saved-searches":             storage.PermReadEvents,
		"/api/v1/ml/train":                   storage.PermAdminSystem,
		"/api/v1/users":                      storage.PermWriteUsers,
		"/api/v1/mitre/import":               storage.PermWriteRules,
		"/api/v1/events/search":              storage.PermReadEvents,
		"/api/v1/events/search/validate":     storage.PermReadEvents,
		"/api/v1/dlq/{id}/replay":            storage.PermAdminSystem,
		"/api/v1/dlq/replay-all":             storage.PermAdminSystem,
		// IOC lifecycle endpoints
		"/api/v1/iocs":                       storage.PermWriteIOCs,
		"/api/v1/iocs/bulk":                  storage.PermWriteIOCs,
		"/api/v1/iocs/{id}/investigations/{investigationId}": storage.PermWriteIOCs,
		// Threat hunt endpoints
		"/api/v1/hunts":                      storage.PermWriteHunts,
		"/api/v1/hunts/{id}/cancel":          storage.PermWriteHunts,
	},
	"PUT": {
		"/api/v1/rules/{id}":                storage.PermWriteRules,
		"/api/v1/actions/{id}":              storage.PermWriteActions,
		"/api/v1/correlation-rules/{id}":    storage.PermWriteRules,
		"/api/v1/investigations/{id}":       storage.PermReadAlerts,
		"/api/v1/investigations/{id}/close": storage.PermReadAlerts,
		"/api/v1/alerts/{id}/status":        storage.PermReadAlerts,
		"/api/v1/alerts/{id}/assign":        storage.PermReadAlerts,
		"/api/v1/saved-searches/{id}":       storage.PermReadEvents,
		"/api/v1/ml/config":                 storage.PermAdminSystem,
		"/api/v1/users/{username}":          storage.PermWriteUsers,
		"/api/v1/users/{username}/role":     storage.PermWriteUsers,
		"/api/v1/mitre/update":              storage.PermWriteRules,
		// IOC lifecycle endpoints
		"/api/v1/iocs/{id}":                 storage.PermWriteIOCs,
		"/api/v1/iocs/bulk/status":          storage.PermWriteIOCs,
	},
	"DELETE": {
		"/api/v1/rules/{id}":             storage.PermWriteRules,
		"/api/v1/actions/{id}":           storage.PermWriteActions,
		"/api/v1/correlation-rules/{id}": storage.PermWriteRules,
		"/api/v1/investigations/{id}":    storage.PermReadAlerts,
		"/api/v1/alerts/{id}":            storage.PermReadAlerts,
		"/api/v1/saved-searches/{id}":    storage.PermReadEvents,
		"/api/v1/users/{username}":       storage.PermWriteUsers,
		"/api/v1/dlq/{id}":               storage.PermAdminSystem, // DELETE requires admin
		// IOC lifecycle endpoints
		"/api/v1/iocs/{id}":              storage.PermWriteIOCs,
		"/api/v1/iocs/{id}/investigations/{investigationId}": storage.PermWriteIOCs,
	},
}

// GetRequiredPermission determines the required permission for an HTTP method and path
// TASK 31.2: Match request to registry using path pattern matching
// Handles path parameters like {id} and {username} by using pattern matching
func GetRequiredPermission(method, path string) (storage.Permission, error) {
	// Normalize path (remove trailing slashes)
	path = strings.TrimSuffix(path, "/")

	// Check exact match first
	if methodPerms, ok := PermissionRegistry[method]; ok {
		if perm, found := methodPerms[path]; found {
			return perm, nil
		}
	}

	// Try pattern matching for path parameters (e.g., /api/v1/rules/{id} matches /api/v1/rules/123)
	if methodPerms, ok := PermissionRegistry[method]; ok {
		for pattern, perm := range methodPerms {
			if matchesPathPattern(path, pattern) {
				return perm, nil
			}
		}
	}

	return "", fmt.Errorf("no permission mapping found for %s %s", method, path)
}

// matchesPathPattern checks if a request path matches a pattern with path parameters
// TASK 31.2: Path pattern matching for endpoints with parameters
// Example: /api/v1/rules/123 matches /api/v1/rules/{id}
func matchesPathPattern(path, pattern string) bool {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(pathParts) != len(patternParts) {
		return false
	}

	for i, patternPart := range patternParts {
		// If pattern part is a parameter placeholder (e.g., {id}, {username}), match any value
		if strings.HasPrefix(patternPart, "{") && strings.HasSuffix(patternPart, "}") {
			continue
		}

		// Otherwise, parts must match exactly
		if pathParts[i] != patternPart {
			return false
		}
	}

	return true
}

// CheckPermission checks if a role has a specific permission
// TASK 31.2: Validate role permissions
// Supports wildcard permissions (e.g., Admin role can have "*" for all permissions)
func CheckPermission(role *storage.Role, permission storage.Permission) bool {
	if role == nil {
		return false
	}

	// Check for wildcard permission ("*") - Admin has all permissions
	for _, perm := range role.Permissions {
		if perm == "*" || perm == permission {
			return true
		}
		// Support resource wildcards (e.g., "rules:*" matches "rules:create", "rules:update", etc.)
		permStr := string(perm)
		permReqStr := string(permission)
		if strings.HasSuffix(permStr, ":*") {
			resource := strings.TrimSuffix(permStr, ":*")
			if strings.HasPrefix(permReqStr, resource+":") {
				return true
			}
		}
	}

	return false
}
