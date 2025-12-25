package storage

import (
	"context"
	"fmt"
	"time"
)

// Permission represents a specific permission in the system
type Permission string

// System permissions - granular, composable permissions
const (
	PermReadEvents           Permission = "read:events"
	PermReadAlerts           Permission = "read:alerts"
	PermAcknowledgeAlerts    Permission = "alert:acknowledge"     // TASK 31: Alert acknowledge permission
	PermCommentAlerts        Permission = "alert:comment"         // TASK 31: Alert comment permission
	PermDispositionAlerts    Permission = "alert:disposition"     // TASK 104: Alert disposition permission
	PermAssignAlerts         Permission = "alert:assign"          // TASK 105: Alert assignment permission
	PermCreateInvestigations Permission = "investigations:create" // TASK 106: Investigation creation permission
	PermReadInvestigations   Permission = "read:investigations"  // Investigation read permission (view, list, evidence download)
	PermWriteInvestigations  Permission = "write:investigations" // Investigation write permission (update, evidence upload/delete)
	PermReadRules            Permission = "read:rules"
	PermWriteRules           Permission = "write:rules"
	PermReadActions          Permission = "read:actions"
	PermWriteActions         Permission = "write:actions"
	PermReadUsers            Permission = "read:users"
	PermWriteUsers           Permission = "write:users"
	PermAdminSystem          Permission = "admin:system"
	PermReadListeners        Permission = "read:listeners"
	PermWriteListeners       Permission = "write:listeners"
	// IOC lifecycle permissions
	PermReadIOCs   Permission = "read:iocs"   // View IOCs and statistics
	PermWriteIOCs  Permission = "write:iocs"  // Create, update, delete IOCs
	PermReadHunts  Permission = "read:hunts"  // View threat hunts and results
	PermWriteHunts Permission = "write:hunts" // Create and manage threat hunts
)

// Role represents a named collection of permissions
type Role struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Predefined role names (constants for type safety)
const (
	RoleViewer   = "viewer"
	RoleAnalyst  = "analyst"
	RoleEngineer = "engineer"
	RoleAdmin    = "admin"
)

// GetDefaultRoles returns the default role definitions with hierarchical permissions
// TASK 31: Updated role permissions to match specification
func GetDefaultRoles() []Role {
	now := time.Now()
	return []Role{
		{
			ID:          1,
			Name:        RoleViewer,
			Description: "Read-only access to events, alerts, rules, and listeners",
			// TASK 31: Viewer gets read-only permissions (events:read, alerts:read, rules:read)
			// TASK 118: Viewer can see listener status for monitoring
			// Investigation evidence: Viewer can view investigations and download evidence
			// IOC lifecycle: Viewer can view IOCs and hunt results (read-only)
			Permissions: []Permission{
				PermReadEvents,
				PermReadAlerts,
				PermReadInvestigations,
				PermReadRules,
				PermReadListeners,
				PermReadIOCs,
				PermReadHunts,
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          2,
			Name:        RoleAnalyst,
			Description: "Viewer permissions plus acknowledge alerts and add comments",
			// TASK 31: Analyst adds alert:acknowledge and alert:comment
			// TASK 104: Analyst can set disposition (analyst verdict)
			// TASK 105: Analyst can assign alerts during triage
			// TASK 106: Analyst can create investigations from alerts
			// Investigation evidence: Analyst can view, upload, and manage evidence
			// IOC lifecycle: Analyst has full IOC and hunt management for threat hunting
			Permissions: []Permission{
				PermReadEvents,
				PermReadAlerts,
				PermAcknowledgeAlerts,
				PermCommentAlerts,
				PermDispositionAlerts,
				PermAssignAlerts,
				PermCreateInvestigations,
				PermReadInvestigations,
				PermWriteInvestigations,
				PermReadRules,
				PermReadActions,
				PermReadListeners,
				PermReadIOCs,
				PermWriteIOCs,
				PermReadHunts,
				PermWriteHunts,
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          3,
			Name:        RoleEngineer,
			Description: "Analyst permissions plus ability to create and modify rules and actions",
			// TASK 31: Engineer adds all create/update/delete permissions for rules/actions/correlation
			// TASK 104: Engineer inherits disposition permission from Analyst
			// TASK 105: Engineer inherits assignment permission from Analyst
			// TASK 106: Engineer inherits investigation creation from Analyst
			// Investigation evidence: Engineer can view, upload, and manage evidence
			// IOC lifecycle: Engineer has full IOC and hunt management
			Permissions: []Permission{
				PermReadEvents,
				PermReadAlerts,
				PermAcknowledgeAlerts,
				PermCommentAlerts,
				PermDispositionAlerts,
				PermAssignAlerts,
				PermCreateInvestigations,
				PermReadInvestigations,
				PermWriteInvestigations,
				PermReadRules,
				PermWriteRules,
				PermReadActions,
				PermWriteActions,
				PermReadListeners,
				PermWriteListeners,
				PermReadIOCs,
				PermWriteIOCs,
				PermReadHunts,
				PermWriteHunts,
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          4,
			Name:        RoleAdmin,
			Description: "Full system access including user management",
			// TASK 31: Admin gets all permissions including user:* operations
			// TASK 104: Admin gets disposition permission
			// TASK 105: Admin gets assignment permission
			// TASK 106: Admin gets investigation creation permission
			// Investigation evidence: Admin has full access to investigations and evidence
			// IOC lifecycle: Admin has full IOC and hunt management
			Permissions: []Permission{
				PermReadEvents,
				PermReadAlerts,
				PermAcknowledgeAlerts,
				PermCommentAlerts,
				PermDispositionAlerts,
				PermAssignAlerts,
				PermCreateInvestigations,
				PermReadInvestigations,
				PermWriteInvestigations,
				PermReadRules,
				PermWriteRules,
				PermReadActions,
				PermWriteActions,
				PermReadUsers,
				PermWriteUsers,
				PermAdminSystem,
				PermReadListeners,
				PermWriteListeners,
				PermReadIOCs,
				PermWriteIOCs,
				PermReadHunts,
				PermWriteHunts,
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}

// GetRolePermissions returns the permission set for a role name
// TASK 31.1: Helper function to retrieve permission set for a role name
func GetRolePermissions(roleName string) ([]Permission, error) {
	defaultRoles := GetDefaultRoles()
	for _, role := range defaultRoles {
		if role.Name == roleName {
			return role.Permissions, nil
		}
	}
	return nil, fmt.Errorf("invalid role name: %s", roleName)
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(perm Permission) bool {
	for _, p := range r.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// User represents a user in the system
type User struct {
	Username  string    `json:"username"`
	Password  string    `json:"-"`                   // Password hash, never return in JSON
	Roles     []string  `json:"roles"`               // DEPRECATED: Legacy field for backward compatibility
	RoleID    *int64    `json:"role_id,omitempty"`   // Foreign key to roles table
	RoleName  string    `json:"role_name,omitempty"` // Denormalized for convenience
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// TASK 8.3: MFA/TOTP support
	TOTPSecret string `json:"-"`                     // TOTP secret (never return in JSON)
	MFAEnabled bool   `json:"mfa_enabled,omitempty"` // Whether MFA is enabled
	// TASK 8.5: Account lockout support
	FailedLoginAttempts int        `json:"-"`                             // Number of consecutive failed login attempts
	LockedUntil         *time.Time `json:"locked_until,omitempty"`        // Account lockout expiration
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty"` // Last password change time (for password expiry)
	// TASK 38.3: Force password change on first login
	MustChangePassword bool `json:"must_change_password,omitempty"` // Force password change on next login
}

// HasPermission checks if the user has a specific permission via their role.
// This is a convenience method - actual permission checking should happen server-side.
// Context is used for the database lookup and should have a reasonable timeout.
func (u *User) HasPermission(ctx context.Context, perm Permission, roleStorage RoleStorage) bool {
	if u.RoleID == nil {
		return false
	}

	role, err := roleStorage.GetRoleByID(ctx, *u.RoleID)
	if err != nil {
		return false
	}

	return role.HasPermission(perm)
}

// RoleStorage interface for role management operations
type RoleStorage interface {
	// Role CRUD operations
	GetRoleByID(ctx context.Context, id int64) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, role *Role) error
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id int64) error

	// Initialize default roles on first startup
	SeedDefaultRoles(ctx context.Context) error
}

// UserStorage interface for user management operations
type UserStorage interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, username string) error
	ListUsers(ctx context.Context) ([]*User, error)
	ValidateCredentials(ctx context.Context, username string, password string) (*User, error)

	// RBAC operations
	UpdateUserRole(ctx context.Context, username string, roleID int64) error
	GetUserWithRole(ctx context.Context, username string) (*User, *Role, error)
}
