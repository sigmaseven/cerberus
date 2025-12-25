package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cerberus/storage"

	"github.com/gorilla/mux"
)

// getCurrentUser godoc
//
//	@Summary		Get current user information
//	@Description	Returns the currently authenticated user with role and permissions (TASK 3.6: Frontend RBAC integration)
//	@Tags			users
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"User with role and permissions"
//	@Failure		401	{string}	string	"Unauthorized"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/users/me [get]
func (a *API) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get current username from context (set by JWT middleware)
	username := getUsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user with role information
	user, role, err := a.userStorage.GetUserWithRole(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	// SECURITY: Never return password hash
	user.Password = ""

	// Build response with role and permissions
	response := map[string]interface{}{
		"username":    user.Username,
		"role_id":     user.RoleID,
		"role_name":   user.RoleName,
		"active":      user.Active,
		"created_at":  user.CreatedAt,
		"updated_at":  user.UpdatedAt,
		"permissions": []string{},
	}

	if role != nil {
		response["role"] = map[string]interface{}{
			"id":          role.ID,
			"name":        role.Name,
			"description": role.Description,
		}
		// Convert Permission slice to string slice for JSON response
		permissions := make([]string, len(role.Permissions))
		for i, perm := range role.Permissions {
			permissions[i] = string(perm)
		}
		response["permissions"] = permissions
	}

	a.respondJSON(w, response, http.StatusOK)
}

// listUsers godoc
//
//	@Summary		List all users
//	@Description	Returns a list of all users (requires read:users permission)
//	@Tags			users
//	@Produce		json
//	@Success		200	{array}		storage.User
//	@Failure		403	{string}	string	"Forbidden"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/users [get]
func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := a.userStorage.ListUsers(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list users", err, a.logger)
		return
	}

	// SECURITY: Never return password hashes in the response
	// The User struct has `json:"-"` on Password field, but double-check
	for _, user := range users {
		user.Password = "" // Explicitly clear password field
	}

	a.respondJSON(w, users, http.StatusOK)
}

// getUser godoc
//
//	@Summary		Get user details
//	@Description	Returns details for a specific user (requires read:users permission)
//	@Tags			users
//	@Produce		json
//	@Param			username	path		string	true	"Username"
//	@Success		200			{object}	storage.User
//	@Failure		403			{string}	string	"Forbidden"
//	@Failure		404			{string}	string	"User not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/users/{username} [get]
func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, role, err := a.userStorage.GetUserWithRole(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	// SECURITY: Never return password hash
	user.Password = ""

	// Include role information in response
	response := map[string]interface{}{
		"username":   user.Username,
		"role_id":    user.RoleID,
		"role_name":  user.RoleName,
		"active":     user.Active,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}

	if role != nil {
		response["role"] = map[string]interface{}{
			"id":          role.ID,
			"name":        role.Name,
			"description": role.Description,
			"permissions": role.Permissions,
		}
	}

	a.respondJSON(w, response, http.StatusOK)
}

// createUser godoc
//
//	@Summary		Create a new user
//	@Description	Creates a new user with assigned role (requires write:users permission)
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			user	body		object{username=string,password=string,role_id=int64}	true	"User details"
//	@Success		201		{object}	storage.User
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		403		{string}	string	"Forbidden"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/users [post]
func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		RoleID   int64  `json:"role_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// SECURITY: Validate username
	if len(req.Username) < 3 || len(req.Username) > 50 {
		writeError(w, http.StatusBadRequest, "Username must be between 3 and 50 characters", nil, a.logger)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "Username can only contain letters, numbers, underscores, and hyphens", nil, a.logger)
		return
	}

	// TASK 38.5: Validate password against password policy
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if a.passwordPolicyManager != nil {
		// Validate password complexity, common passwords, and username variations
		if err := a.passwordPolicyManager.ValidatePassword(ctx, req.Password, req.Username, ""); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Password validation failed: %s", err.Error()), err, a.logger)
			return
		}
	} else {
		// Fallback to basic validation if password policy manager not available
		if len(req.Password) < 8 || len(req.Password) > 128 {
			writeError(w, http.StatusBadRequest, "Password must be between 8 and 128 characters", nil, a.logger)
			return
		}
	}

	// SECURITY: Validate role_id exists

	_, err := a.roleStorage.GetRoleByID(ctx, req.RoleID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid role_id", err, a.logger)
		return
	}

	// Create user
	user := &storage.User{
		Username: req.Username,
		Password: req.Password, // Will be hashed by CreateUser
		RoleID:   &req.RoleID,
		Active:   true,
	}

	if err := a.userStorage.CreateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create user", err, a.logger)
		return
	}

	// AUDIT: Log user creation
	currentUser := getUsernameFromContext(r.Context())
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: User created",
		"action", "create_user",
		"outcome", "success",
		"created_user", user.Username,
		"created_by", currentUser,
		"role_id", req.RoleID,
		"source_ip", ip,
		"timestamp", time.Now().UTC())

	// Return user without password
	user.Password = ""
	a.respondJSON(w, user, http.StatusCreated)
}

// updateUser godoc
//
//	@Summary		Update user
//	@Description	Updates user details (requires write:users permission)
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			username	path		string									true	"Username"
//	@Param			user		body		object{active=bool,password=string}	true	"User updates"
//	@Success		200			{object}	storage.User
//	@Failure		400			{string}	string	"Bad Request"
//	@Failure		403			{string}	string	"Forbidden"
//	@Failure		404			{string}	string	"User not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/users/{username} [put]
func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var req struct {
		Active   *bool   `json:"active,omitempty"`
		Password *string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get existing user
	user, err := a.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	// SECURITY: Prevent self-deactivation
	currentUser := getUsernameFromContext(r.Context())
	if req.Active != nil && !*req.Active && username == currentUser {
		writeError(w, http.StatusBadRequest, "Cannot deactivate your own account", nil, a.logger)
		return
	}

	// Update fields
	if req.Active != nil {
		user.Active = *req.Active
	}
	if req.Password != nil {
		// TASK 38.5: Validate new password against password policy (including history)
		if a.passwordPolicyManager != nil {
			if err := a.passwordPolicyManager.ValidatePassword(ctx, *req.Password, user.Username, user.Username); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("Password validation failed: %s", err.Error()), err, a.logger)
				return
			}
		} else {
			// Fallback to basic validation if password policy manager not available
			if len(*req.Password) < 8 || len(*req.Password) > 128 {
				writeError(w, http.StatusBadRequest, "Password must be between 8 and 128 characters", nil, a.logger)
				return
			}
		}

		// TASK 38.3: Store old password hash in history before updating
		oldPasswordHash := user.Password
		if oldPasswordHash != "" && a.passwordPolicyManager != nil {
			if err := a.passwordPolicyManager.AddPasswordToHistory(ctx, user.Username, oldPasswordHash); err != nil {
				a.logger.Warnf("Failed to add old password to history for user %s: %v", user.Username, err)
				// Continue with password change even if history tracking fails (best effort)
			}
		}

		user.Password = *req.Password // Will be hashed by UpdateUser
		// TASK 38.3: Clear must_change_password flag when password is changed
		user.MustChangePassword = false
	}

	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update user", err, a.logger)
		return
	}

	// TASK 38.3: Store new password hash in history after successful update
	if req.Password != nil && a.passwordPolicyManager != nil {
		// Get updated user to get the new hashed password
		updatedUser, err := a.userStorage.GetUserByUsername(ctx, username)
		if err == nil && updatedUser.Password != "" {
			if err := a.passwordPolicyManager.AddPasswordToHistory(ctx, user.Username, updatedUser.Password); err != nil {
				a.logger.Warnf("Failed to add new password to history for user %s: %v", user.Username, err)
				// Continue even if history tracking fails (best effort)
			}
		}
	}

	// AUDIT: Log user update
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: User updated",
		"action", "update_user",
		"outcome", "success",
		"updated_user", username,
		"updated_by", currentUser,
		"source_ip", ip,
		"timestamp", time.Now().UTC())

	user.Password = ""
	a.respondJSON(w, user, http.StatusOK)
}

// deleteUser godoc
//
//	@Summary		Delete user
//	@Description	Deletes a user (requires write:users permission)
//	@Tags			users
//	@Param			username	path		string	true	"Username"
//	@Success		204			{string}	string	"No Content"
//	@Failure		400			{string}	string	"Bad Request"
//	@Failure		403			{string}	string	"Forbidden"
//	@Failure		404			{string}	string	"User not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/users/{username} [delete]
func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	// SECURITY: Prevent self-deletion
	currentUser := getUsernameFromContext(r.Context())
	if username == currentUser {
		writeError(w, http.StatusBadRequest, "Cannot delete your own account", nil, a.logger)
		return
	}

	// SECURITY: Prevent deletion of last admin user
	// TODO: Implement check for last admin user

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := a.userStorage.DeleteUser(ctx, username); err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete user", err, a.logger)
		return
	}

	// AUDIT: Log user deletion
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: User deleted",
		"action", "delete_user",
		"outcome", "success",
		"deleted_user", username,
		"deleted_by", currentUser,
		"source_ip", ip,
		"timestamp", time.Now().UTC())

	w.WriteHeader(http.StatusNoContent)
}

// updateUserRole godoc
//
//	@Summary		Update user role
//	@Description	Updates a user's role assignment (requires write:users permission)
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			username	path		string				true	"Username"
//	@Param			role		body		object{role_id=int64}	true	"New role ID"
//	@Success		200			{object}	storage.User
//	@Failure		400			{string}	string	"Bad Request"
//	@Failure		403			{string}	string	"Forbidden"
//	@Failure		404			{string}	string	"User not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/users/{username}/role [put]
func (a *API) updateUserRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var req struct {
		RoleID int64 `json:"role_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// SECURITY: Validate role exists
	role, err := a.roleStorage.GetRoleByID(ctx, req.RoleID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid role_id", err, a.logger)
		return
	}

	// SECURITY: Prevent users from assigning themselves admin privileges
	currentUser := getUsernameFromContext(r.Context())
	if username == currentUser {
		writeError(w, http.StatusForbidden, "Cannot change your own role", nil, a.logger)
		return
	}

	if err := a.userStorage.UpdateUserRole(ctx, username, req.RoleID); err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update user role", err, a.logger)
		return
	}

	// AUDIT: Log role change
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: User role changed",
		"action", "update_user_role",
		"outcome", "success",
		"updated_user", username,
		"updated_by", currentUser,
		"new_role_id", req.RoleID,
		"new_role_name", role.Name,
		"source_ip", ip,
		"timestamp", time.Now().UTC())

	// Get updated user with role
	user, _, err := a.userStorage.GetUserWithRole(ctx, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get updated user", err, a.logger)
		return
	}

	user.Password = ""
	a.respondJSON(w, user, http.StatusOK)
}

// listRoles godoc
//
//	@Summary		List all roles
//	@Description	Returns a list of all available roles with their permissions
//	@Tags			roles
//	@Produce		json
//	@Success		200	{array}		storage.Role
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/roles [get]
func (a *API) listRoles(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	roles, err := a.roleStorage.ListRoles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list roles", err, a.logger)
		return
	}

	a.respondJSON(w, roles, http.StatusOK)
}

// getRole godoc
//
//	@Summary		Get role details
//	@Description	Returns details for a specific role including permissions
//	@Tags			roles
//	@Produce		json
//	@Param			id	path		int	true	"Role ID"
//	@Success		200	{object}	storage.Role
//	@Failure		404	{string}	string	"Role not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/roles/{id} [get]
func (a *API) getRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid role ID", err, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	role, err := a.roleStorage.GetRoleByID(ctx, id)
	if err != nil {
		if err.Error() == "role not found" {
			writeError(w, http.StatusNotFound, "Role not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get role", err, a.logger)
		return
	}

	a.respondJSON(w, role, http.StatusOK)
}

// unlockUser godoc
//
//	@Summary		Unlock user account
//	@Description	Unlocks a user account that was locked due to failed login attempts (TASK 39)
//	@Tags			users
//	@Produce		json
//	@Param			username	path		string	true	"Username"
//	@Success		200			{object}	map[string]string
//	@Failure		401			{string}	string	"Unauthorized"
//	@Failure		403			{string}	string	"Forbidden"
//	@Failure		404			{string}	string	"User not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/users/{username}/unlock [post]
func (a *API) unlockUser(w http.ResponseWriter, r *http.Request) {
	// TASK 39: Admin unlock endpoint
	vars := mux.Vars(r)
	username := vars["username"]

	if username == "" {
		writeError(w, http.StatusBadRequest, "Username is required", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get current admin username for audit
	adminUsername := getUsernameFromContext(ctx)
	if adminUsername == "" {
		adminUsername = "system"
	}

	// Get user
	user, err := a.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve user", err, a.logger)
		return
	}

	// Check if account is actually locked
	if user.LockedUntil == nil || time.Now().After(*user.LockedUntil) {
		// Account is not locked or lockout expired
		a.respondJSON(w, map[string]string{
			"message": "Account is not locked",
		}, http.StatusOK)
		return
	}

	// Unlock account
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0

	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unlock user", err, a.logger)
		return
	}

	// TASK 39: Audit logging
	a.logger.Infow("AUDIT: Account unlocked by admin",
		"action", "unlock_account",
		"username", username,
		"unlocked_by", adminUsername,
		"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
		"timestamp", time.Now().UTC())

	// TASK 39: Email notification hook (optional - email service may not be implemented)
	a.logger.Infow("Account unlock notification",
		"username", username,
		"action", "send_unlock_email",
		"note", "Email notification disabled (email service not implemented)")

	a.respondJSON(w, map[string]string{
		"message": "Account unlocked successfully",
	}, http.StatusOK)
}

// AssignableUser represents a simplified user for assignment dropdown
// TASK 108: Create GET /api/users/assignable endpoint
// NOTE: Only includes username and role - no sensitive data exposed
type AssignableUser struct {
	Username string `json:"username"`
	RoleName string `json:"roleName,omitempty"`
}

// AssignableUsersResponse represents the response for assignable users list
type AssignableUsersResponse struct {
	Users  []AssignableUser `json:"users"`
	Total  int              `json:"total"`
	Limit  int              `json:"limit"`
	Search string           `json:"search,omitempty"`
}

// Constants for assignable users endpoint
const (
	maxAssignableUsersLimit     = 500 // Maximum users to return
	defaultAssignableUsersLimit = 100 // Default if not specified
)

// getAssignableUsers godoc
//
//	@Summary		Get assignable users
//	@Description	Returns a list of active users who can be assigned to alerts
//	@Tags			alerts,users
//	@Produce		json
//	@Param			search	query		string	false	"Filter by username (case-insensitive contains)"
//	@Param			limit	query		int		false	"Maximum users to return (1-500, default 100)"
//	@Success		200		{object}	AssignableUsersResponse
//	@Failure		400		{object}	ErrorResponse	"Invalid parameters"
//	@Failure		401		{object}	ErrorResponse	"Authentication required"
//	@Failure		403		{object}	ErrorResponse	"Forbidden"
//	@Failure		500		{object}	ErrorResponse	"Internal server error"
//	@Router			/api/users/assignable [get]
//
// TASK 108: Assignable users endpoint for alert assignment dropdown
// SECURITY: Requires PermAssignAlerts permission (Analyst level and above)
// DESIGN: Uses PermAssignAlerts (not PermReadUsers) because:
//   - Analysts MUST see assignable users to perform their alert triage duties
//   - This endpoint exposes ONLY username and role name (no sensitive data)
//   - Requiring PermReadUsers (admin-level) would break analyst workflow
//   - This is minimal data needed for assignment dropdown functionality
func (a *API) getAssignableUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user for audit logging
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = getUsernameFromContext(r.Context())
	}
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	// Get IP for audit logging
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

	// Parse and validate query parameters
	searchFilter := strings.TrimSpace(r.URL.Query().Get("search"))
	limitStr := r.URL.Query().Get("limit")

	limit := defaultAssignableUsersLimit
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit < 1 || parsedLimit > maxAssignableUsersLimit {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid limit parameter (must be 1-%d)", maxAssignableUsersLimit), nil, a.logger)
			return
		}
		limit = parsedLimit
	}

	if a.userStorage == nil {
		a.logger.Error("User storage not initialized - server misconfiguration")
		writeError(w, http.StatusInternalServerError, "User storage not available", nil, a.logger)
		return
	}

	users, err := a.userStorage.ListUsers(ctx)
	if err != nil {
		a.logger.Errorw("Failed to list users for assignable endpoint",
			"error", err.Error(),
			"username", userID)
		writeError(w, http.StatusInternalServerError, "Failed to list users", nil, a.logger)
		return
	}

	// Filter to only active users, apply search filter, and map to simplified response
	assignableUsers := make([]AssignableUser, 0)
	searchLower := strings.ToLower(searchFilter)

	for _, user := range users {
		// Only include active users
		if !user.Active {
			continue
		}

		// Apply search filter if provided (case-insensitive contains)
		if searchFilter != "" && !strings.Contains(strings.ToLower(user.Username), searchLower) {
			continue
		}

		assignableUsers = append(assignableUsers, AssignableUser{
			Username: user.Username,
			RoleName: user.RoleName,
		})

		// Enforce limit
		if len(assignableUsers) >= limit {
			break
		}
	}

	// AUDIT: Log user enumeration access (security-sensitive operation)
	a.logger.Infow("AUDIT: Assignable users list accessed",
		"action", "list_assignable_users",
		"username", userID,
		"source_ip", ip,
		"search_filter", searchFilter,
		"limit", limit,
		"returned_count", len(assignableUsers),
		"timestamp", time.Now().UTC())

	response := AssignableUsersResponse{
		Users:  assignableUsers,
		Total:  len(assignableUsers),
		Limit:  limit,
		Search: searchFilter,
	}

	a.respondJSON(w, response, http.StatusOK)
}
