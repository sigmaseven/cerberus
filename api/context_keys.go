package api

import (
	"context"

	"cerberus/storage"
)

// contextKey is a private type to prevent context key collisions across packages.
// Using a private type ensures only this package can create context keys,
// preventing malicious code from injecting values that could bypass RBAC.
//
// This addresses staticcheck SA1029: should not use built-in type string as key for value.
// See: https://staticcheck.io/docs/checks#SA1029
type contextKey string

// Context key constants for storing authentication and authorization data.
// These keys are used throughout the API to propagate user identity and permissions.
const (
	// ContextKeyUsername stores the authenticated username (string)
	ContextKeyUsername contextKey = "username"

	// ContextKeyRoles stores the user's roles as a slice ([]string)
	ContextKeyRoles contextKey = "roles"

	// ContextKeyRole stores the user's primary role name (string)
	ContextKeyRole contextKey = "role"

	// ContextKeyPermissions stores the user's permissions ([]string)
	ContextKeyPermissions contextKey = "permissions"

	// ContextKeyUserID stores the user's unique identifier (string)
	ContextKeyUserID contextKey = "user_id"

	// ContextKeySessionID stores the session identifier (string)
	ContextKeySessionID contextKey = "session_id"

	// ContextKeyUser stores the full user object (interface{})
	// Used for passing user details through the request chain
	ContextKeyUser contextKey = "user"

	// ContextKeyCSPNonce stores the Content Security Policy nonce (string)
	// Used for inline script/style security
	ContextKeyCSPNonce contextKey = "csp-nonce"

	// ContextKeyRequestID stores the unique request identifier (string)
	// TASK 152: Used for distributed tracing and log correlation
	ContextKeyRequestID contextKey = "request_id"

	// ContextKeyTraceStart stores the request start time (time.Time)
	// TASK 152: Used for latency tracking
	ContextKeyTraceStart contextKey = "trace_start"
)

// GetUsername extracts the username from the context.
// Returns the username and true if found, empty string and false otherwise.
//
// Security: Type-safe extraction prevents accidental type assertions
// and ensures nil safety.
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(ContextKeyUsername).(string)
	return username, ok
}

// GetRoles extracts the user's roles from the context.
// Returns the roles slice and true if found, nil and false otherwise.
//
// Security: Ensures roles are properly typed and cannot be spoofed
// by string-based context pollution.
func GetRoles(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(ContextKeyRoles).([]string)
	return roles, ok
}

// GetRole extracts the user's primary role from the context.
// Returns the role name and true if found, empty string and false otherwise.
//
// Security: Used by RBAC middleware for permission checks.
func GetRole(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(ContextKeyRole).(string)
	return role, ok
}

// GetPermissions extracts the user's permissions from the context.
// Returns the permissions slice and true if found, nil and false otherwise.
//
// Security: Critical for RBAC - ensures permissions cannot be injected
// through context pollution attacks.
func GetPermissions(ctx context.Context) ([]storage.Permission, bool) {
	permissions, ok := ctx.Value(ContextKeyPermissions).([]storage.Permission)
	return permissions, ok
}

// GetUserID extracts the user ID from the context.
// Returns the user ID and true if found, empty string and false otherwise.
//
// Security: Used for audit trails and user-specific operations.
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(ContextKeyUserID).(string)
	return userID, ok
}

// GetSessionID extracts the session ID from the context.
// Returns the session ID and true if found, empty string and false otherwise.
//
// Security: Used for session tracking and concurrent session limits.
func GetSessionID(ctx context.Context) (string, bool) {
	sessionID, ok := ctx.Value(ContextKeySessionID).(string)
	return sessionID, ok
}

// GetUser extracts the user object from the context.
// Returns the user object and true if found, nil and false otherwise.
//
// The caller must type-assert the interface{} to the expected user type.
func GetUser(ctx context.Context) (interface{}, bool) {
	user := ctx.Value(ContextKeyUser)
	if user == nil {
		return nil, false
	}
	return user, true
}

// GetCSPNonce extracts the Content Security Policy nonce from the context.
// Returns the nonce and true if found, empty string and false otherwise.
//
// Security: Used for inline script/style CSP validation.
func GetCSPNonce(ctx context.Context) (string, bool) {
	nonce, ok := ctx.Value(ContextKeyCSPNonce).(string)
	return nonce, ok
}

// WithUsername creates a new context with the username value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, ContextKeyUsername, username)
}

// WithRoles creates a new context with the roles value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, ContextKeyRoles, roles)
}

// WithRole creates a new context with the role value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, ContextKeyRole, role)
}

// WithPermissions creates a new context with the permissions value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithPermissions(ctx context.Context, permissions []storage.Permission) context.Context {
	return context.WithValue(ctx, ContextKeyPermissions, permissions)
}

// WithUserID creates a new context with the user ID value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ContextKeyUserID, userID)
}

// WithSessionID creates a new context with the session ID value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, ContextKeySessionID, sessionID)
}

// WithUser creates a new context with the user object value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithUser(ctx context.Context, user interface{}) context.Context {
	return context.WithValue(ctx, ContextKeyUser, user)
}

// WithCSPNonce creates a new context with the CSP nonce value.
// This is a convenience wrapper for context.WithValue with type safety.
func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, ContextKeyCSPNonce, nonce)
}

// GetRequestID extracts the request ID from the context.
// Returns the request ID and true if found, empty string and false otherwise.
//
// TASK 152: Used for distributed tracing and log correlation.
// Security: Type-safe extraction prevents context pollution attacks.
func GetRequestID(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(ContextKeyRequestID).(string)
	return requestID, ok
}

// GetRequestIDOrDefault extracts the request ID from the context or returns "unknown".
// This is a convenience function for logging where a default value is acceptable.
//
// TASK 152: Used for structured logging with correlation IDs.
func GetRequestIDOrDefault(ctx context.Context) string {
	if requestID, ok := GetRequestID(ctx); ok && requestID != "" {
		return requestID
	}
	return "unknown"
}

// WithRequestID creates a new context with the request ID value.
// This is a convenience wrapper for context.WithValue with type safety.
//
// TASK 152: Used by RequestIDMiddleware to inject request IDs.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// GetTraceStart extracts the trace start time from the context.
// Returns the start time and true if found, zero time and false otherwise.
//
// TASK 152: Used for request latency calculation.
func GetTraceStart(ctx context.Context) (interface{}, bool) {
	start := ctx.Value(ContextKeyTraceStart)
	if start == nil {
		return nil, false
	}
	return start, true
}

// WithTraceStart creates a new context with the trace start time.
// This is a convenience wrapper for context.WithValue with type safety.
//
// TASK 152: Used by RequestIDMiddleware to record request start time.
func WithTraceStart(ctx context.Context, start interface{}) context.Context {
	return context.WithValue(ctx, ContextKeyTraceStart, start)
}
