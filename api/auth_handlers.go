package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"cerberus/core"
	"cerberus/storage"
	"cerberus/util"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

// TASK 138: Removed unused loginCredentials struct - login uses different request parsing

// handleFailedLoginAttempt increments failed login count and locks account if threshold exceeded.
// TASK 141: Extracted to reduce duplication and improve testability.
func (a *API) handleFailedLoginAttempt(ctx context.Context, user *storage.User, ip, reason string) {
	user.FailedLoginAttempts++

	// Use configurable lockout threshold and duration
	maxFailedAttempts := a.config.Auth.LockoutThreshold
	if maxFailedAttempts <= 0 {
		maxFailedAttempts = 5 // Default: 5 attempts
	}

	lockoutDuration := a.config.Auth.LockoutDuration
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute // Default: 15 minutes
	}

	if user.FailedLoginAttempts >= maxFailedAttempts {
		lockUntil := time.Now().Add(lockoutDuration)
		user.LockedUntil = &lockUntil
		a.logger.Warnw("AUDIT: Account locked due to too many failed login attempts",
			"username", user.Username,
			"failed_attempts", user.FailedLoginAttempts,
			"locked_until", lockUntil.Format(time.RFC3339),
			"source_ip", ip,
			"threshold", maxFailedAttempts,
			"duration_minutes", lockoutDuration.Minutes(),
			"reason", reason)

		// Email notification hook (optional - email service may not be implemented)
		a.logger.Infow("Account lockout notification",
			"username", user.Username,
			"action", "send_lockout_email",
			"note", "Email notification disabled (email service not implemented)")
	}

	// Update user with failed attempt
	if updateErr := a.userStorage.UpdateUser(ctx, user); updateErr != nil {
		a.logger.Warnw("Failed to update failed login attempts", "username", user.Username, "error", updateErr)
	}
}

// login godoc
//
//	@Summary		Authenticate user
//	@Description	Authenticates a user with username and password, returns JWT and CSRF tokens
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			credentials	body		object{username=string,password=string}	true	"Login credentials"
//	@Success		200			{object}	map[string]string
//	@Failure		400			{string}	string	"Bad Request"
//	@Failure		401			{string}	string	"Unauthorized"
//	@Failure		429			{string}	string	"Too Many Requests"
//	@Failure		503			{string}	string	"Service Unavailable"
//	@Router			/api/v1/auth/login [post]
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.config.Auth.Enabled {
		// Return 501 Not Implemented with helpful message instead of 503
		writeError(w, http.StatusNotImplemented, "Authentication is disabled in configuration. To enable authentication, set auth.enabled=true in config.yaml and restart the server.", nil, a.logger)
		return
	}

	// Get client IP for rate limiting
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

	// Check rate limiter BEFORE processing authentication (pre-authentication rate limiting)
	if !a.authManager.authRateLimiter.Allow(ip) {
		a.logger.Errorf("Login rate limit exceeded for IP: %s", ip)
		writeError(w, http.StatusTooManyRequests, "Too many requests", nil, a.logger)
		return
	}

	var creds struct {
		Username string `json:"username" validate:"required,min=3,max=50"`
		Password string `json:"password" validate:"required,min=8,max=128"`
		TOTPCode string `json:"totp_code,omitempty"` // TASK 8.3: Optional TOTP code for MFA
	}

	if err := a.decodeJSONBodyWithLimit(w, r, &creds, int64(a.config.Security.LoginBodyLimit)); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON in request body", err, a.logger)
		return
	}

	// Comprehensive server-side validation (security boundary)
	if len(creds.Username) < 3 {
		writeError(w, http.StatusBadRequest, "Username must be at least 3 characters long", nil, a.logger)
		return
	}
	if len(creds.Username) > 50 {
		writeError(w, http.StatusBadRequest, "Username must be no more than 50 characters long", nil, a.logger)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(creds.Username) {
		writeError(w, http.StatusBadRequest, "Username can only contain letters, numbers, underscores, and hyphens", nil, a.logger)
		return
	}

	if len(creds.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters long", nil, a.logger)
		return
	}
	if len(creds.Password) > 128 {
		writeError(w, http.StatusBadRequest, "Password must be no more than 128 characters long", nil, a.logger)
		return
	}
	// Check for control characters in password
	if regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`).MatchString(creds.Password) {
		writeError(w, http.StatusBadRequest, "Password contains invalid characters", nil, a.logger)
		return
	}

	// Validate input format with struct validator
	validate := validator.New()
	if err := validate.Struct(creds); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid login credentials format", err, a.logger)
		return
	}

	// Authenticate user against user storage
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if a.userStorage == nil {
		writeError(w, http.StatusInternalServerError, "Authentication service unavailable", nil, a.logger)
		return
	}

	// TASK 8.5: Get user to check account lockout before authentication
	user, err := a.userStorage.GetUserByUsername(ctx, creds.Username)
	if err != nil {
		// Don't reveal if user exists - generic error message
		a.logger.Infow("AUDIT: Login attempt failed",
			"action", "login",
			"outcome", "failure",
			"username", creds.Username,
			"source_ip", ip,
			"reason", "user_not_found",
			"timestamp", time.Now().UTC())
		writeError(w, http.StatusUnauthorized, "Invalid credentials", nil, a.logger)
		return
	}

	// TASK 8.5: Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		a.logger.Infow("AUDIT: Login attempt blocked - account locked",
			"action", "login",
			"outcome", "failure",
			"username", creds.Username,
			"source_ip", ip,
			"reason", "account_locked",
			"locked_until", user.LockedUntil.Format(time.RFC3339),
			"timestamp", time.Now().UTC())
		writeError(w, http.StatusLocked, "Account is locked", nil, a.logger)
		return
	}

	// TASK 8.5: Check if lockout has expired
	if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
		// Lockout expired - reset
		user.LockedUntil = nil
		user.FailedLoginAttempts = 0
		if err := a.userStorage.UpdateUser(ctx, user); err != nil {
			a.logger.Warnw("Failed to reset account lockout", "username", creds.Username, "error", err)
		}
	}

	// TASK 38.4: Check password expiry using password policy manager
	if a.passwordPolicyManager != nil {
		expired, err := a.passwordPolicyManager.CheckPasswordExpired(user)
		if err != nil {
			a.logger.Warnf("Failed to check password expiration for user %s: %v", creds.Username, err)
		} else if expired {
			a.logger.Infow("AUDIT: Login attempt blocked - password expired",
				"action", "login",
				"outcome", "failure",
				"username", creds.Username,
				"source_ip", ip,
				"reason", "password_expired",
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusForbidden, "Password has expired. Please reset your password", nil, a.logger)
			return
		}
	} else {
		// Fallback to basic password expiry check if password policy manager not available
		passwordPolicy := util.DefaultPasswordPolicy()
		if passwordPolicy.IsPasswordExpired(user.PasswordChangedAt) {
			a.logger.Infow("AUDIT: Login attempt blocked - password expired",
				"action", "login",
				"outcome", "failure",
				"username", creds.Username,
				"source_ip", ip,
				"reason", "password_expired",
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusForbidden, "Password has expired. Please reset your password", nil, a.logger)
			return
		}
	}

	// TASK 38.4: Check if user must change password on first login
	if user.MustChangePassword {
		// Allow login but require password change - user will need to change password before accessing other endpoints
		// This is handled by middleware in future enhancement
		a.logger.Debugf("User %s must change password on next login", creds.Username)
	}

	// Validate credentials
	validatedUser, err := a.userStorage.ValidateCredentials(ctx, creds.Username, creds.Password)
	if err != nil {
		// TASK 141: Use extracted helper for failed login handling
		a.handleFailedLoginAttempt(ctx, user, ip, "invalid_credentials")

		// AUDIT: Failed login attempt
		a.logger.Infow("AUDIT: Login attempt failed",
			"action", "login",
			"outcome", "failure",
			"username", creds.Username,
			"source_ip", ip,
			"reason", "invalid_credentials",
			"failed_attempts", user.FailedLoginAttempts,
			"timestamp", time.Now().UTC())
		writeError(w, http.StatusUnauthorized, "Invalid credentials", nil, a.logger)
		return
	}

	// TASK 8.3: Validate TOTP code if MFA is enabled
	if validatedUser.MFAEnabled {
		if creds.TOTPCode == "" {
			a.logger.Infow("AUDIT: Login attempt blocked - MFA required",
				"action", "login",
				"outcome", "failure",
				"username", creds.Username,
				"source_ip", ip,
				"reason", "mfa_required",
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusUnauthorized, "MFA code required", nil, a.logger)
			return
		}

		// Validate TOTP code
		if err := validateTOTPCode(creds.TOTPCode, validatedUser.TOTPSecret); err != nil {
			// TASK 141: Use extracted helper for failed login handling
			a.handleFailedLoginAttempt(ctx, user, ip, "invalid_mfa_code")

			a.logger.Infow("AUDIT: Login attempt failed - invalid MFA code",
				"action", "login",
				"outcome", "failure",
				"username", creds.Username,
				"source_ip", ip,
				"reason", "invalid_mfa_code",
				"failed_attempts", user.FailedLoginAttempts,
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusUnauthorized, "Invalid MFA code", nil, a.logger)
			return
		}
	}

	// TASK 8.5: Reset failed login attempts on successful authentication
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		a.logger.Warnw("Failed to reset failed login attempts", "username", creds.Username, "error", err)
	}

	// Check for suspicious activity: detect if user is logging in from multiple different IPs rapidly
	if a.detectSuspiciousLoginActivity(creds.Username, ip) {
		a.logger.Warnw("Suspicious login activity detected for user",
			"username", creds.Username, "ip", ip)
		// Revoke all existing tokens for this user as a security measure
		if revokeErr := a.revokeAllUserTokens(creds.Username); revokeErr != nil {
			a.logger.Errorw("Failed to revoke tokens during suspicious activity", "error", revokeErr)
		}
	}

	// Check maximum concurrent sessions per user to prevent session exhaustion attacks
	// PRODUCTION FIX: Increased from 5 to 100 to support E2E testing and performance requirements
	// FR-PERF-024 requires support for 100 concurrent authenticated user sessions
	const maxConcurrentSessions = 100
	if a.getActiveSessionCount(creds.Username) >= maxConcurrentSessions {
		a.logger.Warnw("Maximum concurrent sessions exceeded for user",
			"username", creds.Username, "max_sessions", maxConcurrentSessions)
		writeError(w, http.StatusTooManyRequests, "Maximum concurrent sessions exceeded", nil, a.logger)
		return
	}

	// Generate JWT and CSRF tokens with mutex protection
	a.authManager.tokenGenMu.Lock()
	token, err := generateJWT(r.Context(), creds.Username, a.config, a.userStorage, a.authManager)
	if err != nil {
		a.authManager.tokenGenMu.Unlock()
		a.logger.Errorw("Failed to generate JWT token", "error", err)
		writeError(w, http.StatusInternalServerError, "Internal server error", err, a.logger)
		return
	}

	csrfToken, err := generateCSRFToken()
	a.authManager.tokenGenMu.Unlock()
	if err != nil {
		a.logger.Errorw("Failed to generate CSRF token", "error", err)
		writeError(w, http.StatusInternalServerError, "Internal server error", err, a.logger)
		return
	}

	// Set httpOnly cookie with JWT token for secure storage
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil, // Set Secure flag only for HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(core.JWTTokenExpiry.Seconds()),
	})

	// Set CSRF token cookie with enhanced security configuration
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		Domain:   "",                                 // Let browser set domain automatically for security
		HttpOnly: false,                              // Frontend needs to read this for X-CSRF-Token header
		Secure:   r.TLS != nil,                       // Secure flag for HTTPS only
		SameSite: http.SameSiteStrictMode,            // Strict same-site policy for CSRF protection
		MaxAge:   int(core.JWTTokenExpiry.Seconds()), // Same expiration as JWT token
		// No Expires field set - let MaxAge control expiration
	})

	// AUDIT: Successful login
	a.logger.Infow("AUDIT: User login successful",
		"action", "login",
		"outcome", "success",
		"username", creds.Username,
		"source_ip", ip,
		"timestamp", time.Now().UTC())

	// TASK 38.4: Build login response with password policy information
	response := map[string]interface{}{
		"message": "Login successful",
	}

	// Add must_change_password flag if user must change password
	if validatedUser.MustChangePassword {
		response["must_change_password"] = true
		response["message"] = "Login successful. Please change your password."
	}

	// Add password expiration warning if password is close to expiring
	if a.passwordPolicyManager != nil {
		warn, daysRemaining := a.passwordPolicyManager.CheckPasswordExpirationWarning(validatedUser)
		if warn {
			response["password_expiration_warning"] = true
			response["password_expires_in_days"] = daysRemaining
			if msg, ok := response["message"].(string); ok {
				response["message"] = fmt.Sprintf("%s Password expires in %d days.", msg, daysRemaining)
			}
		}
	}

	a.respondJSON(w, response, http.StatusOK)
}

// logout godoc
//
//	@Summary		Logout user
//	@Description	Logs out the current user by revoking tokens and clearing cookies
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	map[string]string
//
// extractJTIFromToken attempts to extract the JTI from a JWT token without full validation
func (a *API) extractJTIFromToken(tokenString string) (string, error) {
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Use the secret to verify signature, but we'll ignore other validation errors
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(a.config.Auth.JWTSecret), nil
	})

	// If parsing failed completely, we can't extract JTI
	if err != nil {
		return "", err
	}

	// If token is valid or signature is valid, return the JTI
	if claims.ID != "" {
		return claims.ID, nil
	}

	return "", errors.New("no JTI found in token")
}

// @Router			/api/v1/auth/logout [post]
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	// Extract token from cookie
	var tokenString string
	var username string
	if cookie, err := r.Cookie("auth_token"); err == nil && cookie != nil && cookie.Value != "" {
		tokenString = cookie.Value
		// Try to validate the token to get claims
		if claims, err := a.validateJWT(tokenString, a.config); err == nil && claims != nil && claims.Username != "" {
			username = claims.Username
		} else {
			a.logger.Warnw("Could not validate token for logout", "error", err)
		}
	}

	// Revoke all tokens for the user if we have a valid username
	if username != "" {
		revokedCount := a.authManager.revokeAllUserTokens(username)
		a.logger.Infof("Revoked %d tokens for user: %s", revokedCount, username)

		// AUDIT: Successful logout
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: User logout",
			"action", "logout",
			"outcome", "success",
			"username", username,
			"source_ip", ip,
			"tokens_revoked", revokedCount,
			"timestamp", time.Now().UTC())
	} else if tokenString != "" {
		// If we have a token but couldn't validate it, still blacklist it to prevent reuse
		// Try to extract JTI from the token without full validation
		if jti, err := a.extractJTIFromToken(tokenString); err == nil {
			a.authManager.tokenBlacklist.Store(jti, time.Now().Add(24*time.Hour)) // Blacklist for 24 hours
			a.logger.Infof("Blacklisted potentially invalid token with JTI: %s", jti)
		} else {
			a.logger.Warnw("Could not extract JTI from token for logout", "error", err)
		}
	} else {
		a.logger.Info("No token found for logout")
	}

	// Clear the auth cookie by setting it to expire immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Expire immediately
	})

	// Clear the CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Expire immediately
	})

	response := map[string]string{
		"message": "Logout successful",
	}

	a.respondJSON(w, response, http.StatusOK)
}

// authStatus godoc
//
//	@Summary		Check authentication status
//	@Description	Check if the current request is authenticated and return user info with CSRF token
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		401	{string}	string	"Unauthorized"
//	@Router			/api/auth/status [get]
func (a *API) authStatus(w http.ResponseWriter, r *http.Request) {
	// If authentication is disabled, always return authenticated
	if !a.config.Auth.Enabled {
		response := map[string]interface{}{
			"authenticated": true,
			"username":      "anonymous",
		}
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// If auth is enabled, check for username in header (set by JWT middleware)
	username := r.Header.Get("X-Username")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Unauthorized", nil, a.logger)
		return
	}

	// Get CSRF token from cookie for client-side validation
	csrfToken := ""
	if csrfCookie, err := r.Cookie("csrf_token"); err == nil && csrfCookie != nil && csrfCookie.Value != "" {
		csrfToken = csrfCookie.Value
	}

	response := map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"csrf_token":    csrfToken, // Include CSRF token for immediate client access
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getCSRFToken godoc
//
//	@Summary		Get CSRF token
//	@Description	Returns the current CSRF token from the httpOnly cookie
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	map[string]string
//	@Failure		401	{string}	string	"Unauthorized"
//	@Router			/api/v1/auth/csrf-token [get]
func (a *API) getCSRFToken(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Unauthorized", nil, a.logger)
		return
	}

	csrfToken := ""
	if csrfCookie, err := r.Cookie("csrf_token"); err == nil && csrfCookie != nil {
		csrfToken = csrfCookie.Value
	}

	// Generate a new token if one doesn't exist
	if csrfToken == "" {
		var err error
		csrfToken, err = generateCSRFToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate CSRF token", err, a.logger)
			return
		}

		// Set the CSRF token as an HttpOnly cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			HttpOnly: true,
			Secure:   a.config.API.TLS,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   3600, // 1 hour
		})
	}

	response := map[string]string{
		"csrf_token": csrfToken,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getAuthConfig godoc
//
//	@Summary		Get authentication configuration
//	@Description	Returns authentication configuration for client-side use (public endpoint, no sensitive data)
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Router			/api/auth/config [get]
func (a *API) getAuthConfig(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Only return non-sensitive configuration data
	// Do NOT expose: JWT secrets, password hashes, internal URLs, etc.
	response := map[string]interface{}{
		"authEnabled": a.config.Auth.Enabled,
	}

	// Include additional non-sensitive auth config if auth is enabled
	if a.config.Auth.Enabled {
		response["sessionTimeout"] = int(core.JWTTokenExpiry.Seconds())
		response["passwordPolicy"] = map[string]interface{}{
			"minLength":      8,
			"maxLength":      128,
			"requireUpper":   false, // Can be enhanced later
			"requireLower":   false,
			"requireNumber":  false,
			"requireSpecial": false,
		}
		response["usernamePolicy"] = map[string]interface{}{
			"minLength":         3,
			"maxLength":         50,
			"allowedChars":      "alphanumeric, underscore, hyphen",
			"allowedCharsRegex": "^[a-zA-Z0-9_-]+$",
		}
		// SECURITY: Not exposing maxLoginAttempts or bcryptCost to prevent information disclosure
		// that could help attackers optimize brute force or timing attacks
	}

	a.respondJSON(w, response, http.StatusOK)
}
