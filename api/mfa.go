package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"regexp"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// generateMFASecret generates a TOTP secret for a user
// TASK 8.3: MFA/TOTP implementation
// REQUIREMENT: docs/requirements/user-management-authentication-requirements.md Section 5.3
func generateMFASecret(username string, issuer string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return key, nil
}

// enableMFA godoc
//
//	@Summary		Enable MFA for current user
//	@Description	Generates a TOTP secret and QR code for MFA enrollment
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"QR code and secret"
//	@Failure		400	{string}	string	"Bad Request"
//	@Failure		401	{string}	string	"Unauthorized"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/auth/mfa/enable [post]
//	TASK 8.3: MFA enrollment endpoint
func (a *API) enableMFA(w http.ResponseWriter, r *http.Request) {
	if !a.config.Auth.Enabled {
		writeError(w, http.StatusNotImplemented, "Authentication is disabled", nil, a.logger)
		return
	}

	username := getUsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get current user
	user, err := a.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	// Generate TOTP secret
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate MFA secret", err, a.logger)
		return
	}

	// Store secret in database (but don't enable MFA yet - user needs to verify first)
	user.TOTPSecret = key.Secret()
	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save MFA secret", err, a.logger)
		return
	}

	// Generate QR code
	qrImage, err := key.Image(200, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate QR code", err, a.logger)
		return
	}

	// Convert QR code image to PNG bytes, then to base64
	var buf bytes.Buffer
	if err := png.Encode(&buf, qrImage); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode QR code", err, a.logger)
		return
	}
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	// SECURITY AUDIT: Log MFA enrollment
	a.logger.Infow("AUDIT: MFA enrollment initiated",
		"action", "mfa_enable",
		"outcome", "success",
		"username", username,
		"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
		"timestamp", time.Now().UTC())

	response := map[string]interface{}{
		"secret":  key.Secret(),
		"qr_code": "data:image/png;base64," + qrBase64,
		"url":     key.URL(),
		"message": "Scan QR code with authenticator app. Verify code to complete enrollment.",
	}
	a.respondJSON(w, response, http.StatusOK)
}

// verifyMFA godoc
//
//	@Summary		Verify and enable MFA
//	@Description	Verifies a TOTP code and enables MFA for the user
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			code	body		object{code=string}	true	"TOTP verification code"
//	@Success		200		{object}	map[string]string	"Success message"
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		401		{string}	string	"Unauthorized"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/auth/mfa/verify [post]
//	TASK 8.3: MFA verification endpoint
func (a *API) verifyMFA(w http.ResponseWriter, r *http.Request) {
	if !a.config.Auth.Enabled {
		writeError(w, http.StatusNotImplemented, "Authentication is disabled", nil, a.logger)
		return
	}

	username := getUsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	var req struct {
		Code string `json:"code" validate:"required,len=6"`
	}

	if err := a.decodeJSONBodyWithLimit(w, r, &req, int64(a.config.Security.LoginBodyLimit)); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON in request body", err, a.logger)
		return
	}

	// Validate code format (6 digits)
	if !regexp.MustCompile(`^\d{6}$`).MatchString(req.Code) {
		writeError(w, http.StatusBadRequest, "Invalid code format. Must be 6 digits", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user with secret
	user, err := a.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	if user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "MFA secret not found. Please enable MFA first", nil, a.logger)
		return
	}

	// Verify TOTP code
	valid := totp.Validate(req.Code, user.TOTPSecret)
	if !valid {
		// SECURITY AUDIT: Log failed MFA verification
		a.logger.Infow("AUDIT: MFA verification failed",
			"action", "mfa_verify",
			"outcome", "failure",
			"username", username,
			"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
			"reason", "invalid_code",
			"timestamp", time.Now().UTC())

		writeError(w, http.StatusUnauthorized, "Invalid verification code", nil, a.logger)
		return
	}

	// Enable MFA
	user.MFAEnabled = true
	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enable MFA", err, a.logger)
		return
	}

	// SECURITY AUDIT: Log successful MFA enrollment
	a.logger.Infow("AUDIT: MFA enabled",
		"action", "mfa_verify",
		"outcome", "success",
		"username", username,
		"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
		"timestamp", time.Now().UTC())

	response := map[string]string{
		"message": "MFA enabled successfully",
	}
	a.respondJSON(w, response, http.StatusOK)
}

// disableMFA godoc
//
//	@Summary		Disable MFA for current user
//	@Description	Disables MFA and removes TOTP secret
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			code	body		object{code=string}	true	"TOTP verification code for confirmation"
//	@Success		200		{object}	map[string]string	"Success message"
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		401		{string}	string	"Unauthorized"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/auth/mfa/disable [post]
//	TASK 8.3: MFA disable endpoint
func (a *API) disableMFA(w http.ResponseWriter, r *http.Request) {
	if !a.config.Auth.Enabled {
		writeError(w, http.StatusNotImplemented, "Authentication is disabled", nil, a.logger)
		return
	}

	username := getUsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	var req struct {
		Code string `json:"code" validate:"required,len=6"`
	}

	if err := a.decodeJSONBodyWithLimit(w, r, &req, int64(a.config.Security.LoginBodyLimit)); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON in request body", err, a.logger)
		return
	}

	// Validate code format
	if !regexp.MustCompile(`^\d{6}$`).MatchString(req.Code) {
		writeError(w, http.StatusBadRequest, "Invalid code format. Must be 6 digits", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user
	user, err := a.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "User not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get user", err, a.logger)
		return
	}

	if !user.MFAEnabled || user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "MFA is not enabled", nil, a.logger)
		return
	}

	// Verify code before disabling
	valid := totp.Validate(req.Code, user.TOTPSecret)
	if !valid {
		// SECURITY AUDIT: Log failed MFA disable attempt
		a.logger.Infow("AUDIT: MFA disable verification failed",
			"action", "mfa_disable",
			"outcome", "failure",
			"username", username,
			"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
			"reason", "invalid_code",
			"timestamp", time.Now().UTC())

		writeError(w, http.StatusUnauthorized, "Invalid verification code", nil, a.logger)
		return
	}

	// Disable MFA and remove secret
	user.MFAEnabled = false
	user.TOTPSecret = ""
	if err := a.userStorage.UpdateUser(ctx, user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disable MFA", err, a.logger)
		return
	}

	// SECURITY AUDIT: Log MFA disable
	a.logger.Infow("AUDIT: MFA disabled",
		"action", "mfa_disable",
		"outcome", "success",
		"username", username,
		"source_ip", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
		"timestamp", time.Now().UTC())

	response := map[string]string{
		"message": "MFA disabled successfully",
	}
	a.respondJSON(w, response, http.StatusOK)
}

// validateTOTPCode validates a TOTP code for a user
// TASK 8.3: TOTP validation helper for login
func validateTOTPCode(code, secret string) error {
	if secret == "" {
		return errors.New("TOTP secret not configured")
	}

	valid := totp.Validate(code, secret)
	if !valid {
		return errors.New("invalid TOTP code")
	}

	return nil
}
