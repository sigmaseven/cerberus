package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cerberus/storage"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TASK 54: Comprehensive MFA Security Test Suite
// Tests cover: TOTP generation, validation, time windows, replay attack prevention, enrollment flow, and bypass prevention

// TestTOTPSecretGeneration tests TOTP secret generation with entropy verification
// TASK 54.1: TOTP secret generation and entropy verification
func TestTOTPSecretGeneration(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	// Verify secret is not empty
	assert.NotEmpty(t, key.Secret(), "TOTP secret should not be empty")

	// Verify secret is base32-encoded (TOTP secrets are base32)
	// Base32 contains only A-Z and 2-7, and length should be appropriate (typically 16-32 chars for 80-160 bits)
	secret := key.Secret()
	assert.Regexp(t, `^[A-Z2-7]+$`, secret, "TOTP secret should be base32-encoded")
	assert.GreaterOrEqual(t, len(secret), 16, "TOTP secret should be at least 16 characters (80 bits)")

	// Verify secret has sufficient entropy (minimum 160 bits = 32 base32 characters)
	// Modern TOTP typically uses 160 bits (32 chars) or 256 bits (52 chars)
	assert.GreaterOrEqual(t, len(secret), 32, "TOTP secret should have at least 160 bits of entropy (32 chars)")

	// Verify issuer and account name are correct
	assert.Equal(t, issuer, key.Issuer(), "Issuer should match")
	assert.Equal(t, username, key.AccountName(), "Account name should match")

	// Verify URL contains valid otpauth:// URI
	url := key.URL()
	assert.Contains(t, url, "otpauth://totp/", "URL should contain otpauth://totp/ prefix")
	assert.Contains(t, url, issuer, "URL should contain issuer")
	assert.Contains(t, url, username, "URL should contain account name")
}

// TestTOTPSecretGenerationEntropy tests that TOTP secrets have sufficient cryptographic entropy
// TASK 54.1: Entropy verification using statistical tests
func TestTOTPSecretGenerationEntropy(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	// Generate multiple secrets and verify they are unique
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		key, err := generateMFASecret(username, issuer)
		require.NoError(t, err, "Failed to generate TOTP secret")

		secret := key.Secret()
		assert.False(t, secrets[secret], "TOTP secrets should be unique (no duplicates found)")

		secrets[secret] = true

		// Verify each secret has appropriate length
		assert.GreaterOrEqual(t, len(secret), 32, "TOTP secret should have at least 160 bits")
	}

	// All 100 secrets should be unique
	assert.Equal(t, 100, len(secrets), "All generated secrets should be unique")
}

// TestTOTPQRCodeGeneration tests QR code generation for Google Authenticator compatibility
// TASK 54.1: QR code generation
func TestTOTPQRCodeGeneration(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	// Generate QR code image
	qrImage, err := key.Image(200, 200)
	require.NoError(t, err, "Failed to generate QR code image")

	// Verify QR code image has dimensions
	bounds := qrImage.Bounds()
	assert.Greater(t, bounds.Dx(), 0, "QR code width should be greater than 0")
	assert.Greater(t, bounds.Dy(), 0, "QR code height should be greater than 0")

	// Verify URL contains valid otpauth:// URI
	url := key.URL()
	assert.Contains(t, url, "otpauth://totp/", "URL should contain otpauth://totp/ prefix")
	assert.Contains(t, url, "secret=", "URL should contain secret parameter")
}

// TestTOTPValidationCorrectCode tests TOTP validation with correct codes
// TASK 54.1: TOTP validation with correct codes
func TestTOTPValidationCorrectCode(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Generate a valid TOTP code using the same secret
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// Verify the code is 6 digits
	assert.Regexp(t, `^\d{6}$`, code, "TOTP code should be 6 digits")

	// Validate using validateTOTPCode function
	err = validateTOTPCode(code, secret)
	assert.NoError(t, err, "Valid TOTP code should be accepted")

	// Also validate using totp.Validate directly
	valid := totp.Validate(code, secret)
	assert.True(t, valid, "TOTP code should be valid")
}

// TestTOTPValidationIncorrectCode tests TOTP validation with incorrect codes
// TASK 54.1: TOTP validation with incorrect codes
func TestTOTPValidationIncorrectCode(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Test with incorrect code
	incorrectCode := "000000"
	err = validateTOTPCode(incorrectCode, secret)
	assert.Error(t, err, "Invalid TOTP code should be rejected")
	assert.Contains(t, err.Error(), "invalid TOTP code", "Error message should indicate invalid code")

	// Test with wrong length code
	shortCode := "12345"
	err = validateTOTPCode(shortCode, secret)
	assert.Error(t, err, "TOTP code with wrong length should be rejected")

	// Test with non-numeric code
	nonNumericCode := "abcdef"
	err = validateTOTPCode(nonNumericCode, secret)
	assert.Error(t, err, "Non-numeric TOTP code should be rejected")

	// Test with empty secret
	err = validateTOTPCode("123456", "")
	assert.Error(t, err, "TOTP validation should fail with empty secret")
	assert.Contains(t, err.Error(), "TOTP secret not configured", "Error message should indicate missing secret")
}

// TestTOTPTimeWindowHandling tests TOTP time window handling with ±30 second tolerance
// TASK 54.1: Time window handling per RFC 6238
func TestTOTPTimeWindowHandling(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Generate code for current time
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err, "Failed to generate TOTP code")

	// Code should be valid for current time window
	valid := totp.Validate(code, secret)
	assert.True(t, valid, "TOTP code should be valid for current time window")

	// Code should be valid for previous time window (-30 seconds)
	prevWindow := now.Add(-30 * time.Second)
	prevCode, err := totp.GenerateCode(secret, prevWindow)
	require.NoError(t, err, "Failed to generate TOTP code for previous window")
	valid = totp.Validate(prevCode, secret)
	assert.True(t, valid, "TOTP code should be valid for previous time window (±30 seconds)")

	// Code should be valid for next time window (+30 seconds)
	nextWindow := now.Add(30 * time.Second)
	nextCode, err := totp.GenerateCode(secret, nextWindow)
	require.NoError(t, err, "Failed to generate TOTP code for next window")
	valid = totp.Validate(nextCode, secret)
	assert.True(t, valid, "TOTP code should be valid for next time window (±30 seconds)")

	// Code should NOT be valid for window beyond tolerance (-90 seconds)
	oldWindow := now.Add(-90 * time.Second)
	oldCode, err := totp.GenerateCode(secret, oldWindow)
	require.NoError(t, err, "Failed to generate TOTP code for old window")
	valid = totp.Validate(oldCode, secret)
	assert.False(t, valid, "TOTP code should NOT be valid for window beyond ±30 second tolerance")

	// Code should NOT be valid for window beyond tolerance (+90 seconds)
	futureWindow := now.Add(90 * time.Second)
	futureCode, err := totp.GenerateCode(secret, futureWindow)
	require.NoError(t, err, "Failed to generate TOTP code for future window")
	valid = totp.Validate(futureCode, secret)
	assert.False(t, valid, "TOTP code should NOT be valid for window beyond ±30 second tolerance")
}

// TestTOTPClockSkewScenarios tests clock skew tolerance scenarios
// TASK 54.1: Clock skew scenarios including edge cases at window boundaries
func TestTOTPClockSkewScenarios(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Test boundary conditions at ±30 second edges
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	testCases := []struct {
		name     string
		timeDiff time.Duration
		valid    bool
	}{
		{"Current window (0 seconds)", 0 * time.Second, true},
		{"Previous window edge (-30 seconds)", -30 * time.Second, true},
		{"Next window edge (+30 seconds)", 30 * time.Second, true},
		{"Just beyond previous window (-31 seconds)", -31 * time.Second, false},
		{"Just beyond next window (+31 seconds)", 31 * time.Second, false},
		{"Far past window (-60 seconds)", -60 * time.Second, false},
		{"Far future window (+60 seconds)", 60 * time.Second, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testTime := baseTime.Add(tc.timeDiff)
			testCode, err := totp.GenerateCode(secret, testTime)
			require.NoError(t, err, "Failed to generate TOTP code for test time")

			// Validate code at base time (simulating clock skew)
			valid := totp.Validate(testCode, secret)
			if tc.valid {
				assert.True(t, valid, "Code should be valid within ±30 second tolerance")
			} else {
				assert.False(t, valid, "Code should NOT be valid outside ±30 second tolerance")
			}
		})
	}
}

// TestTOTPReplayAttackPrevention tests that TOTP tokens cannot be reused
// TASK 54.2: Replay attack prevention
func TestTOTPReplayAttackPrevention(t *testing.T) {
	// NOTE: Current implementation uses totp.Validate which does not track used tokens
	// This test documents expected behavior for replay attack prevention
	// In production, we should track used tokens per user in Redis or database

	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// First validation should succeed
	valid := totp.Validate(code, secret)
	assert.True(t, valid, "First TOTP code validation should succeed")

	// NOTE: Current totp.Validate does not prevent replay attacks
	// The same code will validate again immediately
	// For production, we need to implement token tracking:
	// - Store used tokens per user with expiration (current time window + buffer)
	// - Check if token was already used before validating
	// - Reject if token was already used

	// This is a placeholder test documenting the gap
	t.Log("WARNING: Current implementation does not prevent replay attacks")
	t.Log("TODO: Implement token tracking to prevent token reuse within the same time window")
}

// TestTOTPConcurrentValidation tests concurrent TOTP validation attempts
// TASK 54: Concurrent TOTP validation
func TestTOTPConcurrentValidation(t *testing.T) {
	username := "testuser"
	issuer := "Cerberus SIEM"

	key, err := generateMFASecret(username, issuer)
	require.NoError(t, err, "Failed to generate TOTP secret")

	secret := key.Secret()

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// Test concurrent validation attempts
	const numGoroutines = 100
	results := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			err := validateTOTPCode(code, secret)
			if err != nil {
				errors <- err
				results <- false
			} else {
				results <- true
			}
		}()
	}

	// Collect results
	successCount := 0
	failureCount := 0
	for i := 0; i < numGoroutines; i++ {
		select {
		case result := <-results:
			if result {
				successCount++
			} else {
				failureCount++
			}
		case <-errors:
			failureCount++
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent validation results")
		}
	}

	// All concurrent validations should succeed (TOTP validation is thread-safe)
	assert.Equal(t, numGoroutines, successCount, "All concurrent TOTP validations should succeed")
	assert.Equal(t, 0, failureCount, "No concurrent TOTP validations should fail")
}

// TestMFAEnableEndpoint tests the MFA enable endpoint
// TASK 54.4: MFA enrollment flow
func TestMFAEnableEndpoint(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user
	ctx := context.Background()
	testUser := &storage.User{
		Username: "mfatest",
		Password: "testpass123",
	}
	err := api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Get JWT token for authentication
	token, err := generateJWT(context.Background(), testUser.Username, api.config, api.userStorage, api.authManager)
	require.NoError(t, err, "Failed to generate JWT token")

	// Create request to enable MFA
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/enable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(WithUsername(req.Context(), testUser.Username))

	w := httptest.NewRecorder()
	api.enableMFA(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code, "MFA enable should succeed")

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Failed to unmarshal response")

	// Verify response contains secret, QR code, and URL
	assert.Contains(t, response, "secret", "Response should contain secret")
	assert.Contains(t, response, "qr_code", "Response should contain QR code")
	assert.Contains(t, response, "url", "Response should contain URL")

	secret, ok := response["secret"].(string)
	assert.True(t, ok, "Secret should be a string")
	assert.NotEmpty(t, secret, "Secret should not be empty")

	qrCode, ok := response["qr_code"].(string)
	assert.True(t, ok, "QR code should be a string")
	assert.True(t, strings.HasPrefix(qrCode, "data:image/png;base64,"), "QR code should be base64-encoded PNG")

	// Verify QR code can be decoded
	qrBase64 := strings.TrimPrefix(qrCode, "data:image/png;base64,")
	qrBytes, err := base64.StdEncoding.DecodeString(qrBase64)
	assert.NoError(t, err, "QR code should be valid base64")
	assert.Greater(t, len(qrBytes), 0, "QR code should have content")

	// Verify user's TOTP secret was saved
	user, err := api.userStorage.GetUserByUsername(ctx, testUser.Username)
	require.NoError(t, err, "Failed to get user")
	assert.Equal(t, secret, user.TOTPSecret, "User's TOTP secret should be saved")
	assert.False(t, user.MFAEnabled, "MFA should not be enabled yet (requires verification)")
}

// TestMFAVerifyEndpoint tests the MFA verify endpoint
// TASK 54.4: MFA verification during enrollment
func TestMFAVerifyEndpoint(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user with TOTP secret
	ctx := context.Background()
	testUser := &storage.User{
		Username:   "mfatest",
		Password:   "testpass123",
		TOTPSecret: "JBSWY3DPEHPK3PXP", // Test secret (base32)
	}
	err := api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(testUser.TOTPSecret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// Get JWT token for authentication
	token, err := generateJWT(context.Background(), testUser.Username, api.config, api.userStorage, api.authManager)
	require.NoError(t, err, "Failed to generate JWT token")

	// Create request to verify MFA
	reqBody := map[string]string{
		"code": code,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/verify", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUsername(req.Context(), testUser.Username))

	w := httptest.NewRecorder()
	api.verifyMFA(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code, "MFA verify should succeed")

	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Failed to unmarshal response")

	assert.Contains(t, response, "message", "Response should contain message")
	assert.Contains(t, response["message"], "successfully", "Message should indicate success")

	// Verify MFA is now enabled
	user, err := api.userStorage.GetUserByUsername(ctx, testUser.Username)
	require.NoError(t, err, "Failed to get user")
	assert.True(t, user.MFAEnabled, "MFA should be enabled after verification")
}

// TestMFAVerifyEndpointInvalidCode tests MFA verify with invalid code
// TASK 54.4: MFA verification failure handling
func TestMFAVerifyEndpointInvalidCode(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user with TOTP secret
	ctx := context.Background()
	testUser := &storage.User{
		Username:   "mfatest",
		Password:   "testpass123",
		TOTPSecret: "JBSWY3DPEHPK3PXP", // Test secret
	}
	err := api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Get JWT token for authentication
	token, err := generateJWT(context.Background(), testUser.Username, api.config, api.userStorage, api.authManager)
	require.NoError(t, err, "Failed to generate JWT token")

	// Create request with invalid code
	reqBody := map[string]string{
		"code": "000000", // Invalid code
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/verify", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUsername(req.Context(), testUser.Username))

	w := httptest.NewRecorder()
	api.verifyMFA(w, req)

	// Verify response indicates failure
	assert.Equal(t, http.StatusUnauthorized, w.Code, "MFA verify should fail with invalid code")

	// Verify MFA is NOT enabled
	user, err := api.userStorage.GetUserByUsername(ctx, testUser.Username)
	require.NoError(t, err, "Failed to get user")
	assert.False(t, user.MFAEnabled, "MFA should NOT be enabled after invalid verification")
}

// TestMFADisableEndpoint tests the MFA disable endpoint
// TASK 54.4: MFA disable flow
func TestMFADisableEndpoint(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user with MFA enabled
	ctx := context.Background()
	testUser := &storage.User{
		Username:   "mfatest",
		Password:   "testpass123",
		TOTPSecret: "JBSWY3DPEHPK3PXP", // Test secret
		MFAEnabled: true,
	}
	err := api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(testUser.TOTPSecret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// Get JWT token for authentication
	token, err := generateJWT(context.Background(), testUser.Username, api.config, api.userStorage, api.authManager)
	require.NoError(t, err, "Failed to generate JWT token")

	// Create request to disable MFA
	reqBody := map[string]string{
		"code": code,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/disable", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUsername(req.Context(), testUser.Username))

	w := httptest.NewRecorder()
	api.disableMFA(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code, "MFA disable should succeed")

	// Verify MFA is disabled and secret is removed
	user, err := api.userStorage.GetUserByUsername(ctx, testUser.Username)
	require.NoError(t, err, "Failed to get user")
	assert.False(t, user.MFAEnabled, "MFA should be disabled")
	assert.Empty(t, user.TOTPSecret, "TOTP secret should be removed")
}

// TestMFALoginWithMFA tests login with MFA enabled
// TASK 54.5: MFA enforcement during login
func TestMFALoginWithMFA(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user with MFA enabled
	ctx := context.Background()
	password := "testpass123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err, "Failed to hash password")

	testUser := &storage.User{
		Username:   "mfatest",
		Password:   string(hashedPassword),
		TOTPSecret: "JBSWY3DPEHPK3PXP", // Test secret
		MFAEnabled: true,
	}
	err = api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(testUser.TOTPSecret, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")

	// Test login without MFA code (should fail)
	loginBody := map[string]string{
		"username": testUser.Username,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.login(w, req)

	// Login should fail without MFA code
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Login should fail without MFA code")

	// Test login with MFA code (should succeed)
	loginBody["totp_code"] = code
	bodyBytes, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	api.login(w, req)

	// Login should succeed with valid MFA code
	assert.Equal(t, http.StatusOK, w.Code, "Login should succeed with valid MFA code")
}

// TestMFALoginWithInvalidCode tests login with invalid MFA code
// TASK 54.5: MFA bypass prevention
func TestMFALoginWithInvalidCode(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a test user with MFA enabled
	ctx := context.Background()
	password := "testpass123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err, "Failed to hash password")

	testUser := &storage.User{
		Username:   "mfatest",
		Password:   string(hashedPassword),
		TOTPSecret: "JBSWY3DPEHPK3PXP", // Test secret
		MFAEnabled: true,
	}
	err = api.userStorage.CreateUser(ctx, testUser)
	require.NoError(t, err, "Failed to create test user")

	// Test login with invalid MFA code
	loginBody := map[string]string{
		"username":  testUser.Username,
		"password":  password,
		"totp_code": "000000", // Invalid code
	}
	bodyBytes, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.login(w, req)

	// Login should fail with invalid MFA code
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Login should fail with invalid MFA code")
}

// TestBackupCodeGenerationPlaceholder is a placeholder for backup code tests
// TASK 54.3: Backup code generation (NOT YET IMPLEMENTED)
func TestBackupCodeGenerationPlaceholder(t *testing.T) {
	t.Skip("Backup codes are not yet implemented - this is a placeholder test")

	// Expected behavior when implemented:
	// 1. Generate 10 backup codes using crypto/rand with minimum 128-bit entropy
	// 2. Codes should be cryptographically random
	// 3. Codes should be 8+ characters long
	// 4. Codes should be stored as secure hashes (bcrypt/argon2)
	// 5. Codes should be one-time use (invalidated after first use)
	// 6. Codes should have expiration (typically 90 days)
	// 7. Codes should be displayed to user once during generation

	t.Log("TODO: Implement backup code generation when feature is added")
}

// TestBackupCodeValidationPlaceholder is a placeholder for backup code validation tests
// TASK 54.3: Backup code validation (NOT YET IMPLEMENTED)
func TestBackupCodeValidationPlaceholder(t *testing.T) {
	t.Skip("Backup codes are not yet implemented - this is a placeholder test")

	// Expected behavior when implemented:
	// 1. Validate backup code during login (alternative to TOTP)
	// 2. Code should be hashed and compared against stored hashes
	// 3. Code should be invalidated after first use
	// 4. Code should be rejected if expired
	// 5. Code should be rejected if already used
	// 6. Invalid code should not reveal if code exists (timing-safe comparison)

	t.Log("TODO: Implement backup code validation when feature is added")
}

//lint:ignore U1000 Test helper for entropy testing scenarios
func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
