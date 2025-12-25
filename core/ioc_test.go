package core

import (
	"strings"
	"testing"
	"time"
)

// =============================================================================
// IOC Type Validation Tests
// =============================================================================

func TestIOCType_IsValid(t *testing.T) {
	tests := []struct {
		iocType IOCType
		valid   bool
	}{
		{IOCTypeIP, true},
		{IOCTypeCIDR, true},
		{IOCTypeDomain, true},
		{IOCTypeHash, true},
		{IOCTypeURL, true},
		{IOCTypeEmail, true},
		{IOCTypeFilename, true},
		{IOCTypeRegKey, true},
		{IOCTypeCVE, true},
		{IOCTypeJA3, true},
		{"invalid", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.iocType), func(t *testing.T) {
			if tc.iocType.IsValid() != tc.valid {
				t.Errorf("IOCType(%s).IsValid() = %v, want %v", tc.iocType, tc.iocType.IsValid(), tc.valid)
			}
		})
	}
}

// =============================================================================
// IOC Value Validation Tests
// =============================================================================

func TestValidateIOCValue_IP(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"2001:db8::1", false},
		{"not-an-ip", true},
		{"192.168.1.256", true},
		{"", true},
		{"192.168.1.1.1", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeIP, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_CIDR(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"192.168.0.0/24", false},
		{"10.0.0.0/8", false},
		{"2001:db8::/32", false},
		{"192.168.0.0/33", true}, // Invalid prefix length
		{"not-a-cidr", true},
		{"192.168.0.1", true}, // Missing prefix
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeCIDR, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_Domain(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"example.com", false},
		{"subdomain.example.com", false},
		{"a-hyphenated-domain.org", false},
		{"not a domain", true},
		{"invalid.", true},
		{".invalid", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeDomain, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_Hash(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{"valid MD5", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"valid SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", false},
		{"valid SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"valid SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", false},
		{"invalid length", "abc123", true},
		{"not hex", "g41d8cd98f00b204e9800998ecf8427e", true},
		{"empty", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeHash, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_URL(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"https://example.com", false},
		{"http://example.com/path", false},
		{"https://example.com:8080/path?query=1", false},
		{"ftp://example.com", true}, // Not http/https
		{"not-a-url", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeURL, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_Email(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"user@example.com", false},
		{"user.name@example.com", false},
		{"user+tag@example.com", false},
		{"not-an-email", true},
		{"@example.com", true},
		{"user@", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeEmail, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_CVE(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"CVE-2021-44228", false},
		{"CVE-2023-12345", false},
		{"cve-2021-44228", false}, // Lowercase should work
		{"CVE-202-1234", true},    // Year too short
		{"CVE-2021-123", true},    // ID too short
		{"not-a-cve", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeCVE, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_JA3(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", false}, // Valid 32-char hex
		{"abc123", true},                            // Too short
		{"g41d8cd98f00b204e9800998ecf8427e", true},  // Invalid hex char
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeJA3, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_RegistryKey(t *testing.T) {
	tests := []struct {
		value       string
		expectError bool
	}{
		{"HKEY_LOCAL_MACHINE\\SOFTWARE\\Test", false},
		{"HKLM\\SOFTWARE\\Test", false},
		{"HKCU\\Software\\Microsoft", false},
		{"not-a-registry-key", true},
		{"C:\\Windows\\System32", true}, // File path, not registry
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			err := ValidateIOCValue(IOCTypeRegKey, tc.value)
			if tc.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIOCValue_MaxLength(t *testing.T) {
	// Test that values exceeding max length are rejected
	longValue := strings.Repeat("x", MaxIOCValueLength+1)
	err := ValidateIOCValue(IOCTypeFilename, longValue)
	if err == nil {
		t.Error("Expected error for value exceeding max length")
	}
}

// =============================================================================
// IOC Normalization Tests
// =============================================================================

func TestNormalizeIOCValue(t *testing.T) {
	tests := []struct {
		iocType  IOCType
		input    string
		expected string
	}{
		{IOCTypeIP, "  192.168.1.1  ", "192.168.1.1"},
		{IOCTypeDomain, "EXAMPLE.COM", "example.com"},
		{IOCTypeHash, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"},
		{IOCTypeCVE, "cve-2021-44228", "CVE-2021-44228"},
		{IOCTypeEmail, "User@Example.COM", "User@example.com"}, // Local part preserved
	}

	for _, tc := range tests {
		t.Run(string(tc.iocType), func(t *testing.T) {
			result := NormalizeIOCValue(tc.iocType, tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeIOCValue(%s, %q) = %q, want %q", tc.iocType, tc.input, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// IOC Creation Tests
// =============================================================================

func TestNewIOC(t *testing.T) {
	ioc, err := NewIOC(IOCTypeIP, "192.168.1.1", "test-source", "test-user")
	if err != nil {
		t.Fatalf("Failed to create IOC: %v", err)
	}

	if ioc.ID == "" {
		t.Error("IOC ID should not be empty")
	}
	if ioc.Type != IOCTypeIP {
		t.Errorf("Type = %s, want %s", ioc.Type, IOCTypeIP)
	}
	if ioc.Value != "192.168.1.1" {
		t.Errorf("Value = %s, want %s", ioc.Value, "192.168.1.1")
	}
	if ioc.Status != IOCStatusActive {
		t.Errorf("Status = %s, want %s", ioc.Status, IOCStatusActive)
	}
	if ioc.Severity != IOCSeverityMedium {
		t.Errorf("Severity = %s, want %s", ioc.Severity, IOCSeverityMedium)
	}
	if ioc.Confidence != 50.0 {
		t.Errorf("Confidence = %f, want %f", ioc.Confidence, 50.0)
	}
}

func TestNewIOC_InvalidType(t *testing.T) {
	_, err := NewIOC("invalid", "value", "source", "user")
	if err == nil {
		t.Error("Expected error for invalid IOC type")
	}
}

func TestNewIOC_InvalidValue(t *testing.T) {
	_, err := NewIOC(IOCTypeIP, "not-an-ip", "source", "user")
	if err == nil {
		t.Error("Expected error for invalid IP value")
	}
}

// =============================================================================
// IOC Validation Tests
// =============================================================================

func TestIOC_Validate(t *testing.T) {
	ioc, _ := NewIOC(IOCTypeIP, "192.168.1.1", "test", "user")

	// Valid IOC should pass
	if err := ioc.Validate(); err != nil {
		t.Errorf("Valid IOC failed validation: %v", err)
	}

	// Invalid confidence
	ioc.Confidence = 150
	if err := ioc.Validate(); err == nil {
		t.Error("Expected error for confidence > 100")
	}
	ioc.Confidence = 50

	// Too many tags
	ioc.Tags = make([]string, MaxIOCTagCount+1)
	if err := ioc.Validate(); err == nil {
		t.Error("Expected error for too many tags")
	}
	ioc.Tags = []string{}

	// Description too long
	ioc.Description = strings.Repeat("x", MaxIOCDescriptionLength+1)
	if err := ioc.Validate(); err == nil {
		t.Error("Expected error for description too long")
	}
}

// =============================================================================
// Hunt Creation Tests
// =============================================================================

func TestNewIOCHunt(t *testing.T) {
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	hunt, err := NewIOCHunt([]string{"ioc-1", "ioc-2"}, start, end, "test-user")
	if err != nil {
		t.Fatalf("Failed to create hunt: %v", err)
	}

	if hunt.ID == "" {
		t.Error("Hunt ID should not be empty")
	}
	if hunt.Status != HuntStatusPending {
		t.Errorf("Status = %s, want %s", hunt.Status, HuntStatusPending)
	}
	if len(hunt.IOCIDs) != 2 {
		t.Errorf("IOCIDs count = %d, want 2", len(hunt.IOCIDs))
	}
}

func TestNewIOCHunt_InvalidTimeRange(t *testing.T) {
	// End before start
	_, err := NewIOCHunt([]string{"ioc-1"}, time.Now(), time.Now().Add(-1*time.Hour), "user")
	if err == nil {
		t.Error("Expected error when end is before start")
	}

	// Time range too long
	_, err = NewIOCHunt([]string{"ioc-1"}, time.Now().Add(-100*24*time.Hour), time.Now(), "user")
	if err == nil {
		t.Error("Expected error when time range exceeds maximum")
	}

	// Future end time
	_, err = NewIOCHunt([]string{"ioc-1"}, time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour), "user")
	if err == nil {
		t.Error("Expected error when end time is in the future")
	}
}

func TestNewIOCHunt_NoIOCs(t *testing.T) {
	_, err := NewIOCHunt([]string{}, time.Now().Add(-1*time.Hour), time.Now(), "user")
	if err == nil {
		t.Error("Expected error when no IOC IDs provided")
	}
}

// =============================================================================
// Hunt Status Tests
// =============================================================================

func TestHuntStatus_IsValid(t *testing.T) {
	tests := []struct {
		status HuntStatus
		valid  bool
	}{
		{HuntStatusPending, true},
		{HuntStatusRunning, true},
		{HuntStatusCompleted, true},
		{HuntStatusFailed, true},
		{HuntStatusCancelled, true},
		{"invalid", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.status), func(t *testing.T) {
			if tc.status.IsValid() != tc.valid {
				t.Errorf("HuntStatus(%s).IsValid() = %v, want %v", tc.status, tc.status.IsValid(), tc.valid)
			}
		})
	}
}

func TestHuntStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   HuntStatus
		terminal bool
	}{
		{HuntStatusPending, false},
		{HuntStatusRunning, false},
		{HuntStatusCompleted, true},
		{HuntStatusFailed, true},
		{HuntStatusCancelled, true},
	}

	for _, tc := range tests {
		t.Run(string(tc.status), func(t *testing.T) {
			if tc.status.IsTerminal() != tc.terminal {
				t.Errorf("HuntStatus(%s).IsTerminal() = %v, want %v", tc.status, tc.status.IsTerminal(), tc.terminal)
			}
		})
	}
}
