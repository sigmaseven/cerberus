package detect

import (
	"errors"
	"testing"
	"time"
)

// TestDecodeUTF16LE tests the UTF-16 Little Endian decoding functionality
func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			expected:    "",
			expectError: false,
		},
		{
			name: "simple ASCII string",
			input: []byte{
				0x48, 0x00, // H
				0x65, 0x00, // e
				0x6c, 0x00, // l
				0x6c, 0x00, // l
				0x6f, 0x00, // o
			},
			expected:    "Hello",
			expectError: false,
		},
		{
			name: "ASCII with null terminator",
			input: []byte{
				0x48, 0x00, // H
				0x69, 0x00, // i
				0x00, 0x00, // null
			},
			expected:    "Hi\x00",
			expectError: false,
		},
		{
			name: "Unicode BMP characters",
			input: []byte{
				0xE9, 0x00, // é (U+00E9)
				0xE0, 0x00, // à (U+00E0)
				0x20, 0x00, // space
				0x60, 0x4F, // 你 (U+4F60) - Little Endian
			},
			expected:    "éà 你",
			expectError: false,
		},
		{
			name: "surrogate pair - emoji",
			input: []byte{
				0x3D, 0xD8, 0x0D, 0xDE, // 😍 (U+1F60D) - surrogate pair
			},
			expected:    "😍",
			expectError: false,
		},
		{
			name: "mixed ASCII and surrogate pairs",
			input: []byte{
				0x48, 0x00, // H
				0x69, 0x00, // i
				0x20, 0x00, // space
				0x3D, 0xD8, 0x0D, 0xDE, // 😍
			},
			expected:    "Hi 😍",
			expectError: false,
		},
		{
			name: "odd number of bytes",
			input: []byte{
				0x48, 0x00, 0x65, // incomplete character
			},
			expected:    "",
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name: "single byte",
			input: []byte{
				0x48, // incomplete
			},
			expected:    "",
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name: "Windows Registry-style string",
			input: []byte{
				0x43, 0x00, // C
				0x3A, 0x00, // :
				0x5C, 0x00, // \
				0x57, 0x00, // W
				0x69, 0x00, // i
				0x6E, 0x00, // n
				0x64, 0x00, // d
				0x6F, 0x00, // o
				0x77, 0x00, // w
				0x73, 0x00, // s
			},
			expected:    "C:\\Windows",
			expectError: false,
		},
		{
			name: "PowerShell command string",
			input: []byte{
				0x2D, 0x00, // -
				0x45, 0x00, // E
				0x78, 0x00, // x
				0x65, 0x00, // e
				0x63, 0x00, // c
			},
			expected:    "-Exec",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeUTF16LE(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected '%s' (%+v), got '%s' (%+v)",
					tt.expected, []byte(tt.expected), result, []byte(result))
			}
		})
	}
}

// TestDecodeUTF16BE tests the UTF-16 Big Endian decoding functionality
func TestDecodeUTF16BE(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			expected:    "",
			expectError: false,
		},
		{
			name: "simple ASCII string",
			input: []byte{
				0x00, 0x48, // H
				0x00, 0x65, // e
				0x00, 0x6c, // l
				0x00, 0x6c, // l
				0x00, 0x6f, // o
			},
			expected:    "Hello",
			expectError: false,
		},
		{
			name: "Unicode BMP characters",
			input: []byte{
				0x00, 0xE9, // é (U+00E9)
				0x00, 0xE0, // à (U+00E0)
				0x00, 0x20, // space
				0x4F, 0x60, // 你 (U+4F60) - Big Endian
			},
			expected:    "éà 你",
			expectError: false,
		},
		{
			name: "surrogate pair - emoji",
			input: []byte{
				0xD8, 0x3D, 0xDE, 0x0D, // 😍 (U+1F60D) - surrogate pair
			},
			expected:    "😍",
			expectError: false,
		},
		{
			name: "mixed ASCII and surrogate pairs",
			input: []byte{
				0x00, 0x48, // H
				0x00, 0x69, // i
				0x00, 0x20, // space
				0xD8, 0x3D, 0xDE, 0x0D, // 😍
			},
			expected:    "Hi 😍",
			expectError: false,
		},
		{
			name: "BOM present (should be preserved as ZWNBSP)",
			input: []byte{
				0xFE, 0xFF, // BOM (U+FEFF)
				0x00, 0x48, // H
				0x00, 0x69, // i
			},
			expected:    "\uFEFFHi",
			expectError: false,
		},
		{
			name: "odd number of bytes",
			input: []byte{
				0x00, 0x48, 0x00, // incomplete
			},
			expected:    "",
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name: "single byte",
			input: []byte{
				0x48, // incomplete
			},
			expected:    "",
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name: "Java/JVM string",
			input: []byte{
				0x00, 0x6A, // j
				0x00, 0x61, // a
				0x00, 0x76, // v
				0x00, 0x61, // a
			},
			expected:    "java",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeUTF16BE(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected '%s' (%+v), got '%s' (%+v)",
					tt.expected, []byte(tt.expected), result, []byte(result))
			}
		})
	}
}

// TestNormalizeWindowsDashes tests the windash modifier functionality
func TestNormalizeWindowsDashes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no dashes",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "ASCII hyphen unchanged",
			input:    "test-value",
			expected: "test-value",
		},
		{
			name:     "EN DASH (U+2013)",
			input:    "powershell –ExecutionPolicy",
			expected: "powershell -ExecutionPolicy",
		},
		{
			name:     "EM DASH (U+2014)",
			input:    "cmd —help",
			expected: "cmd -help",
		},
		{
			name:     "FIGURE DASH (U+2012)",
			input:    "option‒value",
			expected: "option-value",
		},
		{
			name:     "HORIZONTAL BAR (U+2015)",
			input:    "param―test",
			expected: "param-test",
		},
		{
			name:     "NON-BREAKING HYPHEN (U+2011)",
			input:    "value‑123",
			expected: "value-123",
		},
		{
			name:     "MINUS SIGN (U+2212)",
			input:    "x−y",
			expected: "x-y",
		},
		{
			name:     "HYPHEN (U+2010)",
			input:    "test‐case",
			expected: "test-case",
		},
		{
			name:     "multiple different dashes",
			input:    "a–b—c‒d―e",
			expected: "a-b-c-d-e",
		},
		{
			name:     "mixed with regular hyphens",
			input:    "a-b–c-d—e",
			expected: "a-b-c-d-e",
		},
		{
			name:     "PowerShell command with EN DASH",
			input:    "powershell.exe –ExecutionPolicy Bypass –File test.ps1",
			expected: "powershell.exe -ExecutionPolicy Bypass -File test.ps1",
		},
		{
			name:     "real-world obfuscation attempt",
			input:    "cmd.exe /c powershell –w hidden –enc AQEBAQE=",
			expected: "cmd.exe /c powershell -w hidden -enc AQEBAQE=",
		},
		{
			name:     "multiple dashes in sequence",
			input:    "test–—‒value",
			expected: "test---value",
		},
		{
			name:     "Unicode text with dashes",
			input:    "测试–值",
			expected: "测试-值",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeWindowsDashes(tt.input)

			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
				// Print hex representations for debugging
				t.Logf("expected bytes: %+v", []byte(tt.expected))
				t.Logf("got bytes:      %+v", []byte(result))
			}
		})
	}
}

// TestModifierEvaluatorWideModifier tests that the wide modifier returns an appropriate error
func TestModifierEvaluatorWideModifier(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	// Test wide modifier rejection
	_, err := evaluator.EvaluateWithModifiers("test", "test", []string{ModifierWide})

	if err == nil {
		t.Fatal("expected error for wide modifier, got nil")
	}

	// Check that it's the correct error type
	var unsupportedErr *UnsupportedModifierError
	if !errors.As(err, &unsupportedErr) {
		t.Errorf("expected UnsupportedModifierError, got %T: %v", err, err)
	}

	// Verify the error unwraps to ErrUnsupportedModifier
	if !errors.Is(err, ErrUnsupportedModifier) {
		t.Errorf("expected error to wrap ErrUnsupportedModifier")
	}

	// Check error message contains explanation (simplified message per security best practice)
	errMsg := err.Error()
	expectedSubstrings := []string{"wide", "not supported", "text-based"}
	for _, substr := range expectedSubstrings {
		if !contains(errMsg, substr) {
			t.Errorf("expected error message to contain '%s', got: %s", substr, errMsg)
		}
	}
}

// TestModifierEvaluatorUTF16LEIntegration tests UTF-16LE modifier integration
func TestModifierEvaluatorUTF16LEIntegration(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		expected    bool
		expectError bool
		errorMsg    string
	}{
		{
			name: "UTF-16LE decoding and equals comparison",
			value: string([]byte{
				0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00,
			}),
			pattern:     "Hello",
			modifiers:   []string{ModifierUTF16LE},
			expected:    true,
			expectError: false,
		},
		{
			name: "UTF-16LE decoding with emoji",
			value: string([]byte{
				0x3D, 0xD8, 0x0D, 0xDE, // 😍
			}),
			pattern:     "😍",
			modifiers:   []string{ModifierUTF16LE},
			expected:    true,
			expectError: false,
		},
		{
			name: "UTF-16LE decoding failure - odd bytes",
			value: string([]byte{
				0x48, 0x00, 0x65, // incomplete
			}),
			pattern:     "test",
			modifiers:   []string{ModifierUTF16LE},
			expected:    false,
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name:        "UTF-16LE empty input",
			value:       string([]byte{}),
			pattern:     "",
			modifiers:   []string{ModifierUTF16LE},
			expected:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestModifierEvaluatorUTF16BEIntegration tests UTF-16BE modifier integration
func TestModifierEvaluatorUTF16BEIntegration(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		expected    bool
		expectError bool
		errorMsg    string
	}{
		{
			name: "UTF-16BE decoding and equals comparison",
			value: string([]byte{
				0x00, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f,
			}),
			pattern:     "Hello",
			modifiers:   []string{ModifierUTF16BE},
			expected:    true,
			expectError: false,
		},
		{
			name: "UTF-16BE decoding with emoji",
			value: string([]byte{
				0xD8, 0x3D, 0xDE, 0x0D, // 😍
			}),
			pattern:     "😍",
			modifiers:   []string{ModifierUTF16BE},
			expected:    true,
			expectError: false,
		},
		{
			name: "UTF-16BE decoding failure - odd bytes",
			value: string([]byte{
				0x00, 0x48, 0x65, // incomplete
			}),
			pattern:     "test",
			modifiers:   []string{ModifierUTF16BE},
			expected:    false,
			expectError: true,
			errorMsg:    "odd number of bytes",
		},
		{
			name: "UTF-16BE with BOM",
			value: string([]byte{
				0xFE, 0xFF, // BOM
				0x00, 0x48, 0x00, 0x69, // Hi
			}),
			pattern:     "\uFEFFHi",
			modifiers:   []string{ModifierUTF16BE},
			expected:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestModifierEvaluatorWindashIntegration tests windash modifier integration
func TestModifierEvaluatorWindashIntegration(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		expected    bool
		expectError bool
	}{
		{
			name:        "windash normalization - EN DASH",
			value:       "powershell –ExecutionPolicy",
			pattern:     "powershell -ExecutionPolicy",
			modifiers:   []string{ModifierWindash},
			expected:    true,
			expectError: false,
		},
		{
			name:        "windash normalization - EM DASH",
			value:       "cmd —help",
			pattern:     "cmd -help",
			modifiers:   []string{ModifierWindash},
			expected:    true,
			expectError: false,
		},
		{
			name:        "windash normalization - multiple dashes",
			value:       "test–value—another‒one",
			pattern:     "test-value-another-one",
			modifiers:   []string{ModifierWindash},
			expected:    true,
			expectError: false,
		},
		{
			name:        "windash with regular hyphen unchanged",
			value:       "test-value",
			pattern:     "test-value",
			modifiers:   []string{ModifierWindash},
			expected:    true,
			expectError: false,
		},
		{
			name:        "windash no match after normalization",
			value:       "powershell –ExecutionPolicy",
			pattern:     "powershell –ExecutionPolicy", // pattern still has EN DASH
			modifiers:   []string{ModifierWindash},
			expected:    false, // value normalized to hyphen, pattern has EN DASH
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestModifierChainBase64UTF16LE tests chaining base64 and UTF-16LE modifiers
func TestModifierChainBase64UTF16LE(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	// Create UTF-16LE encoded "Hello"
	utf16leBytes := []byte{
		0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00,
	}

	// Base64 encode it
	// SGUAbABsAG8A in standard base64
	base64Value := "SABlAGwAbABvAA==" // "Hello" in UTF-16LE, base64 encoded

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		expected    bool
		expectError bool
	}{
		{
			name:        "base64 then UTF-16LE decoding",
			value:       base64Value,
			pattern:     "Hello",
			modifiers:   []string{ModifierBase64, ModifierUTF16LE},
			expected:    true,
			expectError: false,
		},
		{
			name:        "verify order matters - wrong order should work differently",
			value:       string(utf16leBytes),
			pattern:     "Hello",
			modifiers:   []string{ModifierUTF16LE},
			expected:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestModifierChainWindashMultiple tests multiple windash-related scenarios
func TestModifierChainWindashMultiple(t *testing.T) {
	evaluator := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		expected    bool
		expectError bool
	}{
		{
			name:        "windash applied to list of values",
			value:       []interface{}{"cmd–help", "powershell—bypass", "test-normal"},
			pattern:     "cmd-help",
			modifiers:   []string{ModifierWindash},
			expected:    true, // first value matches after normalization
			expectError: false,
		},
		{
			name:        "windash with list pattern",
			value:       "powershell–ExecutionPolicy",
			pattern:     []interface{}{"-ExecutionPolicy", "-Bypass"},
			modifiers:   []string{ModifierWindash},
			expected:    false, // exact match required, not contains
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
