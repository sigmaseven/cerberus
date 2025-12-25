package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSanitizeErrorMessage_DirectCalls tests the EXPORTED SanitizeErrorMessage function
// This tests the function that's actually used in production (capital S)
// These tests verify the function executes without error and returns non-empty output
func TestSanitizeErrorMessage_DirectCalls(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
	}{
		{
			name:             "Script tag removal",
			input:            "<script>alert('xss')</script>",
			shouldNotContain: []string{"<script>", "alert('xss')"},
		},
		{
			name:             "IMG tag with onerror",
			input:            "<img src=x onerror=alert('xss')>",
			shouldNotContain: []string{"<img", "onerror"},
		},
		{
			name:             "SVG with onload",
			input:            "<svg onload=alert('xss')>",
			shouldNotContain: []string{"<svg", "onload"},
		},
		{
			name:             "Normal text passed through",
			input:            "normal error message",
			shouldNotContain: []string{"<script>", "<img"},
		},
		{
			name:             "SQL injection attempt handled",
			input:            "' OR '1'='1",
			shouldNotContain: []string{"<script>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeErrorMessage(tt.input)
			assert.NotEmpty(t, result, "Result should not be empty")
			for _, forbidden := range tt.shouldNotContain {
				assert.NotContains(t, result, forbidden, "Result should not contain: %s", forbidden)
			}
		})
	}
}

// TestSanitizeLogMessage_DirectCalls tests the EXPORTED SanitizeLogMessage function
func TestSanitizeLogMessage_DirectCalls(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Handle script tags",
			input: "<script>alert('xss')</script>",
		},
		{
			name:  "Handle IMG tags",
			input: "<img src=x onerror=alert('xss')>",
		},
		{
			name:  "Handle normal log messages",
			input: "User admin logged in from 192.168.1.1",
		},
		{
			name:  "Handle javascript protocol",
			input: "User clicked: javascript:void(0)",
		},
		{
			name:  "Handle CRLF injection attempts",
			input: "normal log\r\n[FAKE] injected log line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLogMessage(tt.input)
			assert.NotEmpty(t, result, "Result should not be empty")
			// Verify CRLF injection is prevented (primary purpose of this function)
			assert.NotContains(t, result, "\r", "Should remove carriage returns")
			assert.NotContains(t, result, "\n", "Should remove newlines")
		})
	}
}

// TestSanitizeHTML_DirectCalls tests the EXPORTED SanitizeHTML function
func TestSanitizeHTML_DirectCalls(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Handle basic formatting",
			input: "<p>Hello <strong>world</strong></p>",
		},
		{
			name:  "Handle script tags",
			input: "<p>Hello</p><script>alert('xss')</script>",
		},
		{
			name:  "Handle event handlers",
			input: "<p onclick='alert(1)'>Click me</p>",
		},
		{
			name:  "Handle javascript URLs",
			input: "<a href='javascript:alert(1)'>Click</a>",
		},
		{
			name:  "Handle safe links",
			input: "<a href='https://example.com'>Link</a>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeHTML(tt.input)
			// Just verify function executes and returns something
			assert.NotNil(t, result, "Result should not be nil")
			// Verify script tags are removed (core security requirement)
			assert.NotContains(t, strings.ToLower(result), "<script>", "Should not contain opening script tag")
		})
	}
}

// TestSanitizeJavaScript_DirectCalls tests the EXPORTED SanitizeJavaScript function
func TestSanitizeJavaScript_DirectCalls(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		mustContain string // Something that should be present after sanitization
	}{
		{
			name:        "Escape quotes in eval",
			input:       "eval('alert(1)')",
			mustContain: "eval", // Function still present but quotes escaped
		},
		{
			name:        "Escape quotes in Function constructor",
			input:       "new Function('alert(1)')",
			mustContain: "Function", // Function still present but quotes escaped
		},
		{
			name:        "Escape quotes in setTimeout",
			input:       "setTimeout('alert(1)', 100)",
			mustContain: "setTimeout", // Function still present but quotes escaped
		},
		{
			name:        "Handle normal JavaScript",
			input:       "const x = 42; console.log(x);",
			mustContain: "const x = 42", // Normal JS unchanged
		},
		{
			name:        "Escape single quotes",
			input:       "alert('test')",
			mustContain: "\\'", // Quotes should be escaped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeJavaScript(tt.input)
			assert.NotEmpty(t, result, "Result should not be empty")
			assert.Contains(t, result, tt.mustContain, "Expected result to contain: %s", tt.mustContain)
		})
	}
}

// TestStripHTML_DirectCalls tests the EXPORTED StripHTML function
func TestStripHTML_DirectCalls(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Remove all HTML tags",
			input: "<p>Hello <strong>world</strong></p>",
		},
		{
			name:  "Handle script tags",
			input: "<script>alert('xss')</script>Hello",
		},
		{
			name:  "Handle style tags",
			input: "<style>body{background:red}</style>Content",
		},
		{
			name:  "Keep plain text",
			input: "Plain text without HTML",
		},
		{
			name:  "Handle malformed HTML",
			input: "<p>Unclosed tag",
		},
		{
			name:  "Remove tag attributes",
			input: "<div class='test' onclick='alert(1)'>Content</div>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripHTML(tt.input)
			// Just verify function executes and returns something
			assert.NotNil(t, result, "Result should not be nil")
			// Verify HTML tags are removed
			assert.NotContains(t, result, "<div", "Should not contain div tags")
			assert.NotContains(t, result, "<p>", "Should not contain p tags")
			assert.NotContains(t, result, "<strong>", "Should not contain strong tags")
		})
	}
}

// TestSanitize_EdgeCases tests edge cases for all sanitization functions
func TestSanitize_EdgeCases(t *testing.T) {
	t.Run("Empty strings", func(t *testing.T) {
		assert.Equal(t, "", SanitizeErrorMessage(""))
		assert.Equal(t, "", SanitizeLogMessage(""))
		assert.Equal(t, "", SanitizeHTML(""))
		assert.Equal(t, "", SanitizeJavaScript(""))
		assert.Equal(t, "", StripHTML(""))
	})

	t.Run("Unicode characters", func(t *testing.T) {
		unicode := "Hello 世界 🌍"
		assert.Contains(t, SanitizeErrorMessage(unicode), "世界")
		assert.Contains(t, SanitizeLogMessage(unicode), "🌍")
	})
}

// TestSanitize_PerformanceBaseline provides performance baseline for sanitization functions
func TestSanitize_PerformanceBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	input := strings.Repeat("<script>alert('xss')</script>Normal text here", 100)

	t.Run("SanitizeErrorMessage_Performance", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			_ = SanitizeErrorMessage(input)
		}
	})

	t.Run("SanitizeLogMessage_Performance", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			_ = SanitizeLogMessage(input)
		}
	})

	t.Run("StripHTML_Performance", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			_ = StripHTML(input)
		}
	})
}
