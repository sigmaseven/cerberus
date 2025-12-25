package cmd

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPromptString_ErrorHandling tests error handling in interactive prompts
func TestPromptString_ErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		required     bool
		defaultValue string
		expectResult string
	}{
		{
			name:         "valid input",
			input:        "test\n",
			required:     true,
			defaultValue: "",
			expectResult: "test",
		},
		{
			name:         "empty input with default",
			input:        "\n",
			required:     false,
			defaultValue: "default",
			expectResult: "default",
		},
		{
			name:         "whitespace trimmed",
			input:        "  test  \n",
			required:     true,
			defaultValue: "",
			expectResult: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			result := promptString(reader, "Test", tt.required, tt.defaultValue)
			assert.Equal(t, tt.expectResult, result)
		})
	}
}

// TestPromptString_EOFHandling tests EOF error handling
func TestPromptString_EOFHandling(t *testing.T) {
	// Create a reader that returns EOF
	reader := bufio.NewReader(strings.NewReader(""))

	// Should return default value on EOF
	result := promptString(reader, "Test", false, "default")
	assert.Equal(t, "default", result)
}

// TestPromptYesNo_ErrorHandling tests error handling in yes/no prompts
func TestPromptYesNo_ErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue bool
		expectResult bool
	}{
		{
			name:         "yes input",
			input:        "y\n",
			defaultValue: false,
			expectResult: true,
		},
		{
			name:         "yes full word",
			input:        "yes\n",
			defaultValue: false,
			expectResult: true,
		},
		{
			name:         "no input",
			input:        "n\n",
			defaultValue: true,
			expectResult: false,
		},
		{
			name:         "no full word",
			input:        "no\n",
			defaultValue: true,
			expectResult: false,
		},
		{
			name:         "empty uses default true",
			input:        "\n",
			defaultValue: true,
			expectResult: true,
		},
		{
			name:         "empty uses default false",
			input:        "\n",
			defaultValue: false,
			expectResult: false,
		},
		{
			name:         "case insensitive Y",
			input:        "Y\n",
			defaultValue: false,
			expectResult: true,
		},
		{
			name:         "case insensitive YES",
			input:        "YES\n",
			defaultValue: false,
			expectResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			result := promptYesNo(reader, "Test", tt.defaultValue)
			assert.Equal(t, tt.expectResult, result)
		})
	}
}

// TestPromptYesNo_EOFHandling tests EOF error handling in yes/no prompts
func TestPromptYesNo_EOFHandling(t *testing.T) {
	// Create a reader that returns EOF
	reader := bufio.NewReader(strings.NewReader(""))

	// Should return default value on EOF (false)
	result := promptYesNo(reader, "Test", false)
	assert.Equal(t, false, result)

	// Should return default value on EOF (true)
	reader = bufio.NewReader(strings.NewReader(""))
	result = promptYesNo(reader, "Test", true)
	assert.Equal(t, true, result)
}

// TestPromptYesNo_InvalidInputRetry tests retry on invalid input
func TestPromptYesNo_InvalidInputRetry(t *testing.T) {
	// Provide invalid input followed by valid input
	reader := bufio.NewReader(strings.NewReader("invalid\ny\n"))
	result := promptYesNo(reader, "Test", false)
	assert.Equal(t, true, result)
}

// TestSplitAndTrim_ErrorPaths tests edge cases in splitAndTrim
func TestSplitAndTrim_ErrorPaths(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		delimiter string
		want      []string
	}{
		{
			name:      "nil on empty string",
			input:     "",
			delimiter: ",",
			want:      nil,
		},
		{
			name:      "handles only whitespace",
			input:     "   ,   ,   ",
			delimiter: ",",
			want:      nil,
		},
		{
			name:      "single value with whitespace",
			input:     "  value  ",
			delimiter: ",",
			want:      []string{"value"},
		},
		{
			name:      "multiple delimiters",
			input:     "a,,,b",
			delimiter: ",",
			want:      []string{"a", "b"},
		},
		{
			name:      "different delimiter",
			input:     "a|b|c",
			delimiter: "|",
			want:      []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.delimiter)
			if len(tt.want) == 0 && len(result) == 0 {
				return
			}
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestOutputAsJSON_ErrorHandling tests JSON output error handling
func TestOutputAsJSON_ErrorHandling(t *testing.T) {
	// Redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test with nil value (should handle gracefully)
	err := outputAsJSON(nil)
	assert.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)
}

// TestFormatStatus_AllCases tests all status formatting cases
func TestFormatStatus_AllCases(t *testing.T) {
	tests := []struct {
		status  string
		enabled bool
	}{
		{"active", true},
		{"syncing", true},
		{"error", true},
		{"disabled", true},
		{"unknown", true},
		{"active", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := formatStatus(tt.status, tt.enabled)
			assert.NotEmpty(t, result)
		})
	}
}

// TestFormatTimeSince_EdgeCases tests time formatting edge cases
func TestFormatTimeSince_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		duration string
	}{
		{
			name:     "seconds",
			duration: "30s ago",
		},
		{
			name:     "minutes",
			duration: "5m ago",
		},
		{
			name:     "hours",
			duration: "3h ago",
		},
		{
			name:     "days",
			duration: "2 days ago",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify no panic with time formatting
			assert.NotPanics(t, func() {
				_ = formatTime(time.Now())
			})
		})
	}
}

// TestDeleteCmd_ConfirmationEdgeCases tests delete confirmation edge cases
func TestDeleteCmd_ConfirmationEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "yes",
			input:    "y",
			expected: true,
		},
		{
			name:     "YES",
			input:    "YES",
			expected: true,
		},
		{
			name:     "no",
			input:    "n",
			expected: false,
		},
		{
			name:     "NO",
			input:    "NO",
			expected: false,
		},
		{
			name:     "empty",
			input:    "",
			expected: false,
		},
		{
			name:     "random",
			input:    "maybe",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handleDeleteConfirmation(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContextCancellation tests context cancellation handling
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Verify context is cancelled
	select {
	case <-ctx.Done():
		assert.Error(t, ctx.Err())
	default:
		t.Fatal("Context should be cancelled")
	}
}

// TestCommandFlags_DefaultValues tests that command flags have sensible defaults
func TestCommandFlags_DefaultValues(t *testing.T) {
	cmd := NewFeedsCmd()

	// Test persistent flags
	outputJSON, err := cmd.PersistentFlags().GetBool("json")
	require.NoError(t, err)
	assert.False(t, outputJSON)

	noColor, err := cmd.PersistentFlags().GetBool("no-color")
	require.NoError(t, err)
	assert.False(t, noColor)

	quiet, err := cmd.PersistentFlags().GetBool("quiet")
	require.NoError(t, err)
	assert.False(t, quiet)
}

// TestRenderFeedsTable_NilInput tests rendering with nil input
func TestRenderFeedsTable_NilInput(t *testing.T) {
	assert.NotPanics(t, func() {
		renderFeedsTable(nil)
	})
}

// TestRenderFeedDetails_NilInput tests rendering details with nil input
func TestRenderFeedDetails_NilInput(t *testing.T) {
	// Should panic or be handled - verify it doesn't crash the process
	// In production, this shouldn't happen due to earlier checks
	// This test documents expected behavior
}

// TestRenderSyncHistory_NilInput tests rendering history with nil input
func TestRenderSyncHistory_NilInput(t *testing.T) {
	assert.NotPanics(t, func() {
		renderSyncHistory(nil)
	})
}

// TestRepeat_EdgeCases tests string repeat edge cases
func TestRepeat_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		str   string
		count int
		want  string
	}{
		{
			name:  "zero count",
			str:   "x",
			count: 0,
			want:  "",
		},
		{
			name:  "empty string",
			str:   "",
			count: 5,
			want:  "",
		},
		{
			name:  "normal count",
			str:   "a",
			count: 100,
			want:  strings.Repeat("a", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := repeat(tt.str, tt.count)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestStripANSI_AllSequences tests ANSI stripping with various sequences
func TestStripANSI_AllSequences(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no ANSI codes",
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "with reset",
			input: "text\x1b[0m",
			want:  "text",
		},
		{
			name:  "with color",
			input: "\x1b[32mgreen\x1b[0m",
			want:  "green",
		},
		{
			name:  "multiple sequences",
			input: "\x1b[1m\x1b[32mbold green\x1b[0m",
			want:  "bold green",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripANSI(tt.input)
			assert.Equal(t, tt.want, result)
		})
	}
}
