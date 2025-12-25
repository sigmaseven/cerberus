package bootstrap

import (
	"strings"
	"testing"
)

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		minLength int
	}{
		{"default length", 16, 16},
		{"24 characters", 24, 24},
		{"short length enforces minimum", 8, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GenerateSecurePassword(tt.length)
			if err != nil {
				t.Fatalf("GenerateSecurePassword() error = %v", err)
			}
			if len(password) < tt.minLength {
				t.Errorf("GenerateSecurePassword(%d) length = %d, want >= %d", tt.length, len(password), tt.minLength)
			}
		})
	}

	// Test uniqueness
	t.Run("generates unique passwords", func(t *testing.T) {
		passwords := make(map[string]bool)
		for i := 0; i < 100; i++ {
			p, _ := GenerateSecurePassword(24)
			if passwords[p] {
				t.Error("Generated duplicate password")
			}
			passwords[p] = true
		}
	})
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"Hello World", "xyz", false},
		{"", "", true},
		{"abc", "", true},
		{"", "abc", false},
		{"connection refused", "Connection Refused", true},
		{"ECONNREFUSED", "econnrefused", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := containsIgnoreCase(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

func TestClassifyConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		addr     string
		contains string
	}{
		{
			name:     "nil error returns empty string",
			err:      nil,
			addr:     "localhost:9000",
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyConnectionError(tt.err, tt.addr)
			if tt.contains == "" && result != "" {
				t.Errorf("ClassifyConnectionError() = %q, want empty string", result)
			}
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("ClassifyConnectionError() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func TestClassifySQLiteError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		dbPath   string
		contains string
	}{
		{
			name:     "nil error returns empty string",
			err:      nil,
			dbPath:   "/data/cerberus.db",
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifySQLiteError(tt.err, tt.dbPath)
			if tt.contains == "" && result != "" {
				t.Errorf("ClassifySQLiteError() = %q, want empty string", result)
			}
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("ClassifySQLiteError() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func TestDefaultDataDirectories(t *testing.T) {
	dirs := DefaultDataDirectories()

	if dirs.Base == "" {
		t.Error("DefaultDataDirectories().Base is empty")
	}
	if dirs.Feeds == "" {
		t.Error("DefaultDataDirectories().Feeds is empty")
	}
	if dirs.ML == "" {
		t.Error("DefaultDataDirectories().ML is empty")
	}
	if dirs.SQLite == "" {
		t.Error("DefaultDataDirectories().SQLite is empty")
	}
}

func TestEqualFoldAt(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		start    int
		expected bool
	}{
		{"Hello", "hello", 0, true},
		{"Hello", "HELLO", 0, true},
		{"Hello World", "world", 6, true},
		{"Hello World", "WORLD", 6, true},
		{"Hello", "xyz", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := equalFoldAt(tt.s, tt.substr, tt.start)
			if result != tt.expected {
				t.Errorf("equalFoldAt(%q, %q, %d) = %v, want %v", tt.s, tt.substr, tt.start, result, tt.expected)
			}
		})
	}
}
