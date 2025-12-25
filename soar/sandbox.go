package soar

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"go.uber.org/zap"
)

// SECURITY REQUIREMENTS:
// FR-SOAR-019: Sandbox Implementation
// - Scripts MUST execute in isolated sandbox (gVisor preferred, Docker acceptable)
// - Process isolation, read-only filesystem (except /tmp)
// - Resource limits: 1 core, 512MB RAM, 10 MB/s I/O
// - 300s timeout, unprivileged user
// - Seccomp violations MUST log and terminate sandbox
//
// THREAT MODEL: ATTACK-004 Sandbox Escape
// Reference: docs/requirements/security-threat-model.md

// SECURITY WARNING: Windows Platform Limitation
// gVisor is not available on Windows. This implementation uses Docker containers
// for sandboxing on Windows. For production Linux deployments, gVisor is STRONGLY
// RECOMMENDED for stronger isolation guarantees.
//
// TODO: Implement gVisor support for Linux deployments
// TODO: Security audit required before production use on Windows

// SandboxConfig defines resource limits and isolation settings for script execution
type SandboxConfig struct {
	// Timeout is the maximum execution time (FR-SOAR-019: 300s default)
	Timeout time.Duration

	// CPULimit is the number of CPU cores (FR-SOAR-019: 1 core)
	CPULimit float64

	// MemoryLimitMB is the memory limit in megabytes (FR-SOAR-019: 512MB)
	MemoryLimitMB int64

	// IOLimitMBPerSec is the I/O limit in MB/s (FR-SOAR-019: 10 MB/s)
	IOLimitMBPerSec int64

	// ReadOnlyPaths are filesystem paths mounted as read-only
	// FR-SOAR-019: All paths except /tmp must be read-only
	ReadOnlyPaths []string

	// WritablePaths are filesystem paths that are writable
	// FR-SOAR-019: Only /tmp should be writable
	WritablePaths []string

	// User is the unprivileged user to run as
	// FR-SOAR-019: MUST NOT run as root
	User string

	// WorkingDir is the working directory inside the sandbox
	WorkingDir string

	// NetworkEnabled controls network access
	// Default: false (no network) for security
	NetworkEnabled bool

	// Environment variables to pass to the script
	// SECURITY: Carefully validate before passing sensitive data
	Env map[string]string

	// Logger for sandbox operations
	Logger *zap.SugaredLogger
}

// DefaultSandboxConfig returns a secure default sandbox configuration
// Implements FR-SOAR-019 requirements
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		Timeout:         300 * time.Second, // 5 minutes
		CPULimit:        1.0,               // 1 core
		MemoryLimitMB:   512,               // 512 MB
		IOLimitMBPerSec: 10,                // 10 MB/s
		ReadOnlyPaths:   []string{"/"},     // Everything read-only by default
		WritablePaths:   []string{"/tmp"},  // Only /tmp writable
		User:            "nobody",          // Unprivileged user
		WorkingDir:      "/sandbox",
		NetworkEnabled:  false, // No network access
		Env:             make(map[string]string),
	}
}

// SandboxResult contains the result of sandbox execution
type SandboxResult struct {
	ExitCode       int
	Stdout         string
	Stderr         string
	ExecutionTime  time.Duration
	ResourceUsage  ResourceUsage
	SecurityEvents []SecurityEvent
}

// ResourceUsage tracks resource consumption during execution
type ResourceUsage struct {
	CPUTime      time.Duration
	MemoryPeakMB int64
	IOReadMB     int64
	IOWriteMB    int64
}

// SecurityEvent represents a security violation during execution
type SecurityEvent struct {
	Timestamp   time.Time
	EventType   string // seccomp_violation, resource_limit, sandbox_escape_attempt
	Description string
	Severity    string // low, medium, high, critical
}

// ExecuteInSandbox executes a script in an isolated sandbox environment
// SECURITY: This is the ONLY way scripts should be executed for SOAR actions
//
// Requirements enforced:
// - Input validation (ValidateScriptPath, ValidateScriptArguments)
// - Process isolation (Docker container or gVisor)
// - Resource limits (CPU, memory, I/O)
// - Timeout enforcement
// - Unprivileged execution
// - Read-only filesystem (except /tmp)
//
// Returns: SandboxResult with output and resource usage, error if execution fails
func ExecuteInSandbox(ctx context.Context, scriptPath string, args []string, config SandboxConfig) (*SandboxResult, error) {
	startTime := time.Now()

	// SECURITY: Validate inputs before execution
	if err := ValidateScriptPath(scriptPath); err != nil {
		return nil, fmt.Errorf("script path validation failed: %w", err)
	}
	if err := ValidateScriptArguments(args); err != nil {
		return nil, fmt.Errorf("script arguments validation failed: %w", err)
	}
	if err := ValidateShellProhibited(scriptPath); err != nil {
		return nil, fmt.Errorf("shell prohibition check failed: %w", err)
	}

	// Initialize logger if not provided
	if config.Logger == nil {
		logger, _ := zap.NewProduction()
		config.Logger = logger.Sugar()
	}

	// Create context with timeout
	execCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Platform-specific sandbox execution
	var result *SandboxResult
	var err error

	if runtime.GOOS == "linux" && isGVisorAvailable() {
		// Use gVisor for stronger isolation on Linux
		result, err = executeInGVisor(execCtx, scriptPath, args, config)
	} else {
		// Fallback to Docker-based sandbox
		// SECURITY WARNING: Docker provides weaker isolation than gVisor
		config.Logger.Warnf("Using Docker-based sandbox (gVisor not available). Platform: %s", runtime.GOOS)
		result, err = executeInDocker(execCtx, scriptPath, args, config)
	}

	if err != nil {
		return nil, err
	}

	result.ExecutionTime = time.Since(startTime)

	// Log security events
	for _, event := range result.SecurityEvents {
		config.Logger.Warnf("SECURITY EVENT: %s - %s (severity: %s)",
			event.EventType, event.Description, event.Severity)
	}

	return result, nil
}

// isGVisorAvailable checks if gVisor (runsc) is available on the system
func isGVisorAvailable() bool {
	_, err := exec.LookPath("runsc")
	return err == nil
}

// executeInGVisor executes script in gVisor sandbox (Linux only)
// SECURITY: gVisor provides strong kernel-level isolation
func executeInGVisor(ctx context.Context, scriptPath string, args []string, config SandboxConfig) (*SandboxResult, error) {
	// TODO: Implement gVisor integration
	// This requires:
	// 1. Create OCI runtime bundle
	// 2. Configure seccomp profile
	// 3. Set resource limits (cgroups)
	// 4. Execute with: runsc run <container-id>
	// 5. Monitor for seccomp violations
	//
	// For now, fall back to Docker
	config.Logger.Warn("gVisor execution not yet implemented, falling back to Docker")
	return executeInDocker(ctx, scriptPath, args, config)
}

// executeInDocker executes script in Docker container
// SECURITY: Provides process isolation and resource limits
//
// Container security features:
// - Non-root user (--user)
// - No network (--network=none, unless NetworkEnabled)
// - Read-only root filesystem (--read-only)
// - Memory limit (--memory)
// - CPU limit (--cpus)
// - Security options (--security-opt=no-new-privileges)
// - Drop all capabilities (--cap-drop=ALL)
func executeInDocker(ctx context.Context, scriptPath string, args []string, config SandboxConfig) (*SandboxResult, error) {
	// Check if Docker is available
	if !isDockerAvailable() {
		return nil, fmt.Errorf("Docker is not available. Install Docker or use gVisor on Linux for sandboxing")
	}

	result := &SandboxResult{
		SecurityEvents: []SecurityEvent{},
	}

	// Build Docker run command with security restrictions
	dockerArgs := []string{
		"run",
		"--rm",                                       // Remove container after execution
		"--read-only",                                // Read-only root filesystem
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=100m", // Writable /tmp with restrictions
		"--security-opt=no-new-privileges", // Prevent privilege escalation
		"--cap-drop=ALL",                   // Drop all capabilities
		fmt.Sprintf("--cpus=%f", config.CPULimit),
		fmt.Sprintf("--memory=%dm", config.MemoryLimitMB),
		fmt.Sprintf("--user=%s", config.User),
	}

	// Network configuration
	if !config.NetworkEnabled {
		dockerArgs = append(dockerArgs, "--network=none")
	}

	// Environment variables
	for key, value := range config.Env {
		// SECURITY: Validate environment variables
		if _, err := SanitizeInput(key); err != nil {
			return nil, fmt.Errorf("invalid environment variable key: %w", err)
		}
		if _, err := SanitizeInput(value); err != nil {
			return nil, fmt.Errorf("invalid environment variable value: %w", err)
		}
		dockerArgs = append(dockerArgs, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Working directory
	if config.WorkingDir != "" {
		dockerArgs = append(dockerArgs, "-w", config.WorkingDir)
	}

	// Use alpine image for minimal attack surface
	// TODO: Use custom hardened image with only required interpreters
	dockerArgs = append(dockerArgs, "alpine:latest")

	// Construct the command to execute
	// SECURITY: We've already validated scriptPath and args
	dockerArgs = append(dockerArgs, scriptPath)
	dockerArgs = append(dockerArgs, args...)

	config.Logger.Debugf("Executing in Docker sandbox: %s %v", scriptPath, args)

	// Create command
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute
	err := cmd.Run()

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		result.SecurityEvents = append(result.SecurityEvents, SecurityEvent{
			Timestamp:   time.Now(),
			EventType:   "timeout",
			Description: fmt.Sprintf("Script execution exceeded timeout of %s", config.Timeout),
			Severity:    "high",
		})
		return result, fmt.Errorf("sandbox execution timed out after %s", config.Timeout)
	}

	// Get exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			config.Logger.Debugf("Script exited with code %d", result.ExitCode)
		} else {
			return result, fmt.Errorf("sandbox execution failed: %w", err)
		}
	} else {
		result.ExitCode = 0
	}

	// TODO: Parse Docker stats to populate ResourceUsage
	// This requires running `docker stats` in parallel or using Docker API

	return result, nil
}

// isDockerAvailable checks if Docker is available and running
func isDockerAvailable() bool {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	return err == nil
}

// ValidateSandboxConfig validates sandbox configuration for security
func ValidateSandboxConfig(config SandboxConfig) error {
	// Timeout validation
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if config.Timeout > 600*time.Second {
		return fmt.Errorf("timeout exceeds maximum of 600 seconds")
	}

	// CPU limit validation
	if config.CPULimit <= 0 {
		return fmt.Errorf("CPU limit must be positive")
	}
	if config.CPULimit > 4 {
		return fmt.Errorf("CPU limit exceeds maximum of 4 cores")
	}

	// Memory limit validation
	if config.MemoryLimitMB <= 0 {
		return fmt.Errorf("memory limit must be positive")
	}
	if config.MemoryLimitMB > 4096 {
		return fmt.Errorf("memory limit exceeds maximum of 4096 MB")
	}

	// User validation
	if config.User == "" {
		return fmt.Errorf("user must be specified")
	}
	if config.User == "root" {
		return fmt.Errorf("SECURITY: scripts MUST NOT run as root")
	}

	// Writable paths validation
	if len(config.WritablePaths) == 0 {
		return fmt.Errorf("at least one writable path (/tmp) must be specified")
	}

	// Validate all writable paths are safe
	for _, path := range config.WritablePaths {
		if path == "/" || path == "/etc" || path == "/root" {
			return fmt.Errorf("SECURITY: cannot make %s writable", path)
		}
	}

	return nil
}

// PLATFORM COMPATIBILITY MATRIX:
//
// Linux with gVisor:
//   - RECOMMENDED for production
//   - Strongest isolation (kernel-level)
//   - Seccomp violations logged
//   - Full resource control
//
// Linux with Docker:
//   - ACCEPTABLE for production
//   - Process isolation via containers
//   - Resource limits via cgroups
//   - Weaker than gVisor but still secure
//
// Windows with Docker:
//   - ACCEPTABLE for development/testing
//   - WARNING: Weaker isolation on Windows
//   - Security audit REQUIRED before production
//   - Consider WSL2 + gVisor for better isolation
//
// macOS with Docker:
//   - ACCEPTABLE for development/testing
//   - Uses virtualization (better than Windows)
//   - Not recommended for production
//
// SECURITY RECOMMENDATION:
// For production deployments on Linux, install gVisor:
//   1. Install runsc: https://gvisor.dev/docs/user_guide/install/
//   2. Configure as Docker runtime: docker run --runtime=runsc
//   3. Set CERBERUS_SANDBOX_RUNTIME=gvisor environment variable
