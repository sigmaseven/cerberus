package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrPathTraversal indicates a path traversal attempt was detected
var ErrPathTraversal = errors.New("path traversal attempt detected")

// ErrSymlinkNotAllowed indicates a symlink was detected and is not allowed
var ErrSymlinkNotAllowed = errors.New("symlink not allowed")

// ErrPathOutsideAllowedDir indicates the path is outside the allowed directory
var ErrPathOutsideAllowedDir = errors.New("path outside allowed directory")

// ValidateFilePath validates a file path to prevent path traversal attacks
// TASK 8.1: Path traversal prevention utility
// REQUIREMENT: docs/requirements/security-threat-model.md Section 6.2
//
// This function:
// 1. Normalizes the path using filepath.Clean()
// 2. Resolves to absolute path
// 3. Validates the path is within the allowed directory
// 4. Checks for symlinks if checkSymlinks is true
//
// Parameters:
//   - path: The file path to validate
//   - allowedDir: The base directory that the path must be within
//   - checkSymlinks: If true, rejects symlinks to prevent symlink attacks
//
// Returns:
//   - string: The validated absolute path
//   - error: Error if validation fails
func ValidateFilePath(path, allowedDir string, checkSymlinks bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	if allowedDir == "" {
		return "", fmt.Errorf("allowed directory cannot be empty")
	}

	// SECURITY: Check for path traversal sequences BEFORE cleaning
	// filepath.Clean() normalizes ".." which would hide the attack
	if strings.Contains(path, "..") {
		return "", ErrPathTraversal
	}

	// Normalize the path
	cleanPath := filepath.Clean(path)

	// SECURITY: Reject null bytes (C string termination attack)
	if strings.Contains(cleanPath, "\x00") {
		return "", fmt.Errorf("null bytes not allowed in path")
	}

	// Resolve to absolute paths
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve allowed directory: %w", err)
	}

	// If path is relative, join it with allowedDir
	var absPath string
	if filepath.IsAbs(cleanPath) {
		absPath, err = filepath.Abs(cleanPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve file path: %w", err)
		}
	} else {
		absPath, err = filepath.Abs(filepath.Join(absAllowedDir, cleanPath))
		if err != nil {
			return "", fmt.Errorf("failed to resolve file path: %w", err)
		}
	}

	// SECURITY: Verify the resolved path is within the allowed directory
	// Normalize paths for comparison (handle both Unix and Windows separators)
	normalizedAbsPath := filepath.ToSlash(absPath)
	normalizedAllowedDir := filepath.ToSlash(absAllowedDir)

	if !strings.HasPrefix(normalizedAbsPath, normalizedAllowedDir) {
		return "", ErrPathOutsideAllowedDir
	}

	// SECURITY: Check for symlinks to prevent symlink attacks
	if checkSymlinks {
		fi, err := os.Lstat(absPath)
		if err != nil {
			// If file doesn't exist yet, that's okay (for create operations)
			// But we should check parent directories for symlinks
			parentDir := filepath.Dir(absPath)
			parentFi, err := os.Lstat(parentDir)
			if err != nil {
				return "", fmt.Errorf("failed to check parent directory: %w", err)
			}
			if parentFi.Mode()&os.ModeSymlink != 0 {
				return "", ErrSymlinkNotAllowed
			}
		} else {
			// File exists - check if it's a symlink
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", ErrSymlinkNotAllowed
			}
		}
	}

	return absPath, nil
}

// ValidateFilePathRelaxed validates a file path but allows it to exist outside allowedDir
// if checkSymlinks is false. This is useful for operations where we want to validate
// the path format but don't need strict directory restrictions.
// TASK 8.1: Relaxed path validation for less restrictive scenarios
func ValidateFilePathRelaxed(path string, checkSymlinks bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	// SECURITY: Check for path traversal sequences
	if strings.Contains(path, "..") {
		return "", ErrPathTraversal
	}

	// Normalize the path
	cleanPath := filepath.Clean(path)

	// SECURITY: Reject null bytes
	if strings.Contains(cleanPath, "\x00") {
		return "", fmt.Errorf("null bytes not allowed in path")
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve file path: %w", err)
	}

	// SECURITY: Check for symlinks if requested
	if checkSymlinks {
		fi, err := os.Lstat(absPath)
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", ErrSymlinkNotAllowed
		}
	}

	return absPath, nil
}

// IsPathSafe checks if a path is safe (no traversal, no null bytes, reasonable length)
// TASK 8.1: Quick safety check without resolving paths
func IsPathSafe(path string) bool {
	if path == "" {
		return false
	}

	// Check length to prevent abuse
	if len(path) > 2048 {
		return false
	}

	// Check for path traversal
	if strings.Contains(path, "..") {
		return false
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}

	return true
}
