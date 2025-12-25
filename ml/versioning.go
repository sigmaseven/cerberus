package ml

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// ModelStorage interface for model version management
// TASK 26.3: Storage interface for version queries
type ModelStorage interface {
	GetLatestVersion(modelName string) (string, error)
	ListVersions(modelName string) ([]string, error)
}

// ParseVersion parses a semantic version string into major, minor, patch components
// TASK 26.3: Parse "1.2.3" to (1,2,3)
func ParseVersion(v string) (major, minor, patch int, err error) {
	// Version format validation: ^\d+\.\d+\.\d+$
	versionRegex := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	matches := versionRegex.FindStringSubmatch(v)
	if len(matches) != 4 {
		return 0, 0, 0, fmt.Errorf("invalid version format: %s (expected format: major.minor.patch)", v)
	}

	major, err = strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major version: %w", err)
	}

	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid minor version: %w", err)
	}

	patch, err = strconv.Atoi(matches[3])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid patch version: %w", err)
	}

	return major, minor, patch, nil
}

// CompareVersions compares two semantic version strings
// TASK 26.3: Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) (int, error) {
	major1, minor1, patch1, err := ParseVersion(v1)
	if err != nil {
		return 0, fmt.Errorf("invalid version v1: %w", err)
	}

	major2, minor2, patch2, err := ParseVersion(v2)
	if err != nil {
		return 0, fmt.Errorf("invalid version v2: %w", err)
	}

	// Compare major version
	if major1 < major2 {
		return -1, nil
	}
	if major1 > major2 {
		return 1, nil
	}

	// Major versions equal, compare minor
	if minor1 < minor2 {
		return -1, nil
	}
	if minor1 > minor2 {
		return 1, nil
	}

	// Minor versions equal, compare patch
	if patch1 < patch2 {
		return -1, nil
	}
	if patch1 > patch2 {
		return 1, nil
	}

	// All components equal
	return 0, nil
}

// IncrementVersion increments a semantic version by the specified change type
// TASK 26.3: changeType: "major", "minor", or "patch"
func IncrementVersion(current string, changeType string) (string, error) {
	major, minor, patch, err := ParseVersion(current)
	if err != nil {
		return "", fmt.Errorf("invalid current version: %w", err)
	}

	switch changeType {
	case "major":
		return fmt.Sprintf("%d.0.0", major+1), nil
	case "minor":
		return fmt.Sprintf("%d.%d.0", major, minor+1), nil
	case "patch":
		return fmt.Sprintf("%d.%d.%d", major, minor, patch+1), nil
	default:
		return "", fmt.Errorf("invalid change type: %s (must be 'major', 'minor', or 'patch')", changeType)
	}
}

// GetNextVersion determines the next version for a model by querying storage and incrementing patch version
// TASK 26.3: Queries latest version from storage, increments patch version
func GetNextVersion(storage ModelStorage, modelName string) (string, error) {
	if storage == nil {
		// No storage available, start with 1.0.0
		return "1.0.0", nil
	}

	latestVersion, err := storage.GetLatestVersion(modelName)
	if err != nil {
		// No existing version, start with 1.0.0
		return "1.0.0", nil
	}

	// Increment patch version by default
	return IncrementVersion(latestVersion, "patch")
}

// SortVersions sorts version strings in descending order (newest first)
func SortVersions(versions []string) ([]string, error) {
	// Validate all versions first
	for _, v := range versions {
		if _, _, _, err := ParseVersion(v); err != nil {
			return nil, fmt.Errorf("invalid version in list: %s: %w", v, err)
		}
	}

	// Create a copy to avoid modifying input
	sorted := make([]string, len(versions))
	copy(sorted, versions)

	// Sort using CompareVersions
	sort.Slice(sorted, func(i, j int) bool {
		result, err := CompareVersions(sorted[i], sorted[j])
		if err != nil {
			// Should not happen since we validated above, but handle gracefully
			return false
		}
		return result > 0 // Descending order (newest first)
	})

	return sorted, nil
}
