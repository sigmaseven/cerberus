package service

// ============================================================================
// Shared Helper Functions
// ============================================================================
//
// This file contains helper functions shared across multiple service implementations.
// Previously, deepCopyValue was defined in playbook_service.go and called from
// event_service.go and rule_service.go, creating hidden coupling.
//
// BLOCKER-3 FIX: Extracted to shared location to eliminate hidden dependencies.

// deepCopyValue creates a deep copy of an interface{} value.
//
// DEFENSIVE PROGRAMMING: Prevents caller from mutating service-managed state
// by recursively copying maps and slices.
//
// BEHAVIOR:
//   - Primitive types (string, int, float64, bool) are copied by value
//   - Maps are deep copied with recursive value copying
//   - Slices are deep copied with recursive element copying
//   - nil returns nil
//
// COMPLEXITY: O(n) where n is total number of nested elements
//
// USAGE:
//   - Event field map deep copying
//   - Rule detection/metadata map deep copying
//   - Playbook parameter map deep copying
func deepCopyValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]interface{}:
		// Deep copy map
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = deepCopyValue(v) // Recursive copy
		}
		return result

	case []interface{}:
		// Deep copy slice
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = deepCopyValue(v) // Recursive copy
		}
		return result

	default:
		// Primitive types are copied by value in Go
		// This includes: string, int, int64, float64, bool, etc.
		return val
	}
}
