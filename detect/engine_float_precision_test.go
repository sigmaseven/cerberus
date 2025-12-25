package detect

import (
	"testing"
)

// TASK #181: Float precision tests for deleted functions
// The following functions were deleted as part of legacy evaluation removal:
// - floatEqual
// - floatEpsilon
// - compareFloat
//
// SIGMA engine uses strict comparison per specification.
// See ADR-002-float-precision.md for historical context on epsilon-based float comparison.
//
// These tests are preserved as skipped tests to document what was previously tested.

// TestFloatPrecisionEpsilon - TASK #181: SKIPPED
// The floatEqual function was deleted as part of legacy evaluation removal.
func TestFloatPrecisionEpsilon(t *testing.T) {
	t.Skip("floatEqual function deleted in Task #181 - SIGMA uses strict comparison")
}

// TestCompareFloat - TASK #181: SKIPPED
// The compareFloat function was deleted as part of legacy evaluation removal.
func TestCompareFloat(t *testing.T) {
	t.Skip("compareFloat function deleted in Task #181 - SIGMA uses strict comparison")
}

// TestFloatPrecisionRealWorldScenarios - TASK #181: SKIPPED
// Tests for epsilon-based float comparison in SIEM scenarios.
func TestFloatPrecisionRealWorldScenarios(t *testing.T) {
	t.Skip("compareFloat function deleted in Task #181 - SIGMA uses strict comparison")
}

// TestFloatPrecisionDocumentation documents the historical context of epsilon comparison
// This test is kept for reference purposes and does not call any deleted functions.
func TestFloatPrecisionDocumentation(t *testing.T) {
	t.Log("\n╔════════════════════════════════════════════════════════════════════════════╗")
	t.Log("║ ADR-002: Float Precision Decision - HISTORICAL REFERENCE                   ║")
	t.Log("╠════════════════════════════════════════════════════════════════════════════╣")
	t.Log("║                                                                            ║")
	t.Log("║ TASK #181: Legacy float comparison functions DELETED                       ║")
	t.Log("║ SIGMA engine uses strict comparison per specification                      ║")
	t.Log("║                                                                            ║")
	t.Log("║ HISTORICAL CONTEXT (no longer applies):                                    ║")
	t.Log("║   IEEE 754: 0.1 + 0.2 = 0.30000000000000004 (precision issue)             ║")
	t.Log("║   Legacy solution: Epsilon comparison with ε = 1e-9                        ║")
	t.Log("║                                                                            ║")
	t.Log("║ CURRENT BEHAVIOR (SIGMA):                                                  ║")
	t.Log("║   SIGMA uses strict float comparison per specification                     ║")
	t.Log("║   Rules should use appropriate thresholds accounting for precision         ║")
	t.Log("║                                                                            ║")
	t.Log("║ SEE: docs/decisions/ADR-002-float-precision.md for history                 ║")
	t.Log("╚════════════════════════════════════════════════════════════════════════════╝")
}

// repeat helper already defined in engine_sigma_type_test.go
