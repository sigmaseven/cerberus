package detect

import (
	"testing"
)

// TASK #182: File-based rule loading tests removed
// All file loading functions have been deleted as part of the database-only architecture.
//
// Deleted tests (for deleted functions):
// - TestLoadRules_JSON (tested LoadRules file loading)
// - TestLoadRules_FileNotFound (tested file not found error)
// - TestLoadRules_InvalidJSON (tested invalid JSON handling)
// - TestLoadCorrelationRules_JSON (tested LoadCorrelationRules file loading)
// - TestLoadCorrelationRules_FileNotFound (tested file not found error)
// - TestLoadCorrelationRules_InvalidJSON (tested invalid JSON handling)
// - TestCompileRegexInRules_InvalidRegex (tested regex compilation)
// - TestCompileRegexInCorrelationRules_InvalidRegex (tested regex compilation)
// - TestLoadRulesFromFile_EmptyRules (tested empty rules handling)
// - TestLoadRulesFromFile_MissingID (tested missing ID validation)
// - TestLoadCorrelationRulesFromFile_MissingID (tested missing ID validation)
// - TestLoadCorrelationRulesFromFile_EmptySequence (tested empty sequence)
// - TestRuleLoader_PathTraversal_SymlinkEscape (tested symlink security)
// - TestRuleLoader_PathTraversal_DotDotSlash (tested ../ security)
// - TestRuleLoader_PathTraversal_AbsolutePathOutsideBase (tested base directory)
//
// Security benefits of deletion:
// - Path traversal vulnerabilities eliminated (no file paths accepted)
// - Symlink escape attacks eliminated (no file system access)
// - No more CERBERUS_TEST_MODE bypass for security checks
//
// These tests are preserved as skipped tests to document what was previously tested.

// TestLoadRules_JSON - TASK #182: SKIPPED
// The LoadRules file loading function was deleted.
func TestLoadRules_JSON(t *testing.T) {
	t.Skip("LoadRules function deleted in Task #182 - database-only architecture")
}

// TestLoadRules_FileNotFound - TASK #182: SKIPPED
func TestLoadRules_FileNotFound(t *testing.T) {
	t.Skip("LoadRules function deleted in Task #182 - database-only architecture")
}

// TestLoadRules_InvalidJSON - TASK #182: SKIPPED
func TestLoadRules_InvalidJSON(t *testing.T) {
	t.Skip("LoadRules function deleted in Task #182 - database-only architecture")
}

// TestLoadCorrelationRules_JSON - TASK #182: SKIPPED
func TestLoadCorrelationRules_JSON(t *testing.T) {
	t.Skip("LoadCorrelationRules function deleted in Task #182 - database-only architecture")
}

// TestLoadCorrelationRules_FileNotFound - TASK #182: SKIPPED
func TestLoadCorrelationRules_FileNotFound(t *testing.T) {
	t.Skip("LoadCorrelationRules function deleted in Task #182 - database-only architecture")
}

// TestLoadCorrelationRules_InvalidJSON - TASK #182: SKIPPED
func TestLoadCorrelationRules_InvalidJSON(t *testing.T) {
	t.Skip("LoadCorrelationRules function deleted in Task #182 - database-only architecture")
}

// TestCompileRegexInRules_InvalidRegex - TASK #182: SKIPPED
func TestCompileRegexInRules_InvalidRegex(t *testing.T) {
	t.Skip("compileRegexInRules function deleted in Task #182 - database-only architecture")
}

// TestCompileRegexInCorrelationRules_InvalidRegex - TASK #182: SKIPPED
func TestCompileRegexInCorrelationRules_InvalidRegex(t *testing.T) {
	t.Skip("compileRegexInCorrelationRules function deleted in Task #182 - database-only architecture")
}

// TestLoadRulesFromFile_EmptyRules - TASK #182: SKIPPED
func TestLoadRulesFromFile_EmptyRules(t *testing.T) {
	t.Skip("loadRulesFromFile function deleted in Task #182 - database-only architecture")
}

// TestLoadRulesFromFile_MissingID - TASK #182: SKIPPED
func TestLoadRulesFromFile_MissingID(t *testing.T) {
	t.Skip("loadRulesFromFile function deleted in Task #182 - database-only architecture")
}

// TestLoadCorrelationRulesFromFile_MissingID - TASK #182: SKIPPED
func TestLoadCorrelationRulesFromFile_MissingID(t *testing.T) {
	t.Skip("loadCorrelationRulesFromFile function deleted in Task #182 - database-only architecture")
}

// TestLoadCorrelationRulesFromFile_EmptySequence - TASK #182: SKIPPED
func TestLoadCorrelationRulesFromFile_EmptySequence(t *testing.T) {
	t.Skip("loadCorrelationRulesFromFile function deleted in Task #182 - database-only architecture")
}

// TestRuleLoader_PathTraversal_SymlinkEscape - TASK #182: SKIPPED
// Security test no longer needed - file loading eliminated.
func TestRuleLoader_PathTraversal_SymlinkEscape(t *testing.T) {
	t.Skip("loadRulesFromFile function deleted in Task #182 - path traversal vulnerability eliminated")
}

// TestRuleLoader_PathTraversal_DotDotSlash - TASK #182: SKIPPED
// Security test no longer needed - file loading eliminated.
func TestRuleLoader_PathTraversal_DotDotSlash(t *testing.T) {
	t.Skip("loadRulesFromFile function deleted in Task #182 - path traversal vulnerability eliminated")
}

// TestRuleLoader_PathTraversal_AbsolutePathOutsideBase - TASK #182: SKIPPED
// Security test no longer needed - file loading eliminated.
func TestRuleLoader_PathTraversal_AbsolutePathOutsideBase(t *testing.T) {
	t.Skip("loadRulesFromFile function deleted in Task #182 - path traversal vulnerability eliminated")
}

// TestLoaderDocumentation documents the historical context of file loading
// This test is kept for reference purposes.
func TestLoaderDocumentation(t *testing.T) {
	t.Log("\n╔════════════════════════════════════════════════════════════════════════════╗")
	t.Log("║ TASK #182: File-Based Rule Loading Removal - HISTORICAL REFERENCE         ║")
	t.Log("╠════════════════════════════════════════════════════════════════════════════╣")
	t.Log("║                                                                            ║")
	t.Log("║ File loading functions DELETED:                                            ║")
	t.Log("║   - LoadRules (file loading wrapper)                                       ║")
	t.Log("║   - LoadCorrelationRules (file loading wrapper)                            ║")
	t.Log("║   - loadRulesFromFile (internal file loading)                              ║")
	t.Log("║   - loadCorrelationRulesFromFile (internal file loading)                   ║")
	t.Log("║   - compileRegexInRules (regex compilation for file rules)                 ║")
	t.Log("║   - compileRegexInCorrelationRules (regex compilation for file rules)      ║")
	t.Log("║                                                                            ║")
	t.Log("║ CURRENT ARCHITECTURE:                                                      ║")
	t.Log("║   - LoadRulesFromDB: Load rules from database                              ║")
	t.Log("║   - LoadCorrelationRulesFromDB: Load correlation rules from database       ║")
	t.Log("║   - SIGMA feeds: Import rules from external sources into database          ║")
	t.Log("║                                                                            ║")
	t.Log("║ SECURITY BENEFITS:                                                         ║")
	t.Log("║   - Path traversal vulnerabilities eliminated                              ║")
	t.Log("║   - Symlink escape attacks eliminated                                      ║")
	t.Log("║   - No file system access for rule loading                                 ║")
	t.Log("║   - Single source of truth (database)                                      ║")
	t.Log("╚════════════════════════════════════════════════════════════════════════════╝")
}
