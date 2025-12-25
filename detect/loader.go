package detect

import (
	"cerberus/core"
	"cerberus/storage"
)

// TASK #182: File-based rule loading removed
// All rules are now loaded exclusively from the database.
// This simplifies the architecture and eliminates file handling security concerns.
//
// Removed functions (file loading):
// - compileRegexInRules (regex compilation for file-loaded rules)
// - compileRegexInCorrelationRules (regex compilation for file-loaded correlation rules)
// - LoadRules (file loading wrapper)
// - LoadCorrelationRules (file loading wrapper)
// - loadRulesFromFile (internal file loading)
// - loadCorrelationRulesFromFile (internal file loading)
//
// Benefits of database-only loading:
// - Eliminates path traversal vulnerabilities
// - Eliminates symlink escape attacks
// - Single source of truth for rules
// - Better auditability and version control
// - SIGMA feeds provide rule ingestion via database

// LoadRulesFromDB loads rules from database
func LoadRulesFromDB(ruleStorage storage.RuleStorageInterface) ([]core.Rule, error) {
	return ruleStorage.GetAllRules()
}

// LoadCorrelationRulesFromDB loads correlation rules from database
func LoadCorrelationRulesFromDB(correlationRuleStorage storage.CorrelationRuleStorageInterface) ([]core.CorrelationRule, error) {
	return correlationRuleStorage.GetAllCorrelationRules()
}
