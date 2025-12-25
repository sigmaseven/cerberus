package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

const (
	// minMitreTechniqueLength defines minimum length for MITRE technique IDs
	// Format: T followed by 4+ digits (e.g., T1234, T1234.001)
	// RECOMMENDATION FIX #8: Magic number constant for MITRE technique validation
	minMitreTechniqueLength = 5 // "T1234" minimum format
)

// CacheInvalidator provides an interface for invalidating cached rules.
// This allows the storage layer to invalidate caches without depending on
// the detect package, maintaining clean separation of concerns.
//
// Implementations:
//   - detect.SigmaEngine implements this via InvalidateCache(ruleID)
//   - Can be nil if caching is not used (legacy deployments)
type CacheInvalidator interface {
	InvalidateCache(ruleID string)
}

// SQLiteRuleStorage handles rule persistence in SQLite
type SQLiteRuleStorage struct {
	sqlite           *SQLite
	regexTimeout     time.Duration
	logger           *zap.SugaredLogger
	cacheInvalidator CacheInvalidator // Optional cache invalidator
}

// NewSQLiteRuleStorage creates a new SQLite rule storage handler
func NewSQLiteRuleStorage(sqlite *SQLite, regexTimeout time.Duration, logger *zap.SugaredLogger) *SQLiteRuleStorage {
	return &SQLiteRuleStorage{
		sqlite:       sqlite,
		regexTimeout: regexTimeout,
		logger:       logger,
	}
}

// SetCacheInvalidator sets the cache invalidator for this storage.
// This should be called after creating the SigmaEngine to enable cache invalidation on updates.
//
// Example:
//
//	storage := NewSQLiteRuleStorage(...)
//	engine := detect.NewSigmaEngine(...)
//	storage.SetCacheInvalidator(engine)
func (srs *SQLiteRuleStorage) SetCacheInvalidator(invalidator CacheInvalidator) {
	srs.cacheInvalidator = invalidator
}

// GetRules retrieves rules with pagination
func (srs *SQLiteRuleStorage) GetRules(limit int, offset int) ([]core.Rule, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := srs.sqlite.ReadDB.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	return srs.scanRules(rows)
}

// GetAllRules retrieves all rules
func (srs *SQLiteRuleStorage) GetAllRules() ([]core.Rule, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		ORDER BY created_at DESC
	`

	rows, err := srs.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all rules: %w", err)
	}
	defer rows.Close()

	return srs.scanRules(rows)
}

// GetRuleCount returns total rule count
func (srs *SQLiteRuleStorage) GetRuleCount() (int64, error) {
	var count int64
	err := srs.sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count rules: %w", err)
	}
	return count, nil
}

// GetRule retrieves a single rule by ID
func (srs *SQLiteRuleStorage) GetRule(id string) (*core.Rule, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		WHERE id = ?
	`

	var rule core.Rule
	var tagsJSON, mitreTacticsJSON, mitreTechniquesJSON, referencesJSON sql.NullString
	var author, falsePositives, metadataJSON sql.NullString
	var detectionJSON, logsourceJSON sql.NullString
	var actionsJSON, queryStr, correlationJSON sql.NullString
	var sigmaYAML, logsourceCategory, logsourceProduct, logsourceService sql.NullString
	var createdAt, updatedAt string

	err := srs.sqlite.ReadDB.QueryRow(query, id).Scan(
		&rule.ID,
		&rule.Type,
		&rule.Name,
		&rule.Description,
		&rule.Severity,
		&rule.Enabled,
		&rule.Version,
		&tagsJSON,
		&mitreTacticsJSON,
		&mitreTechniquesJSON,
		&author,
		&referencesJSON,
		&falsePositives,
		&metadataJSON,
		&detectionJSON,
		&logsourceJSON,
		&actionsJSON,
		&queryStr,
		&correlationJSON,
		&sigmaYAML,
		&logsourceCategory,
		&logsourceProduct,
		&logsourceService,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRuleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}

	// Parse JSON fields with error handling
	if tagsJSON.Valid && tagsJSON.String != "" {
		if err := json.Unmarshal([]byte(tagsJSON.String), &rule.Tags); err != nil {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}
	}
	if mitreTacticsJSON.Valid && mitreTacticsJSON.String != "" {
		if err := json.Unmarshal([]byte(mitreTacticsJSON.String), &rule.MitreTactics); err != nil {
			return nil, fmt.Errorf("failed to parse mitre_tactics: %w", err)
		}
	}
	if mitreTechniquesJSON.Valid && mitreTechniquesJSON.String != "" {
		if err := json.Unmarshal([]byte(mitreTechniquesJSON.String), &rule.MitreTechniques); err != nil {
			return nil, fmt.Errorf("failed to parse mitre_techniques: %w", err)
		}
	}
	if author.Valid {
		rule.Author = author.String
	}
	if referencesJSON.Valid && referencesJSON.String != "" {
		if err := json.Unmarshal([]byte(referencesJSON.String), &rule.References); err != nil {
			return nil, fmt.Errorf("failed to parse references: %w", err)
		}
	}
	if falsePositives.Valid && falsePositives.String != "" {
		if err := json.Unmarshal([]byte(falsePositives.String), &rule.FalsePositives); err != nil {
			return nil, fmt.Errorf("failed to parse false_positives: %w", err)
		}
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		if err := json.Unmarshal([]byte(metadataJSON.String), &rule.Metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	}

	// TASK #184: Detection and Logsource fields removed from core.Rule
	// Data is read from DB for backward compatibility but no longer assigned to rule struct
	// SIGMA rules now use SigmaYAML field exclusively
	_ = detectionJSON  // Intentionally unused - kept for DB compatibility
	_ = logsourceJSON  // Intentionally unused - kept for DB compatibility

	// Actions
	if actionsJSON.Valid && actionsJSON.String != "" {
		if err := json.Unmarshal([]byte(actionsJSON.String), &rule.Actions); err != nil {
			return nil, fmt.Errorf("failed to parse actions: %w", err)
		}
	}

	// CQL-specific fields
	if queryStr.Valid {
		rule.Query = queryStr.String
	}
	if correlationJSON.Valid && correlationJSON.String != "" {
		var correlation map[string]interface{}
		if err := json.Unmarshal([]byte(correlationJSON.String), &correlation); err != nil {
			return nil, fmt.Errorf("failed to parse correlation: %w", err)
		}
		rule.Correlation = correlation
	}

	// SIGMA YAML field (for SIGMA rules)
	if sigmaYAML.Valid && sigmaYAML.String != "" {
		rule.SigmaYAML = sigmaYAML.String
	}

	// Denormalized logsource fields (for efficient filtering)
	if logsourceCategory.Valid {
		rule.LogsourceCategory = logsourceCategory.String
	}
	if logsourceProduct.Valid {
		rule.LogsourceProduct = logsourceProduct.String
	}
	if logsourceService.Valid {
		rule.LogsourceService = logsourceService.String
	}

	// Parse timestamps with error handling
	// BLOCKING FIX #3: Check timestamp parsing errors in GetRule
	rule.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at for rule %s: %w", rule.ID, err)
	}
	rule.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at for rule %s: %w", rule.ID, err)
	}

	return &rule, nil
}

// extractMetadataFromYAML parses the sigma_yaml field and extracts metadata into structured fields.
// This populates the rule's metadata, severity, tags, mitre fields, and denormalized logsource fields.
//
// SECURITY: Validates YAML structure and size limits via core.ValidateSigmaYAML
// PERFORMANCE: Only called during CREATE/UPDATE operations, not during rule evaluation
// SIDE EFFECTS: Modifies the rule in-place, populating extracted fields
// RECOMMENDATION FIX #9: Enhanced documentation for side effects
//
// Extracts:
//   - title → rule.Name (if not already set)
//   - level → rule.Severity (mapped to standard severity levels)
//   - tags → rule.Tags
//   - references → rule.References
//   - author → rule.Author
//   - false_positives → rule.FalsePositives
//   - logsource.category → rule.LogsourceCategory
//   - logsource.product → rule.LogsourceProduct
//   - logsource.service → rule.LogsourceService
//   - detection → rule.Detection (for backward compatibility)
//   - logsource → rule.Logsource (for backward compatibility)
//
// Returns error if YAML is invalid or parsing fails.
func extractMetadataFromYAML(rule *core.Rule) error {
	if rule == nil {
		return fmt.Errorf("cannot extract metadata from nil rule")
	}

	// Only process SIGMA rules with sigma_yaml field
	if strings.ToUpper(strings.TrimSpace(rule.Type)) != "SIGMA" {
		return nil // Not a SIGMA rule, skip
	}

	if strings.TrimSpace(rule.SigmaYAML) == "" {
		return nil // No YAML to extract, skip
	}

	// Validate and parse YAML
	// This provides security checks: size limit, depth limit, ReDoS protection, etc.
	parsed, err := core.ValidateSigmaYAML(rule.SigmaYAML)
	if err != nil {
		return fmt.Errorf("invalid sigma_yaml: %w", err)
	}

	// Extract title (use as name if not already set)
	if title, ok := parsed["title"].(string); ok && title != "" {
		if rule.Name == "" {
			rule.Name = title
		}
	}

	// Extract and map level to severity
	// SIGMA levels: informational, low, medium, high, critical
	// Map to our severity levels: Informational, Low, Medium, High, Critical
	if level, ok := parsed["level"].(string); ok && level != "" {
		levelLower := strings.ToLower(strings.TrimSpace(level))
		switch levelLower {
		case "critical":
			rule.Severity = "Critical"
		case "high":
			rule.Severity = "High"
		case "medium":
			rule.Severity = "Medium"
		case "low":
			rule.Severity = "Low"
		case "informational":
			rule.Severity = "Informational"
		default:
			// Unknown level - default to Medium and log warning
			rule.Severity = "Medium"
		}
	}

	// Extract tags (array of strings)
	if tagsRaw, ok := parsed["tags"]; ok {
		if tagsList, ok := tagsRaw.([]interface{}); ok {
			tags := make([]string, 0, len(tagsList))
			for _, tag := range tagsList {
				if tagStr, ok := tag.(string); ok {
					tags = append(tags, tagStr)
				}
			}
			if len(tags) > 0 {
				rule.Tags = tags
			}
		}
	}

	// Extract references (array of strings)
	if refsRaw, ok := parsed["references"]; ok {
		if refsList, ok := refsRaw.([]interface{}); ok {
			refs := make([]string, 0, len(refsList))
			for _, ref := range refsList {
				if refStr, ok := ref.(string); ok {
					refs = append(refs, refStr)
				}
			}
			if len(refs) > 0 {
				rule.References = refs
			}
		}
	}

	// Extract author
	if author, ok := parsed["author"].(string); ok && author != "" {
		rule.Author = author
	}

	// Extract false positives (array of strings)
	if fpRaw, ok := parsed["falsepositives"]; ok {
		if fpList, ok := fpRaw.([]interface{}); ok {
			fps := make([]string, 0, len(fpList))
			for _, fp := range fpList {
				if fpStr, ok := fp.(string); ok {
					fps = append(fps, fpStr)
				}
			}
			if len(fps) > 0 {
				rule.FalsePositives = fps
			}
		}
	}

	// TASK #184: Detection and Logsource fields removed from core.Rule
	// Detection is no longer stored in struct - SigmaYAML contains all detection info
	// Logsource extraction only populates denormalized columns for efficient filtering

	// Extract logsource and populate denormalized columns only
	if logsource, ok := parsed["logsource"].(map[string]interface{}); ok {
		// Extract denormalized logsource fields for efficient filtering
		if category, ok := logsource["category"].(string); ok && category != "" {
			rule.LogsourceCategory = category
		}
		if product, ok := logsource["product"].(string); ok && product != "" {
			rule.LogsourceProduct = product
		}
		if service, ok := logsource["service"].(string); ok && service != "" {
			rule.LogsourceService = service
		}
	}

	// Extract MITRE ATT&CK tags from tags array
	// Tags like "attack.t1234" or "attack.initial_access" are MITRE-related
	if len(rule.Tags) > 0 {
		mitreTactics := make(map[string]bool)
		mitreTechniques := make(map[string]bool)

		for _, tag := range rule.Tags {
			tagLower := strings.ToLower(tag)
			if strings.HasPrefix(tagLower, "attack.") {
				mitreID := strings.TrimPrefix(tagLower, "attack.")
				// Technique IDs start with 't' followed by digits (e.g., T1234)
				// Use constant instead of magic number
				if len(mitreID) > 0 && mitreID[0] == 't' && len(mitreID) >= minMitreTechniqueLength {
					mitreTechniques[strings.ToUpper(mitreID)] = true
				} else if mitreID != "" {
					// Tactic names (lowercase with underscores)
					tacticName := strings.ReplaceAll(mitreID, "_", "-")
					mitreTactics[tacticName] = true
				}
			}
		}

		// Convert maps to sorted slices
		if len(mitreTactics) > 0 {
			tactics := make([]string, 0, len(mitreTactics))
			for tactic := range mitreTactics {
				tactics = append(tactics, tactic)
			}
			rule.MitreTactics = tactics
		}
		if len(mitreTechniques) > 0 {
			techniques := make([]string, 0, len(mitreTechniques))
			for technique := range mitreTechniques {
				techniques = append(techniques, technique)
			}
			rule.MitreTechniques = techniques
		}
	}

	return nil
}

// CreateRule creates a new rule
func (srs *SQLiteRuleStorage) CreateRule(rule *core.Rule) error {
	// SECURITY & CORRECTNESS: Validate rule type and mutual exclusion
	// REQUIREMENT: Task 130.1 - Validate with core.Rule.Validate()
	// This ensures SIGMA rules have sigma_yaml (not query) and CQL rules have query (not sigma_yaml)
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Check if rule already exists
	existing, err := srs.GetRule(rule.ID)
	if err != nil && !errors.Is(err, ErrRuleNotFound) {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("rule with ID %s already exists", rule.ID)
	}

	// SIGMA YAML metadata extraction
	// REQUIREMENT: Task 130.1 - Extract metadata from sigma_yaml for SIGMA rules
	// This populates severity, tags, logsource fields, etc. from the YAML
	if strings.ToUpper(strings.TrimSpace(rule.Type)) == "SIGMA" && rule.SigmaYAML != "" {
		if err := extractMetadataFromYAML(rule); err != nil {
			return fmt.Errorf("failed to extract metadata from sigma_yaml: %w", err)
		}
	}

	// Set timestamps
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	// Serialize JSON fields with error handling
	// BLOCKING FIX #1: Check ALL json.Marshal errors in CreateRule
	tagsJSON, err := json.Marshal(rule.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	mitreTacticsJSON, err := json.Marshal(rule.MitreTactics)
	if err != nil {
		return fmt.Errorf("failed to marshal mitre_tactics: %w", err)
	}
	mitreTechniquesJSON, err := json.Marshal(rule.MitreTechniques)
	if err != nil {
		return fmt.Errorf("failed to marshal mitre_techniques: %w", err)
	}
	referencesJSON, err := json.Marshal(rule.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}
	falsePositivesJSON, err := json.Marshal(rule.FalsePositives)
	if err != nil {
		return fmt.Errorf("failed to marshal false_positives: %w", err)
	}
	metadataJSON, err := json.Marshal(rule.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	// TASK #184: Detection and Logsource fields removed from core.Rule
	// Write empty values to DB columns for backward compatibility
	var detectionJSON, logsourceJSON []byte

	var correlationJSON []byte
	if rule.Correlation != nil {
		correlationJSON, err = json.Marshal(rule.Correlation)
		if err != nil {
			return fmt.Errorf("failed to marshal correlation: %w", err)
		}
	}

	query := `
		INSERT INTO rules (id, type, name, description, severity, enabled, version,
		                   tags, mitre_tactics, mitre_techniques, author, rule_references,
		                   false_positives, metadata, detection, logsource, actions,
		                   query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		                   created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = srs.sqlite.WriteDB.Exec(query,
		rule.ID,
		rule.Type,
		rule.Name,
		rule.Description,
		rule.Severity,
		rule.Enabled,
		rule.Version,
		nullIfEmpty(string(tagsJSON)),
		nullIfEmpty(string(mitreTacticsJSON)),
		nullIfEmpty(string(mitreTechniquesJSON)),
		nullIfEmpty(rule.Author),
		nullIfEmpty(string(referencesJSON)),
		nullIfEmpty(string(falsePositivesJSON)),
		nullIfEmpty(string(metadataJSON)),
		nullIfEmpty(string(detectionJSON)),
		nullIfEmpty(string(logsourceJSON)),
		nullIfEmpty(string(actionsJSON)),
		nullIfEmpty(rule.Query),
		nullIfEmpty(string(correlationJSON)),
		nullIfEmpty(rule.SigmaYAML),
		nullIfEmpty(rule.LogsourceCategory),
		nullIfEmpty(rule.LogsourceProduct),
		nullIfEmpty(rule.LogsourceService),
		rule.CreatedAt.Format(time.RFC3339),
		rule.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to insert rule: %w", err)
	}

	srs.logger.Infof("Created %s rule %s", rule.Type, rule.ID)
	return nil
}

// nullIfEmpty returns nil for empty strings/arrays to properly store NULL in SQLite
func nullIfEmpty(s string) interface{} {
	if s == "" || s == "null" || s == "[]" || s == "{}" {
		return nil
	}
	return s
}

// UpdateRule updates an existing rule
func (srs *SQLiteRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	// SECURITY & CORRECTNESS: Validate rule type and mutual exclusion
	// REQUIREMENT: Task 130.2 - Same validation as CreateRule
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Check if rule exists
	existing, err := srs.GetRule(id)
	if err != nil {
		if errors.Is(err, ErrRuleNotFound) {
			return ErrRuleNotFound
		}
		return fmt.Errorf("failed to check existing rule: %w", err)
	}

	// SIGMA YAML metadata extraction
	// REQUIREMENT: Task 130.2 - Extract metadata from sigma_yaml for SIGMA rules
	if strings.ToUpper(strings.TrimSpace(rule.Type)) == "SIGMA" && rule.SigmaYAML != "" {
		if err := extractMetadataFromYAML(rule); err != nil {
			return fmt.Errorf("failed to extract metadata from sigma_yaml: %w", err)
		}
	}

	// Preserve creation time
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now()

	// Serialize JSON fields with error handling
	// BLOCKING FIX #1: Check ALL json.Marshal errors in UpdateRule
	tagsJSON, err := json.Marshal(rule.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	mitreTacticsJSON, err := json.Marshal(rule.MitreTactics)
	if err != nil {
		return fmt.Errorf("failed to marshal mitre_tactics: %w", err)
	}
	mitreTechniquesJSON, err := json.Marshal(rule.MitreTechniques)
	if err != nil {
		return fmt.Errorf("failed to marshal mitre_techniques: %w", err)
	}
	referencesJSON, err := json.Marshal(rule.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}
	falsePositivesJSON, err := json.Marshal(rule.FalsePositives)
	if err != nil {
		return fmt.Errorf("failed to marshal false_positives: %w", err)
	}
	metadataJSON, err := json.Marshal(rule.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	// TASK #184: Detection and Logsource fields removed from core.Rule
	// Write empty values to DB columns for backward compatibility
	var detectionJSON, logsourceJSON []byte

	var correlationJSON []byte
	if rule.Correlation != nil {
		correlationJSON, err = json.Marshal(rule.Correlation)
		if err != nil {
			return fmt.Errorf("failed to marshal correlation: %w", err)
		}
	}

	query := `
		UPDATE rules
		SET type = ?, name = ?, description = ?, severity = ?, enabled = ?,
		    version = ?, tags = ?, mitre_tactics = ?, mitre_techniques = ?,
		    author = ?, rule_references = ?, false_positives = ?, metadata = ?,
		    detection = ?, logsource = ?, actions = ?,
		    query = ?, correlation = ?, sigma_yaml = ?, logsource_category = ?,
		    logsource_product = ?, logsource_service = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := srs.sqlite.WriteDB.Exec(query,
		rule.Type,
		rule.Name,
		rule.Description,
		rule.Severity,
		rule.Enabled,
		rule.Version,
		nullIfEmpty(string(tagsJSON)),
		nullIfEmpty(string(mitreTacticsJSON)),
		nullIfEmpty(string(mitreTechniquesJSON)),
		nullIfEmpty(rule.Author),
		nullIfEmpty(string(referencesJSON)),
		nullIfEmpty(string(falsePositivesJSON)),
		nullIfEmpty(string(metadataJSON)),
		nullIfEmpty(string(detectionJSON)),
		nullIfEmpty(string(logsourceJSON)),
		nullIfEmpty(string(actionsJSON)),
		nullIfEmpty(rule.Query),
		nullIfEmpty(string(correlationJSON)),
		nullIfEmpty(rule.SigmaYAML),
		nullIfEmpty(rule.LogsourceCategory),
		nullIfEmpty(rule.LogsourceProduct),
		nullIfEmpty(rule.LogsourceService),
		rule.UpdatedAt.Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrRuleNotFound
	}

	// CACHE INVALIDATION: Invalidate cached rule after successful update
	// REQUIREMENT: Task 130.2 - Call cache invalidator after atomic update
	// This ensures the cache doesn't serve stale rule data after updates
	if srs.cacheInvalidator != nil {
		srs.cacheInvalidator.InvalidateCache(id)
		srs.logger.Debugf("Invalidated cache for updated rule %s", id)
	}

	srs.logger.Infof("Updated %s rule %s", rule.Type, id)
	return nil
}

// DeleteRule deletes a rule
func (srs *SQLiteRuleStorage) DeleteRule(id string) error {
	result, err := srs.sqlite.WriteDB.Exec("DELETE FROM rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrRuleNotFound
	}

	srs.logger.Infof("Deleted rule %s", id)
	return nil
}

// DeleteAllRules deletes all rules, optionally filtered by type.
// If ruleType is empty, all rules are deleted.
// If ruleType is "SIGMA" or "CQL", only rules of that type are deleted.
// Returns the number of rules deleted.
func (srs *SQLiteRuleStorage) DeleteAllRules(ruleType string) (int64, error) {
	var result sql.Result
	var err error

	if ruleType == "" {
		result, err = srs.sqlite.WriteDB.Exec("DELETE FROM rules")
	} else {
		result, err = srs.sqlite.WriteDB.Exec("DELETE FROM rules WHERE type = ?", ruleType)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to delete rules: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	srs.logger.Infof("Deleted %d rules (type filter: %q)", rowsAffected, ruleType)
	return rowsAffected, nil
}

// EnsureIndexes ensures database indexes exist (indexes created in schema)
func (srs *SQLiteRuleStorage) EnsureIndexes() error {
	// Indexes are created in the schema during table creation
	return nil
}

// scanRules is a helper to scan multiple rules from query results
func (srs *SQLiteRuleStorage) scanRules(rows *sql.Rows) ([]core.Rule, error) {
	// Initialize with make() to ensure non-nil slice for JSON serialization.
	// nil slices serialize to null, breaking frontend contract expecting [].
	rules := make([]core.Rule, 0)

	for rows.Next() {
		var rule core.Rule
		var tagsJSON, mitreTacticsJSON, mitreTechniquesJSON, referencesJSON sql.NullString
		var author, falsePositives, metadataJSON sql.NullString
		var detectionJSON, logsourceJSON sql.NullString
		var actionsJSON, queryStr, correlationJSON sql.NullString
		var sigmaYAML, logsourceCategory, logsourceProduct, logsourceService sql.NullString
		var createdAt, updatedAt string

		err := rows.Scan(
			&rule.ID,
			&rule.Type,
			&rule.Name,
			&rule.Description,
			&rule.Severity,
			&rule.Enabled,
			&rule.Version,
			&tagsJSON,
			&mitreTacticsJSON,
			&mitreTechniquesJSON,
			&author,
			&referencesJSON,
			&falsePositives,
			&metadataJSON,
			&detectionJSON,
			&logsourceJSON,
			&actionsJSON,
			&queryStr,
			&correlationJSON,
			&sigmaYAML,
			&logsourceCategory,
			&logsourceProduct,
			&logsourceService,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}

		// Parse JSON fields with error handling
		// BLOCKING FIX #2: Check ALL json.Unmarshal errors in scanRules
		if tagsJSON.Valid && tagsJSON.String != "" {
			if err := json.Unmarshal([]byte(tagsJSON.String), &rule.Tags); err != nil {
				return nil, fmt.Errorf("failed to unmarshal tags for rule %s: %w", rule.ID, err)
			}
		}
		if mitreTacticsJSON.Valid && mitreTacticsJSON.String != "" {
			if err := json.Unmarshal([]byte(mitreTacticsJSON.String), &rule.MitreTactics); err != nil {
				return nil, fmt.Errorf("failed to unmarshal mitre_tactics for rule %s: %w", rule.ID, err)
			}
		}
		if mitreTechniquesJSON.Valid && mitreTechniquesJSON.String != "" {
			if err := json.Unmarshal([]byte(mitreTechniquesJSON.String), &rule.MitreTechniques); err != nil {
				return nil, fmt.Errorf("failed to unmarshal mitre_techniques for rule %s: %w", rule.ID, err)
			}
		}
		if author.Valid {
			rule.Author = author.String
		}
		if referencesJSON.Valid && referencesJSON.String != "" {
			if err := json.Unmarshal([]byte(referencesJSON.String), &rule.References); err != nil {
				return nil, fmt.Errorf("failed to unmarshal references for rule %s: %w", rule.ID, err)
			}
		}
		if falsePositives.Valid && falsePositives.String != "" {
			if err := json.Unmarshal([]byte(falsePositives.String), &rule.FalsePositives); err != nil {
				return nil, fmt.Errorf("failed to unmarshal false_positives for rule %s: %w", rule.ID, err)
			}
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			if err := json.Unmarshal([]byte(metadataJSON.String), &rule.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata for rule %s: %w", rule.ID, err)
			}
		}

		// TASK #184: Detection and Logsource fields removed from core.Rule
		// Data is read from DB for backward compatibility but no longer assigned to rule struct
		// SIGMA rules now use SigmaYAML field exclusively
		_ = detectionJSON  // Intentionally unused - kept for DB compatibility
		_ = logsourceJSON  // Intentionally unused - kept for DB compatibility

		// Actions
		if actionsJSON.Valid && actionsJSON.String != "" {
			if err := json.Unmarshal([]byte(actionsJSON.String), &rule.Actions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal actions for rule %s: %w", rule.ID, err)
			}
		}

		// CQL-specific fields
		if queryStr.Valid {
			rule.Query = queryStr.String
		}
		if correlationJSON.Valid && correlationJSON.String != "" {
			var correlation map[string]interface{}
			if err := json.Unmarshal([]byte(correlationJSON.String), &correlation); err != nil {
				return nil, fmt.Errorf("failed to unmarshal correlation for rule %s: %w", rule.ID, err)
			}
			rule.Correlation = correlation
		}

		// SIGMA YAML field (for SIGMA rules)
		if sigmaYAML.Valid && sigmaYAML.String != "" {
			rule.SigmaYAML = sigmaYAML.String
		}

		// Denormalized logsource fields (for efficient filtering)
		if logsourceCategory.Valid {
			rule.LogsourceCategory = logsourceCategory.String
		}
		if logsourceProduct.Valid {
			rule.LogsourceProduct = logsourceProduct.String
		}
		if logsourceService.Valid {
			rule.LogsourceService = logsourceService.String
		}

		// Parse timestamps with error handling
		// BLOCKING FIX #3: Check timestamp parsing errors in scanRules
		rule.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at for rule %s: %w", rule.ID, err)
		}
		rule.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at for rule %s: %w", rule.ID, err)
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// GetRulesByType retrieves rules filtered by type (sigma or cql)
func (srs *SQLiteRuleStorage) GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		WHERE type = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := srs.sqlite.ReadDB.Query(query, ruleType, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules by type: %w", err)
	}
	defer rows.Close()

	return srs.scanRules(rows)
}

// GetEnabledRules retrieves all enabled rules
func (srs *SQLiteRuleStorage) GetEnabledRules() ([]core.Rule, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		WHERE enabled = 1
		ORDER BY created_at DESC
	`

	rows, err := srs.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled rules: %w", err)
	}
	defer rows.Close()

	return srs.scanRules(rows)
}

// EnableRule enables a rule by ID
func (srs *SQLiteRuleStorage) EnableRule(id string) error {
	result, err := srs.sqlite.WriteDB.Exec("UPDATE rules SET enabled = 1, updated_at = ? WHERE id = ?", time.Now().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("failed to enable rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrRuleNotFound
	}

	srs.logger.Infof("Enabled rule %s", id)
	return nil
}

// DisableRule disables a rule by ID
func (srs *SQLiteRuleStorage) DisableRule(id string) error {
	result, err := srs.sqlite.WriteDB.Exec("UPDATE rules SET enabled = 0, updated_at = ? WHERE id = ?", time.Now().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("failed to disable rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrRuleNotFound
	}

	srs.logger.Infof("Disabled rule %s", id)
	return nil
}

// SearchRules searches rules by name, description, or tags
func (srs *SQLiteRuleStorage) SearchRules(query string) ([]core.Rule, error) {
	searchQuery := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		WHERE name LIKE ? ESCAPE '\' OR description LIKE ? ESCAPE '\' OR tags LIKE ? ESCAPE '\'
		ORDER BY created_at DESC
	`

	// Escape LIKE special characters to prevent injection
	escapedQuery := query
	escapedQuery = strings.ReplaceAll(escapedQuery, "\\", "\\\\") // Escape backslash first
	escapedQuery = strings.ReplaceAll(escapedQuery, "%", "\\%")   // Escape %
	escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")   // Escape _
	searchPattern := "%" + escapedQuery + "%"
	rows, err := srs.sqlite.ReadDB.Query(searchQuery, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search rules: %w", err)
	}
	defer rows.Close()

	return srs.scanRules(rows)
}

// GetRulesWithFilters retrieves rules with advanced filtering
func (srs *SQLiteRuleStorage) GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) {
	// Build dynamic query based on filters
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       created_at, updated_at
		FROM rules
		WHERE 1=1
	`

	countQuery := "SELECT COUNT(*) FROM rules WHERE 1=1"
	var args []interface{}
	var countArgs []interface{}

	// Build WHERE clauses
	whereClauses := []string{}

	// Search filter
	if filters.Search != "" {
		escapedQuery := filters.Search
		escapedQuery = strings.ReplaceAll(escapedQuery, "\\", "\\\\")
		escapedQuery = strings.ReplaceAll(escapedQuery, "%", "\\%")
		escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")
		searchPattern := "%" + escapedQuery + "%"
		whereClauses = append(whereClauses, "(name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')")
		args = append(args, searchPattern, searchPattern, searchPattern)
		countArgs = append(countArgs, searchPattern, searchPattern, searchPattern)
	}

	// Severity filter
	if len(filters.Severities) > 0 {
		placeholders := make([]string, len(filters.Severities))
		for i, sev := range filters.Severities {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(sev))
			countArgs = append(countArgs, strings.ToLower(sev))
		}
		whereClauses = append(whereClauses, fmt.Sprintf("LOWER(severity) IN (%s)", strings.Join(placeholders, ",")))
	}

	// Enabled filter
	if filters.Enabled != nil {
		whereClauses = append(whereClauses, "enabled = ?")
		args = append(args, *filters.Enabled)
		countArgs = append(countArgs, *filters.Enabled)
	}

	// Type filter
	if len(filters.Types) > 0 {
		placeholders := make([]string, len(filters.Types))
		for i, t := range filters.Types {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(t))
			countArgs = append(countArgs, strings.ToLower(t))
		}
		whereClauses = append(whereClauses, fmt.Sprintf("LOWER(type) IN (%s)", strings.Join(placeholders, ",")))
	}

	// Feed ID filter
	if len(filters.FeedIDs) > 0 {
		feedClauses := make([]string, len(filters.FeedIDs))
		for i, feedID := range filters.FeedIDs {
			feedClauses[i] = "metadata LIKE ?"
			args = append(args, "%\"feed_id\":\""+feedID+"\"%")
			countArgs = append(countArgs, "%\"feed_id\":\""+feedID+"\"%")
		}
		whereClauses = append(whereClauses, "("+strings.Join(feedClauses, " OR ")+")")
	}

	// Author filter
	if len(filters.Authors) > 0 {
		placeholders := make([]string, len(filters.Authors))
		for i, author := range filters.Authors {
			placeholders[i] = "?"
			args = append(args, author)
			countArgs = append(countArgs, author)
		}
		whereClauses = append(whereClauses, fmt.Sprintf("author IN (%s)", strings.Join(placeholders, ",")))
	}

	// Tags filter (any tag matches)
	if len(filters.Tags) > 0 {
		tagClauses := make([]string, len(filters.Tags))
		for i, tag := range filters.Tags {
			tagClauses[i] = "tags LIKE ?"
			pattern := "%" + tag + "%"
			args = append(args, pattern)
			countArgs = append(countArgs, pattern)
		}
		whereClauses = append(whereClauses, "("+strings.Join(tagClauses, " OR ")+")")
	}

	// Logsource filters (denormalized columns for efficient filtering)
	// REQUIREMENT: Task 130.5 - Use denormalized logsource columns with indexes
	// PERFORMANCE: These indexed columns enable fast filtering without JSON parsing
	// The LogSources filter can match against category, product, or service
	if len(filters.LogSources) > 0 {
		logSourceClauses := make([]string, len(filters.LogSources))
		for i, logsource := range filters.LogSources {
			// Match against any of the three logsource dimensions
			// Example: "windows" could match product=windows, category=windows, or service=windows
			logSourceClauses[i] = "(logsource_category = ? OR logsource_product = ? OR logsource_service = ?)"
			args = append(args, logsource, logsource, logsource)
			countArgs = append(countArgs, logsource, logsource, logsource)
		}
		whereClauses = append(whereClauses, "("+strings.Join(logSourceClauses, " OR ")+")")
	}

	// MITRE Tactics filter
	if len(filters.MitreTactics) > 0 {
		tacticClauses := make([]string, len(filters.MitreTactics))
		for i, tactic := range filters.MitreTactics {
			tacticClauses[i] = "LOWER(mitre_tactics) LIKE ?"
			pattern := "%" + strings.ToLower(tactic) + "%"
			args = append(args, pattern)
			countArgs = append(countArgs, pattern)
		}
		whereClauses = append(whereClauses, "("+strings.Join(tacticClauses, " OR ")+")")
	}

	// MITRE Techniques filter
	if len(filters.MitreTechniques) > 0 {
		techniqueClauses := make([]string, len(filters.MitreTechniques))
		for i, technique := range filters.MitreTechniques {
			techniqueClauses[i] = "mitre_techniques LIKE ?"
			pattern := "%" + technique + "%"
			args = append(args, pattern)
			countArgs = append(countArgs, pattern)
		}
		whereClauses = append(whereClauses, "("+strings.Join(techniqueClauses, " OR ")+")")
	}

	// Date filters
	if filters.CreatedAfter != nil {
		whereClauses = append(whereClauses, "created_at >= ?")
		args = append(args, filters.CreatedAfter)
		countArgs = append(countArgs, filters.CreatedAfter)
	}
	if filters.CreatedBefore != nil {
		whereClauses = append(whereClauses, "created_at <= ?")
		args = append(args, filters.CreatedBefore)
		countArgs = append(countArgs, filters.CreatedBefore)
	}
	if filters.UpdatedAfter != nil {
		whereClauses = append(whereClauses, "updated_at >= ?")
		args = append(args, filters.UpdatedAfter)
		countArgs = append(countArgs, filters.UpdatedAfter)
	}
	if filters.UpdatedBefore != nil {
		whereClauses = append(whereClauses, "updated_at <= ?")
		args = append(args, filters.UpdatedBefore)
		countArgs = append(countArgs, filters.UpdatedBefore)
	}

	// Add WHERE clauses to queries
	if len(whereClauses) > 0 {
		whereStr := " AND " + strings.Join(whereClauses, " AND ")
		query += whereStr
		countQuery += whereStr
	}

	// Get total count
	var total int64
	err := srs.sqlite.ReadDB.QueryRow(countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count filtered rules: %w", err)
	}

	// Add sorting with whitelist validation to prevent SQL injection
	// Only allow specific column names and sort orders
	sortBy := "created_at"
	if filters.SortBy != "" {
		switch filters.SortBy {
		case "name", "severity", "created_at", "updated_at":
			sortBy = filters.SortBy
		default:
			// Invalid sort field, use default (don't trust user input)
			sortBy = "created_at"
		}
	}
	sortOrder := "DESC"
	if strings.ToUpper(filters.SortOrder) == "ASC" {
		sortOrder = "ASC"
	} else {
		// Invalid sort order, use default
		sortOrder = "DESC"
	}
	// Safe to use string concatenation here since both values are from whitelists
	query += " ORDER BY " + sortBy + " " + sortOrder

	// Add pagination
	if filters.Limit <= 0 {
		filters.Limit = 100
	}
	if filters.Page <= 0 {
		filters.Page = 1
	}
	offset := (filters.Page - 1) * filters.Limit
	// Prevent excessive offset to avoid resource exhaustion and integer overflow
	const maxOffset = 100000
	if offset > maxOffset {
		return []core.Rule{}, 0, fmt.Errorf("pagination offset too large: %d (maximum %d records)", offset, maxOffset)
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, filters.Limit, offset)

	// Execute query
	rows, err := srs.sqlite.ReadDB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query filtered rules: %w", err)
	}
	defer rows.Close()

	rules, err := srs.scanRules(rows)
	if err != nil {
		return nil, 0, err
	}

	return rules, total, nil
}

// GetRuleFilterMetadata returns available filter options
func (srs *SQLiteRuleStorage) GetRuleFilterMetadata() (*core.RuleFilterMetadata, error) {
	metadata := &core.RuleFilterMetadata{
		Severities: []string{"critical", "high", "medium", "low", "informational"},
		Types:      []string{"sigma", "cql"},
		LogSources: []string{"windows", "linux", "macos", "cloud", "network"},
	}

	// Get unique MITRE tactics
	tacticsQuery := "SELECT DISTINCT mitre_tactics FROM rules WHERE mitre_tactics IS NOT NULL AND mitre_tactics != ''"
	tacticsRows, err := srs.sqlite.ReadDB.Query(tacticsQuery)
	if err == nil {
		defer tacticsRows.Close()
		tacticsMap := make(map[string]bool)
		for tacticsRows.Next() {
			var tacticsJSON string
			if err := tacticsRows.Scan(&tacticsJSON); err == nil {
				var tactics []string
				if err := json.Unmarshal([]byte(tacticsJSON), &tactics); err == nil {
					for _, tactic := range tactics {
						tacticsMap[strings.ToLower(tactic)] = true
					}
				}
			}
		}
		for tactic := range tacticsMap {
			metadata.MitreTactics = append(metadata.MitreTactics, tactic)
		}
	}

	// Get unique MITRE techniques
	techniquesQuery := "SELECT DISTINCT mitre_techniques FROM rules WHERE mitre_techniques IS NOT NULL AND mitre_techniques != ''"
	techniquesRows, err := srs.sqlite.ReadDB.Query(techniquesQuery)
	if err == nil {
		defer techniquesRows.Close()
		techniquesMap := make(map[string]bool)
		for techniquesRows.Next() {
			var techniquesJSON string
			if err := techniquesRows.Scan(&techniquesJSON); err == nil {
				var techniques []string
				if err := json.Unmarshal([]byte(techniquesJSON), &techniques); err == nil {
					for _, technique := range techniques {
						techniquesMap[technique] = true
					}
				}
			}
		}
		for technique := range techniquesMap {
			metadata.MitreTechniques = append(metadata.MitreTechniques, technique)
		}
	}

	// Get unique authors
	authorsQuery := "SELECT DISTINCT author FROM rules WHERE author IS NOT NULL AND author != '' ORDER BY author LIMIT 100"
	authorsRows, err := srs.sqlite.ReadDB.Query(authorsQuery)
	if err == nil {
		defer authorsRows.Close()
		for authorsRows.Next() {
			var author string
			if err := authorsRows.Scan(&author); err == nil {
				metadata.Authors = append(metadata.Authors, author)
			}
		}
	}

	// Get unique tags (top 100 most common)
	tagsQuery := "SELECT DISTINCT tags FROM rules WHERE tags IS NOT NULL AND tags != '' LIMIT 1000"
	tagsRows, err := srs.sqlite.ReadDB.Query(tagsQuery)
	if err == nil {
		defer tagsRows.Close()
		tagsMap := make(map[string]int)
		for tagsRows.Next() {
			var tagsJSON string
			if err := tagsRows.Scan(&tagsJSON); err == nil {
				var tags []string
				if err := json.Unmarshal([]byte(tagsJSON), &tags); err == nil {
					for _, tag := range tags {
						tagsMap[tag]++
					}
				}
			}
		}
		// Get top 100 tags
		for tag := range tagsMap {
			metadata.Tags = append(metadata.Tags, tag)
			if len(metadata.Tags) >= 100 {
				break
			}
		}
	}

	// Get unique feed IDs
	feedsQuery := `
		SELECT DISTINCT json_extract(metadata, '$.feed_id') as feed_id,
		       json_extract(metadata, '$.feed_name') as feed_name
		FROM rules
		WHERE json_extract(metadata, '$.feed_id') IS NOT NULL
		ORDER BY feed_id
	`
	feedsRows, err := srs.sqlite.ReadDB.Query(feedsQuery)
	if err == nil {
		defer feedsRows.Close()
		for feedsRows.Next() {
			var feedID, feedName sql.NullString
			if err := feedsRows.Scan(&feedID, &feedName); err == nil && feedID.Valid {
				metadata.Feeds = append(metadata.Feeds, core.FeedInfo{
					ID:   feedID.String,
					Name: feedName.String,
				})
			}
		}
	}

	// Get total rule count
	var totalRules int
	err = srs.sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&totalRules)
	if err == nil {
		metadata.TotalRules = totalRules
	}

	return metadata, nil
}
