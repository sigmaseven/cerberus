package storage

import (
	"cerberus/core"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// RuleWithLifecycle extends core.Rule with lifecycle management fields
// This struct represents rules with lifecycle status for state transitions
type RuleWithLifecycle struct {
	core.Rule
	LifecycleStatus  string         `json:"lifecycle_status"`
	DeprecatedAt     sql.NullTime   `json:"deprecated_at,omitempty"`
	DeprecatedReason sql.NullString `json:"deprecated_reason,omitempty"`
	DeprecatedBy     sql.NullString `json:"deprecated_by,omitempty"`
	SunsetDate       sql.NullTime   `json:"sunset_date,omitempty"`
}

// GetRuleWithLifecycle retrieves a rule with lifecycle fields
// This method extends the base GetRule to include lifecycle management fields
func (srs *SQLiteRuleStorage) GetRuleWithLifecycle(id string) (*RuleWithLifecycle, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, conditions, actions,
		       query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
		       lifecycle_status, deprecated_at, deprecated_reason, deprecated_by, sunset_date,
		       created_at, updated_at
		FROM rules
		WHERE id = ?
	`

	var rule RuleWithLifecycle
	var tagsJSON, mitreTacticsJSON, mitreTechniquesJSON, referencesJSON sql.NullString
	var author, falsePositives, metadataJSON sql.NullString
	var detectionJSON, logsourceJSON sql.NullString
	var conditionsJSON, actionsJSON, queryStr, correlationJSON sql.NullString
	var sigmaYAML, logsourceCategory, logsourceProduct, logsourceService sql.NullString
	var lifecycleStatus sql.NullString
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
		&conditionsJSON,
		&actionsJSON,
		&queryStr,
		&correlationJSON,
		&sigmaYAML,
		&logsourceCategory,
		&logsourceProduct,
		&logsourceService,
		&lifecycleStatus,
		&rule.DeprecatedAt,
		&rule.DeprecatedReason,
		&rule.DeprecatedBy,
		&rule.SunsetDate,
		&createdAt,
		&updatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	// Set lifecycle status with default
	if lifecycleStatus.Valid {
		rule.LifecycleStatus = lifecycleStatus.String
	} else {
		rule.LifecycleStatus = "experimental"
	}

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		rule.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		rule.UpdatedAt = t
	}

	// Parse nullable string fields
	if author.Valid {
		rule.Author = author.String
	}
	if falsePositives.Valid && falsePositives.String != "" {
		_ = json.Unmarshal([]byte(falsePositives.String), &rule.FalsePositives)
	}
	if sigmaYAML.Valid {
		rule.SigmaYAML = sigmaYAML.String
	}
	if logsourceCategory.Valid {
		rule.LogsourceCategory = logsourceCategory.String
	}
	if logsourceProduct.Valid {
		rule.LogsourceProduct = logsourceProduct.String
	}
	if logsourceService.Valid {
		rule.LogsourceService = logsourceService.String
	}
	if queryStr.Valid {
		rule.Query = queryStr.String
	}

	// Parse JSON fields with inline unmarshaling
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &rule.Tags)
	}
	if mitreTacticsJSON.Valid && mitreTacticsJSON.String != "" {
		_ = json.Unmarshal([]byte(mitreTacticsJSON.String), &rule.MitreTactics)
	}
	if mitreTechniquesJSON.Valid && mitreTechniquesJSON.String != "" {
		_ = json.Unmarshal([]byte(mitreTechniquesJSON.String), &rule.MitreTechniques)
	}
	if referencesJSON.Valid && referencesJSON.String != "" {
		_ = json.Unmarshal([]byte(referencesJSON.String), &rule.References)
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		_ = json.Unmarshal([]byte(metadataJSON.String), &rule.Metadata)
	}
	// TASK #184: Detection and Logsource fields removed - use SigmaYAML instead
	if correlationJSON.Valid && correlationJSON.String != "" {
		_ = json.Unmarshal([]byte(correlationJSON.String), &rule.Correlation)
	}
	// TASK #184: Conditions field removed - SIGMA rules use SigmaYAML
	if actionsJSON.Valid && actionsJSON.String != "" {
		_ = json.Unmarshal([]byte(actionsJSON.String), &rule.Actions)
	}

	return &rule, nil
}

// GetDeprecatedRules retrieves all rules with deprecated status
// This is used by the lifecycle manager to enforce sunset dates
func (srs *SQLiteRuleStorage) GetDeprecatedRules() ([]RuleWithLifecycle, error) {
	query := `
		SELECT id, type, name, description, severity, enabled, version,
		       lifecycle_status, deprecated_at, deprecated_reason, deprecated_by, sunset_date,
		       created_at, updated_at
		FROM rules
		WHERE lifecycle_status = 'deprecated'
		ORDER BY sunset_date ASC
	`

	rows, err := srs.sqlite.ReadDB.Query(query)
	if err != nil {
		// Gracefully handle missing lifecycle_status column (migration not yet run)
		if strings.Contains(err.Error(), "no such column") {
			return []RuleWithLifecycle{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var rules []RuleWithLifecycle
	for rows.Next() {
		var rule RuleWithLifecycle
		var createdAt, updatedAt string
		var lifecycleStatus sql.NullString

		err := rows.Scan(
			&rule.ID,
			&rule.Type,
			&rule.Name,
			&rule.Description,
			&rule.Severity,
			&rule.Enabled,
			&rule.Version,
			&lifecycleStatus,
			&rule.DeprecatedAt,
			&rule.DeprecatedReason,
			&rule.DeprecatedBy,
			&rule.SunsetDate,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Set lifecycle status
		if lifecycleStatus.Valid {
			rule.LifecycleStatus = lifecycleStatus.String
		} else {
			rule.LifecycleStatus = "deprecated"
		}

		// Parse timestamps
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			rule.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
			rule.UpdatedAt = t
		}

		rules = append(rules, rule)
	}

	return rules, rows.Err()
}
