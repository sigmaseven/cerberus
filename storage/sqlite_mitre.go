package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/mitre"

	"go.uber.org/zap"
)

// SQLiteMitreStorage implements MitreStorageInterface using SQLite
// TASK 9.1: MITRE storage implementation with sub-technique support
type SQLiteMitreStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteMitreStorage creates a new SQLite-based MITRE storage
func NewSQLiteMitreStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteMitreStorage {
	return &SQLiteMitreStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// GetTactics retrieves all tactics
func (sms *SQLiteMitreStorage) GetTactics() ([]mitre.Tactic, error) {
	query := `SELECT id, stix_id, name, description, short_name, version, deprecated, created_at, updated_at FROM mitre_tactics ORDER BY id`
	rows, err := sms.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tactics: %w", err)
	}
	defer rows.Close()

	var tactics []mitre.Tactic
	for rows.Next() {
		var tactic mitre.Tactic
		var createdAt, updatedAt string
		var deprecated int

		var stixID string
		err := rows.Scan(
			&tactic.ID,
			&stixID,
			&tactic.Name,
			&tactic.Description,
			&tactic.ShortName,
			&tactic.Version,
			&deprecated,
			&createdAt,
			&updatedAt,
		)
		_ = stixID // Store for reference but types use ID field
		if err != nil {
			return nil, fmt.Errorf("failed to scan tactic: %w", err)
		}

		tactic.Deprecated = deprecated == 1
		tactic.Created, _ = time.Parse(time.RFC3339, createdAt)
		tactic.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		tactics = append(tactics, tactic)
	}

	return tactics, nil
}

// GetTactic retrieves a tactic by ID
func (sms *SQLiteMitreStorage) GetTactic(id string) (*mitre.Tactic, error) {
	query := `SELECT id, stix_id, name, description, short_name, version, deprecated, created_at, updated_at FROM mitre_tactics WHERE id = ?`
	var tactic mitre.Tactic
	var createdAt, updatedAt string
	var deprecated int

	var stixID string
	err := sms.sqlite.ReadDB.QueryRow(query, id).Scan(
		&tactic.ID,
		&stixID,
		&tactic.Name,
		&tactic.Description,
		&tactic.ShortName,
		&tactic.Version,
		&deprecated,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tactic not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tactic: %w", err)
	}

	tactic.Deprecated = deprecated == 1
	tactic.Created, _ = time.Parse(time.RFC3339, createdAt)
	tactic.Modified, _ = time.Parse(time.RFC3339, updatedAt)

	return &tactic, nil
}

// GetTechniques retrieves techniques with optional filtering
// TASK 9.1: Support sub-techniques in queries
func (sms *SQLiteMitreStorage) GetTechniques(limit int, offset int, tacticID string) ([]mitre.Technique, error) {
	var query string
	var args []interface{}

	if tacticID != "" {
		// Join with technique-tactic mapping table
		query = `
			SELECT DISTINCT t.id, t.stix_id, t.name, t.description, t.detection_methods, t.data_sources, 
			       t.platforms, t.is_subtechnique, t.parent_technique_id, t.version, t.deprecated, t.revoked,
			       t.created_at, t.updated_at
			FROM mitre_techniques t
			JOIN mitre_technique_tactics tt ON t.id = tt.technique_id
			WHERE tt.tactic_id = ?
			ORDER BY t.id
			LIMIT ? OFFSET ?
		`
		args = []interface{}{tacticID, limit, offset}
	} else {
		query = `
			SELECT id, stix_id, name, description, detection_methods, data_sources, platforms,
			       is_subtechnique, parent_technique_id, version, deprecated, revoked,
			       created_at, updated_at
			FROM mitre_techniques
			ORDER BY id
			LIMIT ? OFFSET ?
		`
		args = []interface{}{limit, offset}
	}

	rows, err := sms.sqlite.ReadDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query techniques: %w", err)
	}
	defer rows.Close()

	var techniques []mitre.Technique
	for rows.Next() {
		var tech mitre.Technique
		var detectionMethodsJSON, dataSourcesJSON, platformsJSON sql.NullString
		var parentTechniqueID sql.NullString
		var createdAt, updatedAt string
		var isSubtechnique, deprecated, revoked int

		var stixID string
		err := rows.Scan(
			&tech.ID,
			&stixID,
			&tech.Name,
			&tech.Description,
			&detectionMethodsJSON,
			&dataSourcesJSON,
			&platformsJSON,
			&isSubtechnique,
			&parentTechniqueID,
			&tech.Version,
			&deprecated,
			&revoked,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan technique: %w", err)
		}
		_ = stixID // Store for reference but types use ID field

		tech.XMitreIsSubTechnique = isSubtechnique == 1
		tech.Deprecated = deprecated == 1
		tech.Revoked = revoked == 1

		if detectionMethodsJSON.Valid {
			json.Unmarshal([]byte(detectionMethodsJSON.String), &tech.Detection)
		}
		if dataSourcesJSON.Valid {
			json.Unmarshal([]byte(dataSourcesJSON.String), &tech.DataSources)
		}
		if platformsJSON.Valid {
			json.Unmarshal([]byte(platformsJSON.String), &tech.Platforms)
		}

		tech.Created, _ = time.Parse(time.RFC3339, createdAt)
		tech.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		techniques = append(techniques, tech)
	}

	return techniques, nil
}

// GetTechniqueCount returns the total count of techniques
func (sms *SQLiteMitreStorage) GetTechniqueCount() (int64, error) {
	var count int64
	err := sms.sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM mitre_techniques").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get technique count: %w", err)
	}
	return count, nil
}

// GetTechnique retrieves a technique by ID
// TASK 9.1: Support sub-techniques
func (sms *SQLiteMitreStorage) GetTechnique(id string) (*mitre.Technique, error) {
	query := `
		SELECT id, stix_id, name, description, detection_methods, data_sources, platforms,
		       is_subtechnique, parent_technique_id, version, deprecated, revoked,
		       created_at, updated_at
		FROM mitre_techniques
		WHERE id = ?
	`

	var tech mitre.Technique
	var detectionMethodsJSON, dataSourcesJSON, platformsJSON sql.NullString
	var parentTechniqueID sql.NullString
	var createdAt, updatedAt string
	var isSubtechnique, deprecated, revoked int

	var stixID string
	err := sms.sqlite.ReadDB.QueryRow(query, id).Scan(
		&tech.ID,
		&stixID,
		&tech.Name,
		&tech.Description,
		&detectionMethodsJSON,
		&dataSourcesJSON,
		&platformsJSON,
		&isSubtechnique,
		&parentTechniqueID,
		&tech.Version,
		&deprecated,
		&revoked,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("technique not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get technique: %w", err)
	}

	tech.XMitreIsSubTechnique = isSubtechnique == 1
	tech.Deprecated = deprecated == 1
	tech.Revoked = revoked == 1

	if detectionMethodsJSON.Valid {
		json.Unmarshal([]byte(detectionMethodsJSON.String), &tech.Detection)
	}
	if dataSourcesJSON.Valid {
		json.Unmarshal([]byte(dataSourcesJSON.String), &tech.DataSources)
	}
	if platformsJSON.Valid {
		json.Unmarshal([]byte(platformsJSON.String), &tech.Platforms)
	}

	tech.Created, _ = time.Parse(time.RFC3339, createdAt)
	tech.Modified, _ = time.Parse(time.RFC3339, updatedAt)

	// Get tactics for this technique
	tactics, err := sms.GetTacticsForTechnique(id)
	if err == nil {
		for _, tactic := range tactics {
			tech.KillChainPhases = append(tech.KillChainPhases, mitre.KillChainPhase{
				KillChainName: "mitre-attack",
				PhaseName:     tactic.ShortName,
			})
		}
	}

	return &tech, nil
}

// GetSubTechniques retrieves all sub-techniques for a parent technique
// TASK 9.1: Sub-technique retrieval
func (sms *SQLiteMitreStorage) GetSubTechniques(parentTechniqueID string) ([]mitre.Technique, error) {
	query := `
		SELECT id, stix_id, name, description, detection_methods, data_sources, platforms,
		       is_subtechnique, parent_technique_id, version, deprecated, revoked,
		       created_at, updated_at
		FROM mitre_techniques
		WHERE parent_technique_id = ?
		ORDER BY id
	`

	rows, err := sms.sqlite.ReadDB.Query(query, parentTechniqueID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sub-techniques: %w", err)
	}
	defer rows.Close()

	var techniques []mitre.Technique
	for rows.Next() {
		var tech mitre.Technique
		var detectionMethodsJSON, dataSourcesJSON, platformsJSON sql.NullString
		var parentTechniqueID sql.NullString
		var createdAt, updatedAt string
		var isSubtechnique, deprecated, revoked int

		var stixID string
		err := rows.Scan(
			&tech.ID,
			&stixID,
			&tech.Name,
			&tech.Description,
			&detectionMethodsJSON,
			&dataSourcesJSON,
			&platformsJSON,
			&isSubtechnique,
			&parentTechniqueID,
			&tech.Version,
			&deprecated,
			&revoked,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sub-technique: %w", err)
		}
		_ = stixID // Store for reference but types use ID field

		tech.XMitreIsSubTechnique = isSubtechnique == 1
		tech.Deprecated = deprecated == 1
		tech.Revoked = revoked == 1

		if detectionMethodsJSON.Valid {
			json.Unmarshal([]byte(detectionMethodsJSON.String), &tech.Detection)
		}
		if dataSourcesJSON.Valid {
			json.Unmarshal([]byte(dataSourcesJSON.String), &tech.DataSources)
		}
		if platformsJSON.Valid {
			json.Unmarshal([]byte(platformsJSON.String), &tech.Platforms)
		}

		tech.Created, _ = time.Parse(time.RFC3339, createdAt)
		tech.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		techniques = append(techniques, tech)
	}

	return techniques, nil
}

// GetTacticsForTechnique retrieves all tactics associated with a technique
func (sms *SQLiteMitreStorage) GetTacticsForTechnique(techniqueID string) ([]mitre.Tactic, error) {
	query := `
		SELECT t.id, t.stix_id, t.name, t.description, t.short_name, t.version, t.deprecated, t.created_at, t.updated_at
		FROM mitre_tactics t
		JOIN mitre_technique_tactics tt ON t.id = tt.tactic_id
		WHERE tt.technique_id = ?
	`

	rows, err := sms.sqlite.ReadDB.Query(query, techniqueID)
	if err != nil {
		return nil, fmt.Errorf("failed to query tactics for technique: %w", err)
	}
	defer rows.Close()

	var tactics []mitre.Tactic
	for rows.Next() {
		var tactic mitre.Tactic
		var createdAt, updatedAt string
		var deprecated int

		var stixID string
		err := rows.Scan(
			&tactic.ID,
			&stixID,
			&tactic.Name,
			&tactic.Description,
			&tactic.ShortName,
			&tactic.Version,
			&deprecated,
			&createdAt,
			&updatedAt,
		)
		_ = stixID // Store for reference but types use ID field
		if err != nil {
			return nil, fmt.Errorf("failed to scan tactic: %w", err)
		}

		tactic.Deprecated = deprecated == 1
		tactic.Created, _ = time.Parse(time.RFC3339, createdAt)
		tactic.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		tactics = append(tactics, tactic)
	}

	return tactics, nil
}

// SearchTechniques searches techniques by name or description
func (sms *SQLiteMitreStorage) SearchTechniques(query string, limit int) ([]mitre.Technique, error) {
	searchPattern := "%" + query + "%"
	sqlQuery := `
		SELECT id, stix_id, name, description, detection_methods, data_sources, platforms,
		       is_subtechnique, parent_technique_id, version, deprecated, revoked,
		       created_at, updated_at
		FROM mitre_techniques
		WHERE name LIKE ? OR description LIKE ? OR id LIKE ?
		ORDER BY id
		LIMIT ?
	`

	rows, err := sms.sqlite.ReadDB.Query(sqlQuery, searchPattern, searchPattern, searchPattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search techniques: %w", err)
	}
	defer rows.Close()

	var techniques []mitre.Technique
	for rows.Next() {
		var tech mitre.Technique
		var detectionMethodsJSON, dataSourcesJSON, platformsJSON sql.NullString
		var parentTechniqueID sql.NullString
		var createdAt, updatedAt string
		var isSubtechnique, deprecated, revoked int

		var stixID string
		err := rows.Scan(
			&tech.ID,
			&stixID,
			&tech.Name,
			&tech.Description,
			&detectionMethodsJSON,
			&dataSourcesJSON,
			&platformsJSON,
			&isSubtechnique,
			&parentTechniqueID,
			&tech.Version,
			&deprecated,
			&revoked,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan technique: %w", err)
		}
		_ = stixID // Store for reference but types use ID field

		tech.XMitreIsSubTechnique = isSubtechnique == 1
		tech.Deprecated = deprecated == 1
		tech.Revoked = revoked == 1

		if detectionMethodsJSON.Valid {
			json.Unmarshal([]byte(detectionMethodsJSON.String), &tech.Detection)
		}
		if dataSourcesJSON.Valid {
			json.Unmarshal([]byte(dataSourcesJSON.String), &tech.DataSources)
		}
		if platformsJSON.Valid {
			json.Unmarshal([]byte(platformsJSON.String), &tech.Platforms)
		}

		tech.Created, _ = time.Parse(time.RFC3339, createdAt)
		tech.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		techniques = append(techniques, tech)
	}

	return techniques, nil
}

// CreateTactic creates a new tactic
func (sms *SQLiteMitreStorage) CreateTactic(tactic *mitre.Tactic) error {
	query := `
		INSERT OR REPLACE INTO mitre_tactics (id, stix_id, name, description, short_name, version, deprecated, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	deprecated := 0
	if tactic.Deprecated {
		deprecated = 1
	}

	// Set tactic ID from external reference if not already set
	tacticID := tactic.GetTacticID()
	if tacticID == "" {
		tacticID = tactic.ID // Use STIX ID as fallback
	}
	if tacticID == "" {
		return fmt.Errorf("tactic missing ID")
	}

	// Use STIX ID from tactic.ID for database
	stixID := tactic.ID
	if stixID == "" {
		stixID = tacticID
	}

	// Set ID field for return value
	tactic.ID = tacticID

	_, err := sms.sqlite.WriteDB.Exec(query,
		tacticID,
		stixID,
		tactic.Name,
		tactic.Description,
		tactic.ShortName,
		tactic.Version,
		deprecated,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to create tactic: %w", err)
	}

	sms.logger.Debugf("Created tactic: %s", tacticID)
	return nil
}

// CreateTechnique creates a new technique
// TASK 9.1: Support sub-techniques and parent relationships
func (sms *SQLiteMitreStorage) CreateTechnique(technique *mitre.Technique) error {
	query := `
		INSERT OR REPLACE INTO mitre_techniques 
		(id, stix_id, name, description, detection_methods, data_sources, platforms,
		 is_subtechnique, parent_technique_id, version, deprecated, revoked, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()

	// Get technique ID from external references
	techID := technique.GetTechniqueID()
	if techID == "" {
		// Fallback: try to extract from ID if it's a technique ID pattern
		if strings.HasPrefix(technique.ID, "attack-pattern--") {
			// This is a STIX ID, we need the external ID
			return fmt.Errorf("technique missing ID in external references")
		}
		techID = technique.ID // Last resort fallback
	}

	// Determine if sub-technique and get parent
	isSubtechnique := technique.IsSubTechnique()
	parentID := technique.GetParentTechniqueID()

	// Serialize JSON fields
	detectionMethodsJSON, _ := json.Marshal(technique.Detection)
	dataSourcesJSON, _ := json.Marshal(technique.DataSources)
	platformsJSON, _ := json.Marshal(technique.Platforms)

	isSubtechInt := 0
	if isSubtechnique {
		isSubtechInt = 1
	}

	deprecated := 0
	if technique.Deprecated {
		deprecated = 1
	}

	revoked := 0
	if technique.Revoked {
		revoked = 1
	}

	var parentIDPtr interface{}
	if parentID != "" {
		parentIDPtr = parentID
	}

	// Use STIX ID from technique.ID field
	stixID := technique.ID

	_, err := sms.sqlite.WriteDB.Exec(query,
		techID,
		stixID,
		technique.Name,
		technique.Description,
		string(detectionMethodsJSON),
		string(dataSourcesJSON),
		string(platformsJSON),
		isSubtechInt,
		parentIDPtr,
		technique.Version,
		deprecated,
		revoked,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to create technique: %w", err)
	}

	// Create tactic-technique relationships
	for _, kc := range technique.KillChainPhases {
		if kc.KillChainName == "mitre-attack" {
			// Get tactic ID by short name
			tactic, err := sms.GetTacticByShortName(kc.PhaseName)
			if err == nil && tactic != nil {
				if err := sms.CreateTechniqueTacticMapping(techID, tactic.ID); err != nil {
					sms.logger.Warnf("Failed to create tactic-technique mapping: %v", err)
				}
			}
		}
	}

	sms.logger.Debugf("Created technique: %s (sub-technique: %v, parent: %s)", techID, isSubtechnique, parentID)
	return nil
}

// GetTacticByShortName retrieves a tactic by its short name (e.g., "initial-access")
func (sms *SQLiteMitreStorage) GetTacticByShortName(shortName string) (*mitre.Tactic, error) {
	query := `SELECT id, stix_id, name, description, short_name, version, deprecated, created_at, updated_at FROM mitre_tactics WHERE short_name = ?`
	var tactic mitre.Tactic
	var createdAt, updatedAt string
	var deprecated int

	var stixID string
	err := sms.sqlite.ReadDB.QueryRow(query, shortName).Scan(
		&tactic.ID,
		&stixID,
		&tactic.Name,
		&tactic.Description,
		&tactic.ShortName,
		&tactic.Version,
		&deprecated,
		&createdAt,
		&updatedAt,
	)
	_ = stixID // Store for reference but types use ID field

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tactic not found: %s", shortName)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tactic: %w", err)
	}

	tactic.Deprecated = deprecated == 1
	tactic.Created, _ = time.Parse(time.RFC3339, createdAt)
	tactic.Modified, _ = time.Parse(time.RFC3339, updatedAt)

	return &tactic, nil
}

// CreateTechniqueTacticMapping creates a many-to-many relationship between technique and tactic
func (sms *SQLiteMitreStorage) CreateTechniqueTacticMapping(techniqueID, tacticID string) error {
	query := `INSERT OR IGNORE INTO mitre_technique_tactics (technique_id, tactic_id) VALUES (?, ?)`
	_, err := sms.sqlite.WriteDB.Exec(query, techniqueID, tacticID)
	if err != nil {
		return fmt.Errorf("failed to create technique-tactic mapping: %w", err)
	}
	return nil
}

// UpdateTactic updates an existing tactic
func (sms *SQLiteMitreStorage) UpdateTactic(id string, tactic *mitre.Tactic) error {
	query := `
		UPDATE mitre_tactics
		SET name = ?, description = ?, short_name = ?, version = ?, deprecated = ?, updated_at = ?
		WHERE id = ?
	`

	deprecated := 0
	if tactic.Deprecated {
		deprecated = 1
	}

	_, err := sms.sqlite.WriteDB.Exec(query,
		tactic.Name,
		tactic.Description,
		tactic.ShortName,
		tactic.Version,
		deprecated,
		time.Now().Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update tactic: %w", err)
	}

	return nil
}

// UpdateTechnique updates an existing technique
func (sms *SQLiteMitreStorage) UpdateTechnique(id string, technique *mitre.Technique) error {
	query := `
		UPDATE mitre_techniques
		SET name = ?, description = ?, detection_methods = ?, data_sources = ?, platforms = ?,
		    is_subtechnique = ?, parent_technique_id = ?, version = ?, deprecated = ?, revoked = ?, updated_at = ?
		WHERE id = ?
	`

	// Serialize JSON fields
	detectionMethodsJSON, _ := json.Marshal(technique.Detection)
	dataSourcesJSON, _ := json.Marshal(technique.DataSources)
	platformsJSON, _ := json.Marshal(technique.Platforms)

	isSubtechnique := 0
	if technique.IsSubTechnique() {
		isSubtechnique = 1
	}

	deprecated := 0
	if technique.Deprecated {
		deprecated = 1
	}

	revoked := 0
	if technique.Revoked {
		revoked = 1
	}

	parentID := technique.GetParentTechniqueID()
	var parentIDPtr interface{}
	if parentID != "" {
		parentIDPtr = parentID
	}

	_, err := sms.sqlite.WriteDB.Exec(query,
		technique.Name,
		technique.Description,
		string(detectionMethodsJSON),
		string(dataSourcesJSON),
		string(platformsJSON),
		isSubtechnique,
		parentIDPtr,
		technique.Version,
		deprecated,
		revoked,
		time.Now().Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update technique: %w", err)
	}

	return nil
}

// DeleteAllTactics deletes all tactics (for import/refresh)
func (sms *SQLiteMitreStorage) DeleteAllTactics() error {
	_, err := sms.sqlite.WriteDB.Exec("DELETE FROM mitre_tactics")
	if err != nil {
		return fmt.Errorf("failed to delete all tactics: %w", err)
	}
	return nil
}

// DeleteAllTechniques deletes all techniques (for import/refresh)
func (sms *SQLiteMitreStorage) DeleteAllTechniques() error {
	_, err := sms.sqlite.WriteDB.Exec("DELETE FROM mitre_technique_tactics")
	if err != nil {
		return fmt.Errorf("failed to delete technique-tactic mappings: %w", err)
	}
	_, err = sms.sqlite.WriteDB.Exec("DELETE FROM mitre_technique_data_sources")
	if err != nil {
		return fmt.Errorf("failed to delete technique-data source mappings: %w", err)
	}
	_, err = sms.sqlite.WriteDB.Exec("DELETE FROM mitre_techniques")
	if err != nil {
		return fmt.Errorf("failed to delete all techniques: %w", err)
	}
	return nil
}

// GetTacticCoverage returns coverage statistics by tactic
func (sms *SQLiteMitreStorage) GetTacticCoverage() ([]mitre.TacticCoverage, error) {
	// Query joins techniques with rules to calculate coverage
	query := `
		SELECT 
			t.id as tactic_id,
			t.name as tactic_name,
			COUNT(DISTINCT tech.id) as total_rules,
			0 as total_alerts,
			'' as last_alert_time
		FROM mitre_tactics t
		LEFT JOIN mitre_technique_tactics tt ON t.id = tt.tactic_id
		LEFT JOIN mitre_techniques tech ON tt.technique_id = tech.id
		LEFT JOIN rules r ON (
			r.mitre_techniques LIKE '%' || tech.id || '%' OR
			tech.id LIKE r.mitre_techniques || '%'
		)
		WHERE tech.id IS NOT NULL
		GROUP BY t.id, t.name
	`

	rows, err := sms.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tactic coverage: %w", err)
	}
	defer rows.Close()

	var coverage []mitre.TacticCoverage
	for rows.Next() {
		var tc mitre.TacticCoverage
		err := rows.Scan(
			&tc.TacticID,
			&tc.TacticName,
			&tc.TotalRules,
			&tc.TotalAlerts,
			&tc.LastAlertTime,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tactic coverage: %w", err)
		}
		coverage = append(coverage, tc)
	}

	return coverage, nil
}

// GetTechniqueCoverage returns coverage statistics by technique
func (sms *SQLiteMitreStorage) GetTechniqueCoverage() ([]mitre.TechniqueCoverage, error) {
	// Simplified query - full implementation would join with alerts
	query := `
		SELECT 
			tech.id as technique_id,
			tech.name as technique_name,
			COUNT(DISTINCT r.id) as total_rules,
			0 as total_alerts,
			'' as last_alert_time
		FROM mitre_techniques tech
		LEFT JOIN rules r ON (
			r.mitre_techniques LIKE '%' || tech.id || '%' OR
			tech.id LIKE r.mitre_techniques || '%'
		)
		GROUP BY tech.id, tech.name
	`

	rows, err := sms.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query technique coverage: %w", err)
	}
	defer rows.Close()

	var coverage []mitre.TechniqueCoverage
	for rows.Next() {
		var tc mitre.TechniqueCoverage
		err := rows.Scan(
			&tc.TechniqueID,
			&tc.TechniqueName,
			&tc.TotalRules,
			&tc.TotalAlerts,
			&tc.LastAlertTime,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan technique coverage: %w", err)
		}
		coverage = append(coverage, tc)
	}

	return coverage, nil
}

// EnsureIndexes ensures database indexes exist
func (sms *SQLiteMitreStorage) EnsureIndexes() error {
	// Indexes are created in schema
	return nil
}

// CreateDataSource creates a new data source
// TASK 9.1: Data source storage
func (sms *SQLiteMitreStorage) CreateDataSource(dataSource *mitre.DataSource) error {
	query := `
		INSERT OR REPLACE INTO mitre_data_sources 
		(id, stix_id, name, description, collection_layers, platforms, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()

	// Get external ID from references
	extID := ""
	for _, ref := range dataSource.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			extID = ref.ExternalID
			break
		}
	}
	if extID == "" {
		extID = dataSource.ID // Fallback to STIX ID
	}

	collectionLayersJSON, _ := json.Marshal(dataSource.CollectionLayers)
	platformsJSON, _ := json.Marshal(dataSource.Platforms)

	_, err := sms.sqlite.WriteDB.Exec(query,
		extID,
		dataSource.ID, // STIX ID
		dataSource.Name,
		dataSource.Description,
		string(collectionLayersJSON),
		string(platformsJSON),
		dataSource.Version,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to create data source: %w", err)
	}

	sms.logger.Debugf("Created data source: %s", extID)
	return nil
}

// GetDataSources retrieves all data sources
// TASK 9.1: Data source retrieval
func (sms *SQLiteMitreStorage) GetDataSources() ([]mitre.DataSource, error) {
	query := `SELECT id, stix_id, name, description, collection_layers, platforms, version, created_at, updated_at FROM mitre_data_sources ORDER BY id`
	rows, err := sms.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query data sources: %w", err)
	}
	defer rows.Close()

	var dataSources []mitre.DataSource
	for rows.Next() {
		var ds mitre.DataSource
		var collectionLayersJSON, platformsJSON sql.NullString
		var createdAt, updatedAt string

		var stixID string
		err := rows.Scan(
			&ds.ID,
			&stixID,
			&ds.Name,
			&ds.Description,
			&collectionLayersJSON,
			&platformsJSON,
			&ds.Version,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan data source: %w", err)
		}

		if collectionLayersJSON.Valid {
			json.Unmarshal([]byte(collectionLayersJSON.String), &ds.CollectionLayers)
		}
		if platformsJSON.Valid {
			json.Unmarshal([]byte(platformsJSON.String), &ds.Platforms)
		}

		ds.Created, _ = time.Parse(time.RFC3339, createdAt)
		ds.Modified, _ = time.Parse(time.RFC3339, updatedAt)

		dataSources = append(dataSources, ds)
	}

	return dataSources, nil
}

// CreateTechniqueDataSourceMapping creates a many-to-many relationship between technique and data source
// TASK 9.1: Technique-data source mapping
func (sms *SQLiteMitreStorage) CreateTechniqueDataSourceMapping(techniqueID, dataSourceID string) error {
	query := `INSERT OR IGNORE INTO mitre_technique_data_sources (technique_id, data_source_id) VALUES (?, ?)`
	_, err := sms.sqlite.WriteDB.Exec(query, techniqueID, dataSourceID)
	if err != nil {
		return fmt.Errorf("failed to create technique-data source mapping: %w", err)
	}
	return nil
}
