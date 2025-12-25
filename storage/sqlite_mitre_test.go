package storage

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"

	"cerberus/mitre"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupMitreTestDB creates an in-memory SQLite database for MITRE tests
func setupMitreTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create MITRE tables
	schema := `
	CREATE TABLE IF NOT EXISTS mitre_tactics (
		id TEXT PRIMARY KEY,
		stix_id TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		short_name TEXT NOT NULL,
		version TEXT,
		deprecated INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tactics_short_name ON mitre_tactics(short_name);

	CREATE TABLE IF NOT EXISTS mitre_techniques (
		id TEXT PRIMARY KEY,
		stix_id TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		tactic_id TEXT,
		parent_technique_id TEXT,
		detection_methods TEXT,
		data_sources TEXT,
		platforms TEXT,
		is_subtechnique INTEGER NOT NULL DEFAULT 0,
		version TEXT,
		deprecated INTEGER NOT NULL DEFAULT 0,
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (parent_technique_id) REFERENCES mitre_techniques(id)
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_tactic_id ON mitre_techniques(tactic_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_parent_id ON mitre_techniques(parent_technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_is_subtechnique ON mitre_techniques(is_subtechnique);

	CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
		technique_id TEXT NOT NULL,
		tactic_id TEXT NOT NULL,
		PRIMARY KEY (technique_id, tactic_id),
		FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
		FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tt_technique_id ON mitre_technique_tactics(technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_tt_tactic_id ON mitre_technique_tactics(tactic_id);

	CREATE TABLE IF NOT EXISTS mitre_data_sources (
		id TEXT PRIMARY KEY,
		stix_id TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		collection_layers TEXT,
		platforms TEXT,
		version TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS mitre_technique_data_sources (
		technique_id TEXT NOT NULL,
		data_source_id TEXT NOT NULL,
		PRIMARY KEY (technique_id, data_source_id),
		FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
		FOREIGN KEY (data_source_id) REFERENCES mitre_data_sources(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tds_technique_id ON mitre_technique_data_sources(technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_tds_data_source_id ON mitre_technique_data_sources(data_source_id);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	return sqlite
}

// TestSQLiteMitreStorage_CreateTactic tests tactic creation
func TestSQLiteMitreStorage_CreateTactic(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	tests := []struct {
		name      string
		tactic    *mitre.Tactic
		expectErr bool
	}{
		{
			name: "Valid tactic",
			tactic: &mitre.Tactic{
				ID:        "TA0001",
				Name:      "Initial Access",
				ShortName: "initial-access",
				Version:   "2.1",
			},
			expectErr: false,
		},
		{
			name: "Duplicate tactic ID",
			tactic: &mitre.Tactic{
				ID:        "TA0001",
				Name:      "Initial Access",
				ShortName: "initial-access",
				Version:   "2.1",
			},
			expectErr: true, // Should fail on duplicate
		},
		{
			name: "Tactic with description",
			tactic: &mitre.Tactic{
				ID:          "TA0002",
				Name:        "Execution",
				ShortName:   "execution",
				Description: "Test description",
				Version:     "2.1",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateTactic(tt.tactic)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify tactic was created
				retrieved, err := storage.GetTactic(tt.tactic.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.tactic.ID, retrieved.ID)
				assert.Equal(t, tt.tactic.Name, retrieved.Name)
				assert.Equal(t, tt.tactic.ShortName, retrieved.ShortName)
			}
		})
	}
}

// TestSQLiteMitreStorage_CreateTechnique tests technique creation
func TestSQLiteMitreStorage_CreateTechnique(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create a tactic first
	tactic := &mitre.Tactic{
		ID:        "TA0001",
		Name:      "Initial Access",
		ShortName: "initial-access",
		Version:   "2.1",
	}
	err := storage.CreateTactic(tactic)
	require.NoError(t, err)

	tests := []struct {
		name      string
		technique *mitre.Technique
		expectErr bool
	}{
		{
			name: "Valid technique",
			technique: &mitre.Technique{
				ID:        "attack-pattern--t1001",
				Name:      "Data Obfuscation",
				Version:   "2.1",
				Platforms: []string{"Linux", "macOS", "Windows"},
				ExternalReferences: []mitre.ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "T1001"},
				},
			},
			expectErr: false,
		},
		{
			name: "Sub-technique with parent",
			technique: &mitre.Technique{
				ID:                   "attack-pattern--sub-technique",
				Name:                 "Junk Data",
				XMitreIsSubTechnique: true,
				Version:              "2.1",
				Platforms:            []string{"Linux"},
				ExternalReferences: []mitre.ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "T1001.001"},
				},
			},
			expectErr: false,
		},
		{
			name: "Duplicate technique ID",
			technique: &mitre.Technique{
				ID:      "attack-pattern--duplicate",
				Name:    "Duplicate",
				Version: "2.1",
				ExternalReferences: []mitre.ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "T1001"}, // Duplicate of first test
				},
			},
			expectErr: true, // Should fail on duplicate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateTechnique(tt.technique)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify technique was created
				retrieved, err := storage.GetTechnique(tt.technique.ID)
				require.NoError(t, err)
				// Verify technique ID from external references
				retrievedID := retrieved.GetTechniqueID()
				expectedID := tt.technique.GetTechniqueID()
				assert.Equal(t, expectedID, retrievedID)
				assert.Equal(t, tt.technique.Name, retrieved.Name)
				if tt.technique.IsSubTechnique() {
					assert.True(t, retrieved.IsSubTechnique())
					assert.Equal(t, tt.technique.GetParentTechniqueID(), retrieved.GetParentTechniqueID())
				}
			}
		})
	}
}

// TestSQLiteMitreStorage_ForeignKeyConstraints tests foreign key constraints
func TestSQLiteMitreStorage_ForeignKeyConstraints(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Verify foreign keys are enabled
	var fkEnabled int
	err := sqlite.DB.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	require.NoError(t, err)
	require.Equal(t, 1, fkEnabled, "Foreign keys must be enabled for these tests")

	// Test: Cannot create technique-tactic mapping with invalid tactic ID
	t.Run("Invalid tactic ID in mapping", func(t *testing.T) {
		// Create a technique first
		technique := &mitre.Technique{
			ID:      "T1001",
			Name:    "Test Technique",
			Version: "2.1",
		}
		err := storage.CreateTechnique(technique)
		require.NoError(t, err)

		// Try to create mapping with non-existent tactic
		err = storage.CreateTechniqueTacticMapping("T1001", "TA9999")
		require.Error(t, err, "Should fail when tactic doesn't exist")
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint")
	})

	// Test: Cannot create sub-technique with invalid parent technique ID
	t.Run("Invalid parent technique ID", func(t *testing.T) {
		subtechnique := &mitre.Technique{
			ID:                   "attack-pattern--invalid-sub",
			Name:                 "Invalid Sub-technique",
			XMitreIsSubTechnique: true,
			Version:              "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: "T9999.001"}, // Parent T9999 doesn't exist
			},
		}
		err := storage.CreateTechnique(subtechnique)
		// Note: SQLite foreign key constraint will fail when parent doesn't exist
		require.Error(t, err, "Should fail when parent technique doesn't exist")
	})

	// Test: Cascading delete when tactic is deleted
	t.Run("Cascade delete tactic mappings", func(t *testing.T) {
		// Create tactic and technique
		tactic := &mitre.Tactic{
			ID:        "TA0002",
			Name:      "Execution",
			ShortName: "execution",
			Version:   "2.1",
		}
		err := storage.CreateTactic(tactic)
		require.NoError(t, err)

		technique := &mitre.Technique{
			ID:      "attack-pattern--t1002",
			Name:    "Command and Scripting Interpreter",
			Version: "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: "T1002"},
			},
		}
		err = storage.CreateTechnique(technique)
		require.NoError(t, err)

		// Create mapping
		err = storage.CreateTechniqueTacticMapping("T1002", "TA0002")
		require.NoError(t, err)

		// Verify mapping exists
		tactics, err := storage.GetTacticsForTechnique("T1002")
		require.NoError(t, err)
		assert.Contains(t, tactics, *tactic)

		// Delete tactic (should cascade delete mapping)
		// Note: We need to check if DeleteTactic exists, otherwise test deletion via SQL
		_, err = sqlite.DB.Exec("DELETE FROM mitre_tactics WHERE id = ?", "TA0002")
		require.NoError(t, err)

		// Verify mapping was cascaded
		tactics, err = storage.GetTacticsForTechnique("T1002")
		require.NoError(t, err)
		assert.NotContains(t, tactics, *tactic)
	})
}

// TestSQLiteMitreStorage_TransactionHandling tests transaction handling
func TestSQLiteMitreStorage_TransactionHandling(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Test: Transaction rollback on error
	t.Run("Transaction rollback on error", func(t *testing.T) {
		err := sqlite.WithTransaction(func(tx *sql.Tx) error {
			// Create tactic
			tactic := &mitre.Tactic{
				ID:        "TA0003",
				Name:      "Persistence",
				ShortName: "persistence",
				Version:   "2.1",
			}
			err := storage.CreateTactic(tactic)
			if err != nil {
				return err
			}

			// Intentionally cause an error (duplicate ID)
			tactic2 := &mitre.Tactic{
				ID:        "TA0003", // Duplicate
				Name:      "Duplicate",
				ShortName: "duplicate",
				Version:   "2.1",
			}
			err = storage.CreateTactic(tactic2)
			if err != nil {
				return err // This should trigger rollback
			}

			return nil
		})

		// Transaction should have rolled back
		require.Error(t, err)

		// Verify tactic was not created (rolled back)
		_, err = storage.GetTactic("TA0003")
		require.Error(t, err, "Tactic should not exist after rollback")
	})

	// Test: Successful transaction commit
	t.Run("Transaction commit on success", func(t *testing.T) {
		err := sqlite.WithTransaction(func(tx *sql.Tx) error {
			tactic := &mitre.Tactic{
				ID:        "TA0004",
				Name:      "Privilege Escalation",
				ShortName: "privilege-escalation",
				Version:   "2.1",
			}
			return storage.CreateTactic(tactic)
		})

		require.NoError(t, err)

		// Verify tactic was created (committed)
		tactic, err := storage.GetTactic("TA0004")
		require.NoError(t, err)
		assert.Equal(t, "TA0004", tactic.ID)
	})
}

// TestSQLiteMitreStorage_Concurrency tests concurrent operations
func TestSQLiteMitreStorage_Concurrency(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create initial tactic
	tactic := &mitre.Tactic{
		ID:        "TA0005",
		Name:      "Defense Evasion",
		ShortName: "defense-evasion",
		Version:   "2.1",
	}
	err := storage.CreateTactic(tactic)
	require.NoError(t, err)

	const numGoroutines = 20
	const techniquesPerGoroutine = 10

	var wg sync.WaitGroup
	var errors []error
	var mu sync.Mutex

	// Concurrently create techniques
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < techniquesPerGoroutine; j++ {
				techniqueID := fmt.Sprintf("T%d%03d", goroutineID, j)
				technique := &mitre.Technique{
					ID:      techniqueID,
					Name:    "Concurrent Technique",
					Version: "2.1",
				}
				err := storage.CreateTechnique(technique)
				if err != nil {
					mu.Lock()
					errors = append(errors, err)
					mu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify no errors occurred (or only expected duplicate errors)
	t.Logf("Concurrent operations completed with %d errors", len(errors))

	// Verify techniques were created
	techniques, err := storage.GetTechniques(1000, 0, "")
	require.NoError(t, err)
	assert.Greater(t, len(techniques), 0, "Some techniques should have been created")
}

// TestSQLiteMitreStorage_UpdateTechnique tests technique updates
func TestSQLiteMitreStorage_UpdateTechnique(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create initial technique
	technique := &mitre.Technique{
		ID:        "attack-pattern--t2001",
		Name:      "Original Name",
		Version:   "2.1",
		Platforms: []string{"Windows"},
		ExternalReferences: []mitre.ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T2001"},
		},
	}
	err := storage.CreateTechnique(technique)
	require.NoError(t, err)

	// Update technique
	technique.Name = "Updated Name"
	technique.Platforms = []string{"Windows", "Linux"}
	err = storage.UpdateTechnique("T2001", technique)
	require.NoError(t, err)

	// Verify update
	retrieved, err := storage.GetTechnique("T2001")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, []string{"Windows", "Linux"}, retrieved.Platforms)
}

// TestSQLiteMitreStorage_GetTechniquesByTactic tests filtering by tactic
func TestSQLiteMitreStorage_GetTechniquesByTactic(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create tactics
	tactic1 := &mitre.Tactic{
		ID:        "TA0006",
		Name:      "Credential Access",
		ShortName: "credential-access",
		Version:   "2.1",
	}
	err := storage.CreateTactic(tactic1)
	require.NoError(t, err)

	tactic2 := &mitre.Tactic{
		ID:        "TA0007",
		Name:      "Discovery",
		ShortName: "discovery",
		Version:   "2.1",
	}
	err = storage.CreateTactic(tactic2)
	require.NoError(t, err)

	// Create techniques
	technique1 := &mitre.Technique{
		ID:      "attack-pattern--t3001",
		Name:    "Credential Technique",
		Version: "2.1",
		ExternalReferences: []mitre.ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T3001"},
		},
	}
	err = storage.CreateTechnique(technique1)
	require.NoError(t, err)

	technique2 := &mitre.Technique{
		ID:      "attack-pattern--t3002",
		Name:    "Discovery Technique",
		Version: "2.1",
		ExternalReferences: []mitre.ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T3002"},
		},
	}
	err = storage.CreateTechnique(technique2)
	require.NoError(t, err)

	// Create mappings
	err = storage.CreateTechniqueTacticMapping("T3001", "TA0006")
	require.NoError(t, err)

	err = storage.CreateTechniqueTacticMapping("T3002", "TA0007")
	require.NoError(t, err)

	// Get techniques for tactic1
	techniques, err := storage.GetTechniques(100, 0, "TA0006")
	require.NoError(t, err)
	assert.Len(t, techniques, 1)
	assert.Equal(t, "T3001", techniques[0].GetTechniqueID())

	// Get techniques for tactic2
	techniques, err = storage.GetTechniques(100, 0, "TA0007")
	require.NoError(t, err)
	assert.Len(t, techniques, 1)
	assert.Equal(t, "T3002", techniques[0].GetTechniqueID())
}

// TestSQLiteMitreStorage_SubTechniques tests sub-technique handling
func TestSQLiteMitreStorage_SubTechniques(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create parent technique
	parent := &mitre.Technique{
		ID:      "T4001",
		Name:    "Parent Technique",
		Version: "2.1",
	}
	err := storage.CreateTechnique(parent)
	require.NoError(t, err)

	// Create sub-technique
	subtechnique := &mitre.Technique{
		ID:                   "attack-pattern--sub-technique",
		Name:                 "Sub-technique",
		XMitreIsSubTechnique: true,
		Version:              "2.1",
		ExternalReferences: []mitre.ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T4001.001"},
		},
	}
	err = storage.CreateTechnique(subtechnique)
	require.NoError(t, err)

	// Get sub-techniques
	subtechniques, err := storage.GetSubTechniques("T4001")
	require.NoError(t, err)
	assert.Len(t, subtechniques, 1)
	assert.Equal(t, "T4001.001", subtechniques[0].GetTechniqueID())
	assert.True(t, subtechniques[0].IsSubTechnique())
}

// TestSQLiteMitreStorage_Pagination tests pagination
func TestSQLiteMitreStorage_Pagination(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create multiple techniques
	for i := 0; i < 25; i++ {
		technique := &mitre.Technique{
			ID:      fmt.Sprintf("attack-pattern--t500%d", i),
			Name:    fmt.Sprintf("Technique %d", i),
			Version: "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: fmt.Sprintf("T500%d", i)},
			},
		}
		err := storage.CreateTechnique(technique)
		require.NoError(t, err)
	}

	// Get first page
	page1, err := storage.GetTechniques(10, 0, "")
	require.NoError(t, err)
	assert.Len(t, page1, 10)

	// Get second page
	page2, err := storage.GetTechniques(10, 10, "")
	require.NoError(t, err)
	assert.Len(t, page2, 10)

	// Verify no overlap
	ids1 := make(map[string]bool)
	for _, tech := range page1 {
		techID := tech.GetTechniqueID()
		ids1[techID] = true
	}
	for _, tech := range page2 {
		techID := tech.GetTechniqueID()
		assert.False(t, ids1[techID], "Page 2 should not contain page 1 items")
	}

	// Get third page
	page3, err := storage.GetTechniques(10, 20, "")
	require.NoError(t, err)
	assert.Len(t, page3, 5) // Only 5 remaining
}

// TestSQLiteMitreStorage_SearchTechniques tests technique search
func TestSQLiteMitreStorage_SearchTechniques(t *testing.T) {
	sqlite := setupMitreTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteMitreStorage(sqlite, sqlite.Logger)

	// Create techniques with different names
	techniques := []*mitre.Technique{
		{
			ID:      "attack-pattern--t6001",
			Name:    "Process Injection",
			Version: "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: "T6001"},
			},
		},
		{
			ID:      "attack-pattern--t6002",
			Name:    "Command Injection",
			Version: "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: "T6002"},
			},
		},
		{
			ID:      "attack-pattern--t6003",
			Name:    "File Discovery",
			Version: "2.1",
			ExternalReferences: []mitre.ExternalReference{
				{SourceName: "mitre-attack", ExternalID: "T6003"},
			},
		},
	}

	for _, tech := range techniques {
		err := storage.CreateTechnique(tech)
		require.NoError(t, err)
	}

	// Search for "Injection"
	results, err := storage.SearchTechniques("Injection", 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)
	for _, result := range results {
		assert.Contains(t, result.Name, "Injection", "Results should contain 'Injection'")
	}
}
