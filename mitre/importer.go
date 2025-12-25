package mitre

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// MitreStorageInterface defines the minimal interface needed for importing (to avoid import cycles)
// TASK 9.2-9.3: Import interface to avoid circular dependencies
type MitreStorageInterface interface {
	CreateTactic(tactic *Tactic) error
	CreateTechnique(technique *Technique) error
	CreateDataSource(dataSource *DataSource) error
	CreateTechniqueTacticMapping(techniqueID, tacticID string) error
	CreateTechniqueDataSourceMapping(techniqueID, dataSourceID string) error
	GetTacticByShortName(shortName string) (*Tactic, error)
}

// STIXImporter handles importing MITRE ATT&CK data from STIX bundles
// TASK 9.2-9.3: STIX bundle importer with sub-technique support
type STIXImporter struct {
	storage MitreStorageInterface
	logger  *zap.SugaredLogger
}

// NewSTIXImporter creates a new STIX importer
func NewSTIXImporter(storage MitreStorageInterface, logger *zap.SugaredLogger) *STIXImporter {
	return &STIXImporter{
		storage: storage,
		logger:  logger,
	}
}

// ImportResult represents the result of an import operation
type ImportResult struct {
	TechniquesImported  int
	TacticsImported     int
	DataSourcesImported int
	Errors              []string
}

// ImportBundle imports a STIX bundle from a file path
// TASK 9.3: Import STIX bundle and extract techniques, sub-techniques, and data sources
func (si *STIXImporter) ImportBundle(bundlePath string) (*ImportResult, error) {
	result := &ImportResult{
		Errors: []string{},
	}

	// Load framework using existing loader
	framework, err := LoadFramework(bundlePath, si.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load STIX bundle: %w", err)
	}

	si.logger.Infof("Starting STIX bundle import from %s", bundlePath)

	// Import tactics first (techniques depend on them)
	si.logger.Info("Importing tactics...")
	for _, tactic := range framework.Tactics {
		if err := si.storage.CreateTactic(&tactic); err != nil {
			si.logger.Warnf("Failed to import tactic %s: %v", tactic.GetTacticID(), err)
			result.Errors = append(result.Errors, fmt.Sprintf("tactic %s: %v", tactic.GetTacticID(), err))
			continue
		}
		result.TacticsImported++
	}

	// Import data sources
	si.logger.Info("Importing data sources...")
	dataSourceMap := make(map[string]*DataSource) // Map STIX ID to DataSource
	for _, ds := range framework.DataSources {
		dataSourceMap[ds.ID] = &ds
		if err := si.storage.CreateDataSource(&ds); err != nil {
			si.logger.Warnf("Failed to import data source %s: %v", ds.ID, err)
			result.Errors = append(result.Errors, fmt.Sprintf("data source %s: %v", ds.ID, err))
			continue
		}
		result.DataSourcesImported++

		// Extract external ID for mapping
		extID := ""
		for _, ref := range ds.ExternalReferences {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				extID = ref.ExternalID
				break
			}
		}
		if extID == "" {
			extID = ds.ID
		}

		// Map data components to data sources
		for _, dc := range framework.DataComponents {
			if dc.DataSourceRef == ds.ID {
				// This component belongs to this data source
				// Components are stored as part of data source collection_layers
				si.logger.Debugf("Mapped data component %s to data source %s", dc.ID, extID)
			}
		}
	}

	// Import techniques (including sub-techniques)
	// TASK 9.1: Handle sub-technique parent relationships
	si.logger.Info("Importing techniques...")

	// First pass: Import main techniques (non-sub-techniques)
	techniqueMap := make(map[string]*AttackPattern) // Map STIX ID to AttackPattern
	subTechniques := []AttackPattern{}

	for i := range framework.Techniques {
		tech := framework.Techniques[i]
		techID := tech.GetTechniqueID()
		if techID == "" {
			si.logger.Warnf("Skipping technique without ID: %s", tech.ID)
			continue
		}

		techniqueMap[tech.ID] = &tech

		if tech.IsSubTechnique() {
			subTechniques = append(subTechniques, tech)
		} else {
			// Main technique - import now
			if err := si.storage.CreateTechnique(&tech); err != nil {
				si.logger.Warnf("Failed to import technique %s: %v", techID, err)
				result.Errors = append(result.Errors, fmt.Sprintf("technique %s: %v", techID, err))
				continue
			}
			result.TechniquesImported++

			// Create data source mappings from data_sources field
			for _, dsName := range tech.DataSources {
				// Find data source by name
				for _, ds := range framework.DataSources {
					if ds.Name == dsName {
						// Get external ID
						extID := ""
						for _, ref := range ds.ExternalReferences {
							if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
								extID = ref.ExternalID
								break
							}
						}
						if extID == "" {
							extID = ds.ID
						}

						if err := si.storage.CreateTechniqueDataSourceMapping(techID, extID); err != nil {
							si.logger.Warnf("Failed to create technique-data source mapping: %v", err)
						}
						break
					}
				}
			}
		}
	}

	// Second pass: Import sub-techniques (they depend on parent techniques existing)
	si.logger.Infof("Importing %d sub-techniques...", len(subTechniques))
	for i := range subTechniques {
		tech := subTechniques[i]
		techID := tech.GetTechniqueID()

		if err := si.storage.CreateTechnique(&tech); err != nil {
			si.logger.Warnf("Failed to import sub-technique %s: %v", techID, err)
			result.Errors = append(result.Errors, fmt.Sprintf("sub-technique %s: %v", techID, err))
			continue
		}
		result.TechniquesImported++

		// Create data source mappings
		for _, dsName := range tech.DataSources {
			for _, ds := range framework.DataSources {
				if ds.Name == dsName {
					extID := ""
					for _, ref := range ds.ExternalReferences {
						if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
							extID = ref.ExternalID
							break
						}
					}
					if extID == "" {
						extID = ds.ID
					}

					if err := si.storage.CreateTechniqueDataSourceMapping(techID, extID); err != nil {
						si.logger.Warnf("Failed to create technique-data source mapping: %v", err)
					}
					break
				}
			}
		}
	}

	si.logger.Infof("Import completed: %d tactics, %d techniques (including sub-techniques), %d data sources",
		result.TacticsImported, result.TechniquesImported, result.DataSourcesImported)

	return result, nil
}

// DownloadLatestBundle downloads the latest MITRE ATT&CK STIX bundle from GitHub
// TASK 9.4: Dynamic bundle download
func (si *STIXImporter) DownloadLatestBundle(ctx context.Context) (string, error) {
	url := "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

	si.logger.Infof("Downloading latest MITRE ATT&CK bundle from %s", url)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Cerberus-SIEM/1.0")

	// Execute request with retry logic
	var resp *http.Response
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if i < maxRetries-1 {
			backoff := time.Duration(i+1) * time.Second
			si.logger.Warnf("Download failed (attempt %d/%d), retrying in %v: %v", i+1, maxRetries, backoff, err)
			time.Sleep(backoff)
		}
	}

	if err != nil {
		return "", fmt.Errorf("failed to download bundle after %d retries: %w", maxRetries, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Verify Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "text/json") {
		si.logger.Warnf("Unexpected Content-Type: %s", contentType)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "mitre-attack-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Stream download with progress tracking
	si.logger.Info("Streaming download...")
	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to write bundle to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	si.logger.Infof("Downloaded %d bytes to %s", written, tmpPath)
	return tmpPath, nil
}

// ImportLatest downloads and imports the latest bundle
// TASK 9.4: Download and import in one operation
func (si *STIXImporter) ImportLatest(ctx context.Context) (*ImportResult, error) {
	tmpPath, err := si.DownloadLatestBundle(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to download latest bundle: %w", err)
	}

	// Clean up temp file after import
	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			si.logger.Warnf("Failed to remove temp file %s: %v", tmpPath, err)
		}
	}()

	result, err := si.ImportBundle(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to import bundle: %w", err)
	}

	return result, nil
}

// ImportFromFile is an alias for ImportBundle for backward compatibility
func (si *STIXImporter) ImportFromFile(bundlePath string) (*ImportResult, error) {
	return si.ImportBundle(bundlePath)
}
