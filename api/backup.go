package api

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/storage"
	"go.uber.org/zap"
)

// BackupManager handles backup and restore operations for critical configuration data
type BackupManager struct {
	ruleStorage            storage.RuleStorageInterface
	actionStorage          storage.ActionStorageInterface
	correlationRuleStorage storage.CorrelationRuleStorageInterface
	logger                 *zap.SugaredLogger
}

// NewBackupManager creates a new backup manager
func NewBackupManager(
	ruleStorage storage.RuleStorageInterface,
	actionStorage storage.ActionStorageInterface,
	correlationRuleStorage storage.CorrelationRuleStorageInterface,
	logger *zap.SugaredLogger,
) *BackupManager {
	return &BackupManager{
		ruleStorage:            ruleStorage,
		actionStorage:          actionStorage,
		correlationRuleStorage: correlationRuleStorage,
		logger:                 logger,
	}
}

// BackupData represents a complete backup of critical configuration
type BackupData struct {
	Timestamp        time.Time              `json:"timestamp"`
	Version          string                 `json:"version"`
	Rules            []core.Rule            `json:"rules"`
	Actions          []core.Action          `json:"actions"`
	CorrelationRules []core.CorrelationRule `json:"correlation_rules"`
}

// CreateBackup creates a backup of all critical configuration data
func (bm *BackupManager) CreateBackup(ctx context.Context, outputPath string) error {
	bm.logger.Infow("Creating backup", "output_path", outputPath)

	// Validate output path for security (prevent path traversal)
	if err := validateBackupPath(outputPath); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	// Create backup data structure
	backup := &BackupData{
		Timestamp: time.Now(),
		Version:   "1.0",
	}

	// Fetch all rules
	rules, err := bm.ruleStorage.GetAllRules()
	if err != nil {
		return fmt.Errorf("failed to fetch rules: %w", err)
	}
	backup.Rules = rules

	// Fetch all actions
	actions, err := bm.actionStorage.GetActions()
	if err != nil {
		return fmt.Errorf("failed to fetch actions: %w", err)
	}
	backup.Actions = actions

	// Fetch all correlation rules
	correlationRules, err := bm.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		return fmt.Errorf("failed to fetch correlation rules: %w", err)
	}
	backup.CorrelationRules = correlationRules

	// Marshal backup data to JSON
	jsonData, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup data: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer outFile.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Write backup data to tar archive
	header := &tar.Header{
		Name:    "cerberus-backup.json",
		Size:    int64(len(jsonData)),
		Mode:    0600,
		ModTime: time.Now(),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	if _, err := tarWriter.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write backup data to tar: %w", err)
	}

	bm.logger.Infow("Backup created successfully",
		"output_path", outputPath,
		"rules_count", len(backup.Rules),
		"actions_count", len(backup.Actions),
		"correlation_rules_count", len(backup.CorrelationRules),
	)

	return nil
}

// RestoreBackup restores configuration from a backup file
func (bm *BackupManager) RestoreBackup(ctx context.Context, backupPath string, options RestoreOptions) error {
	bm.logger.Infow("Restoring from backup", "backup_path", backupPath)

	// Validate backup path for security
	if err := validateBackupPath(backupPath); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	// Open backup file
	backupFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer backupFile.Close()

	// Create gzip reader
	gzipReader, err := gzip.NewReader(backupFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzipReader)

	// Read backup data from tar archive
	var jsonData []byte
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == "cerberus-backup.json" {
			jsonData, err = io.ReadAll(tarReader)
			if err != nil {
				return fmt.Errorf("failed to read backup data: %w", err)
			}
			break
		}
	}

	if len(jsonData) == 0 {
		return fmt.Errorf("backup file does not contain cerberus-backup.json")
	}

	// Unmarshal backup data
	var backup BackupData
	if err := json.Unmarshal(jsonData, &backup); err != nil {
		return fmt.Errorf("failed to unmarshal backup data: %w", err)
	}

	// Validate backup version
	if backup.Version != "1.0" {
		return fmt.Errorf("unsupported backup version: %s", backup.Version)
	}

	// Restore rules
	if options.RestoreRules {
		for _, rule := range backup.Rules {
			if err := bm.ruleStorage.CreateRule(&rule); err != nil {
				bm.logger.Warnw("Failed to restore rule", "rule_id", rule.ID, "error", err)
				if !options.ContinueOnError {
					return fmt.Errorf("failed to restore rule %s: %w", rule.ID, err)
				}
			}
		}
		bm.logger.Infow("Restored rules", "count", len(backup.Rules))
	}

	// Restore actions
	if options.RestoreActions {
		for _, action := range backup.Actions {
			if err := bm.actionStorage.CreateAction(&action); err != nil {
				bm.logger.Warnw("Failed to restore action", "action_id", action.ID, "error", err)
				if !options.ContinueOnError {
					return fmt.Errorf("failed to restore action %s: %w", action.ID, err)
				}
			}
		}
		bm.logger.Infow("Restored actions", "count", len(backup.Actions))
	}

	// Restore correlation rules
	if options.RestoreCorrelationRules {
		for _, correlationRule := range backup.CorrelationRules {
			if err := bm.correlationRuleStorage.CreateCorrelationRule(&correlationRule); err != nil {
				bm.logger.Warnw("Failed to restore correlation rule", "rule_id", correlationRule.ID, "error", err)
				if !options.ContinueOnError {
					return fmt.Errorf("failed to restore correlation rule %s: %w", correlationRule.ID, err)
				}
			}
		}
		bm.logger.Infow("Restored correlation rules", "count", len(backup.CorrelationRules))
	}

	bm.logger.Infow("Restore completed successfully",
		"backup_timestamp", backup.Timestamp,
		"rules_restored", len(backup.Rules),
		"actions_restored", len(backup.Actions),
		"correlation_rules_restored", len(backup.CorrelationRules),
	)

	return nil
}

// RestoreOptions specifies what to restore from backup
type RestoreOptions struct {
	RestoreRules            bool
	RestoreActions          bool
	RestoreCorrelationRules bool
	ContinueOnError         bool
}

// DefaultRestoreOptions returns default restore options (restore everything)
func DefaultRestoreOptions() RestoreOptions {
	return RestoreOptions{
		RestoreRules:            true,
		RestoreActions:          true,
		RestoreCorrelationRules: true,
		ContinueOnError:         false,
	}
}

// validateBackupPath validates backup path for security to prevent path traversal attacks
func validateBackupPath(path string) error {
	// Get the absolute path of the requested path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Clean the path to remove any ".." or other traversal attempts
	cleanPath := filepath.Clean(absPath)

	// Ensure the path equals the cleaned absolute path (no traversal patterns)
	if absPath != cleanPath {
		return fmt.Errorf("path contains traversal patterns")
	}

	// Get the current working directory as the safe base
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Get absolute path of safe base directory
	safeBase, err := filepath.Abs(cwd)
	if err != nil {
		return fmt.Errorf("failed to get absolute base path: %w", err)
	}

	// Use filepath.Rel to check if the path is within the safe base
	relPath, err := filepath.Rel(safeBase, cleanPath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	// Check if the relative path tries to escape the safe base
	// filepath.Rel returns a path starting with ".." if it's outside the base
	if len(relPath) >= 2 && relPath[0:2] == ".." {
		return fmt.Errorf("path is outside the allowed directory: %s", path)
	}

	// Additional check: ensure the cleaned path starts with the safe base
	// This is a secondary defense-in-depth measure
	// Normalize paths for comparison (handle both Unix and Windows separators)
	normalizedClean := filepath.ToSlash(cleanPath)
	normalizedBase := filepath.ToSlash(safeBase)

	if !strings.HasPrefix(normalizedClean, normalizedBase) {
		return fmt.Errorf("path must be within the working directory")
	}

	return nil
}

// ListBackups lists all available backups in a directory
func (bm *BackupManager) ListBackups(backupDir string) ([]BackupInfo, error) {
	// Validate backup directory path
	if err := validateBackupPath(backupDir); err != nil {
		return nil, fmt.Errorf("invalid backup directory: %w", err)
	}

	files, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []BackupInfo
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Check if file has .tar.gz extension
		if filepath.Ext(file.Name()) != ".gz" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			bm.logger.Warnw("Failed to get file info", "file", file.Name(), "error", err)
			continue
		}

		backups = append(backups, BackupInfo{
			Filename:  file.Name(),
			Path:      filepath.Join(backupDir, file.Name()),
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	return backups, nil
}

// BackupInfo contains information about a backup file
type BackupInfo struct {
	Filename  string    `json:"filename"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}
