package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	"cerberus/api"
	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"
	threatfeeds "cerberus/threat/feeds"

	"go.uber.org/zap"
)

// StorageComponents holds all storage-related components.
type StorageComponents struct {
	ClickHouse             *storage.ClickHouse
	SQLite                 *storage.SQLite
	EventStorage           *storage.ClickHouseEventStorage
	AlertStorage           *storage.ClickHouseAlertStorage
	RuleStorage            storage.RuleStorageInterface
	ActionStorage          storage.ActionStorageInterface
	CorrelationRuleStorage storage.CorrelationRuleStorageInterface
	InvestigationStorage   api.InvestigationStorer
	UserStorage            storage.UserStorage
	RoleStorage            storage.RoleStorage
	FieldMappingStorage    storage.FieldMappingStorage
	LifecycleAuditStorage       *storage.SQLiteLifecycleAuditStorage       // TASK 169: Lifecycle audit trail storage
	LifecycleManager            *storage.LifecycleManager                  // TASK 169: Lifecycle automation manager
	FieldMappingAuditStorage    *storage.SQLiteFieldMappingAuditStorage    // TASK 185: Field mapping lifecycle audit trail storage
	IOCStorage                  core.IOCStorage                            // IOC lifecycle management storage
	IOCFeedStorage              threatfeeds.IOCFeedStorage                 // IOC feed metadata storage
}

// InitClickHouse initializes ClickHouse connection with retry logic.
func InitClickHouse(cfg *config.Config, sugar *zap.SugaredLogger) (*storage.ClickHouse, error) {
	const maxRetries = 3
	retryDelays := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

	var clickhouse *storage.ClickHouse
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			sugar.Infow("Retrying ClickHouse connection",
				"attempt", attempt,
				"max_retries", maxRetries,
				"delay", retryDelays[attempt-1])
			time.Sleep(retryDelays[attempt-1])
		}

		clickhouse, lastErr = storage.NewClickHouse(cfg, sugar)
		if lastErr == nil {
			break
		}

		sugar.Warnw("ClickHouse connection attempt failed",
			"attempt", attempt+1,
			"error", lastErr)
	}

	if lastErr != nil {
		errMsg := ClassifyConnectionError(lastErr, cfg.ClickHouse.Addr)
		fmt.Fprintf(os.Stderr, "\n========================================\n")
		fmt.Fprintf(os.Stderr, "FATAL: ClickHouse Connection Failed\n")
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "%s\n", errMsg)
		fmt.Fprintf(os.Stderr, "========================================\n\n")
		return nil, fmt.Errorf("failed to connect to ClickHouse after %d attempts: %w", maxRetries+1, lastErr)
	}

	sugar.Info("Connected to ClickHouse successfully")

	// Ensure tables exist and run migrations
	ctx := context.Background()
	if err := clickhouse.CreateTablesIfNotExist(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "\n========================================\n")
		fmt.Fprintf(os.Stderr, "FATAL: ClickHouse Schema Setup Failed\n")
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "Failed to create/verify ClickHouse tables: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nRemediation:\n")
		fmt.Fprintf(os.Stderr, "  - Check ClickHouse has sufficient permissions\n")
		fmt.Fprintf(os.Stderr, "  - Verify the database '%s' exists\n", cfg.ClickHouse.Database)
		fmt.Fprintf(os.Stderr, "  - Check ClickHouse logs for detailed error\n")
		fmt.Fprintf(os.Stderr, "========================================\n\n")
		return nil, fmt.Errorf("failed to ensure ClickHouse tables: %w", err)
	}

	return clickhouse, nil
}

// InitSQLite initializes SQLite connection.
func InitSQLite(dirs DataDirectories, sugar *zap.SugaredLogger) (*storage.SQLite, error) {
	sqlite, err := storage.NewSQLite(dirs.SQLite, sugar)
	if err != nil {
		errMsg := ClassifySQLiteError(err, dirs.SQLite)
		fmt.Fprintf(os.Stderr, "\n========================================\n")
		fmt.Fprintf(os.Stderr, "FATAL: SQLite Initialization Failed\n")
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "%s\n", errMsg)
		fmt.Fprintf(os.Stderr, "========================================\n\n")
		return nil, fmt.Errorf("failed to initialize SQLite: %w", err)
	}

	sugar.Info("SQLite initialized successfully")
	return sqlite, nil
}

// InitStorageWorkers initializes all storage workers and returns the storage components.
func InitStorageWorkers(ctx context.Context, clickhouse *storage.ClickHouse, sqlite *storage.SQLite, cfg *config.Config, processedEventCh chan *core.Event, alertCh chan *core.Alert, sugar *zap.SugaredLogger) (*StorageComponents, error) {
	// Initialize ClickHouse event storage
	eventStorage, err := storage.NewClickHouseEventStorage(ctx, clickhouse, cfg, processedEventCh, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ClickHouse event storage: %w", err)
	}

	// Create cursor pagination indexes
	if err := eventStorage.CreateEventIndexes(context.Background()); err != nil {
		sugar.Warnf("Failed to create event indexes: %v", err)
	} else {
		sugar.Info("Event indexes created or verified successfully")
	}

	eventStorage.Start(cfg.Engine.WorkerCount)
	sugar.Info("ClickHouse event storage initialized successfully")

	// Initialize ClickHouse alert storage
	alertStorage, err := storage.NewClickHouseAlertStorage(ctx, clickhouse, cfg, alertCh, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ClickHouse alert storage: %w", err)
	}
	alertStorage.Start(cfg.Engine.WorkerCount)
	sugar.Info("ClickHouse alert storage initialized successfully")

	// Initialize SQLite-based metadata storage
	if sqlite == nil {
		return nil, fmt.Errorf("SQLite is required for metadata storage")
	}

	// Rule storage
	ruleStorage := storage.NewSQLiteRuleStorage(sqlite, 5*time.Second, sugar)
	if err := ruleStorage.EnsureIndexes(); err != nil {
		return nil, fmt.Errorf("failed to ensure rule indexes: %w", err)
	}
	sugar.Info("Rule storage initialized successfully")

	// Action storage
	actionStorage := storage.NewSQLiteActionStorage(sqlite, sugar)
	if err := actionStorage.EnsureIndexes(); err != nil {
		return nil, fmt.Errorf("failed to ensure action indexes: %w", err)
	}
	sugar.Info("Action storage initialized successfully")

	// Correlation rule storage
	correlationRuleStorage := storage.NewSQLiteCorrelationRuleStorage(sqlite, sugar)
	if err := correlationRuleStorage.EnsureIndexes(); err != nil {
		return nil, fmt.Errorf("failed to ensure correlation rule indexes: %w", err)
	}
	sugar.Info("Correlation rule storage initialized successfully")

	// Investigation storage
	investigationStorage, err := storage.NewSQLiteInvestigationStorage(sqlite, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize investigation storage: %w", err)
	}
	sugar.Info("Investigation storage initialized successfully")

	// User storage
	userStorage := storage.NewSQLiteUserStorage(sqlite, sugar)

	// Role storage
	roleStorage := storage.NewSQLiteRoleStorage(sqlite, sugar)

	// Seed default roles
	ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := roleStorage.SeedDefaultRoles(ctxTimeout); err != nil {
		sugar.Errorw("Failed to seed default roles", "error", err)
	} else {
		sugar.Info("Default roles initialized successfully")
	}

	// Link role storage to user storage
	userStorage.SetRoleStorage(roleStorage)

	// Field mapping storage
	var fieldMappingStorage storage.FieldMappingStorage
	if sqlite.DB != nil {
		fieldMappingStorage, err = storage.NewSQLiteFieldMappingStorage(sqlite.DB)
		if err != nil {
			sugar.Warnf("Failed to initialize field mapping storage: %v", err)
		} else {
			sugar.Info("Field mapping storage initialized successfully")
		}
	}

	// TASK 169: Lifecycle audit storage for rule lifecycle management
	lifecycleAuditStorage := storage.NewSQLiteLifecycleAuditStorage(sqlite, sugar)
	sugar.Info("Lifecycle audit storage initialized successfully")

	// TASK 169: Lifecycle manager for automated sunset date enforcement
	// ruleStorage is already *SQLiteRuleStorage, no cast needed
	lifecycleManager := storage.NewLifecycleManager(ruleStorage, lifecycleAuditStorage, sqlite, sugar)
	sugar.Info("Lifecycle manager initialized successfully")

	// TASK 185: Field mapping lifecycle audit storage
	fieldMappingAuditStorage := storage.NewSQLiteFieldMappingAuditStorage(sqlite, sugar)
	sugar.Info("Field mapping audit storage initialized successfully")

	// IOC storage for threat intelligence indicators
	iocStorage, err := storage.NewSQLiteIOCStorage(sqlite, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IOC storage: %w", err)
	}
	sugar.Info("IOC storage initialized successfully")

	// IOC feed storage for threat intelligence feed metadata
	iocFeedStorage, err := storage.NewSQLiteIOCFeedStorage(sqlite, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IOC feed storage: %w", err)
	}
	sugar.Info("IOC feed storage initialized successfully")

	return &StorageComponents{
		ClickHouse:             clickhouse,
		SQLite:                 sqlite,
		EventStorage:           eventStorage,
		AlertStorage:           alertStorage,
		RuleStorage:            ruleStorage,
		ActionStorage:          actionStorage,
		CorrelationRuleStorage: correlationRuleStorage,
		InvestigationStorage:   investigationStorage,
		UserStorage:            userStorage,
		RoleStorage:            roleStorage,
		FieldMappingStorage:      fieldMappingStorage,
		LifecycleAuditStorage:    lifecycleAuditStorage,    // TASK 169
		LifecycleManager:         lifecycleManager,         // TASK 169
		FieldMappingAuditStorage: fieldMappingAuditStorage, // TASK 185
		IOCStorage:               iocStorage,               // IOC lifecycle management
		IOCFeedStorage:           iocFeedStorage,           // IOC feed metadata
	}, nil
}
