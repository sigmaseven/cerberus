package bootstrap

import (
	"context"
	"fmt"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"
	"cerberus/storage"
	sigmafeeds "cerberus/sigma/feeds"

	"go.uber.org/zap"
)

// DetectionComponents holds detection-related components.
type DetectionComponents struct {
	Detector         *detect.Detector
	Rules            []core.Rule
	CorrelationRules []core.CorrelationRule
}

// InitDetector creates and starts the detection engine.
// TASK 144.4: Updated to accept parent context for graceful shutdown propagation
// The context is passed to the rule engine for cleanup goroutine coordination.
func InitDetector(ctx context.Context, cfg *config.Config, rules []core.Rule, correlationRules []core.CorrelationRule, rawEventCh chan *core.Event, processedEventCh chan *core.Event, alertCh chan *core.Alert, sugar *zap.SugaredLogger) (*detect.Detector, error) {
	// Build rule engine configuration
	engineConfig := &detect.RuleEngineConfig{
		EnableNativeSigmaEngine:    cfg.Engine.EnableNativeSigmaEngine,
		SigmaFieldMappingConfig:    cfg.Engine.SigmaFieldMappingConfig,
		SigmaEngineCacheSize:       cfg.Engine.SigmaEngineCacheSize,
		SigmaEngineCacheTTL:        cfg.Engine.SigmaEngineCacheTTL,
		SigmaEngineCleanupInterval: cfg.Engine.SigmaEngineCleanupInterval,
		Logger:                     sugar,
	}

	// TASK 144.4: Create rule engine with parent context for lifecycle management
	// This allows cleanup goroutines to respond to application shutdown
	ruleEngine := detect.NewRuleEngineWithContext(ctx, rules, correlationRules, cfg.Engine.CorrelationStateTTL, engineConfig)

	// Log SIGMA engine mode
	if cfg.Engine.EnableNativeSigmaEngine {
		sugar.Infow("SIGMA native engine enabled",
			"field_mapping_config", cfg.Engine.SigmaFieldMappingConfig,
			"cache_size", cfg.Engine.SigmaEngineCacheSize,
			"cache_ttl", cfg.Engine.SigmaEngineCacheTTL,
			"cleanup_interval", cfg.Engine.SigmaEngineCleanupInterval)
	} else {
		sugar.Info("SIGMA native engine disabled (using traditional JSON rules only)")
	}

	detector, err := detect.NewDetector(ruleEngine, rawEventCh, processedEventCh, alertCh, cfg, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}
	detector.Start()
	return detector, nil
}

// LoadRules loads detection rules from the database.
// TASK #182: File-based loading removed - database is the single source of truth.
func LoadRules(cfg *config.Config, ruleStorage storage.RuleStorageInterface, sugar *zap.SugaredLogger) ([]core.Rule, bool, error) {
	// Load detection rules from SQLite database
	rules, err := detect.LoadRulesFromDB(ruleStorage)
	dbWasEmpty := false

	if err != nil {
		sugar.Warnf("Failed to load rules from database (%v) - starting with empty rule set", err)
		rules = []core.Rule{}
		dbWasEmpty = true
	} else {
		if len(rules) == 0 {
			dbWasEmpty = true
			sugar.Warn("No rules found in database")
		} else {
			sugar.Infof("Loaded %d rules from database", len(rules))
		}
	}

	return rules, dbWasEmpty, nil
}

// LoadCorrelationRules loads correlation rules from the database.
// TASK #182: File-based loading removed - database is the single source of truth.
func LoadCorrelationRules(cfg *config.Config, correlationRuleStorage storage.CorrelationRuleStorageInterface, sugar *zap.SugaredLogger) ([]core.CorrelationRule, error) {
	correlationRules, err := correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		sugar.Warnf("Failed to load correlation rules from database (%v) - starting with empty set", err)
		return []core.CorrelationRule{}, nil
	}

	if len(correlationRules) == 0 {
		sugar.Info("No correlation rules found in database")
	} else {
		sugar.Infof("Loaded %d correlation rules from database", len(correlationRules))
	}
	return correlationRules, nil
}

// InitSigmaFeeds initializes the SIGMA feed system.
func InitSigmaFeeds(ctx context.Context, cfg *config.Config, sqlite *storage.SQLite, ruleStorage storage.RuleStorageInterface, dbWasEmpty bool, sugar *zap.SugaredLogger) (*sigmafeeds.Manager, error) {
	if !cfg.Feeds.Enabled {
		return nil, nil
	}

	sugar.Info("Initializing SIGMA feeds system...")

	feedStorage, err := storage.NewSQLiteFeedStorage(sqlite, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize feed storage: %w", err)
	}

	// Create adapter for rule storage
	sqliteRuleStorage, ok := ruleStorage.(*storage.SQLiteRuleStorage)
	if !ok {
		return nil, fmt.Errorf("rule storage is not SQLiteRuleStorage")
	}

	ruleStorageAdapter := storage.NewFeedRuleStorageAdapter(sqliteRuleStorage)
	feedManager, err := sigmafeeds.NewManager(feedStorage, ruleStorageAdapter, cfg.Feeds.WorkingDir, sugar)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize feeds manager: %w", err)
	}
	sugar.Info("SIGMA feeds manager initialized")

	// Create default feed if database was empty
	if dbWasEmpty && cfg.Feeds.DefaultFeed.Enabled {
		ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
		feeds, err := feedManager.ListFeeds(ctxTimeout)
		cancel()

		if err != nil || len(feeds) == 0 {
			sugar.Info("Creating default SigmaHQ feed...")
			defaultFeed := &sigmafeeds.RuleFeed{
				ID:              "sigmahq-default",
				Name:            cfg.Feeds.DefaultFeed.Name,
				Type:            sigmafeeds.FeedTypeGit,
				Status:          sigmafeeds.FeedStatusActive,
				Enabled:         true,
				URL:             cfg.Feeds.DefaultFeed.URL,
				Branch:          cfg.Feeds.DefaultFeed.Branch,
				Path:            cfg.Feeds.DefaultFeed.Path,
				MinSeverity:     cfg.Feeds.DefaultFeed.MinSeverity,
				AutoEnableRules: true,
				Priority:        100,
				UpdateStrategy:  sigmafeeds.UpdateStartup,
			}

			ctxTimeout, cancel = context.WithTimeout(ctx, 30*time.Second)
			if err := feedManager.CreateFeed(ctxTimeout, defaultFeed); err != nil {
				sugar.Warnf("Failed to create default feed: %v", err)
			} else {
				sugar.Info("Default SigmaHQ feed created successfully")
			}
			cancel()
		}
	}

	// Start scheduler if enabled
	if cfg.Feeds.SchedulerEnabled {
		if err := feedManager.StartScheduler(); err != nil {
			sugar.Warnf("Failed to start feed scheduler: %v", err)
		} else {
			sugar.Info("SIGMA feeds scheduler started")
		}
	}

	return feedManager, nil
}

// SyncFeedsOnStartup syncs all feeds on startup if configured.
func SyncFeedsOnStartup(ctx context.Context, cfg *config.Config, feedManager *sigmafeeds.Manager, ruleStorage storage.RuleStorageInterface, sugar *zap.SugaredLogger) ([]core.Rule, error) {
	if feedManager == nil || !cfg.Feeds.SyncOnStartup {
		return nil, nil
	}

	sugar.Info("Syncing SIGMA feeds on startup...")
	ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Minute)
	results, err := feedManager.SyncAllFeeds(ctxTimeout)
	cancel()

	if err != nil {
		sugar.Warnf("Feed sync encountered errors: %v", err)
	}

	totalImported := 0
	for _, result := range results {
		if result.Success {
			totalImported += result.Stats.ImportedRules + result.Stats.UpdatedRules
			sugar.Infof("Feed '%s': imported=%d, updated=%d, skipped=%d",
				result.FeedName, result.Stats.ImportedRules, result.Stats.UpdatedRules, result.Stats.SkippedRules)
		} else {
			sugar.Warnf("Feed '%s' sync failed: %v", result.FeedName, result.Errors)
		}
	}

	if totalImported > 0 {
		// Reload rules from database after feed sync
		sugar.Infof("Reloading rules after feed sync (imported/updated %d rules)...", totalImported)
		rules, err := detect.LoadRulesFromDB(ruleStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to reload rules after feed sync: %w", err)
		}
		sugar.Infof("Loaded %d rules from database after feed sync", len(rules))
		return rules, nil
	}

	return nil, nil
}
