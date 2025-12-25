package bootstrap

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"cerberus/api"
	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"
	"cerberus/ingest"
	"cerberus/ml"
	sigmafeeds "cerberus/sigma/feeds"
	"cerberus/soar"
	"cerberus/storage"
	threatfeeds "cerberus/threat/feeds"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// App represents the Cerberus application with all its components.
type App struct {
	// Configuration
	Config *config.Config
	Logger *zap.Logger
	Sugar  *zap.SugaredLogger

	// Storage
	Storage *StorageComponents

	// Channels
	RawEventCh       chan *core.Event
	ProcessedEventCh chan *core.Event
	AlertCh          chan *core.Alert

	// Detection
	Detector         *detect.Detector
	Rules            []core.Rule
	CorrelationRules []core.CorrelationRule

	// Services
	SyslogListener  *ingest.SyslogListener
	CEFListener     *ingest.CEFListener
	JSONListener    *ingest.JSONListener
	ListenerManager *ingest.ListenerManager
	APIServer       *api.API
	DLQ             *ingest.DLQ
	FeedManager     *sigmafeeds.Manager
	IOCFeedManager  *threatfeeds.Manager
	MLSystem        *ml.AnomalyDetectionSystem

	// Lifecycle
	serviceWg  *sync.WaitGroup
	shutdownCh chan struct{}
}

// NewApp creates a new application instance and initializes all components.
func NewApp(ctx context.Context) (*App, error) {
	app := &App{
		serviceWg:  &sync.WaitGroup{},
		shutdownCh: make(chan struct{}),
	}

	// Initialize logger
	logger, sugar, err := InitLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	app.Logger = logger
	app.Sugar = sugar

	sugar.Info("Cerberus SIEM starting...")

	// Pre-flight checks
	sugar.Info("Running pre-flight checks...")
	_, err = EnsureDataDirectories(sugar)
	if err != nil {
		return nil, fmt.Errorf("pre-flight check failed: %w", err)
	}

	// Load configuration
	cfg, err := InitConfig(sugar)
	if err != nil {
		return nil, err
	}
	app.Config = cfg

	// Use config-based directories
	dirs := DataDirectoriesFromConfig(cfg)

	// Initialize storage
	clickhouse, err := InitClickHouse(cfg, sugar)
	if err != nil {
		return nil, err
	}

	sqlite, err := InitSQLite(dirs, sugar)
	if err != nil {
		return nil, err
	}

	// Initialize communication channels
	app.RawEventCh = make(chan *core.Event, cfg.Engine.ChannelBufferSize)
	app.ProcessedEventCh = make(chan *core.Event, cfg.Engine.ChannelBufferSize)
	app.AlertCh = make(chan *core.Alert, cfg.Engine.ChannelBufferSize)

	// Initialize storage workers
	storageComponents, err := InitStorageWorkers(ctx, clickhouse, sqlite, cfg, app.ProcessedEventCh, app.AlertCh, sugar)
	if err != nil {
		return nil, err
	}
	app.Storage = storageComponents

	// Load rules
	rules, dbWasEmpty, err := LoadRules(cfg, storageComponents.RuleStorage, sugar)
	if err != nil {
		return nil, err
	}
	app.Rules = rules

	// Initialize SIGMA feeds
	feedManager, err := InitSigmaFeeds(ctx, cfg, sqlite, storageComponents.RuleStorage, dbWasEmpty, sugar)
	if err != nil {
		sugar.Errorf("Failed to initialize feed system: %v", err)
	}
	app.FeedManager = feedManager

	// Sync feeds on startup
	if updatedRules, err := SyncFeedsOnStartup(ctx, cfg, feedManager, storageComponents.RuleStorage, sugar); err != nil {
		sugar.Errorf("Failed to sync feeds: %v", err)
	} else if updatedRules != nil {
		app.Rules = updatedRules
	}

	// Initialize IOC feed manager for threat intelligence feeds
	if cfg.IOCFeeds.Enabled && storageComponents.IOCFeedStorage != nil && storageComponents.IOCStorage != nil {
		iocFeedManager, err := threatfeeds.NewManager(&threatfeeds.ManagerConfig{
			Config:     threatfeeds.DefaultIOCFeedConfig(),
			Storage:    storageComponents.IOCFeedStorage,
			IOCStorage: storageComponents.IOCStorage,
		})
		if err != nil {
			sugar.Errorf("Failed to initialize IOC feed manager: %v", err)
		} else {
			app.IOCFeedManager = iocFeedManager
			sugar.Info("IOC feed manager initialized successfully")
		}
	} else if !cfg.IOCFeeds.Enabled {
		sugar.Info("IOC feed system disabled by configuration")
	}

	// Load correlation rules
	correlationRules, err := LoadCorrelationRules(cfg, storageComponents.CorrelationRuleStorage, sugar)
	if err != nil {
		return nil, err
	}
	app.CorrelationRules = correlationRules

	// First-run setup
	firstRunResult, err := app.runFirstRunSetup(sqlite)
	if err != nil {
		sugar.Errorf("First-run setup encountered errors: %v", err)
	} else if firstRunResult.IsFirstRun {
		sugar.Infow("First-run setup completed",
			"admin_created", firstRunResult.AdminCreated,
			"admin_username", firstRunResult.AdminUsername)
	}

	return app, nil
}

// Start starts all application services.
func (a *App) Start(ctx context.Context) error {
	// TASK 144.4: Initialize detector with context for graceful shutdown coordination
	// The context allows cleanup goroutines to respond to shutdown signals
	detector, err := InitDetector(ctx, a.Config, a.Rules, a.CorrelationRules, a.RawEventCh, a.ProcessedEventCh, a.AlertCh, a.Sugar)
	if err != nil {
		return fmt.Errorf("failed to initialize detector: %w", err)
	}
	a.Detector = detector

	// Initialize DLQ
	a.DLQ = ingest.NewDLQ(a.Storage.SQLite.DB, a.Sugar)
	a.Sugar.Info("DLQ initialized successfully")

	// Initialize listener manager
	listenerStorage, err := storage.NewSQLiteDynamicListenerStorage(a.Storage.SQLite, a.Sugar)
	if err != nil {
		return fmt.Errorf("failed to initialize listener storage: %w", err)
	}

	a.ListenerManager = ingest.NewListenerManager(
		listenerStorage,
		a.Storage.FieldMappingStorage,
		a.RawEventCh,
		a.Config,
		a.Sugar,
		a.DLQ,
	)

	// Load SIGMA field mappings and set default normalizer for ingestion-time normalization
	sigmaFieldMappings, err := core.LoadFieldMappings("config/sigma_field_mappings.yaml")
	if err != nil {
		a.Sugar.Warnf("Failed to load SIGMA field mappings: %v - field normalization will be disabled", err)
	} else {
		defaultNormalizer := core.NewFieldNormalizer(sigmaFieldMappings)
		a.ListenerManager.SetDefaultFieldNormalizer(defaultNormalizer)
		a.Sugar.Infof("SIGMA field normalizer loaded with %d log source mappings", len(sigmaFieldMappings.Mappings))
	}

	if err := a.ListenerManager.RestoreListeners(); err != nil {
		a.Sugar.Errorf("Failed to restore dynamic listeners: %v", err)
	} else {
		a.Sugar.Info("Dynamic listeners restored successfully")
	}

	// Start event listeners
	a.startEventListeners()

	// TASK 169: Start lifecycle manager for sunset date enforcement
	if a.Storage.LifecycleManager != nil {
		a.Storage.LifecycleManager.Start()
		a.Sugar.Info("Lifecycle manager started successfully")
	}

	// Start API server
	if err := a.startAPIServer(); err != nil {
		return err
	}

	return nil
}

// WaitForShutdown blocks until a shutdown signal is received.
func (a *App) WaitForShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

// Shutdown gracefully shuts down all components.
func (a *App) Shutdown() {
	a.Sugar.Info("Shutting down...")

	// Phase 1 - Stop listeners
	a.Sugar.Info("Phase 1: Stopping event listeners...")
	if a.SyslogListener != nil {
		a.SyslogListener.Stop()
	}
	if a.CEFListener != nil {
		a.CEFListener.Stop()
	}
	if a.JSONListener != nil {
		a.JSONListener.Stop()
	}
	if a.ListenerManager != nil {
		a.ListenerManager.Shutdown()
	}

	// Phase 2 - Wait for listeners to drain
	a.Sugar.Info("Phase 2: Waiting for listeners to drain...")
	time.Sleep(2 * time.Second)

	// Phase 3 - Stop detector FIRST (consumer before channel close)
	a.Sugar.Info("Phase 3: Stopping detector...")
	if a.Detector != nil {
		a.Detector.Stop()
	}

	// Phase 4 - Close input channels AFTER detector stops
	a.Sugar.Info("Phase 4: Closing input channels...")
	close(a.RawEventCh)

	// Phase 5 - Close output channels
	a.Sugar.Info("Phase 5: Closing output channels...")
	close(a.ProcessedEventCh)
	close(a.AlertCh)

	// Phase 6 - Stop storage workers
	a.Sugar.Info("Phase 6: Stopping storage workers...")
	if a.Storage != nil {
		if a.Storage.EventStorage != nil {
			if err := a.Storage.EventStorage.Stop(); err != nil {
				a.Sugar.Errorw("Event storage shutdown timed out", "error", err)
			}
		}
		if a.Storage.AlertStorage != nil {
			if err := a.Storage.AlertStorage.Stop(); err != nil {
				a.Sugar.Errorw("Alert storage shutdown timed out", "error", err)
			}
		}
	}

	// Phase 7 - Stop API server
	a.Sugar.Info("Phase 7: Stopping API server...")
	if a.APIServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.APIServer.Stop(ctx); err != nil {
			a.Sugar.Errorw("Failed to stop API server", "error", err)
		}
	}

	// Phase 8 - Wait for service goroutines
	a.Sugar.Info("Phase 8: Waiting for service goroutines to complete...")
	done := make(chan struct{})
	go func() {
		a.serviceWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		a.Sugar.Info("All service goroutines stopped successfully")
	case <-time.After(15 * time.Second): // BLOCKER-3 FIX: 5s API timeout + 10s buffer
		a.Sugar.Warn("Service goroutine shutdown timed out")
	}

	// TASK 169: Stop lifecycle manager before closing databases
	a.Sugar.Info("Phase 9: Stopping lifecycle manager...")
	if a.Storage != nil && a.Storage.LifecycleManager != nil {
		a.Storage.LifecycleManager.Stop()
	}

	// Close database connections
	a.Sugar.Info("Phase 10: Closing database connections...")
	if a.Storage != nil {
		if a.Storage.ClickHouse != nil {
			if err := a.Storage.ClickHouse.Conn.Close(); err != nil {
				a.Sugar.Errorw("Failed to close ClickHouse connection", "error", err)
			}
		}
		if a.Storage.SQLite != nil {
			a.Storage.SQLite.Close()
		}
	}

	a.Sugar.Info("Shutdown complete")
	a.Logger.Sync()
}

// startEventListeners creates and starts all event listeners.
func (a *App) startEventListeners() {
	a.SyslogListener = ingest.NewSyslogListener(a.Config.Listeners.Syslog.Host, a.Config.Listeners.Syslog.Port, a.Config.Engine.RateLimit, a.RawEventCh, a.Sugar)
	a.CEFListener = ingest.NewCEFListener(a.Config.Listeners.CEF.Host, a.Config.Listeners.CEF.Port, a.Config.Engine.RateLimit, a.RawEventCh, a.Sugar)
	a.JSONListener = ingest.NewJSONListener(a.Config.Listeners.JSON.Host, a.Config.Listeners.JSON.Port, a.Config.Listeners.JSON.TLS, a.Config.Listeners.JSON.CertFile, a.Config.Listeners.JSON.KeyFile, a.Config.Engine.RateLimit, a.RawEventCh, a.Sugar)

	// Set DLQ
	if a.DLQ != nil {
		a.SyslogListener.BaseListener.SetDLQ(a.DLQ, "syslog")
		a.CEFListener.BaseListener.SetDLQ(a.DLQ, "cef")
		a.JSONListener.BaseListener.SetDLQ(a.DLQ, "json")
	}

	// Start listeners with panic recovery
	startListener := func(name string, startFunc func() error) {
		a.serviceWg.Add(1)
		go func() {
			defer a.serviceWg.Done()
			defer func() {
				if r := recover(); r != nil {
					a.Sugar.Errorw(fmt.Sprintf("%s listener panicked", name), "panic", r)
				}
			}()
			if err := startFunc(); err != nil {
				a.Sugar.Errorw(fmt.Sprintf("Failed to start %s listener", name), "error", err)
			} else {
				a.Sugar.Infof("%s listener started successfully", name)
			}
		}()
	}

	startListener("Syslog", a.SyslogListener.Start)
	startListener("CEF", a.CEFListener.Start)
	startListener("JSON", a.JSONListener.Start)
}

// startAPIServer creates and starts the API server.
func (a *App) startAPIServer() error {
	// Initialize additional storages needed for API
	savedSearchStorage, _ := storage.NewSQLiteSavedSearchStorage(a.Storage.SQLite, a.Sugar)

	// Initialize ML system
	var mlDetector api.MLAnomalyDetector
	var mlModelStorage *storage.MLModelStorage
	if a.Config.ML.Enabled {
		a.MLSystem = ml.NewAnomalyDetectionSystem(a.Config, a.Storage.EventStorage, nil, a.Sugar)

		if a.Storage.SQLite != nil {
			mlModelStorage = storage.NewMLModelStorage(a.Storage.SQLite, a.Sugar)

			modelDir := a.Config.ML.ModelPath
			if modelDir == "" {
				modelDir = "./data/ml_models"
			}

			storageAdapter := &ml.StorageModelStorageAdapter{Storage: mlModelStorage}
			modelPersistence, err := ml.NewModelPersistence(modelDir, storageAdapter, a.Sugar)
			if err != nil {
				a.Sugar.Errorw("Failed to initialize model persistence", "error", err)
			} else {
				modelLoader := ml.NewModelLoader(mlModelStorage, modelPersistence, a.Sugar)
				a.MLSystem.SetModelLoader(modelLoader)

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := a.MLSystem.LoadPersistedModels(ctx); err != nil {
					a.Sugar.Warnw("Failed to load persisted models", "error", err)
				} else {
					a.Sugar.Info("ML models loaded successfully")
				}
			}
		}
		mlDetector = a.MLSystem
		a.Sugar.Info("ML anomaly detection system initialized")
	}

	// Initialize MITRE storage
	mitreStorage := storage.NewSQLiteMitreStorage(a.Storage.SQLite, a.Sugar)

	// Initialize SOAR components
	var playbookExecutor *soar.Executor
	var playbookExecutionStorage *storage.SQLitePlaybookExecutionStorage
	var auditLogger soar.AuditLogger = &soar.NoOpAuditLogger{}

	if a.Storage.ClickHouse != nil {
		chAuditLogger, err := storage.NewClickHouseSOARAuditLogger(a.Storage.ClickHouse, a.Sugar)
		if err == nil {
			auditLogger = chAuditLogger
		}
	}

	playbookExecutor = soar.NewExecutor(10, a.Sugar, auditLogger)
	var storageErr error
	playbookExecutionStorage, storageErr = storage.NewSQLitePlaybookExecutionStorage(a.Storage.SQLite, a.Sugar)
	if storageErr != nil {
		a.Sugar.Warnf("Failed to initialize playbook execution storage (non-critical): %v", storageErr)
	}

	// Initialize additional storages (non-critical - handlers check for nil)
	passwordHistoryStorage := storage.NewSQLitePasswordHistoryStorage(a.Storage.SQLite, a.Sugar)
	var playbookStorage *storage.SQLitePlaybookStorage
	var evidenceStorage *storage.SQLiteEvidenceStorage
	var alertLinkStorage *storage.SQLiteAlertLinkStorage

	playbookStorage, storageErr = storage.NewSQLitePlaybookStorage(a.Storage.SQLite, a.Sugar)
	if storageErr != nil {
		a.Sugar.Warnf("Failed to initialize playbook storage (non-critical): %v", storageErr)
	}
	evidenceStorage, storageErr = storage.NewSQLiteEvidenceStorage(a.Storage.SQLite, a.Sugar)
	if storageErr != nil {
		a.Sugar.Warnf("Failed to initialize evidence storage (non-critical): %v", storageErr)
	}
	alertLinkStorage, storageErr = storage.NewSQLiteAlertLinkStorage(a.Storage.SQLite, a.Sugar)
	if storageErr != nil {
		a.Sugar.Warnf("Failed to initialize alert link storage (non-critical): %v", storageErr)
	}

	// Seed field mappings
	if a.Storage.FieldMappingStorage != nil {
		yamlPath := a.Config.FieldMappings.YAMLPath
		if yamlPath == "" {
			yamlPath = "config/field_mappings.yaml"
		}
		if _, err := os.Stat(yamlPath); err == nil {
			if err := a.Storage.FieldMappingStorage.SeedDefaults(yamlPath); err != nil {
				a.Sugar.Warnf("Failed to seed field mappings: %v", err)
			}
		}
	}

	// Create API server
	a.APIServer = api.NewAPI(
		a.Storage.EventStorage,
		a.Storage.AlertStorage,
		a.Storage.RuleStorage,
		a.Storage.ActionStorage,
		a.Storage.CorrelationRuleStorage,
		a.Storage.InvestigationStorage,
		a.Storage.UserStorage,
		a.Storage.RoleStorage,
		savedSearchStorage,
		a.Detector,
		mlDetector,
		a.Config,
		a.Sugar,
		a.DLQ,
		mitreStorage,
		playbookExecutor,
		playbookExecutionStorage,
		passwordHistoryStorage,
		mlModelStorage,
		a.Storage.FieldMappingStorage,
		a.ListenerManager,
		playbookStorage,
		evidenceStorage,
		alertLinkStorage,
		a.Storage.LifecycleAuditStorage,       // TASK 169: Rule lifecycle audit trail storage
		a.Storage.FieldMappingAuditStorage,    // TASK 185: Field mapping lifecycle audit trail storage
	)

	a.APIServer.SetHealthCheckDependencies(a.Storage.ClickHouse, a.Storage.SQLite)

	// Set IOC components if available
	if a.Storage.IOCStorage != nil {
		a.APIServer.SetIOCStorage(a.Storage.IOCStorage)
		a.Sugar.Info("IOC storage connected to API server")
	}
	if a.IOCFeedManager != nil {
		a.APIServer.SetIOCFeedManager(a.IOCFeedManager)
		a.Sugar.Info("IOC feed manager connected to API server")
	}

	// Start API server
	a.serviceWg.Add(1)
	go func() {
		defer a.serviceWg.Done()
		addr := fmt.Sprintf(":%d", a.Config.API.Port)
		a.Sugar.Infof("API server started on %s", addr)

		var err error
		if a.Config.API.TLS {
			err = a.APIServer.StartTLS(addr, a.Config.API.CertFile, a.Config.API.KeyFile)
		} else {
			err = a.APIServer.Start(addr)
		}

		if err != nil && err.Error() != "http: Server closed" {
			a.Sugar.Errorf("API server error: %v", err)
		}
	}()

	return nil
}

// FirstRunResult contains information about first-run initialization.
type FirstRunResult struct {
	IsFirstRun    bool
	AdminCreated  bool
	AdminUsername string
	AdminPassword string
}

// runFirstRunSetup performs first-run initialization tasks.
func (a *App) runFirstRunSetup(sqlite *storage.SQLite) (*FirstRunResult, error) {
	result := &FirstRunResult{}

	// Check if first run
	var userCount int
	err := sqlite.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil || userCount == 0 {
		result.IsFirstRun = true
	}

	if !result.IsFirstRun {
		return result, nil
	}

	a.Sugar.Info("========================================")
	a.Sugar.Info("FIRST RUN DETECTED - Running initial setup")
	a.Sugar.Info("========================================")

	// Create default admin user if auth is enabled
	if a.Config.Auth.Enabled {
		adminUsername := "admin"
		adminPassword, err := GenerateSecurePassword(24)
		if err != nil {
			return result, fmt.Errorf("failed to generate admin password: %w", err)
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), a.Config.Auth.BcryptCost)
		if err != nil {
			return result, fmt.Errorf("failed to hash admin password: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		adminRole, err := a.Storage.RoleStorage.GetRoleByName(ctx, storage.RoleAdmin)
		if err != nil {
			a.Sugar.Warnf("Admin role not found: %v", err)
		}

		adminUser := &storage.User{
			Username:           adminUsername,
			Password:           string(hashedPassword),
			Active:             true,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
			MustChangePassword: true,
		}

		if adminRole != nil {
			adminUser.RoleID = &adminRole.ID
			adminUser.RoleName = adminRole.Name
		}

		if err := a.Storage.UserStorage.CreateUser(ctx, adminUser); err != nil {
			a.Sugar.Warnf("Failed to create admin user: %v", err)
		} else {
			result.AdminCreated = true
			result.AdminUsername = adminUsername
			result.AdminPassword = adminPassword

			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "========================================\n")
			fmt.Fprintf(os.Stderr, "     DEFAULT ADMIN CREDENTIALS\n")
			fmt.Fprintf(os.Stderr, "========================================\n")
			fmt.Fprintf(os.Stderr, "  Username: %s\n", adminUsername)
			fmt.Fprintf(os.Stderr, "  Password: %s\n", adminPassword)
			fmt.Fprintf(os.Stderr, "========================================\n")
			fmt.Fprintf(os.Stderr, "  IMPORTANT: This password will NOT be\n")
			fmt.Fprintf(os.Stderr, "  shown again! Store it securely now.\n")
			fmt.Fprintf(os.Stderr, "========================================\n\n")
		}
	}

	a.Sugar.Info("First-run setup completed")
	return result, nil
}
