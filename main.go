package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cerberus/api"
	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"
	_ "cerberus/docs"
	"cerberus/ingest"
	"cerberus/storage"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type SystemInitResult struct {
	Cfg                    *config.Config
	MongoDB                *storage.MongoDB
	RawEventCh             chan *core.Event
	ProcessedEventCh       chan *core.Event
	AlertCh                chan *core.Alert
	EventStorage           *storage.EventStorage
	AlertStorage           *storage.AlertStorage
	RuleStorage            *storage.RuleStorage
	ActionStorage          *storage.ActionStorage
	CorrelationRuleStorage *storage.CorrelationRuleStorage
	RetentionManager       *storage.RetentionManager
	Rules                  []core.Rule
	CorrelationRules       []core.CorrelationRule
}

// initLogger initializes the logger
func initLogger() (*zap.Logger, *zap.SugaredLogger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}
	sugar := logger.Sugar()
	return logger, sugar, nil
}

// initConfig loads the configuration
func initConfig(sugar *zap.SugaredLogger) *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		sugar.Fatalf("Failed to load config: %v", err)
	}
	if viper.ConfigFileUsed() == "" {
		sugar.Info("No config file found, using defaults and env vars")
	}
	sugar.Infow("Config loaded",
		"mongodb_enabled", cfg.MongoDB.Enabled,
		"syslog_port", cfg.Listeners.Syslog.Port)
	return cfg
}

// initMongoDB initializes MongoDB connection
func initMongoDB(cfg *config.Config, sugar *zap.SugaredLogger) *storage.MongoDB {
	var mongoDB *storage.MongoDB
	if cfg.MongoDB.Enabled {
		var err error
		mongoDB, err = storage.NewMongoDB(cfg.MongoDB.URI, cfg.MongoDB.Database, cfg.MongoDB.MaxPoolSize, sugar)
		if err != nil {
			sugar.Fatalf("Failed to connect to MongoDB: %v", err)
		}
		sugar.Info("Connected to MongoDB successfully")
	} else {
		sugar.Warn("MongoDB is disabled, running without persistent storage")
	}
	return mongoDB
}

// startStorageWorkers starts storage workers and retention manager
func startStorageWorkers(mongoDB *storage.MongoDB, cfg *config.Config, processedEventCh chan *core.Event, alertCh chan *core.Alert, sugar *zap.SugaredLogger) (*storage.EventStorage, *storage.AlertStorage, *storage.RuleStorage, *storage.ActionStorage, *storage.CorrelationRuleStorage, *storage.RetentionManager) {
	var eventStorage *storage.EventStorage
	var alertStorage *storage.AlertStorage
	var ruleStorage *storage.RuleStorage
	var actionStorage *storage.ActionStorage
	var correlationRuleStorage *storage.CorrelationRuleStorage
	var retentionManager *storage.RetentionManager

	if mongoDB != nil {
		eventStorage = storage.NewEventStorage(mongoDB, cfg, processedEventCh, sugar)
		eventStorage.Start(cfg.Engine.WorkerCount)

		alertStorage = storage.NewAlertStorage(mongoDB, cfg, alertCh, sugar)
		alertStorage.Start(cfg.Engine.WorkerCount)

		ruleStorage = storage.NewRuleStorage(mongoDB)
		if err := ruleStorage.EnsureIndexes(); err != nil {
			sugar.Fatalf("Failed to ensure rule indexes: %v", err)
		}

		actionStorage = storage.NewActionStorage(mongoDB)
		if err := actionStorage.EnsureIndexes(); err != nil {
			sugar.Fatalf("Failed to ensure action indexes: %v", err)
		}

		correlationRuleStorage = storage.NewCorrelationRuleStorage(mongoDB)
		if err := correlationRuleStorage.EnsureIndexes(); err != nil {
			sugar.Fatalf("Failed to ensure correlation rule indexes: %v", err)
		}

		// Start retention manager for data cleanup
		retentionManager = storage.NewRetentionManager(eventStorage, alertStorage, cfg.Retention.Events, cfg.Retention.Alerts, sugar)
		retentionManager.Start()
	} else {
		// Drain channels to prevent blocking when no storage
		go func() {
			for range processedEventCh {
				// Drop events
			}
		}()
		go func() {
			for range alertCh {
				// Drop alerts
			}
		}()
	}

	return eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, retentionManager
}

// initSystem initializes the system components
func initSystem(sugar *zap.SugaredLogger) (*SystemInitResult, error) {
	cfg := initConfig(sugar)

	mongoDB := initMongoDB(cfg, sugar)

	// Initialize communication channels
	rawEventCh := make(chan *core.Event, cfg.Engine.ChannelBufferSize)       // From listeners
	processedEventCh := make(chan *core.Event, cfg.Engine.ChannelBufferSize) // To storage
	alertCh := make(chan *core.Alert, cfg.Engine.ChannelBufferSize)

	eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, retentionManager := startStorageWorkers(mongoDB, cfg, processedEventCh, alertCh, sugar)

	// Load detection rules
	var rules []core.Rule
	var correlationRules []core.CorrelationRule
	var err error
	if cfg.MongoDB.Enabled {
		rules, err = detect.LoadRulesFromDB(ruleStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from DB: %w", err)
		}
		correlationRules, err = correlationRuleStorage.GetCorrelationRules()
		if err != nil {
			return nil, fmt.Errorf("failed to load correlation rules from DB: %w", err)
		}
	} else {
		rules, err = detect.LoadRules(cfg.Rules.File, sugar)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from file: %w", err)
		}
		sugar.Infof("Loaded %d rules from %s", len(rules), cfg.Rules.File)

		if cfg.CorrelationRules.File != "" {
			correlationRules, err = detect.LoadCorrelationRules(cfg.CorrelationRules.File, sugar)
			if err != nil {
				sugar.Errorf("Failed to load correlation rules from file: %v", err)
				correlationRules = []core.CorrelationRule{}
			}
		} else {
			correlationRules = []core.CorrelationRule{}
		}
	}

	return &SystemInitResult{
		Cfg:                    cfg,
		MongoDB:                mongoDB,
		RawEventCh:             rawEventCh,
		ProcessedEventCh:       processedEventCh,
		AlertCh:                alertCh,
		EventStorage:           eventStorage,
		AlertStorage:           alertStorage,
		RuleStorage:            ruleStorage,
		ActionStorage:          actionStorage,
		CorrelationRuleStorage: correlationRuleStorage,
		RetentionManager:       retentionManager,
		Rules:                  rules,
		CorrelationRules:       correlationRules,
	}, nil
}

// startServices starts the detector, listeners, and API
func startServices(cfg *config.Config, mongoDB *storage.MongoDB, rawEventCh chan *core.Event, processedEventCh chan *core.Event, alertCh chan *core.Alert, eventStorage *storage.EventStorage, alertStorage *storage.AlertStorage, ruleStorage *storage.RuleStorage, actionStorage *storage.ActionStorage, correlationRuleStorage *storage.CorrelationRuleStorage, rules []core.Rule, correlationRules []core.CorrelationRule, sugar *zap.SugaredLogger) (*detect.Detector, *ingest.SyslogListener, *ingest.CEFListener, *ingest.JSONListener, *api.API) {
	// Initialize detection components
	detector := initializeDetector(cfg, rules, correlationRules, rawEventCh, processedEventCh, alertCh, sugar)

	// Start event listeners
	syslogListener, cefListener, jsonListener := startEventListeners(cfg, rawEventCh, sugar)

	// Start API server
	apiServer := startAPIServer(cfg, mongoDB, eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, sugar)

	return detector, syslogListener, cefListener, jsonListener, apiServer
}

// initializeDetector creates and starts the detection engine
func initializeDetector(cfg *config.Config, rules []core.Rule, correlationRules []core.CorrelationRule, rawEventCh chan *core.Event, processedEventCh chan *core.Event, alertCh chan *core.Alert, sugar *zap.SugaredLogger) *detect.Detector {
	ruleEngine := detect.NewRuleEngine(rules, correlationRules, cfg.Engine.CorrelationStateTTL)
	detector := detect.NewDetector(ruleEngine, rawEventCh, processedEventCh, alertCh, cfg, sugar)
	detector.Start()
	return detector
}

// startEventListeners creates and starts all event listeners
func startEventListeners(cfg *config.Config, rawEventCh chan *core.Event, sugar *zap.SugaredLogger) (*ingest.SyslogListener, *ingest.CEFListener, *ingest.JSONListener) {
	syslogListener := ingest.NewSyslogListener(cfg.Listeners.Syslog.Host, cfg.Listeners.Syslog.Port, cfg.Engine.RateLimit, rawEventCh, sugar)
	cefListener := ingest.NewCEFListener(cfg.Listeners.CEF.Host, cfg.Listeners.CEF.Port, cfg.Engine.RateLimit, rawEventCh, sugar)
	jsonListener := ingest.NewJSONListener(cfg.Listeners.JSON.Host, cfg.Listeners.JSON.Port, cfg.Listeners.JSON.TLS, cfg.Listeners.JSON.CertFile, cfg.Listeners.JSON.KeyFile, cfg.Engine.RateLimit, rawEventCh, sugar)

	// Start listeners with panic recovery
	startListener := func(name string, startFunc func() error) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					sugar.Errorw(fmt.Sprintf("%s listener panicked", name), "panic", r)
				}
			}()
			if err := startFunc(); err != nil {
				sugar.Errorw(fmt.Sprintf("Failed to start %s listener", name), "error", err)
			} else {
				sugar.Infof("%s listener started successfully", name)
			}
		}()
	}

	startListener("Syslog", syslogListener.Start)
	startListener("CEF", cefListener.Start)
	startListener("JSON", jsonListener.Start)

	return syslogListener, cefListener, jsonListener
}

// startAPIServer creates and starts the API server if MongoDB is available
func startAPIServer(cfg *config.Config, mongoDB *storage.MongoDB, eventStorage *storage.EventStorage, alertStorage *storage.AlertStorage, ruleStorage *storage.RuleStorage, actionStorage *storage.ActionStorage, correlationRuleStorage *storage.CorrelationRuleStorage, sugar *zap.SugaredLogger) *api.API {
	if mongoDB == nil {
		sugar.Warnf("API server not started: MongoDB is disabled. Enable MongoDB in config to access the web interface on port %d", cfg.API.Port)
		return nil
	}

	apiServer := api.NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, sugar)

	go func() {
		addr := fmt.Sprintf(":%d", cfg.API.Port)
		sugar.Infof("API server started on %s", addr)

		var err error
		if cfg.API.TLS {
			err = apiServer.StartTLS(addr, cfg.API.CertFile, cfg.API.KeyFile)
		} else {
			err = apiServer.Start(addr)
		}

		if err != nil && err.Error() != "http: Server closed" {
			sugar.Fatalf("Failed to start API server: %v", err)
		} else if err == nil {
			sugar.Info("API server stopped during shutdown")
		}
	}()

	return apiServer
}

// shutdownSystem performs graceful shutdown
func shutdownSystem(mongoDB *storage.MongoDB, syslogListener *ingest.SyslogListener, cefListener *ingest.CEFListener, jsonListener *ingest.JSONListener, rawEventCh chan *core.Event, detector *detect.Detector, processedEventCh chan *core.Event, alertCh chan *core.Alert, eventStorage *storage.EventStorage, alertStorage *storage.AlertStorage, retentionManager *storage.RetentionManager, apiServer *api.API, sugar *zap.SugaredLogger) {
	sugar.Info("Shutting down...")

	// Graceful shutdown sequence
	syslogListener.Stop()
	cefListener.Stop()
	jsonListener.Stop()
	close(rawEventCh)

	detector.Stop()

	close(processedEventCh)
	close(alertCh)
	if mongoDB != nil {
		eventStorage.Stop()
		alertStorage.Stop()
	}

	if retentionManager != nil {
		retentionManager.Stop()
	}

	if apiServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := apiServer.Stop(ctx); err != nil {
			sugar.Errorw("Failed to stop API server", "error", err)
		}
	}

	sugar.Info("Shutdown complete")
}

// run initializes and starts the Cerberus SIEM system
func run() error {
	logger, sugar, err := initLogger()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	sugar.Info("Cerberus SIEM starting...")

	result, err := initSystem(sugar)
	if err != nil {
		return err
	}
	if result.MongoDB != nil {
		defer result.MongoDB.Close(context.Background())
	}

	detector, syslogListener, cefListener, jsonListener, apiServer := startServices(result.Cfg, result.MongoDB, result.RawEventCh, result.ProcessedEventCh, result.AlertCh, result.EventStorage, result.AlertStorage, result.RuleStorage, result.ActionStorage, result.CorrelationRuleStorage, result.Rules, result.CorrelationRules, sugar)

	// Wait for shutdown signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	shutdownSystem(result.MongoDB, syslogListener, cefListener, jsonListener, result.RawEventCh, detector, result.ProcessedEventCh, result.AlertCh, result.EventStorage, result.AlertStorage, result.RetentionManager, apiServer, sugar)

	return nil
}

// main is the entry point
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
