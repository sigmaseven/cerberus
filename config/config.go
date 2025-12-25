package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// StartupMode defines how Cerberus handles initialization failures
type StartupMode string

const (
	// StartupModeStrict fails fast on any initialization error (default)
	StartupModeStrict StartupMode = "strict"
	// StartupModeGraceful starts with degraded functionality, logging warnings
	StartupModeGraceful StartupMode = "graceful"
)

// DataPaths holds all data directory and file path configuration
// These paths can be overridden via environment variables
type DataPaths struct {
	// DataDir is the base data directory (CERBERUS_DATA_DIR, default: ./data)
	DataDir string `mapstructure:"data_dir"`
	// SQLitePath is the SQLite database file path (CERBERUS_SQLITE_PATH, default: ${DataDir}/cerberus.db)
	SQLitePath string `mapstructure:"sqlite_path"`
	// FeedsDir is the SIGMA feeds working directory (CERBERUS_FEEDS_DIR, default: ${DataDir}/feeds)
	FeedsDir string `mapstructure:"feeds_dir"`
	// MLDir is the ML models directory (CERBERUS_ML_DIR, default: ${DataDir}/ml_models)
	MLDir string `mapstructure:"ml_dir"`
}

// Config holds all configuration for the Cerberus service
type Config struct {
	// StartupMode controls how initialization failures are handled
	// "strict" (default): Fail fast on any error
	// "graceful": Start with degraded functionality, log warnings
	StartupMode StartupMode `mapstructure:"startup_mode"`

	// DataPaths holds all data directory configuration
	DataPaths DataPaths `mapstructure:"data_paths"`

	MongoDB struct {
		URI                string `mapstructure:"uri"`
		Database           string `mapstructure:"database"`
		Enabled            bool   `mapstructure:"enabled"`
		BatchInsertTimeout int    `mapstructure:"batch_insert_timeout"` // seconds
		MaxPoolSize        uint64 `mapstructure:"max_pool_size"`
	} `mapstructure:"mongodb"`

	Listeners struct {
		Syslog struct {
			Port int    `mapstructure:"port"`
			Host string `mapstructure:"host"`
		} `mapstructure:"syslog"`
		CEF struct {
			Port int    `mapstructure:"port"`
			Host string `mapstructure:"host"`
		} `mapstructure:"cef"`
		JSON struct {
			Port     int    `mapstructure:"port"`
			Host     string `mapstructure:"host"`
			TLS      bool   `mapstructure:"tls"`
			CertFile string `mapstructure:"cert_file"`
			KeyFile  string `mapstructure:"key_file"`
		} `mapstructure:"json"`
		Fluentd struct {
			Port           int    `mapstructure:"port"`
			Host           string `mapstructure:"host"`
			TLS            bool   `mapstructure:"tls"`
			CertFile       string `mapstructure:"cert_file"`
			KeyFile        string `mapstructure:"key_file"`
			SharedKey      string `mapstructure:"shared_key"`
			RequireACK     bool   `mapstructure:"require_ack"`
			ChunkSizeLimit int    `mapstructure:"chunk_size_limit"`
		} `mapstructure:"fluentd"`
		FluentBit struct {
			Port     int    `mapstructure:"port"`
			Host     string `mapstructure:"host"`
			TLS      bool   `mapstructure:"tls"`
			CertFile string `mapstructure:"cert_file"`
			KeyFile  string `mapstructure:"key_file"`
		} `mapstructure:"fluentbit"`
		SkipOnError          bool `mapstructure:"skip_on_error"`
		MaxTCPConnections    int  `mapstructure:"max_tcp_connections"`    // Maximum concurrent TCP connections per listener
		TCPConnectionTimeout int  `mapstructure:"tcp_connection_timeout"` // TCP connection read timeout in seconds
		TCPConnectionBacklog int  `mapstructure:"tcp_connection_backlog"` // Queue size for pending connections
	} `mapstructure:"listeners"`

	API struct {
		Version              string   `mapstructure:"version"`
		Port                 int      `mapstructure:"port"`
		TLS                  bool     `mapstructure:"tls"`
		CertFile             string   `mapstructure:"cert_file"`
		KeyFile              string   `mapstructure:"key_file"`
		AllowedOrigins       []string `mapstructure:"allowed_origins"`
		TrustProxy           bool     `mapstructure:"trust_proxy"`
		TrustedProxyNetworks []string `mapstructure:"trusted_proxy_networks"`
		RateLimit            struct {
			RequestsPerSecond int `mapstructure:"requests_per_second"`
			Burst             int `mapstructure:"burst"`
			MaxAuthFailures   int `mapstructure:"max_auth_failures"`
			// TASK 24: Multi-tier rate limiting configuration
			Login struct {
				Limit  int           `mapstructure:"limit"`  // Default: 5 attempts
				Window time.Duration `mapstructure:"window"` // Default: 1 minute
				Burst  int           `mapstructure:"burst"`  // Default: 5
			} `mapstructure:"login"`
			API struct {
				Limit  int           `mapstructure:"limit"`  // Default: 100 requests
				Window time.Duration `mapstructure:"window"` // Default: 1 minute
				Burst  int           `mapstructure:"burst"`  // Default: 100
			} `mapstructure:"api"`
			Global struct {
				Limit  int           `mapstructure:"limit"`  // Default: 10000 requests
				Window time.Duration `mapstructure:"window"` // Default: 1 second
				Burst  int           `mapstructure:"burst"`  // Default: 10000
			} `mapstructure:"global"`
			ExemptIPs []string `mapstructure:"exempt_ips"` // IPs exempt from rate limiting
			Redis     struct {
				Enabled  bool   `mapstructure:"enabled"`
				Addr     string `mapstructure:"addr"`
				Password string `mapstructure:"password"`
				DB       int    `mapstructure:"db"`
				PoolSize int    `mapstructure:"pool_size"`
			} `mapstructure:"redis"`
		} `mapstructure:"rate_limit"`
	} `mapstructure:"api"`

	Auth struct {
		Enabled        bool   `mapstructure:"enabled"`
		Username       string `mapstructure:"username"`
		Password       string `mapstructure:"password"`
		HashedPassword string
		BcryptCost     int           `mapstructure:"bcrypt_cost"`
		JWTSecret      string        `mapstructure:"jwt_secret"`
		JWTExpiry      time.Duration `mapstructure:"jwt_expiry"`
		// TASK 39: Account lockout configuration
		LockoutThreshold int           `mapstructure:"lockout_threshold"` // Number of failed attempts before lockout (default: 5)
		LockoutDuration  time.Duration `mapstructure:"lockout_duration"`  // Lockout duration (default: 15 minutes)
	} `mapstructure:"auth"`

	// TASK #183: Rules.File and CorrelationRules.File config fields deleted
	// Rules are now loaded exclusively from the database.
	// Use SIGMA feeds or API to import rules into the database.

	Retention struct {
		Events int `mapstructure:"events"` // days
		Alerts int `mapstructure:"alerts"` // days
	} `mapstructure:"retention"`

	Storage struct {
		Deduplication     bool `mapstructure:"deduplication"`
		DedupCacheSize    int  `mapstructure:"dedup_cache_size"`
		DedupEvictionSize int  `mapstructure:"dedup_eviction_size"`
		BufferSize        int  `mapstructure:"buffer_size"`
	} `mapstructure:"storage"`

	Engine struct {
		ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
		WorkerCount         int `mapstructure:"worker_count"`
		ActionWorkerCount   int `mapstructure:"action_worker_count"`
		RateLimit           int `mapstructure:"rate_limit"`
		CorrelationStateTTL int `mapstructure:"correlation_state_ttl"` // seconds
		ActionTimeout       int `mapstructure:"action_timeout"`        // seconds
		CircuitBreaker      struct {
			MaxFailures         int `mapstructure:"max_failures"`           // Number of failures before opening circuit
			TimeoutSeconds      int `mapstructure:"timeout_seconds"`        // Time to wait before attempting half-open
			MaxHalfOpenRequests int `mapstructure:"max_half_open_requests"` // Concurrent requests allowed in half-open
		} `mapstructure:"circuit_breaker"`
		// ReDoS Protection Configuration
		// REQUIREMENT: Task #2 - ReDoS Protection for Regex Evaluation
		// SECURITY: Prevents Regular Expression Denial of Service attacks
		RegexTimeoutMs             int  `mapstructure:"regex_timeout_ms"`              // Timeout for regex evaluation (default: 500ms)
		RegexMaxLength             int  `mapstructure:"regex_max_length"`              // Maximum regex pattern length (default: 1000)
		RegexEnableComplexityCheck bool `mapstructure:"regex_enable_complexity_check"` // Enable complexity validation (default: true)
		// SIGMA Engine Configuration
		// REQUIREMENT: Task #131 - Native SIGMA Detection Engine Integration
		// Enables native SIGMA YAML rule evaluation alongside traditional JSON rules
		EnableNativeSigmaEngine    bool          `mapstructure:"enable_native_sigma_engine"`    // Feature flag to enable native SIGMA engine (default: false)
		SigmaFieldMappingConfig    string        `mapstructure:"sigma_field_mapping_config"`    // Path to SIGMA field mapping YAML (default: config/sigma_field_mappings.yaml)
		SigmaEngineCacheSize       int           `mapstructure:"sigma_engine_cache_size"`       // Maximum number of SIGMA rules to cache (default: 1000)
		SigmaEngineCacheTTL        time.Duration `mapstructure:"sigma_engine_cache_ttl"`        // Cache entry TTL (default: 30m)
		SigmaEngineCleanupInterval time.Duration `mapstructure:"sigma_engine_cleanup_interval"` // Background cache cleanup interval (default: 5m)
		// SIGMA Rollout Configuration
		// REQUIREMENT: Task #131.5 - Feature Flags for Gradual SIGMA Rollout
		// PRODUCTION: Enables canary deployment of SIGMA engine for safe rollout
		SigmaRolloutPercentage    int      `mapstructure:"sigma_rollout_percentage"`     // Percentage of rules using native engine (0-100, default: 0)
		SigmaRolloutEnabledRules  []string `mapstructure:"sigma_rollout_enabled_rules"`  // Explicit whitelist of rule IDs for native engine (default: empty)
		SigmaRolloutDisabledRules []string `mapstructure:"sigma_rollout_disabled_rules"` // Explicit blocklist of rule IDs for legacy engine (default: empty)
	} `mapstructure:"engine"`

	Filtering struct {
		Enabled          bool     `mapstructure:"enabled"`
		SamplingRate     float64  `mapstructure:"sampling_rate"`
		DropEventTypes   []string `mapstructure:"drop_event_types"`
		SampleEventTypes []string `mapstructure:"sample_event_types"`
		WhitelistSources []string `mapstructure:"whitelist_sources"`
	} `mapstructure:"filtering"`

	Security struct {
		TLSMinVersion       string        `mapstructure:"tls_min_version"`
		EnableHSTS          bool          `mapstructure:"enable_hsts"`
		EnableCSP           bool          `mapstructure:"enable_csp"`
		EnableXSSProtection bool          `mapstructure:"enable_xss_protection"`
		JSONBodyLimit       int           `mapstructure:"json_body_limit"`
		LoginBodyLimit      int           `mapstructure:"login_body_limit"`
		RegexTimeout        time.Duration `mapstructure:"regex_timeout"` // TASK 32.3: Regex timeout for ReDoS protection (default: 100ms)
		Webhooks            struct {
			AllowLocalhost  bool     `mapstructure:"allow_localhost"`
			AllowPrivateIPs bool     `mapstructure:"allow_private_ips"`
			Allowlist       []string `mapstructure:"allowlist"` // Allowed domains/IPs for webhooks
			Timeout         int      `mapstructure:"timeout"`   // Webhook timeout in seconds (default: 10)
		} `mapstructure:"webhooks"`
		Actions struct {
			AllowLocalhost  bool `mapstructure:"allow_localhost"`
			AllowPrivateIPs bool `mapstructure:"allow_private_ips"`
		} `mapstructure:"actions"`
		// TASK 38.1: Password policy configuration
		PasswordPolicy struct {
			MinLength          int    `mapstructure:"min_length"`           // Minimum password length (default: 12)
			RequireClasses     int    `mapstructure:"require_classes"`      // Number of character classes required (default: 3 of 4)
			MaxHistory         int    `mapstructure:"max_history"`          // Maximum password history entries (default: 5)
			ExpirationDays     int    `mapstructure:"expiration_days"`      // Password expiration in days (default: 90, 0 = disabled)
			WarningDays        int    `mapstructure:"warning_days"`         // Days before expiration to send warning (default: 14)
			CommonPasswordFile string `mapstructure:"common_password_file"` // Path to common passwords list (default: data/common-passwords.txt)
		} `mapstructure:"password_policy"`
	} `mapstructure:"security"`

	Secrets struct {
		Provider string `mapstructure:"provider"` // env, vault, aws
		Vault    struct {
			Address string `mapstructure:"address"`
			Token   string `mapstructure:"token"`
			Path    string `mapstructure:"path"`
		} `mapstructure:"vault"`
		AWS struct {
			Region    string `mapstructure:"region"`
			AccessKey string `mapstructure:"access_key"`
			SecretKey string `mapstructure:"secret_key"`
			SecretID  string `mapstructure:"secret_id"`
		} `mapstructure:"aws"`
	} `mapstructure:"secrets"`

	ClickHouse struct {
		Addr          string `mapstructure:"addr"`
		Database      string `mapstructure:"database"`
		Username      string `mapstructure:"username"`
		Password      string `mapstructure:"password"`
		TLS           bool   `mapstructure:"tls"`
		MaxPoolSize   int    `mapstructure:"max_pool_size"`
		BatchSize     int    `mapstructure:"batch_size"`
		FlushInterval int    `mapstructure:"flush_interval"` // seconds
	} `mapstructure:"clickhouse"`

	ML struct {
		Mode                 string   `mapstructure:"mode"` // simple, advanced
		Enabled              bool     `mapstructure:"enabled"`
		ModelPath            string   `mapstructure:"model_path"`
		TrainingDataDir      string   `mapstructure:"training_data_dir"`
		BatchSize            int      `mapstructure:"batch_size"`
		Threshold            float64  `mapstructure:"threshold"`
		UpdateInterval       int      `mapstructure:"update_interval"` // minutes
		FeatureCacheSize     int      `mapstructure:"feature_cache_size"`
		Algorithms           []string `mapstructure:"algorithms"`
		TrainingInterval     int      `mapstructure:"training_interval"` // hours
		RetrainThreshold     int      `mapstructure:"retrain_threshold"` // changed to int
		EnableDriftDetection bool     `mapstructure:"enable_drift_detection"`
		AnomalyThreshold     float64  `mapstructure:"anomaly_threshold"`
		MinTrainingSamples   int      `mapstructure:"min_training_samples"`
	} `mapstructure:"ml"`

	SOAR struct {
		// DestructiveActionsEnabled controls whether destructive SOAR actions can execute
		// FR-SOAR-020: Approval workflow placeholder
		// SECURITY: Destructive actions (block IP, isolate host) require approval
		// Default: false (disabled for safety)
		DestructiveActionsEnabled bool `mapstructure:"destructive_actions_enabled"`

		// ApprovalRequired controls whether actions require manual approval
		// TODO: Implement full approval workflow with API endpoints
		ApprovalRequired bool `mapstructure:"approval_required"`

		// SandboxEnabled controls whether scripts run in sandbox
		// FR-SOAR-019: Sandbox execution is REQUIRED for production
		SandboxEnabled bool `mapstructure:"sandbox_enabled"`

		// SandboxRuntime specifies the sandbox runtime (docker, gvisor)
		// FR-SOAR-019: gVisor is RECOMMENDED for Linux production
		SandboxRuntime string `mapstructure:"sandbox_runtime"` // docker, gvisor
	} `mapstructure:"soar"`

	// Feeds configuration for SIGMA rule sources
	Feeds struct {
		// Enabled controls whether the feed system is active
		Enabled bool `mapstructure:"enabled"`

		// WorkingDir is the directory for feed operations (e.g., git clones)
		WorkingDir string `mapstructure:"working_dir"`

		// SyncOnStartup controls whether to sync feeds with update_strategy="startup" on boot
		SyncOnStartup bool `mapstructure:"sync_on_startup"`

		// SchedulerEnabled controls whether the feed scheduler runs for automatic syncs
		SchedulerEnabled bool `mapstructure:"scheduler_enabled"`

		// DefaultFeed is the default SIGMA rule feed to create if no feeds exist
		DefaultFeed struct {
			Enabled     bool   `mapstructure:"enabled"`
			Name        string `mapstructure:"name"`
			URL         string `mapstructure:"url"`
			Branch      string `mapstructure:"branch"`
			Path        string `mapstructure:"path"` // Subdirectory within the repo
			MinSeverity string `mapstructure:"min_severity"`
		} `mapstructure:"default_feed"`
	} `mapstructure:"feeds"`

	// FieldMappings configuration for SIGMA field normalization
	FieldMappings struct {
		// YAMLPath is the path to the field mappings YAML file
		YAMLPath string `mapstructure:"yaml_path"`
	} `mapstructure:"field_mappings"`

	// IOCFeeds configuration for Threat Intelligence IOC feeds
	IOCFeeds struct {
		// Enabled controls whether the IOC feed system is active
		Enabled bool `mapstructure:"enabled"`

		// SyncOnStartup controls whether to sync IOC feeds on server startup
		SyncOnStartup bool `mapstructure:"sync_on_startup"`

		// SchedulerEnabled controls whether the IOC feed scheduler runs for automatic syncs
		SchedulerEnabled bool `mapstructure:"scheduler_enabled"`

		// ExpirationCheckInterval is how often to check for expired IOCs (default: 1h)
		ExpirationCheckInterval string `mapstructure:"expiration_check_interval"`

		// DefaultAutoExpireDays is the default expiration for IOCs without explicit expiration (0 = never)
		DefaultAutoExpireDays int `mapstructure:"default_auto_expire_days"`
	} `mapstructure:"ioc_feeds"`
}

// setDefaults sets default configuration values
func setDefaults() {
	// Startup mode: strict (fail fast) or graceful (degraded functionality)
	viper.SetDefault("startup_mode", string(StartupModeStrict))

	// Data paths with environment variable overrides
	// Base directory - all other paths derive from this by default
	viper.SetDefault("data_paths.data_dir", "./data")
	viper.SetDefault("data_paths.sqlite_path", "") // Empty = derive from data_dir
	viper.SetDefault("data_paths.feeds_dir", "")   // Empty = derive from data_dir
	viper.SetDefault("data_paths.ml_dir", "")      // Empty = derive from data_dir

	viper.SetDefault("mongodb.uri", "mongodb://localhost:27017")
	viper.SetDefault("mongodb.database", "cerberus")
	viper.SetDefault("mongodb.enabled", true)
	viper.SetDefault("mongodb.batch_insert_timeout", 5)
	viper.SetDefault("mongodb.max_pool_size", 10)
	viper.SetDefault("listeners.syslog.port", 514)
	viper.SetDefault("listeners.syslog.host", "0.0.0.0")
	viper.SetDefault("listeners.cef.port", 515)
	viper.SetDefault("listeners.cef.host", "0.0.0.0")
	viper.SetDefault("listeners.json.port", 8080)
	viper.SetDefault("listeners.json.host", "0.0.0.0")
	viper.SetDefault("listeners.json.tls", true)
	viper.SetDefault("listeners.json.cert_file", "server.crt")
	viper.SetDefault("listeners.json.key_file", "server.key")
	viper.SetDefault("listeners.fluentd.port", 24224)
	viper.SetDefault("listeners.fluentd.host", "0.0.0.0")
	viper.SetDefault("listeners.fluentd.tls", false)
	viper.SetDefault("listeners.fluentd.cert_file", "server.crt")
	viper.SetDefault("listeners.fluentd.key_file", "server.key")
	viper.SetDefault("listeners.fluentd.shared_key", "")
	viper.SetDefault("listeners.fluentd.require_ack", false)
	viper.SetDefault("listeners.fluentd.chunk_size_limit", 8388608) // 8MB
	viper.SetDefault("listeners.fluentbit.port", 24225)
	viper.SetDefault("listeners.fluentbit.host", "0.0.0.0")
	viper.SetDefault("listeners.fluentbit.tls", false)
	viper.SetDefault("listeners.fluentbit.cert_file", "server.crt")
	viper.SetDefault("listeners.fluentbit.key_file", "server.key")
	viper.SetDefault("listeners.max_tcp_connections", 1000)
	viper.SetDefault("listeners.tcp_connection_timeout", 300) // 5 minutes
	viper.SetDefault("listeners.tcp_connection_backlog", 100)
	viper.SetDefault("api.version", "v1")
	viper.SetDefault("api.port", 8081)
	viper.SetDefault("api.tls", true)
	viper.SetDefault("api.cert_file", "server.crt")
	viper.SetDefault("api.key_file", "server.key")
	viper.SetDefault("api.allowed_origins", []string{"http://localhost:3000", "https://localhost:3000"})
	viper.SetDefault("api.trust_proxy", false)
	viper.SetDefault("api.trusted_proxy_networks", []string{})
	viper.SetDefault("api.rate_limit.requests_per_second", 100)
	viper.SetDefault("api.rate_limit.burst", 100)
	viper.SetDefault("api.rate_limit.max_auth_failures", 5000)
	// TASK 24: Multi-tier rate limiting defaults
	viper.SetDefault("api.rate_limit.login.limit", 5)
	viper.SetDefault("api.rate_limit.login.window", 1*time.Minute)
	viper.SetDefault("api.rate_limit.login.burst", 5)
	viper.SetDefault("api.rate_limit.api.limit", 100)
	viper.SetDefault("api.rate_limit.api.window", 1*time.Minute)
	viper.SetDefault("api.rate_limit.api.burst", 100)
	viper.SetDefault("api.rate_limit.global.limit", 10000)
	viper.SetDefault("api.rate_limit.global.window", 1*time.Second)
	viper.SetDefault("api.rate_limit.global.burst", 10000)
	viper.SetDefault("api.rate_limit.exempt_ips", []string{})
	viper.SetDefault("api.rate_limit.redis.enabled", false)
	viper.SetDefault("api.rate_limit.redis.addr", "localhost:6379")
	viper.SetDefault("api.rate_limit.redis.password", "")
	viper.SetDefault("api.rate_limit.redis.db", 0)
	viper.SetDefault("api.rate_limit.redis.pool_size", 10)
	viper.SetDefault("auth.bcrypt_cost", 10)
	viper.SetDefault("auth.jwt_expiry", 24*time.Hour) // 24 hours
	// TASK 39: Account lockout defaults
	viper.SetDefault("auth.lockout_threshold", 5)             // Default: 5 failed attempts
	viper.SetDefault("auth.lockout_duration", 15*time.Minute) // Default: 15 minutes
	// TASK #183: rules.file and correlation_rules.file defaults removed (database-only)
	viper.SetDefault("retention.events", 30)
	viper.SetDefault("retention.alerts", 30)
	viper.SetDefault("storage.dedup_cache_size", 10000)
	viper.SetDefault("storage.deduplication", true)
	viper.SetDefault("storage.dedup_eviction_size", 1000)
	viper.SetDefault("storage.buffer_size", 100)
	viper.SetDefault("engine.channel_buffer_size", 1000)
	viper.SetDefault("engine.worker_count", 4)
	viper.SetDefault("engine.action_worker_count", 5)
	viper.SetDefault("engine.rate_limit", 1000)
	viper.SetDefault("engine.correlation_state_ttl", 3600) // 1 hour
	viper.SetDefault("engine.action_timeout", 10)          // seconds
	viper.SetDefault("engine.circuit_breaker.max_failures", 5)
	viper.SetDefault("engine.circuit_breaker.timeout_seconds", 60)
	viper.SetDefault("engine.circuit_breaker.max_half_open_requests", 3)
	// ReDoS Protection Defaults
	viper.SetDefault("engine.regex_timeout_ms", 500)               // 500ms timeout
	viper.SetDefault("engine.regex_max_length", 1000)              // Max 1000 characters
	viper.SetDefault("engine.regex_enable_complexity_check", true) // Enable by default
	// SIGMA Engine Defaults - Task #131
	viper.SetDefault("engine.enable_native_sigma_engine", false)                              // Disabled by default (feature flag)
	viper.SetDefault("engine.sigma_field_mapping_config", "config/sigma_field_mappings.yaml") // Default field mapping file
	viper.SetDefault("engine.sigma_engine_cache_size", 1000)                                  // 1000 rules (≈5-10MB)
	viper.SetDefault("engine.sigma_engine_cache_ttl", 30*time.Minute)                         // 30 minute TTL
	viper.SetDefault("engine.sigma_engine_cleanup_interval", 5*time.Minute)                   // 5 minute cleanup
	// SIGMA Rollout Defaults - Task #131.5
	viper.SetDefault("engine.sigma_rollout_percentage", 0)              // 0% rollout (all legacy) by default
	viper.SetDefault("engine.sigma_rollout_enabled_rules", []string{})  // No whitelist by default
	viper.SetDefault("engine.sigma_rollout_disabled_rules", []string{}) // No blocklist by default
	viper.SetDefault("filtering.enabled", false)
	viper.SetDefault("filtering.sampling_rate", 0.1)
	viper.SetDefault("filtering.drop_event_types", []string{})
	viper.SetDefault("filtering.sample_event_types", []string{})
	viper.SetDefault("filtering.whitelist_sources", []string{})
	// Use 127.0.0.1 instead of localhost to avoid IPv6 resolution issues on Windows
	viper.SetDefault("clickhouse.addr", "127.0.0.1:9000")
	viper.SetDefault("clickhouse.database", "cerberus")
	viper.SetDefault("clickhouse.username", "default")
	viper.SetDefault("clickhouse.password", "")
	viper.SetDefault("clickhouse.tls", false)
	viper.SetDefault("clickhouse.max_pool_size", 10)
	viper.SetDefault("clickhouse.batch_size", 1000)
	viper.SetDefault("clickhouse.flush_interval", 5)
	viper.SetDefault("security.json_body_limit", 1048576)            // 1MB
	viper.SetDefault("security.login_body_limit", 10240)             // 10KB
	viper.SetDefault("security.regex_timeout", 100*time.Millisecond) // TASK 32.3: Default 100ms regex timeout
	viper.SetDefault("security.webhooks.allow_localhost", false)
	viper.SetDefault("security.webhooks.allow_private_ips", false)
	viper.SetDefault("security.webhooks.allowlist", []string{}) // Empty allowlist by default
	viper.SetDefault("security.webhooks.timeout", 10)           // 10 seconds default timeout
	viper.SetDefault("security.actions.allow_localhost", false)
	viper.SetDefault("security.actions.allow_private_ips", false)
	// TASK 38.1: Password policy defaults
	viper.SetDefault("security.password_policy.min_length", 12)                                    // Minimum 12 characters
	viper.SetDefault("security.password_policy.require_classes", 3)                                // Require 3 of 4 character classes
	viper.SetDefault("security.password_policy.max_history", 5)                                    // Keep last 5 passwords in history
	viper.SetDefault("security.password_policy.expiration_days", 90)                               // Expire after 90 days
	viper.SetDefault("security.password_policy.warning_days", 14)                                  // Warn 14 days before expiration
	viper.SetDefault("security.password_policy.common_password_file", "data/common-passwords.txt") // Common passwords list
	viper.SetDefault("soar.destructive_actions_enabled", false)                                    // FR-SOAR-020: Disabled by default
	viper.SetDefault("soar.approval_required", true)                                               // Require approval by default
	viper.SetDefault("soar.sandbox_enabled", true)                                                 // FR-SOAR-019: Sandbox enabled
	viper.SetDefault("soar.sandbox_runtime", "docker")                                             // Default to Docker

	// Feed system defaults - SIGMA rules auto-import
	viper.SetDefault("feeds.enabled", true)                                            // Enable feed system by default
	viper.SetDefault("feeds.working_dir", "./data/feeds")                              // Working directory for git clones etc.
	viper.SetDefault("feeds.sync_on_startup", true)                                    // Sync feeds on startup
	viper.SetDefault("feeds.scheduler_enabled", true)                                  // Enable scheduled syncs
	viper.SetDefault("feeds.default_feed.enabled", true)                               // Create default SigmaHQ feed
	viper.SetDefault("feeds.default_feed.name", "SigmaHQ Rules")                       // Default feed name
	viper.SetDefault("feeds.default_feed.url", "https://github.com/SigmaHQ/sigma.git") // Official SigmaHQ repository
	viper.SetDefault("feeds.default_feed.branch", "master")                            // Default branch
	viper.SetDefault("feeds.default_feed.path", "rules")                               // Rules subdirectory in repo
	viper.SetDefault("feeds.default_feed.min_severity", "medium")                      // Only import medium+ severity rules

	// IOC Feed system defaults - Threat Intelligence feeds
	viper.SetDefault("ioc_feeds.enabled", true)                       // Enable IOC feed system by default
	viper.SetDefault("ioc_feeds.sync_on_startup", false)              // Don't sync on startup by default (requires feeds to be configured first)
	viper.SetDefault("ioc_feeds.scheduler_enabled", true)             // Enable scheduled syncs
	viper.SetDefault("ioc_feeds.expiration_check_interval", "1h")     // Check for expired IOCs every hour
	viper.SetDefault("ioc_feeds.default_auto_expire_days", 30)        // Default 30 days expiration for IOCs

	// Field mappings defaults
	viper.SetDefault("field_mappings.yaml_path", "config/field_mappings.yaml") // Default YAML path
}

// loadFromEnv sets up environment variable loading
func loadFromEnv() {
	viper.SetEnvPrefix("CERBERUS")
	viper.AutomaticEnv()

	// Explicit environment variable bindings for path settings
	// These allow shorter, cleaner env var names
	_ = viper.BindEnv("startup_mode", "CERBERUS_STARTUP_MODE")
	_ = viper.BindEnv("data_paths.data_dir", "CERBERUS_DATA_DIR")
	_ = viper.BindEnv("data_paths.sqlite_path", "CERBERUS_SQLITE_PATH")
	_ = viper.BindEnv("data_paths.feeds_dir", "CERBERUS_FEEDS_DIR")
	_ = viper.BindEnv("data_paths.ml_dir", "CERBERUS_ML_DIR")
}

// validateAndHash validates and hashes the password
func validateAndHash(config *Config) error {
	// CRITICAL SECURITY FIX: Validate JWT secret strength
	if config.Auth.Enabled && config.Auth.JWTSecret != "" {
		if len(config.Auth.JWTSecret) < 32 {
			return fmt.Errorf("JWT secret must be at least 32 characters (256 bits) for security")
		}

		// Check for weak/default secrets
		weakSecrets := []string{
			"secret", "password", "changeme", "default", "admin",
			"jwt_secret", "supersecret", "mysecret", "test", "example",
		}
		lowerSecret := strings.ToLower(config.Auth.JWTSecret)
		for _, weak := range weakSecrets {
			if strings.Contains(lowerSecret, weak) {
				return fmt.Errorf("JWT secret appears to contain weak/default value: please use a cryptographically secure random string")
			}
		}
	}

	// Hash the password if provided
	if config.Auth.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(config.Auth.Password), config.Auth.BcryptCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		config.Auth.HashedPassword = string(hashed)
		config.Auth.Password = "" // clear plain password
	}

	if err := validateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	setDefaults()
	loadFromEnv()

	if err := viper.ReadInConfig(); err != nil {
		// Config file not found, will use defaults and env vars
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	// TASK #183: Rules.File and CorrelationRules.File path adjustment removed (database-only)

	if err := validateAndHash(&config); err != nil {
		return nil, err
	}

	// Resolve data paths (derive from data_dir if not explicitly set)
	config.ResolveDataPaths()

	return &config, nil
}

// ResolveDataPaths resolves all data paths, deriving from DataDir if not explicitly set
func (c *Config) ResolveDataPaths() {
	// Get base data directory
	dataDir := c.DataPaths.DataDir
	if dataDir == "" {
		dataDir = "./data"
	}

	// Resolve SQLite path
	if c.DataPaths.SQLitePath == "" {
		c.DataPaths.SQLitePath = filepath.Join(dataDir, "cerberus.db")
	} else if !filepath.IsAbs(c.DataPaths.SQLitePath) {
		// Convert relative paths to be relative to current directory, not data_dir
		c.DataPaths.SQLitePath = filepath.Clean(c.DataPaths.SQLitePath)
	}

	// Resolve feeds directory
	if c.DataPaths.FeedsDir == "" {
		c.DataPaths.FeedsDir = filepath.Join(dataDir, "feeds")
	} else if !filepath.IsAbs(c.DataPaths.FeedsDir) {
		c.DataPaths.FeedsDir = filepath.Clean(c.DataPaths.FeedsDir)
	}

	// Resolve ML models directory
	if c.DataPaths.MLDir == "" {
		c.DataPaths.MLDir = filepath.Join(dataDir, "ml_models")
	} else if !filepath.IsAbs(c.DataPaths.MLDir) {
		c.DataPaths.MLDir = filepath.Clean(c.DataPaths.MLDir)
	}

	// Update data_dir to resolved path
	c.DataPaths.DataDir = dataDir

	// Also update related config sections for backward compatibility
	if c.Feeds.WorkingDir == "" || c.Feeds.WorkingDir == "./data/feeds" {
		c.Feeds.WorkingDir = c.DataPaths.FeedsDir
	}
	if c.ML.ModelPath == "" || c.ML.ModelPath == "./data/ml_models" {
		c.ML.ModelPath = c.DataPaths.MLDir
	}
}

// GetDataDir returns the resolved base data directory
func (c *Config) GetDataDir() string {
	if c.DataPaths.DataDir == "" {
		return "./data"
	}
	return c.DataPaths.DataDir
}

// GetSQLitePath returns the resolved SQLite database path
func (c *Config) GetSQLitePath() string {
	if c.DataPaths.SQLitePath == "" {
		return filepath.Join(c.GetDataDir(), "cerberus.db")
	}
	return c.DataPaths.SQLitePath
}

// GetFeedsDir returns the resolved feeds directory
func (c *Config) GetFeedsDir() string {
	if c.DataPaths.FeedsDir == "" {
		return filepath.Join(c.GetDataDir(), "feeds")
	}
	return c.DataPaths.FeedsDir
}

// GetMLDir returns the resolved ML models directory
func (c *Config) GetMLDir() string {
	if c.DataPaths.MLDir == "" {
		return filepath.Join(c.GetDataDir(), "ml_models")
	}
	return c.DataPaths.MLDir
}

// IsGracefulMode returns true if the startup mode is graceful
func (c *Config) IsGracefulMode() bool {
	return c.StartupMode == StartupModeGraceful
}

// validateConfig validates the configuration for security and correctness
func validateConfig(config *Config) error {
	// Validate MongoDB URI
	if config.MongoDB.Enabled {
		if !strings.HasPrefix(config.MongoDB.URI, "mongodb://") && !strings.HasPrefix(config.MongoDB.URI, "mongodb+srv://") {
			return fmt.Errorf("invalid MongoDB URI: must start with mongodb:// or mongodb+srv://")
		}
		parsed, err := url.Parse(config.MongoDB.URI)
		if err != nil {
			return fmt.Errorf("invalid MongoDB URI: %w", err)
		}
		if parsed.Host == "" {
			return fmt.Errorf("invalid MongoDB URI: missing host")
		}
		if config.MongoDB.Database == "" {
			return fmt.Errorf("MongoDB database cannot be empty")
		}
	}

	// Validate listener ports and hosts
	listeners := []struct {
		name string
		port int
		host string
	}{
		{"syslog", config.Listeners.Syslog.Port, config.Listeners.Syslog.Host},
		{"cef", config.Listeners.CEF.Port, config.Listeners.CEF.Host},
		{"json", config.Listeners.JSON.Port, config.Listeners.JSON.Host},
	}

	for _, l := range listeners {
		if l.port < 1 || l.port > 65535 {
			return fmt.Errorf("invalid %s port: %d (must be 1-65535)", l.name, l.port)
		}
		if l.host == "" {
			return fmt.Errorf("invalid %s host: host cannot be empty", l.name)
		}
	}

	// Validate API port
	if config.API.Port < 1 || config.API.Port > 65535 {
		return fmt.Errorf("invalid API port: %d (must be 1-65535)", config.API.Port)
	}

	// Validate retention
	if config.Retention.Events <= 0 {
		return fmt.Errorf("retention events must be positive")
	}
	if config.Retention.Alerts <= 0 {
		return fmt.Errorf("retention alerts must be positive")
	}

	// TASK 2.4: Validate ReDoS protection configuration
	if config.Engine.RegexTimeoutMs < 1 || config.Engine.RegexTimeoutMs > 60000 {
		return fmt.Errorf("engine.regex_timeout_ms must be between 1 and 60000 ms, got %d", config.Engine.RegexTimeoutMs)
	}
	if config.Engine.RegexMaxLength < 1 || config.Engine.RegexMaxLength > 10000 {
		return fmt.Errorf("engine.regex_max_length must be between 1 and 10000, got %d", config.Engine.RegexMaxLength)
	}

	// TASK 131.1: Validate SIGMA engine configuration
	if config.Engine.EnableNativeSigmaEngine {
		// Field mapping config path validation
		if config.Engine.SigmaFieldMappingConfig == "" {
			return fmt.Errorf("engine.sigma_field_mapping_config cannot be empty when SIGMA engine is enabled")
		}
		// Cache size must be positive and reasonable (1-100000)
		if config.Engine.SigmaEngineCacheSize < 1 || config.Engine.SigmaEngineCacheSize > 100000 {
			return fmt.Errorf("engine.sigma_engine_cache_size must be between 1 and 100000, got %d", config.Engine.SigmaEngineCacheSize)
		}
		// Cache TTL must be positive (minimum 1 minute, maximum 24 hours)
		if config.Engine.SigmaEngineCacheTTL < 1*time.Minute {
			return fmt.Errorf("engine.sigma_engine_cache_ttl must be at least 1 minute, got %v", config.Engine.SigmaEngineCacheTTL)
		}
		if config.Engine.SigmaEngineCacheTTL > 24*time.Hour {
			return fmt.Errorf("engine.sigma_engine_cache_ttl must be at most 24 hours, got %v", config.Engine.SigmaEngineCacheTTL)
		}
		// Cleanup interval must be positive (minimum 1 minute, maximum 1 hour)
		if config.Engine.SigmaEngineCleanupInterval < 1*time.Minute {
			return fmt.Errorf("engine.sigma_engine_cleanup_interval must be at least 1 minute, got %v", config.Engine.SigmaEngineCleanupInterval)
		}
		if config.Engine.SigmaEngineCleanupInterval > 1*time.Hour {
			return fmt.Errorf("engine.sigma_engine_cleanup_interval must be at most 1 hour, got %v", config.Engine.SigmaEngineCleanupInterval)
		}
		// Cleanup interval should not exceed TTL (warning case - not fatal)
		if config.Engine.SigmaEngineCleanupInterval > config.Engine.SigmaEngineCacheTTL {
			// This is logged as a warning in production, but not a fatal error
			// The cleanup will still work, just less efficiently
		}
	}

	// TASK 131.5: Validate SIGMA rollout configuration
	// Rollout percentage must be 0-100
	if config.Engine.SigmaRolloutPercentage < 0 || config.Engine.SigmaRolloutPercentage > 100 {
		return fmt.Errorf("engine.sigma_rollout_percentage must be between 0 and 100, got %d", config.Engine.SigmaRolloutPercentage)
	}

	// Validate circuit breaker configuration
	if config.Engine.CircuitBreaker.MaxFailures <= 0 {
		return fmt.Errorf("circuit breaker max_failures must be positive, got %d", config.Engine.CircuitBreaker.MaxFailures)
	}
	if config.Engine.CircuitBreaker.TimeoutSeconds <= 0 {
		return fmt.Errorf("circuit breaker timeout_seconds must be positive, got %d", config.Engine.CircuitBreaker.TimeoutSeconds)
	}
	if config.Engine.CircuitBreaker.MaxHalfOpenRequests <= 0 {
		return fmt.Errorf("circuit breaker max_half_open_requests must be positive, got %d", config.Engine.CircuitBreaker.MaxHalfOpenRequests)
	}

	// Validate auth
	if config.Auth.Enabled && config.Auth.HashedPassword == "" {
		return fmt.Errorf("authentication enabled but no password set")
	}
	if config.Auth.Enabled && config.Auth.Username == "" {
		return fmt.Errorf("username cannot be empty when auth is enabled")
	}

	// TASK #183: Rules file validation removed - rules loaded from database only
	// Use SIGMA feeds or API to import rules into the database

	// SECURITY: Enforce HTTPS in production mode
	env := os.Getenv("CERBERUS_ENV")
	if env == "production" {
		if !config.API.TLS {
			return fmt.Errorf("CRITICAL SECURITY ERROR: TLS must be enabled for API in production (CERBERUS_ENV=production, api.tls=false)")
		}
		if !config.Listeners.JSON.TLS {
			return fmt.Errorf("CRITICAL SECURITY ERROR: TLS must be enabled for JSON listener in production (CERBERUS_ENV=production, listeners.json.tls=false)")
		}
		if !config.Listeners.Fluentd.TLS {
			return fmt.Errorf("CRITICAL SECURITY ERROR: TLS must be enabled for Fluentd listener in production (CERBERUS_ENV=production, listeners.fluentd.tls=false)")
		}
		if !config.Listeners.FluentBit.TLS {
			return fmt.Errorf("CRITICAL SECURITY ERROR: TLS must be enabled for FluentBit listener in production (CERBERUS_ENV=production, listeners.fluentbit.tls=false)")
		}
	}

	// Validate webhook configuration
	if config.Security.Webhooks.Timeout < 1 || config.Security.Webhooks.Timeout > 60 {
		return fmt.Errorf("security.webhooks.timeout must be between 1 and 60 seconds, got %d", config.Security.Webhooks.Timeout)
	}

	// TASK 32.3: Validate regex timeout (minimum 10ms, maximum 5000ms)
	if config.Security.RegexTimeout < 10*time.Millisecond {
		return fmt.Errorf("security.regex_timeout must be at least 10ms, got %v", config.Security.RegexTimeout)
	}
	if config.Security.RegexTimeout > 5000*time.Millisecond {
		return fmt.Errorf("security.regex_timeout must be at most 5000ms, got %v", config.Security.RegexTimeout)
	}

	// Validate allowlist entries are valid domains or IPs/CIDRs
	for _, entry := range config.Security.Webhooks.Allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Check if it's a valid domain or IP/CIDR
		if !isValidDomain(entry) && !isValidIPOrCIDR(entry) {
			return fmt.Errorf("invalid webhook allowlist entry: %s (must be valid domain, IP, or CIDR)", entry)
		}
	}

	return nil
}

// isValidDomain checks if a string is a valid domain name
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	// Basic domain validation (allows alphanumeric, dots, hyphens)
	for _, r := range domain {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
			return false
		}
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}

// isValidIPOrCIDR checks if a string is a valid IP address or CIDR
func isValidIPOrCIDR(ipStr string) bool {
	// Try parsing as IP
	if ip := net.ParseIP(ipStr); ip != nil {
		return true
	}
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(ipStr); err == nil {
		return true
	}
	return false
}

// GetRegexTimeout returns the configured regex timeout, defaulting to 100ms if not set
// TASK 32.3: Getter method for regex timeout with backward compatibility
func (c *Config) GetRegexTimeout() time.Duration {
	if c.Security.RegexTimeout == 0 {
		return 100 * time.Millisecond // Default value
	}
	return c.Security.RegexTimeout
}
