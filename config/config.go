package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// Config holds all configuration for the Cerberus service
type Config struct {
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
		SkipOnError bool `mapstructure:"skip_on_error"`
	} `mapstructure:"listeners"`

	API struct {
		Version        string   `mapstructure:"version"`
		Port           int      `mapstructure:"port"`
		TLS            bool     `mapstructure:"tls"`
		CertFile       string   `mapstructure:"cert_file"`
		KeyFile        string   `mapstructure:"key_file"`
		AllowedOrigins []string `mapstructure:"allowed_origins"`
		TrustProxy     bool     `mapstructure:"trust_proxy"`
		RateLimit      struct {
			RequestsPerSecond int `mapstructure:"requests_per_second"`
			Burst             int `mapstructure:"burst"`
		} `mapstructure:"rate_limit"`
	} `mapstructure:"api"`

	Auth struct {
		Enabled        bool   `mapstructure:"enabled"`
		Username       string `mapstructure:"username"`
		Password       string `mapstructure:"password"`
		HashedPassword string
		BcryptCost     int `mapstructure:"bcrypt_cost"`
	} `mapstructure:"auth"`

	Rules struct {
		File string `mapstructure:"file"`
	} `mapstructure:"rules"`

	CorrelationRules struct {
		File string `mapstructure:"file"`
	} `mapstructure:"correlation_rules"`

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
	} `mapstructure:"engine"`
}

// setDefaults sets default configuration values
func setDefaults() {
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
	viper.SetDefault("api.version", "v1")
	viper.SetDefault("api.port", 8081)
	viper.SetDefault("api.tls", true)
	viper.SetDefault("api.cert_file", "server.crt")
	viper.SetDefault("api.key_file", "server.key")
	viper.SetDefault("api.allowed_origins", []string{"http://localhost:3000", "https://localhost:3000"})
	viper.SetDefault("api.trust_proxy", false)
	viper.SetDefault("api.rate_limit.requests_per_second", 100)
	viper.SetDefault("api.rate_limit.burst", 100)
	viper.SetDefault("auth.bcrypt_cost", 10)
	viper.SetDefault("rules.file", "rules.json")
	viper.SetDefault("correlation_rules.file", "correlation_rules.json")
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
}

// loadFromEnv sets up environment variable loading
func loadFromEnv() {
	viper.SetEnvPrefix("CERBERUS")
	viper.AutomaticEnv()
}

// validateAndHash validates and hashes the password
func validateAndHash(config *Config) error {
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

	// Adjust relative paths to be relative to the current working directory
	if config.Rules.File != "" && !filepath.IsAbs(config.Rules.File) {
		config.Rules.File = filepath.Join(".", config.Rules.File)
	}
	if config.CorrelationRules.File != "" && !filepath.IsAbs(config.CorrelationRules.File) {
		config.CorrelationRules.File = filepath.Join(".", config.CorrelationRules.File)
	}

	if err := validateAndHash(&config); err != nil {
		return nil, err
	}

	return &config, nil
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

	// Validate auth
	if config.Auth.Enabled && config.Auth.HashedPassword == "" {
		return fmt.Errorf("authentication enabled but no password set")
	}
	if config.Auth.Enabled && config.Auth.Username == "" {
		return fmt.Errorf("username cannot be empty when auth is enabled")
	}

	// Validate rules file (basic check) only if MongoDB is disabled
	if !config.MongoDB.Enabled {
		if config.Rules.File == "" {
			return fmt.Errorf("rules file cannot be empty")
		}
		if !strings.HasSuffix(config.Rules.File, ".json") && !strings.HasSuffix(config.Rules.File, ".yaml") && !strings.HasSuffix(config.Rules.File, ".yml") {
			return fmt.Errorf("rules file must be a JSON or YAML file")
		}
		if _, err := os.Stat(config.Rules.File); os.IsNotExist(err) {
			return fmt.Errorf("rules file does not exist")
		}
	}

	// Validate correlation rules file (basic check) only if MongoDB is disabled
	if !config.MongoDB.Enabled && config.CorrelationRules.File != "" {
		if !strings.HasSuffix(config.CorrelationRules.File, ".json") && !strings.HasSuffix(config.CorrelationRules.File, ".yaml") && !strings.HasSuffix(config.CorrelationRules.File, ".yml") {
			return fmt.Errorf("correlation rules file must be a JSON or YAML file")
		}
		if _, err := os.Stat(config.CorrelationRules.File); os.IsNotExist(err) {
			return fmt.Errorf("correlation rules file does not exist")
		}
	}

	return nil
}
