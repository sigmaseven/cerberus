package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestConfig returns a valid Config for testing
func newTestConfig() Config {
	return Config{
		MongoDB: struct {
			URI                string `mapstructure:"uri"`
			Database           string `mapstructure:"database"`
			Enabled            bool   `mapstructure:"enabled"`
			BatchInsertTimeout int    `mapstructure:"batch_insert_timeout"`
			MaxPoolSize        uint64 `mapstructure:"max_pool_size"`
		}{
			URI:                "mongodb://localhost:27017",
			Database:           "test",
			Enabled:            true,
			BatchInsertTimeout: 5,
			MaxPoolSize:        10,
		},
		Listeners: struct {
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
			MaxTCPConnections    int  `mapstructure:"max_tcp_connections"`
			TCPConnectionTimeout int  `mapstructure:"tcp_connection_timeout"`
			TCPConnectionBacklog int  `mapstructure:"tcp_connection_backlog"`
		}{
			Syslog: struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			}{Port: 514, Host: "0.0.0.0"},
			CEF: struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			}{Port: 515, Host: "0.0.0.0"},
			JSON: struct {
				Port     int    `mapstructure:"port"`
				Host     string `mapstructure:"host"`
				TLS      bool   `mapstructure:"tls"`
				CertFile string `mapstructure:"cert_file"`
				KeyFile  string `mapstructure:"key_file"`
			}{Port: 8080, Host: "0.0.0.0", TLS: true, CertFile: "server.crt", KeyFile: "server.key"},
			Fluentd: struct {
				Port           int    `mapstructure:"port"`
				Host           string `mapstructure:"host"`
				TLS            bool   `mapstructure:"tls"`
				CertFile       string `mapstructure:"cert_file"`
				KeyFile        string `mapstructure:"key_file"`
				SharedKey      string `mapstructure:"shared_key"`
				RequireACK     bool   `mapstructure:"require_ack"`
				ChunkSizeLimit int    `mapstructure:"chunk_size_limit"`
			}{Port: 24224, Host: "0.0.0.0"},
			FluentBit: struct {
				Port     int    `mapstructure:"port"`
				Host     string `mapstructure:"host"`
				TLS      bool   `mapstructure:"tls"`
				CertFile string `mapstructure:"cert_file"`
				KeyFile  string `mapstructure:"key_file"`
			}{Port: 24225, Host: "0.0.0.0"},
		},
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
			CircuitBreaker      struct {
				MaxFailures         int `mapstructure:"max_failures"`
				TimeoutSeconds      int `mapstructure:"timeout_seconds"`
				MaxHalfOpenRequests int `mapstructure:"max_half_open_requests"`
			} `mapstructure:"circuit_breaker"`
			RegexTimeoutMs             int           `mapstructure:"regex_timeout_ms"`
			RegexMaxLength             int           `mapstructure:"regex_max_length"`
			RegexEnableComplexityCheck bool          `mapstructure:"regex_enable_complexity_check"`
			EnableNativeSigmaEngine    bool          `mapstructure:"enable_native_sigma_engine"`
			SigmaFieldMappingConfig    string        `mapstructure:"sigma_field_mapping_config"`
			SigmaEngineCacheSize       int           `mapstructure:"sigma_engine_cache_size"`
			SigmaEngineCacheTTL        time.Duration `mapstructure:"sigma_engine_cache_ttl"`
			SigmaEngineCleanupInterval time.Duration `mapstructure:"sigma_engine_cleanup_interval"`
			SigmaRolloutPercentage     int           `mapstructure:"sigma_rollout_percentage"`
			SigmaRolloutEnabledRules   []string      `mapstructure:"sigma_rollout_enabled_rules"`
			SigmaRolloutDisabledRules  []string      `mapstructure:"sigma_rollout_disabled_rules"`
		}{
			ChannelBufferSize:   1000,
			WorkerCount:         10,
			ActionWorkerCount:   5,
			RateLimit:           1000,
			CorrelationStateTTL: 300,
			ActionTimeout:       30,
			CircuitBreaker: struct {
				MaxFailures         int `mapstructure:"max_failures"`
				TimeoutSeconds      int `mapstructure:"timeout_seconds"`
				MaxHalfOpenRequests int `mapstructure:"max_half_open_requests"`
			}{
				MaxFailures:         5,
				TimeoutSeconds:      60,
				MaxHalfOpenRequests: 3,
			},
			RegexTimeoutMs:             500,
			RegexMaxLength:             1000,
			RegexEnableComplexityCheck: true,
			EnableNativeSigmaEngine:    false,
			SigmaFieldMappingConfig:    "config/sigma_field_mappings.yaml",
			SigmaEngineCacheSize:       1000,
			SigmaEngineCacheTTL:        30 * time.Minute,
			SigmaEngineCleanupInterval: 5 * time.Minute,
			SigmaRolloutPercentage:     0,
			SigmaRolloutEnabledRules:   []string{},
			SigmaRolloutDisabledRules:  []string{},
		},
		API: struct {
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
				Login             struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"login"`
				API struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"api"`
				Global struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"global"`
				ExemptIPs []string `mapstructure:"exempt_ips"`
				Redis     struct {
					Enabled  bool   `mapstructure:"enabled"`
					Addr     string `mapstructure:"addr"`
					Password string `mapstructure:"password"`
					DB       int    `mapstructure:"db"`
					PoolSize int    `mapstructure:"pool_size"`
				} `mapstructure:"redis"`
			} `mapstructure:"rate_limit"`
		}{
			Version:              "v1",
			Port:                 8081,
			AllowedOrigins:       []string{"http://localhost:3000"},
			TrustProxy:           false,
			TrustedProxyNetworks: []string{},
			RateLimit: struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
				MaxAuthFailures   int `mapstructure:"max_auth_failures"`
				Login             struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"login"`
				API struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"api"`
				Global struct {
					Limit  int           `mapstructure:"limit"`
					Window time.Duration `mapstructure:"window"`
					Burst  int           `mapstructure:"burst"`
				} `mapstructure:"global"`
				ExemptIPs []string `mapstructure:"exempt_ips"`
				Redis     struct {
					Enabled  bool   `mapstructure:"enabled"`
					Addr     string `mapstructure:"addr"`
					Password string `mapstructure:"password"`
					DB       int    `mapstructure:"db"`
					PoolSize int    `mapstructure:"pool_size"`
				} `mapstructure:"redis"`
			}{RequestsPerSecond: 5, Burst: 10, MaxAuthFailures: 5},
		},
		// TASK #183: Rules.File config removed (database-only)
		Retention: struct {
			Events int `mapstructure:"events"`
			Alerts int `mapstructure:"alerts"`
		}{Events: 30, Alerts: 30},
		Security: struct {
			TLSMinVersion       string        `mapstructure:"tls_min_version"`
			EnableHSTS          bool          `mapstructure:"enable_hsts"`
			EnableCSP           bool          `mapstructure:"enable_csp"`
			EnableXSSProtection bool          `mapstructure:"enable_xss_protection"`
			JSONBodyLimit       int           `mapstructure:"json_body_limit"`
			LoginBodyLimit      int           `mapstructure:"login_body_limit"`
			RegexTimeout        time.Duration `mapstructure:"regex_timeout"`
			Webhooks            struct {
				AllowLocalhost  bool     `mapstructure:"allow_localhost"`
				AllowPrivateIPs bool     `mapstructure:"allow_private_ips"`
				Allowlist       []string `mapstructure:"allowlist"`
				Timeout         int      `mapstructure:"timeout"`
			} `mapstructure:"webhooks"`
			Actions struct {
				AllowLocalhost  bool `mapstructure:"allow_localhost"`
				AllowPrivateIPs bool `mapstructure:"allow_private_ips"`
			} `mapstructure:"actions"`
			PasswordPolicy struct {
				MinLength          int    `mapstructure:"min_length"`
				RequireClasses     int    `mapstructure:"require_classes"`
				MaxHistory         int    `mapstructure:"max_history"`
				ExpirationDays     int    `mapstructure:"expiration_days"`
				WarningDays        int    `mapstructure:"warning_days"`
				CommonPasswordFile string `mapstructure:"common_password_file"`
			} `mapstructure:"password_policy"`
		}{
			TLSMinVersion:       "1.2",
			EnableHSTS:          true,
			EnableCSP:           true,
			EnableXSSProtection: true,
			JSONBodyLimit:       10485760,
			LoginBodyLimit:      1024,
			RegexTimeout:        100 * time.Millisecond,
			Webhooks: struct {
				AllowLocalhost  bool     `mapstructure:"allow_localhost"`
				AllowPrivateIPs bool     `mapstructure:"allow_private_ips"`
				Allowlist       []string `mapstructure:"allowlist"`
				Timeout         int      `mapstructure:"timeout"`
			}{
				AllowLocalhost:  false,
				AllowPrivateIPs: false,
				Allowlist:       []string{},
				Timeout:         10, // Required: 1-60 seconds
			},
			Actions: struct {
				AllowLocalhost  bool `mapstructure:"allow_localhost"`
				AllowPrivateIPs bool `mapstructure:"allow_private_ips"`
			}{
				AllowLocalhost:  false,
				AllowPrivateIPs: false,
			},
			PasswordPolicy: struct {
				MinLength          int    `mapstructure:"min_length"`
				RequireClasses     int    `mapstructure:"require_classes"`
				MaxHistory         int    `mapstructure:"max_history"`
				ExpirationDays     int    `mapstructure:"expiration_days"`
				WarningDays        int    `mapstructure:"warning_days"`
				CommonPasswordFile string `mapstructure:"common_password_file"`
			}{
				MinLength:          12,
				RequireClasses:     3,
				MaxHistory:         5,
				ExpirationDays:     90,
				WarningDays:        14,
				CommonPasswordFile: "data/common-passwords.txt",
			},
		},
	}
}

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig()
	require.NoError(t, err)
	assert.NotNil(t, config)

	// Check defaults
	assert.Equal(t, "mongodb://localhost:27017", config.MongoDB.URI)
	assert.Equal(t, "cerberus", config.MongoDB.Database)
	assert.True(t, config.MongoDB.Enabled)

	assert.Equal(t, 514, config.Listeners.Syslog.Port)
	assert.Equal(t, "0.0.0.0", config.Listeners.Syslog.Host)

	assert.Equal(t, 8081, config.API.Port)
	assert.Equal(t, "v1", config.API.Version)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  newTestConfig(),
			wantErr: false,
		},
		{
			name: "invalid mongodb uri",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.URI = "invalid"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid mongodb uri missing host",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.URI = "mongodb://"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "empty mongodb database",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Database = ""
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid syslog port",
			config: func() Config {
				c := newTestConfig()
				c.Listeners.Syslog.Port = 99999
				return c
			}(),
			wantErr: true,
		},
		{
			name: "empty syslog host",
			config: func() Config {
				c := newTestConfig()
				c.Listeners.Syslog.Host = ""
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid API port",
			config: func() Config {
				c := newTestConfig()
				c.API.Port = 0
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative retention events",
			config: func() Config {
				c := newTestConfig()
				c.Retention.Events = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative retention alerts",
			config: func() Config {
				c := newTestConfig()
				c.Retention.Alerts = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "auth enabled but no password",
			config: func() Config {
				c := newTestConfig()
				c.Auth.Enabled = true
				c.Auth.HashedPassword = ""
				return c
			}(),
			wantErr: true,
		},
		{
			name: "auth enabled but empty username",
			config: func() Config {
				c := newTestConfig()
				c.Auth.Enabled = true
				c.Auth.Username = ""
				c.Auth.HashedPassword = "hashed"
				return c
			}(),
			wantErr: true,
		},
		// TASK #183: Rules.File and CorrelationRules.File validation tests removed
		// Rules are now loaded exclusively from the database.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAndHash(t *testing.T) {
	config := newTestConfig()
	config.Auth.Password = "testpassword"
	config.Auth.BcryptCost = 10

	err := validateAndHash(&config)
	require.NoError(t, err)
	assert.NotEmpty(t, config.Auth.HashedPassword)
	assert.Empty(t, config.Auth.Password) // should be cleared
}
