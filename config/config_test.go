package config

import (
	"testing"

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
			SkipOnError bool `mapstructure:"skip_on_error"`
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
		},
		API: struct {
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
		}{
			Version:        "v1",
			Port:           8081,
			AllowedOrigins: []string{"http://localhost:3000"},
			TrustProxy:     false,
			RateLimit: struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			}{RequestsPerSecond: 5, Burst: 10},
		},
		Rules: struct {
			File string `mapstructure:"file"`
		}{File: "../rules.json"},
		Retention: struct {
			Events int `mapstructure:"events"`
			Alerts int `mapstructure:"alerts"`
		}{Events: 30, Alerts: 30},
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
		{
			name: "mongodb disabled, empty rules file",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Enabled = false
				c.Rules.File = ""
				return c
			}(),
			wantErr: true,
		},
		{
			name: "mongodb disabled, invalid rules file suffix",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Enabled = false
				c.Rules.File = "rules.txt"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "mongodb disabled, rules file does not exist",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Enabled = false
				c.Rules.File = "nonexistent.json"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "mongodb disabled, invalid correlation rules file suffix",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Enabled = false
				c.CorrelationRules.File = "corr.txt"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "mongodb disabled, correlation rules file does not exist",
			config: func() Config {
				c := newTestConfig()
				c.MongoDB.Enabled = false
				c.CorrelationRules.File = "nonexistent_corr.json"
				return c
			}(),
			wantErr: true,
		},
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
