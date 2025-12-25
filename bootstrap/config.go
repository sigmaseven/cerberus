package bootstrap

import (
	"fmt"
	"os"

	"cerberus/config"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// InitLogger initializes the zap logger with colored console output.
func InitLogger() (*zap.Logger, *zap.SugaredLogger, error) {
	// Create a colored console encoder config
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Colored levels
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder        // Readable timestamps
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder      // Short file paths

	// Create console encoder with colors
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// Write to stdout
	core := zapcore.NewCore(
		consoleEncoder,
		zapcore.AddSync(os.Stdout),
		zapcore.DebugLevel,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return logger, logger.Sugar(), nil
}

// InitConfig loads the application configuration.
func InitConfig(sugar *zap.SugaredLogger) (*config.Config, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to load config: %v\n", err)
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if viper.ConfigFileUsed() == "" {
		sugar.Info("No config file found, using defaults and env vars")
	}

	// Log startup mode
	startupMode := cfg.StartupMode
	if startupMode == "" {
		startupMode = config.StartupModeStrict
	}
	sugar.Infow("Startup mode",
		"mode", string(startupMode),
		"description", func() string {
			if startupMode == config.StartupModeGraceful {
				return "will continue with degraded functionality on non-critical errors"
			}
			return "will fail fast on any initialization error"
		}())

	// Log data paths for visibility
	sugar.Infow("Data paths configuration",
		"data_dir", cfg.GetDataDir(),
		"sqlite_path", cfg.GetSQLitePath(),
		"feeds_dir", cfg.GetFeedsDir(),
		"ml_dir", cfg.GetMLDir())

	sugar.Infow("Config loaded",
		"clickhouse_addr", cfg.ClickHouse.Addr,
		"syslog_port", cfg.Listeners.Syslog.Port)

	return cfg, nil
}

// DataDirectoriesFromConfig creates DataDirectories from configuration.
func DataDirectoriesFromConfig(cfg *config.Config) DataDirectories {
	return DataDirectories{
		Base:   cfg.GetDataDir(),
		Feeds:  cfg.GetFeedsDir(),
		ML:     cfg.GetMLDir(),
		SQLite: cfg.GetSQLitePath(),
	}
}
