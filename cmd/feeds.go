// Package cmd provides command-line interface commands for Cerberus SIEM.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/sigma/feeds"
	"cerberus/storage"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// CLI output formatters
var (
	successColor = color.New(color.FgGreen, color.Bold)
	errorColor   = color.New(color.FgRed, color.Bold)
	warningColor = color.New(color.FgYellow)
	infoColor    = color.New(color.FgCyan)
	headerColor  = color.New(color.FgBlue, color.Bold)
)

// Global flags for feeds commands
var (
	outputJSON bool
	configFile string
	noColor    bool
	quiet      bool
)

// Security constants
const (
	maxImportFileSize = 10 * 1024 * 1024 // 10MB - protection against memory exhaustion
	defaultTimeout    = 5 * time.Minute  // Default context timeout for CLI operations
)

// validateFilePath validates a file path to prevent path traversal attacks.
// Security consideration: This function prevents directory traversal attacks by:
// 1. URL decoding to prevent encoding bypass attacks
// 2. Rejecting paths containing ".." sequences (both in original and decoded)
// 3. Cleaning the path using filepath.Clean
// 4. Ensuring the absolute path doesn't escape the current working directory
func validateFilePath(filename string) error {
	// Decode URL encoding to prevent bypass (e.g., %2e%2e%2f)
	decoded, err := url.QueryUnescape(filename)
	if err != nil {
		// If decoding fails, use original filename for safety
		decoded = filename
	}

	// Check for path traversal patterns in both original and decoded
	if strings.Contains(decoded, "..") || strings.Contains(filename, "..") {
		return fmt.Errorf("path traversal detected: '..' not allowed in file path")
	}

	// Clean the decoded path to normalize it
	cleanPath := filepath.Clean(decoded)

	// Get absolute path to verify it's within current directory
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Get current working directory
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Ensure the absolute path is within or equals the working directory
	// This prevents paths that escape after normalization
	if !strings.HasPrefix(absPath, workDir) {
		return fmt.Errorf("path escapes current directory")
	}

	return nil
}

// NewFeedsCmd creates the root feeds command with all subcommands.
func NewFeedsCmd() *cobra.Command {
	feedsCmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage SIGMA rule feeds",
		Long: `Manage SIGMA rule feeds including creation, synchronization, and monitoring.

Feeds provide a way to automatically import and update detection rules from external sources
such as Git repositories, filesystems, or HTTP endpoints.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if noColor {
				color.NoColor = true
			}
		},
	}

	// Add persistent flags
	feedsCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	feedsCmd.PersistentFlags().StringVar(&configFile, "config", "config.yaml", "Config file path")
	feedsCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	feedsCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Suppress non-essential output")

	// Add subcommands
	feedsCmd.AddCommand(newListCmd())
	feedsCmd.AddCommand(newShowCmd())
	feedsCmd.AddCommand(newAddCmd())
	feedsCmd.AddCommand(newUpdateCmd())
	feedsCmd.AddCommand(newDeleteCmd())
	feedsCmd.AddCommand(newSyncCmd())
	feedsCmd.AddCommand(newSyncAllCmd())
	feedsCmd.AddCommand(newHistoryCmd())
	feedsCmd.AddCommand(newTestCmd())
	feedsCmd.AddCommand(newEnableCmd())
	feedsCmd.AddCommand(newDisableCmd())
	feedsCmd.AddCommand(newImportCmd())
	feedsCmd.AddCommand(newExportCmd())
	feedsCmd.AddCommand(newTemplatesCmd())

	return feedsCmd
}

// newListCmd creates the 'list' subcommand
func newListCmd() *cobra.Command {
	var showDisabled bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all feeds",
		Long:    "Display a table of all configured feeds with their status and statistics.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedsList, err := mgr.ListFeeds(ctx)
			if err != nil {
				return fmt.Errorf("failed to list feeds: %w", err)
			}

			// Filter disabled if needed
			if !showDisabled {
				var filtered []*feeds.RuleFeed
				for _, f := range feedsList {
					if f.Enabled {
						filtered = append(filtered, f)
					}
				}
				feedsList = filtered
			}

			if outputJSON {
				return outputAsJSON(feedsList)
			}

			renderFeedsTable(feedsList)
			return nil
		},
	}

	cmd.Flags().BoolVar(&showDisabled, "all", false, "Show disabled feeds")

	return cmd
}

// newShowCmd creates the 'show' subcommand
func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <feed-id>",
		Short: "Show detailed feed information",
		Long:  "Display detailed information about a specific feed including configuration and statistics.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feed, err := mgr.GetFeed(ctx, args[0])
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			if outputJSON {
				return outputAsJSON(feed)
			}

			renderFeedDetails(feed)
			return nil
		},
	}
}

// newAddCmd creates the 'add' subcommand
func newAddCmd() *cobra.Command {
	var (
		name            string
		description     string
		feedType        string
		url             string
		branch          string
		path            string
		autoEnable      bool
		priority        int
		updateStrategy  string
		updateSchedule  string
		interactive     bool
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new feed",
		Long:  "Add a new SIGMA rule feed. Can be run interactively or with flags.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feed := &feeds.RuleFeed{
				ID:              uuid.New().String(),
				Name:            name,
				Description:     description,
				Type:            feedType,
				URL:             url,
				Branch:          branch,
				Path:            path,
				Enabled:         true,
				AutoEnableRules: autoEnable,
				Priority:        priority,
				UpdateStrategy:  updateStrategy,
				UpdateSchedule:  updateSchedule,
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}

			// Interactive mode
			if interactive || (name == "" && !cmd.Flags().Changed("name")) {
				if err := promptFeedConfiguration(feed); err != nil {
					return fmt.Errorf("interactive input failed: %w", err)
				}
			}

			// Validate required fields
			if feed.Name == "" {
				return fmt.Errorf("feed name is required (use --name or --interactive)")
			}
			if feed.Type == "" {
				return fmt.Errorf("feed type is required (use --type or --interactive)")
			}

			// Create the feed
			if err := mgr.CreateFeed(ctx, feed); err != nil {
				return fmt.Errorf("failed to create feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed created successfully: %s (ID: %s)\n", feed.Name, feed.ID)
			}

			if outputJSON {
				return outputAsJSON(feed)
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&name, "name", "", "Feed name")
	cmd.Flags().StringVar(&description, "description", "", "Feed description")
	cmd.Flags().StringVar(&feedType, "type", "git", "Feed type (git, filesystem, http)")
	cmd.Flags().StringVar(&url, "url", "", "Feed URL (for git/http feeds)")
	cmd.Flags().StringVar(&branch, "branch", "main", "Git branch (for git feeds)")
	cmd.Flags().StringVar(&path, "path", "", "Local path (for filesystem feeds)")
	cmd.Flags().BoolVar(&autoEnable, "auto-enable", false, "Auto-enable imported rules")
	cmd.Flags().IntVar(&priority, "priority", 100, "Feed priority (higher = higher precedence)")
	cmd.Flags().StringVar(&updateStrategy, "update-strategy", "manual", "Update strategy (manual, startup, scheduled)")
	cmd.Flags().StringVar(&updateSchedule, "update-schedule", "", "Update schedule (cron format)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode")

	return cmd
}

// newUpdateCmd creates the 'update' subcommand
func newUpdateCmd() *cobra.Command {
	var (
		name           string
		description    string
		enabled        *bool
		autoEnable     *bool
		priority       *int
		updateStrategy string
		updateSchedule string
	)

	cmd := &cobra.Command{
		Use:   "update <feed-id>",
		Short: "Update feed configuration",
		Long:  "Update configuration settings for an existing feed.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			// Get existing feed
			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			// Update fields if provided
			if cmd.Flags().Changed("name") {
				feed.Name = name
			}
			if cmd.Flags().Changed("description") {
				feed.Description = description
			}
			if cmd.Flags().Changed("enabled") && enabled != nil {
				feed.Enabled = *enabled
			}
			if cmd.Flags().Changed("auto-enable") && autoEnable != nil {
				feed.AutoEnableRules = *autoEnable
			}
			if cmd.Flags().Changed("priority") && priority != nil {
				feed.Priority = *priority
			}
			if cmd.Flags().Changed("update-strategy") {
				feed.UpdateStrategy = updateStrategy
			}
			if cmd.Flags().Changed("update-schedule") {
				feed.UpdateSchedule = updateSchedule
			}

			// Update the feed
			if err := mgr.UpdateFeed(ctx, feedID, feed); err != nil {
				return fmt.Errorf("failed to update feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed updated successfully: %s\n", feed.Name)
			}

			if outputJSON {
				return outputAsJSON(feed)
			}

			return nil
		},
	}

	// Add flags - using pointers to detect if flag was set
	cmd.Flags().StringVar(&name, "name", "", "Feed name")
	cmd.Flags().StringVar(&description, "description", "", "Feed description")
	enabled = cmd.Flags().Bool("enabled", true, "Enable/disable feed")
	autoEnable = cmd.Flags().Bool("auto-enable", false, "Auto-enable imported rules")
	priority = cmd.Flags().Int("priority", 100, "Feed priority")
	cmd.Flags().StringVar(&updateStrategy, "update-strategy", "", "Update strategy")
	cmd.Flags().StringVar(&updateSchedule, "update-schedule", "", "Update schedule")

	return cmd
}

// newDeleteCmd creates the 'delete' subcommand
func newDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <feed-id>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a feed",
		Long:    "Delete a feed and optionally its imported rules.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			// Get feed info for confirmation
			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			// Confirm deletion unless force flag is set
			if !force {
				fmt.Printf("Are you sure you want to delete feed '%s' (ID: %s)? [y/N]: ", feed.Name, feedID)
				var response string
				// BLOCKER-3: Check error from Scanln and handle EOF gracefully
				_, err = fmt.Scanln(&response)
				if err != nil {
					// Handle EOF or other input errors gracefully
					if err.Error() == "unexpected newline" || err.Error() == "EOF" {
						// Treat empty input or EOF as "no"
						fmt.Println("\nDeletion cancelled")
						return nil
					}
					return fmt.Errorf("failed to read confirmation: %w", err)
				}
				if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
					fmt.Println("Deletion cancelled")
					return nil
				}
			}

			// Delete the feed
			if err := mgr.DeleteFeed(ctx, feedID); err != nil {
				return fmt.Errorf("failed to delete feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed deleted successfully: %s\n", feed.Name)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

// newSyncCmd creates the 'sync' subcommand
func newSyncCmd() *cobra.Command {
	var showProgress bool

	cmd := &cobra.Command{
		Use:   "sync <feed-id>",
		Short: "Synchronize a feed",
		Long:  "Synchronize a specific feed to import or update rules.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			// Get feed info
			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			if !quiet {
				infoColor.Printf("Syncing feed: %s\n", feed.Name)
			}

			// Show progress spinner if requested
			var s *spinner.Spinner
			if showProgress && !outputJSON && !quiet {
				s = spinner.New(spinner.CharSets[14], 100*time.Millisecond)
				s.Suffix = " Synchronizing feed..."
				s.Start()
			}

			// Perform sync
			result, err := mgr.SyncFeed(ctx, feedID)

			if s != nil {
				s.Stop()
			}

			if err != nil {
				return fmt.Errorf("failed to sync feed: %w", err)
			}

			if outputJSON {
				return outputAsJSON(result)
			}

			renderSyncResult(result)
			return nil
		},
	}

	cmd.Flags().BoolVar(&showProgress, "progress", true, "Show progress indicator")

	return cmd
}

// newSyncAllCmd creates the 'sync-all' subcommand
func newSyncAllCmd() *cobra.Command {
	var showProgress bool

	cmd := &cobra.Command{
		Use:   "sync-all",
		Short: "Synchronize all enabled feeds",
		Long:  "Synchronize all enabled feeds to import or update rules.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			if !quiet {
				infoColor.Println("Syncing all enabled feeds...")
			}

			// Show progress spinner if requested
			var s *spinner.Spinner
			if showProgress && !outputJSON && !quiet {
				s = spinner.New(spinner.CharSets[14], 100*time.Millisecond)
				s.Suffix = " Synchronizing feeds..."
				s.Start()
			}

			// Perform sync
			results, err := mgr.SyncAllFeeds(ctx)

			if s != nil {
				s.Stop()
			}

			if err != nil {
				return fmt.Errorf("failed to sync feeds: %w", err)
			}

			if outputJSON {
				return outputAsJSON(results)
			}

			// Display results for each feed
			for _, result := range results {
				renderSyncResult(result)
				fmt.Println()
			}

			// Summary
			successCount := 0
			for _, r := range results {
				if r.Success {
					successCount++
				}
			}

			if !quiet {
				if successCount == len(results) {
					successColor.Printf("✓ All %d feeds synchronized successfully\n", successCount)
				} else {
					warningColor.Printf("⚠ %d/%d feeds synchronized successfully\n", successCount, len(results))
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showProgress, "progress", true, "Show progress indicator")

	return cmd
}

// newHistoryCmd creates the 'history' subcommand
func newHistoryCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "history <feed-id>",
		Short: "Show feed synchronization history",
		Long:  "Display the synchronization history for a specific feed.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			history, err := mgr.GetSyncHistory(ctx, feedID, limit)
			if err != nil {
				return fmt.Errorf("failed to get sync history: %w", err)
			}

			if outputJSON {
				return outputAsJSON(history)
			}

			renderSyncHistory(history)
			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 10, "Number of history entries to show")

	return cmd
}

// newTestCmd creates the 'test' subcommand
func newTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <feed-id>",
		Short: "Test feed connectivity",
		Long:  "Test the connection to a feed source without performing a full sync.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			// Get feed info
			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			if !quiet {
				infoColor.Printf("Testing connection to feed: %s\n", feed.Name)
			}

			// Test connection
			if err := mgr.TestFeedConnection(ctx, feedID); err != nil {
				errorColor.Printf("✗ Connection test failed: %v\n", err)
				return err
			}

			successColor.Println("✓ Connection test successful")
			return nil
		},
	}
}

// newEnableCmd creates the 'enable' subcommand
func newEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <feed-id>",
		Short: "Enable a feed",
		Long:  "Enable a disabled feed.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			feed.Enabled = true
			if err := mgr.UpdateFeed(ctx, feedID, feed); err != nil {
				return fmt.Errorf("failed to enable feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed enabled: %s\n", feed.Name)
			}

			return nil
		},
	}
}

// newDisableCmd creates the 'disable' subcommand
func newDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <feed-id>",
		Short: "Disable a feed",
		Long:  "Disable an enabled feed.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedID := args[0]

			feed, err := mgr.GetFeed(ctx, feedID)
			if err != nil {
				return fmt.Errorf("failed to get feed: %w", err)
			}

			feed.Enabled = false
			if err := mgr.UpdateFeed(ctx, feedID, feed); err != nil {
				return fmt.Errorf("failed to disable feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed disabled: %s\n", feed.Name)
			}

			return nil
		},
	}
}

// newImportCmd creates the 'import' subcommand
func newImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import feeds from YAML file",
		Long:  "Import multiple feeds from a YAML configuration file.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			filename := args[0]

			// BLOCKER-1: Validate file path to prevent path traversal attacks
			if err := validateFilePath(filename); err != nil {
				return fmt.Errorf("invalid file path: %w", err)
			}

			// BLOCKER-5: Check file size before reading to prevent memory exhaustion
			fileInfo, err := os.Stat(filename)
			if err != nil {
				return fmt.Errorf("failed to stat file: %w", err)
			}
			if fileInfo.Size() > maxImportFileSize {
				return fmt.Errorf("file too large: maximum size is %d bytes (%d MB), got %d bytes",
					maxImportFileSize, maxImportFileSize/(1024*1024), fileInfo.Size())
			}

			// Read file
			data, err := os.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			// Parse YAML
			var feedsConfig struct {
				Feeds []feeds.RuleFeed `yaml:"feeds"`
			}
			if err := yaml.Unmarshal(data, &feedsConfig); err != nil {
				return fmt.Errorf("failed to parse YAML: %w", err)
			}

			// Import each feed
			imported := 0
			failed := 0
			for _, feed := range feedsConfig.Feeds {
				// Generate ID if not provided
				if feed.ID == "" {
					feed.ID = uuid.New().String()
				}

				if err := mgr.CreateFeed(ctx, &feed); err != nil {
					errorColor.Printf("✗ Failed to import feed %s: %v\n", feed.Name, err)
					failed++
				} else {
					if !quiet {
						successColor.Printf("✓ Imported feed: %s\n", feed.Name)
					}
					imported++
				}
			}

			if !quiet {
				fmt.Printf("\nImported %d feeds, %d failed\n", imported, failed)
			}

			return nil
		},
	}
}

// newExportCmd creates the 'export' subcommand
func newExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export [file]",
		Short: "Export feeds to YAML file",
		Long:  "Export all feeds to a YAML configuration file. If no file is specified, output to stdout.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			feedsList, err := mgr.ListFeeds(ctx)
			if err != nil {
				return fmt.Errorf("failed to list feeds: %w", err)
			}

			// Convert to slice of values (not pointers)
			feedValues := make([]feeds.RuleFeed, len(feedsList))
			for i, f := range feedsList {
				feedValues[i] = *f
			}

			// Create config structure
			feedsConfig := struct {
				Feeds []feeds.RuleFeed `yaml:"feeds"`
			}{
				Feeds: feedValues,
			}

			// Marshal to YAML
			data, err := yaml.Marshal(feedsConfig)
			if err != nil {
				return fmt.Errorf("failed to marshal YAML: %w", err)
			}

			// Output to file or stdout
			if len(args) > 0 {
				filename := args[0]

				// BLOCKER-1: Validate file path to prevent path traversal attacks
				if err := validateFilePath(filename); err != nil {
					return fmt.Errorf("invalid file path: %w", err)
				}

				if err := os.WriteFile(filename, data, 0644); err != nil {
					return fmt.Errorf("failed to write file: %w", err)
				}
				if !quiet {
					successColor.Printf("✓ Exported %d feeds to %s\n", len(feedsList), filename)
				}
			} else {
				fmt.Print(string(data))
			}

			return nil
		},
	}
}

// initFeedManager initializes the feed manager with required dependencies.
// Returns the manager and a cleanup function.
func initFeedManager(ctx context.Context) (*feeds.Manager, func(), error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	sugar := logger.Sugar()

	// Initialize SQLite storage
	dbPath := "./data/cerberus.db"
	if cfg.DataPaths.SQLitePath != "" {
		dbPath = cfg.DataPaths.SQLitePath
	}

	sqlite, err := storage.NewSQLite(dbPath, sugar)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize SQLite: %w", err)
	}

	// Initialize feed storage
	feedStorage, err := storage.NewSQLiteFeedStorage(sqlite, sugar)
	if err != nil {
		sqlite.Close()
		return nil, nil, fmt.Errorf("failed to initialize feed storage: %w", err)
	}

	// Initialize rule storage - using 30 second timeout for regex operations
	regexTimeout := 30 * time.Second
	if cfg.Engine.RegexTimeoutMs > 0 {
		regexTimeout = time.Duration(cfg.Engine.RegexTimeoutMs) * time.Millisecond
	}
	ruleStorage := storage.NewSQLiteRuleStorage(sqlite, regexTimeout, sugar)

	// Initialize feed manager
	workingDir := "./data/feeds"
	if cfg.DataPaths.FeedsDir != "" {
		workingDir = cfg.DataPaths.FeedsDir
	}

	manager, err := feeds.NewManager(feedStorage, &ruleStorageAdapter{ruleStorage}, workingDir, sugar)
	if err != nil {
		sqlite.Close()
		return nil, nil, fmt.Errorf("failed to create feed manager: %w", err)
	}

	// Cleanup function
	// BLOCKER-4: Log warnings for cleanup errors instead of ignoring them
	cleanup := func() {
		if err := sqlite.Close(); err != nil {
			sugar.Warnf("Failed to close SQLite connection during cleanup: %v", err)
		}
		if err := logger.Sync(); err != nil {
			// Sync errors on stderr are common and can be ignored in most cases
			// but we log them for debugging purposes
			sugar.Debugf("Failed to sync logger during cleanup: %v", err)
		}
	}

	return manager, cleanup, nil
}

// ruleStorageAdapter adapts SQLiteRuleStorage to feeds.RuleStorage interface
// by adding context parameters to methods
type ruleStorageAdapter struct {
	storage *storage.SQLiteRuleStorage
}

func (a *ruleStorageAdapter) CreateRule(ctx context.Context, rule *core.Rule) error {
	return a.storage.CreateRule(rule)
}

func (a *ruleStorageAdapter) GetRuleByID(ctx context.Context, id string) (*core.Rule, error) {
	return a.storage.GetRule(id)
}

func (a *ruleStorageAdapter) UpdateRule(ctx context.Context, rule *core.Rule) error {
	return a.storage.UpdateRule(rule.ID, rule)
}

// outputAsJSON outputs data as JSON to stdout.
func outputAsJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// newTemplatesCmd creates the 'templates' subcommand for template management
func newTemplatesCmd() *cobra.Command {
	templatesCmd := &cobra.Command{
		Use:     "templates",
		Aliases: []string{"template", "tpl"},
		Short:   "Manage feed templates",
		Long: `Manage feed templates for quick feed creation.

Templates provide pre-configured settings for popular SIGMA rule sources
like SigmaHQ, SOC Prime, and community feeds.`,
	}

	templatesCmd.AddCommand(newTemplatesListCmd())
	templatesCmd.AddCommand(newTemplatesShowCmd())
	templatesCmd.AddCommand(newTemplatesApplyCmd())

	return templatesCmd
}

// newTemplatesListCmd creates the 'templates list' subcommand
func newTemplatesListCmd() *cobra.Command {
	var (
		filterTag  string
		filterType string
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available feed templates",
		Long:    "Display all available feed templates with their details.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create template manager
			tm, err := feeds.NewTemplateManager()
			if err != nil {
				return fmt.Errorf("failed to initialize template manager: %w", err)
			}

			var templates []feeds.FeedTemplate

			// Apply filters
			if filterTag != "" {
				templates = tm.GetTemplatesByTag(filterTag)
			} else if filterType != "" {
				templates = tm.GetTemplatesByType(filterType)
			} else {
				templates = tm.ListTemplates()
			}

			if outputJSON {
				return outputAsJSON(templates)
			}

			renderTemplatesTable(templates)
			return nil
		},
	}

	cmd.Flags().StringVar(&filterTag, "tag", "", "Filter by tag")
	cmd.Flags().StringVar(&filterType, "type", "", "Filter by feed type")

	return cmd
}

// newTemplatesShowCmd creates the 'templates show' subcommand
func newTemplatesShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <template-id>",
		Short: "Show template details",
		Long:  "Display detailed information about a specific template.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tm, err := feeds.NewTemplateManager()
			if err != nil {
				return fmt.Errorf("failed to initialize template manager: %w", err)
			}

			templateID := args[0]
			template := tm.GetTemplate(templateID)
			if template == nil {
				return fmt.Errorf("template not found: %s", templateID)
			}

			if outputJSON {
				return outputAsJSON(template)
			}

			renderTemplateDetails(template)
			return nil
		},
	}
}

// newTemplatesApplyCmd creates the 'templates apply' subcommand
func newTemplatesApplyCmd() *cobra.Command {
	var (
		templateID     string
		name           string
		enabled        bool
		autoEnable     bool
		priority       int
		updateStrategy string
		updateSchedule string
		branch         string
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Create feed from template",
		Long: `Create a new feed from a template with optional overrides.

Example:
  cerberus feeds templates apply --template=sigmahq-core --name="My Rules"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// BLOCKER-6: Add context timeout for operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			mgr, cleanup, err := initFeedManager(ctx)
			if err != nil {
				return err
			}
			defer cleanup()

			// Validate required fields
			if templateID == "" {
				return fmt.Errorf("template ID is required (use --template)")
			}
			if name == "" {
				return fmt.Errorf("feed name is required (use --name)")
			}

			// Create template manager
			tm, err := feeds.NewTemplateManager()
			if err != nil {
				return fmt.Errorf("failed to initialize template manager: %w", err)
			}

			// Prepare overrides
			overrides := map[string]interface{}{
				"name":    name,
				"enabled": enabled,
			}

			if cmd.Flags().Changed("auto-enable") {
				overrides["auto_enable_rules"] = autoEnable
			}
			if cmd.Flags().Changed("priority") {
				overrides["priority"] = priority
			}
			if cmd.Flags().Changed("update-strategy") {
				overrides["update_strategy"] = updateStrategy
			}
			if cmd.Flags().Changed("update-schedule") {
				overrides["update_schedule"] = updateSchedule
			}
			if cmd.Flags().Changed("branch") {
				overrides["branch"] = branch
			}

			// Apply template
			feed, err := tm.ApplyTemplate(templateID, overrides)
			if err != nil {
				return fmt.Errorf("failed to apply template: %w", err)
			}

			// Create the feed
			if err := mgr.CreateFeed(ctx, feed); err != nil {
				return fmt.Errorf("failed to create feed: %w", err)
			}

			if !quiet {
				successColor.Printf("✓ Feed created from template '%s': %s (ID: %s)\n",
					templateID, feed.Name, feed.ID)
			}

			if outputJSON {
				return outputAsJSON(feed)
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&templateID, "template", "", "Template ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Feed name (required)")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "Enable feed")
	cmd.Flags().BoolVar(&autoEnable, "auto-enable", false, "Auto-enable imported rules")
	cmd.Flags().IntVar(&priority, "priority", 0, "Feed priority (0 = use template default)")
	cmd.Flags().StringVar(&updateStrategy, "update-strategy", "", "Update strategy (manual, startup, scheduled)")
	cmd.Flags().StringVar(&updateSchedule, "update-schedule", "", "Update schedule (cron format)")
	cmd.Flags().StringVar(&branch, "branch", "", "Git branch (override template)")

	cmd.MarkFlagRequired("template")
	cmd.MarkFlagRequired("name")

	return cmd
}
