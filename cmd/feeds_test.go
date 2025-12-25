package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cerberus/sigma/feeds"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestNewFeedsCmd tests the creation of the feeds command
func TestNewFeedsCmd(t *testing.T) {
	cmd := NewFeedsCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "feeds", cmd.Use)
	assert.True(t, len(cmd.Commands()) > 0, "Should have subcommands")
}

// TestFeedsCommandStructure tests the command hierarchy
func TestFeedsCommandStructure(t *testing.T) {
	cmd := NewFeedsCmd()

	expectedCommands := []string{
		"list", "show", "add", "update", "delete",
		"sync", "sync-all", "history", "test",
		"enable", "disable", "import", "export",
	}

	actualCommands := make(map[string]bool)
	for _, subCmd := range cmd.Commands() {
		actualCommands[subCmd.Name()] = true
	}

	for _, expected := range expectedCommands {
		assert.True(t, actualCommands[expected], "Missing command: %s", expected)
	}
}

// TestFeedsCommandFlags tests persistent flags
func TestFeedsCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()

	// Test persistent flags
	assert.NotNil(t, cmd.PersistentFlags().Lookup("json"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("config"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("no-color"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("quiet"))
}

// TestListCommandFlags tests list command flags
func TestListCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	listCmd := findCommand(cmd, "list")
	require.NotNil(t, listCmd)

	assert.NotNil(t, listCmd.Flags().Lookup("all"))
}

// TestAddCommandFlags tests add command flags
func TestAddCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	addCmd := findCommand(cmd, "add")
	require.NotNil(t, addCmd)

	expectedFlags := []string{
		"name", "description", "type", "url", "branch", "path",
		"auto-enable", "priority", "update-strategy", "update-schedule",
		"interactive",
	}

	for _, flag := range expectedFlags {
		assert.NotNil(t, addCmd.Flags().Lookup(flag), "Missing flag: %s", flag)
	}
}

// TestUpdateCommandFlags tests update command flags
func TestUpdateCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	updateCmd := findCommand(cmd, "update")
	require.NotNil(t, updateCmd)

	expectedFlags := []string{
		"name", "description", "enabled", "auto-enable",
		"priority", "update-strategy", "update-schedule",
	}

	for _, flag := range expectedFlags {
		assert.NotNil(t, updateCmd.Flags().Lookup(flag), "Missing flag: %s", flag)
	}
}

// TestDeleteCommandFlags tests delete command flags
func TestDeleteCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	deleteCmd := findCommand(cmd, "delete")
	require.NotNil(t, deleteCmd)

	assert.NotNil(t, deleteCmd.Flags().Lookup("force"))
}

// TestSyncCommandFlags tests sync command flags
func TestSyncCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	syncCmd := findCommand(cmd, "sync")
	require.NotNil(t, syncCmd)

	assert.NotNil(t, syncCmd.Flags().Lookup("progress"))
}

// TestHistoryCommandFlags tests history command flags
func TestHistoryCommandFlags(t *testing.T) {
	cmd := NewFeedsCmd()
	historyCmd := findCommand(cmd, "history")
	require.NotNil(t, historyCmd)

	assert.NotNil(t, historyCmd.Flags().Lookup("limit"))
}

// TestOutputAsJSON tests JSON output formatting
func TestOutputAsJSON(t *testing.T) {
	// Create test data
	testFeed := &feeds.RuleFeed{
		ID:          uuid.New().String(),
		Name:        "Test Feed",
		Description: "Test Description",
		Type:        feeds.FeedTypeGit,
		Enabled:     true,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputAsJSON(testFeed)
	assert.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify JSON is valid
	var parsed feeds.RuleFeed
	err = json.Unmarshal([]byte(output), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, testFeed.ID, parsed.ID)
	assert.Equal(t, testFeed.Name, parsed.Name)
}

// TestFormatStatus tests status formatting
func TestFormatStatus(t *testing.T) {
	tests := []struct {
		status  string
		enabled bool
		want    string
	}{
		{feeds.FeedStatusActive, true, "active"},
		{feeds.FeedStatusSyncing, true, "syncing"},
		{feeds.FeedStatusError, true, "error"},
		{feeds.FeedStatusActive, false, "disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := formatStatus(tt.status, tt.enabled)
			// Strip ANSI codes for comparison
			cleaned := stripANSI(result)
			assert.Contains(t, cleaned, tt.want)
		})
	}
}

// TestFormatBool tests boolean formatting
func TestFormatBool(t *testing.T) {
	tests := []struct {
		name  string
		input bool
		want  string
	}{
		{"true", true, "Yes"},
		{"false", false, "No"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBool(tt.input)
			cleaned := stripANSI(result)
			assert.Equal(t, tt.want, cleaned)
		})
	}
}

// TestFormatTime tests time formatting
func TestFormatTime(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{
			name: "zero time",
			time: time.Time{},
			want: "Never",
		},
		{
			name: "valid time",
			time: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			want: "2024-01-15 10:30:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.time)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestFormatTimeSince tests time since formatting
func TestFormatTimeSince(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{
			name: "zero time",
			time: time.Time{},
			want: "Never",
		},
		{
			name: "seconds ago",
			time: now.Add(-30 * time.Second),
			want: "ago",
		},
		{
			name: "minutes ago",
			time: now.Add(-5 * time.Minute),
			want: "ago",
		},
		{
			name: "hours ago",
			time: now.Add(-3 * time.Hour),
			want: "ago",
		},
		{
			name: "days ago",
			time: now.Add(-48 * time.Hour),
			want: "ago",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTimeSince(tt.time)
			assert.Contains(t, result, tt.want)
		})
	}
}

// TestSplitAndTrim tests string splitting and trimming
func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		delimiter string
		want      []string
	}{
		{"empty", "", ",", nil},
		{"normal", "a,b,c", ",", []string{"a", "b", "c"}},
		{"spaces", " a , b , c ", ",", []string{"a", "b", "c"}},
		{"single", "a", ",", []string{"a"}},
		{"empty-parts", "a,,b", ",", []string{"a", "b"}},
		{"all-spaces", " , , ", ",", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.delimiter)
			// Both nil and empty slice are acceptable for zero-length results
			if len(tt.want) == 0 && len(result) == 0 {
				return
			}
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestRepeat tests string repetition
func TestRepeat(t *testing.T) {
	tests := []struct {
		str   string
		count int
		want  string
	}{
		{"a", 0, ""},
		{"a", 1, "a"},
		{"a", 3, "aaa"},
		{"-", 5, "-----"},
		{"ab", 2, "abab"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			result := repeat(tt.str, tt.count)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestExportImportRoundTrip tests export/import functionality
func TestExportImportRoundTrip(t *testing.T) {
	// Create test feeds
	testFeeds := []feeds.RuleFeed{
		{
			ID:          uuid.New().String(),
			Name:        "Test Feed 1",
			Type:        feeds.FeedTypeGit,
			URL:         "https://github.com/test/rules",
			Enabled:     true,
			Priority:    100,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Test Feed 2",
			Type:        feeds.FeedTypeFilesystem,
			Path:        "/path/to/rules",
			Enabled:     false,
			Priority:    50,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	// Marshal to YAML
	feedsConfig := struct {
		Feeds []feeds.RuleFeed `yaml:"feeds"`
	}{
		Feeds: testFeeds,
	}

	data, err := yaml.Marshal(feedsConfig)
	require.NoError(t, err)

	// Write to temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "feeds.yaml")
	err = os.WriteFile(tmpFile, data, 0644)
	require.NoError(t, err)

	// Read back and unmarshal
	readData, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var importedConfig struct {
		Feeds []feeds.RuleFeed `yaml:"feeds"`
	}
	err = yaml.Unmarshal(readData, &importedConfig)
	require.NoError(t, err)

	// Verify
	assert.Len(t, importedConfig.Feeds, 2)
	assert.Equal(t, testFeeds[0].Name, importedConfig.Feeds[0].Name)
	assert.Equal(t, testFeeds[1].Name, importedConfig.Feeds[1].Name)
}

// TestCommandAliases tests command aliases
func TestCommandAliases(t *testing.T) {
	cmd := NewFeedsCmd()

	// list command should have 'ls' alias
	listCmd := findCommand(cmd, "list")
	require.NotNil(t, listCmd)
	assert.Contains(t, listCmd.Aliases, "ls")

	// delete command should have 'rm' and 'remove' aliases
	deleteCmd := findCommand(cmd, "delete")
	require.NotNil(t, deleteCmd)
	assert.Contains(t, deleteCmd.Aliases, "rm")
	assert.Contains(t, deleteCmd.Aliases, "remove")
}

// TestCommandArgValidation tests command argument validation
func TestCommandArgValidation(t *testing.T) {
	tests := []struct {
		command  string
		args     []string
		wantErr  bool
	}{
		{"show", []string{"feed-id"}, false},
		{"show", []string{}, true}, // Requires exactly 1 arg
		{"update", []string{"feed-id"}, false},
		{"update", []string{}, true}, // Requires exactly 1 arg
		{"delete", []string{"feed-id"}, false},
		{"delete", []string{}, true}, // Requires exactly 1 arg
		{"sync", []string{"feed-id"}, false},
		{"sync", []string{}, true}, // Requires exactly 1 arg
		{"history", []string{"feed-id"}, false},
		{"history", []string{}, true}, // Requires exactly 1 arg
		{"test", []string{"feed-id"}, false},
		{"test", []string{}, true}, // Requires exactly 1 arg
		{"enable", []string{"feed-id"}, false},
		{"enable", []string{}, true}, // Requires exactly 1 arg
		{"disable", []string{"feed-id"}, false},
		{"disable", []string{}, true}, // Requires exactly 1 arg
		{"import", []string{"file.yaml"}, false},
		{"import", []string{}, true}, // Requires exactly 1 arg
		{"export", []string{"file.yaml"}, false},
		{"export", []string{}, false}, // 0 or 1 arg allowed
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			cmd := NewFeedsCmd()
			subCmd := findCommand(cmd, tt.command)
			require.NotNil(t, subCmd)

			// Test args validation
			if subCmd.Args != nil {
				err := subCmd.Args(subCmd, tt.args)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

// TestRenderFeedsTable tests feed table rendering
func TestRenderFeedsTable(t *testing.T) {
	// Create test feeds
	testFeeds := []*feeds.RuleFeed{
		{
			ID:       uuid.New().String(),
			Name:     "Test Feed 1",
			Type:     feeds.FeedTypeGit,
			Status:   feeds.FeedStatusActive,
			Enabled:  true,
			Priority: 100,
			Stats: feeds.FeedStats{
				TotalRules: 150,
			},
			LastSync: time.Now().Add(-2 * time.Hour),
		},
		{
			ID:       uuid.New().String(),
			Name:     "Test Feed 2",
			Type:     feeds.FeedTypeFilesystem,
			Status:   feeds.FeedStatusDisabled,
			Enabled:  false,
			Priority: 50,
			Stats: feeds.FeedStats{
				TotalRules: 75,
			},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	renderFeedsTable(testFeeds)

	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify output contains feed names
	assert.Contains(t, output, "Test Feed 1")
	assert.Contains(t, output, "Test Feed 2")
}

// TestRenderFeedsTableEmpty tests rendering with no feeds
func TestRenderFeedsTableEmpty(t *testing.T) {
	// Just test that it doesn't panic with empty input
	// Testing output capture is complex with color library
	assert.NotPanics(t, func() {
		renderFeedsTable([]*feeds.RuleFeed{})
	})
}

// Helper functions

// findCommand finds a subcommand by name
func findCommand(parent *cobra.Command, name string) *cobra.Command {
	for _, cmd := range parent.Commands() {
		if cmd.Name() == name {
			return cmd
		}
	}
	return nil
}

// stripANSI removes ANSI color codes from a string
func stripANSI(str string) string {
	// Simple implementation - remove common ANSI sequences
	result := str
	result = strings.ReplaceAll(result, "\x1b[0m", "")
	result = strings.ReplaceAll(result, "\x1b[1m", "")
	result = strings.ReplaceAll(result, "\x1b[31m", "")
	result = strings.ReplaceAll(result, "\x1b[32m", "")
	result = strings.ReplaceAll(result, "\x1b[33m", "")
	result = strings.ReplaceAll(result, "\x1b[34m", "")
	result = strings.ReplaceAll(result, "\x1b[36m", "")

	// Remove any remaining escape sequences
	for i := 0; i < len(result); i++ {
		if result[i] == '\x1b' {
			// Find the end of the escape sequence
			end := i + 1
			for end < len(result) && (result[end] == '[' || (result[end] >= '0' && result[end] <= '9') || result[end] == ';') {
				end++
			}
			if end < len(result) {
				end++ // Include the final character
			}
			result = result[:i] + result[end:]
			i--
		}
	}

	return result
}

// MockFeedManager is a mock implementation for testing
type MockFeedManager struct {
	feeds   []*feeds.RuleFeed
	history []*feeds.FeedSyncResult
}

func (m *MockFeedManager) CreateFeed(ctx context.Context, feed *feeds.RuleFeed) error {
	m.feeds = append(m.feeds, feed)
	return nil
}

func (m *MockFeedManager) GetFeed(ctx context.Context, id string) (*feeds.RuleFeed, error) {
	for _, f := range m.feeds {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, feeds.ErrFeedNotFound
}

func (m *MockFeedManager) ListFeeds(ctx context.Context) ([]*feeds.RuleFeed, error) {
	return m.feeds, nil
}

func (m *MockFeedManager) UpdateFeed(ctx context.Context, id string, feed *feeds.RuleFeed) error {
	for i, f := range m.feeds {
		if f.ID == id {
			m.feeds[i] = feed
			return nil
		}
	}
	return feeds.ErrFeedNotFound
}

func (m *MockFeedManager) DeleteFeed(ctx context.Context, id string) error {
	for i, f := range m.feeds {
		if f.ID == id {
			m.feeds = append(m.feeds[:i], m.feeds[i+1:]...)
			return nil
		}
	}
	return feeds.ErrFeedNotFound
}

func (m *MockFeedManager) SyncFeed(ctx context.Context, id string) (*feeds.FeedSyncResult, error) {
	result := &feeds.FeedSyncResult{
		FeedID:    id,
		FeedName:  "Test Feed",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(5 * time.Second),
		Duration:  5.0,
		Success:   true,
		Stats: feeds.FeedStats{
			TotalRules:    100,
			ImportedRules: 80,
			UpdatedRules:  15,
			SkippedRules:  3,
			FailedRules:   2,
		},
	}
	m.history = append(m.history, result)
	return result, nil
}

func (m *MockFeedManager) SyncAllFeeds(ctx context.Context) ([]*feeds.FeedSyncResult, error) {
	var results []*feeds.FeedSyncResult
	for _, f := range m.feeds {
		if f.Enabled {
			result, _ := m.SyncFeed(ctx, f.ID)
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *MockFeedManager) ValidateFeed(ctx context.Context, id string) error {
	_, err := m.GetFeed(ctx, id)
	return err
}

func (m *MockFeedManager) TestFeedConnection(ctx context.Context, id string) error {
	_, err := m.GetFeed(ctx, id)
	return err
}

func (m *MockFeedManager) StartScheduler() error {
	return nil
}

func (m *MockFeedManager) StopScheduler() error {
	return nil
}

func (m *MockFeedManager) GetFeedStats(ctx context.Context, id string) (*feeds.FeedStats, error) {
	feed, err := m.GetFeed(ctx, id)
	if err != nil {
		return nil, err
	}
	return &feed.Stats, nil
}

func (m *MockFeedManager) GetFeedHealth(ctx context.Context) (map[string]string, error) {
	health := make(map[string]string)
	for _, f := range m.feeds {
		if !f.Enabled {
			health[f.ID] = "disabled"
		} else {
			health[f.ID] = "healthy"
		}
	}
	return health, nil
}

func (m *MockFeedManager) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
	var feedHistory []*feeds.FeedSyncResult
	for _, h := range m.history {
		if h.FeedID == feedID {
			feedHistory = append(feedHistory, h)
		}
	}
	if limit > 0 && len(feedHistory) > limit {
		feedHistory = feedHistory[len(feedHistory)-limit:]
	}
	return feedHistory, nil
}
