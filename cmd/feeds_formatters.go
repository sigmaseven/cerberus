package cmd

import (
	"fmt"
	"strings"
	"time"

	"cerberus/sigma/feeds"

	"github.com/fatih/color"
)

// renderFeedsTable displays feeds in a formatted table
func renderFeedsTable(feedsList []*feeds.RuleFeed) {
	if len(feedsList) == 0 {
		warningColor.Println("No feeds configured")
		return
	}

	// Print header
	headerColor.Println("FEEDS")
	headerColor.Println(strings.Repeat("=", 120))
	fmt.Printf("%-10s %-25s %-12s %-10s %-8s %-8s %-15s %-8s\n",
		"ID", "Name", "Type", "Status", "Enabled", "Rules", "Last Sync", "Priority")
	fmt.Println(strings.Repeat("-", 120))

	// Print rows
	for _, feed := range feedsList {
		// Format status with color
		status := formatStatusPlain(feed.Status, feed.Enabled)

		// Format enabled
		enabled := "No"
		if feed.Enabled {
			enabled = "Yes"
		}

		// Format last sync
		lastSync := "Never"
		if !feed.LastSync.IsZero() {
			lastSync = formatTimeSince(feed.LastSync)
		}

		// Short ID (first 8 chars)
		shortID := feed.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		// Truncate name if too long
		name := feed.Name
		if len(name) > 24 {
			name = name[:21] + "..."
		}

		fmt.Printf("%-10s %-25s %-12s %-10s %-8s %-8d %-15s %-8d\n",
			shortID, name, feed.Type, status, enabled, feed.Stats.TotalRules, lastSync, feed.Priority)
	}

	fmt.Println(strings.Repeat("=", 120))
}

// renderFeedDetails displays detailed feed information
func renderFeedDetails(feed *feeds.RuleFeed) {
	headerColor.Println("═══════════════════════════════════════════════════════════════")
	headerColor.Printf("  Feed Details: %s\n", feed.Name)
	headerColor.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Basic information
	printSection("Basic Information")
	printField("ID", feed.ID)
	printField("Name", feed.Name)
	printField("Description", feed.Description)
	printField("Type", feed.Type)
	printField("Status", formatStatus(feed.Status, feed.Enabled))
	printField("Enabled", formatBool(feed.Enabled))
	printField("Priority", fmt.Sprintf("%d", feed.Priority))
	fmt.Println()

	// Connection details
	printSection("Connection Details")
	if feed.URL != "" {
		printField("URL", feed.URL)
	}
	if feed.Branch != "" {
		printField("Branch", feed.Branch)
	}
	if feed.Path != "" {
		printField("Path", feed.Path)
	}
	fmt.Println()

	// Import configuration
	printSection("Import Configuration")
	printField("Auto-Enable Rules", formatBool(feed.AutoEnableRules))
	printField("Update Strategy", feed.UpdateStrategy)
	if feed.UpdateSchedule != "" {
		printField("Update Schedule", feed.UpdateSchedule)
	}
	if feed.MinSeverity != "" {
		printField("Min Severity", feed.MinSeverity)
	}
	if len(feed.IncludeTags) > 0 {
		printField("Include Tags", fmt.Sprintf("%v", feed.IncludeTags))
	}
	if len(feed.ExcludeTags) > 0 {
		printField("Exclude Tags", fmt.Sprintf("%v", feed.ExcludeTags))
	}
	fmt.Println()

	// Statistics
	printSection("Statistics")
	printField("Total Rules", fmt.Sprintf("%d", feed.Stats.TotalRules))
	printField("Imported Rules", fmt.Sprintf("%d", feed.Stats.ImportedRules))
	printField("Updated Rules", fmt.Sprintf("%d", feed.Stats.UpdatedRules))
	printField("Skipped Rules", fmt.Sprintf("%d", feed.Stats.SkippedRules))
	printField("Failed Rules", fmt.Sprintf("%d", feed.Stats.FailedRules))
	printField("Sync Count", fmt.Sprintf("%d", feed.Stats.SyncCount))
	if feed.Stats.LastSyncDuration > 0 {
		printField("Last Sync Duration", fmt.Sprintf("%.2fs", feed.Stats.LastSyncDuration))
	}
	if feed.Stats.LastError != "" {
		printField("Last Error", feed.Stats.LastError)
	}
	fmt.Println()

	// Timestamps
	printSection("Timestamps")
	if !feed.LastSync.IsZero() {
		printField("Last Sync", formatTime(feed.LastSync))
	}
	if !feed.NextSync.IsZero() {
		printField("Next Sync", formatTime(feed.NextSync))
	}
	printField("Created At", formatTime(feed.CreatedAt))
	printField("Updated At", formatTime(feed.UpdatedAt))
	if feed.CreatedBy != "" {
		printField("Created By", feed.CreatedBy)
	}
	fmt.Println()
}

// renderSyncResult displays synchronization result
func renderSyncResult(result *feeds.FeedSyncResult) {
	if result.Success {
		successColor.Printf("✓ %s - Sync Successful\n", result.FeedName)
	} else {
		errorColor.Printf("✗ %s - Sync Failed\n", result.FeedName)
	}

	fmt.Printf("  Duration: %.2fs\n", result.Duration)
	fmt.Printf("  Total Rules: %d\n", result.Stats.TotalRules)
	fmt.Printf("  Imported: %d, Updated: %d, Skipped: %d, Failed: %d\n",
		result.Stats.ImportedRules, result.Stats.UpdatedRules,
		result.Stats.SkippedRules, result.Stats.FailedRules)

	if len(result.Errors) > 0 {
		errorColor.Println("\n  Errors:")
		for _, err := range result.Errors {
			fmt.Printf("    - %s\n", err)
		}
	}
}

// renderSyncHistory displays synchronization history
func renderSyncHistory(history []*feeds.FeedSyncResult) {
	if len(history) == 0 {
		warningColor.Println("No synchronization history found")
		return
	}

	// Print header
	headerColor.Println("SYNC HISTORY")
	headerColor.Println(strings.Repeat("=", 100))
	fmt.Printf("%-20s %-10s %-8s %-8s %-10s %-10s %-10s %-10s\n",
		"Start Time", "Duration", "Success", "Total", "Imported", "Updated", "Skipped", "Failed")
	fmt.Println(strings.Repeat("-", 100))

	// Print rows
	for _, h := range history {
		success := "✗"
		if h.Success {
			success = "✓"
		}

		fmt.Printf("%-20s %-10s %-8s %-8d %-10d %-10d %-10d %-10d\n",
			formatTime(h.StartTime),
			fmt.Sprintf("%.1fs", h.Duration),
			success,
			h.Stats.TotalRules,
			h.Stats.ImportedRules,
			h.Stats.UpdatedRules,
			h.Stats.SkippedRules,
			h.Stats.FailedRules,
		)
	}

	fmt.Println(strings.Repeat("=", 100))
}

// printSection prints a section header
func printSection(title string) {
	headerColor.Printf("  %s\n", title)
	headerColor.Println("  " + strings.Repeat("─", len(title)))
}

// printField prints a key-value field
func printField(key, value string) {
	if value == "" {
		value = "(not set)"
	}
	fmt.Printf("  %-25s %s\n", key+":", value)
}

// formatStatus returns a colored status string
func formatStatus(status string, enabled bool) string {
	if !enabled {
		return color.New(color.FgYellow).Sprint("disabled")
	}

	switch status {
	case feeds.FeedStatusActive:
		return color.New(color.FgGreen).Sprint("active")
	case feeds.FeedStatusSyncing:
		return color.New(color.FgCyan).Sprint("syncing")
	case feeds.FeedStatusError:
		return color.New(color.FgRed).Sprint("error")
	case feeds.FeedStatusDisabled:
		return color.New(color.FgYellow).Sprint("disabled")
	default:
		return status
	}
}

// formatStatusPlain returns a plain status string (no color codes)
func formatStatusPlain(status string, enabled bool) string {
	if !enabled {
		return "disabled"
	}
	return status
}

// formatBool returns a colored boolean string
func formatBool(b bool) string {
	if b {
		return color.New(color.FgGreen).Sprint("Yes")
	}
	return color.New(color.FgRed).Sprint("No")
}

// formatTime formats a timestamp
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	return t.Format("2006-01-02 15:04:05")
}

// formatTimeSince formats time since a timestamp
func formatTimeSince(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}

	duration := time.Since(t)
	if duration < time.Minute {
		return fmt.Sprintf("%ds ago", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm ago", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(duration.Hours()))
	}
	days := int(duration.Hours() / 24)
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

// repeat repeats a string n times
func repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

// renderTemplatesTable displays templates in a formatted table
func renderTemplatesTable(templates []feeds.FeedTemplate) {
	if len(templates) == 0 {
		warningColor.Println("No templates available")
		return
	}

	// Print header
	headerColor.Println("FEED TEMPLATES")
	headerColor.Println(strings.Repeat("=", 130))
	fmt.Printf("%-25s %-35s %-12s %-10s %-8s %s\n",
		"ID", "Name", "Type", "Priority", "Rules", "Tags")
	fmt.Println(strings.Repeat("-", 130))

	// Print rows
	for _, template := range templates {
		// Truncate name if too long
		name := template.Name
		if len(name) > 34 {
			name = name[:31] + "..."
		}

		// Truncate ID if too long
		id := template.ID
		if len(id) > 24 {
			id = id[:21] + "..."
		}

		// Format tags
		tags := strings.Join(template.Tags, ", ")
		if len(tags) > 30 {
			tags = tags[:27] + "..."
		}

		fmt.Printf("%-25s %-35s %-12s %-10d %-8d %s\n",
			id, name, template.Type, template.RecommendedPriority,
			template.EstimatedRuleCount, tags)
	}

	fmt.Println(strings.Repeat("=", 130))
	fmt.Printf("\nTotal templates: %d\n", len(templates))
}

// renderTemplateDetails displays detailed template information
func renderTemplateDetails(template *feeds.FeedTemplate) {
	headerColor.Println("═══════════════════════════════════════════════════════════════")
	headerColor.Printf("  Template Details: %s\n", template.Name)
	headerColor.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Basic information
	printSection("Basic Information")
	printField("ID", template.ID)
	printField("Name", template.Name)
	printField("Description", template.Description)
	printField("Type", template.Type)
	printField("Recommended Priority", fmt.Sprintf("%d", template.RecommendedPriority))
	printField("Estimated Rule Count", fmt.Sprintf("%d", template.EstimatedRuleCount))
	fmt.Println()

	// Connection details
	printSection("Configuration")
	if template.URL != "" {
		printField("URL", template.URL)
	}
	if template.Branch != "" {
		printField("Branch", template.Branch)
	}
	fmt.Println()

	// Path configuration
	if len(template.IncludePaths) > 0 {
		printSection("Include Paths")
		for _, path := range template.IncludePaths {
			fmt.Printf("  • %s\n", path)
		}
		fmt.Println()
	}

	if len(template.ExcludePaths) > 0 {
		printSection("Exclude Paths")
		for _, path := range template.ExcludePaths {
			fmt.Printf("  • %s\n", path)
		}
		fmt.Println()
	}

	// Tags
	if len(template.Tags) > 0 {
		printSection("Tags")
		for _, tag := range template.Tags {
			infoColor.Printf("  • %s\n", tag)
		}
		fmt.Println()
	}

	// Usage example
	printSection("Usage Example")
	fmt.Printf("  cerberus feeds templates apply \\\n")
	fmt.Printf("    --template=%s \\\n", template.ID)
	fmt.Printf("    --name=\"My Custom Feed\" \\\n")
	fmt.Printf("    --enabled=true\n")
	fmt.Println()
}
