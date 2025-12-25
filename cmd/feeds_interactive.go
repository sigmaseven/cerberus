package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"cerberus/sigma/feeds"
)

// promptFeedConfiguration interactively prompts for feed configuration.
func promptFeedConfiguration(feed *feeds.RuleFeed) error {
	reader := bufio.NewReader(os.Stdin)

	// Feed name
	if feed.Name == "" {
		feed.Name = promptString(reader, "Feed name", true, "")
	}

	// Feed description
	if feed.Description == "" {
		feed.Description = promptString(reader, "Description", false, "")
	}

	// Feed type
	if feed.Type == "" {
		fmt.Println("\nFeed types:")
		fmt.Println("  1. git        - Git repository")
		fmt.Println("  2. filesystem - Local filesystem path")
		fmt.Println("  3. http       - HTTP/HTTPS URL")
		fmt.Println("  4. api        - REST API endpoint")

		typeChoice := promptString(reader, "Feed type (1-4 or name)", true, "1")
		switch typeChoice {
		case "1", "git":
			feed.Type = feeds.FeedTypeGit
		case "2", "filesystem":
			feed.Type = feeds.FeedTypeFilesystem
		case "3", "http":
			feed.Type = feeds.FeedTypeHTTP
		case "4", "api":
			feed.Type = feeds.FeedTypeAPI
		default:
			feed.Type = typeChoice // Allow direct type names
		}
	}

	// Type-specific configuration
	switch feed.Type {
	case feeds.FeedTypeGit:
		if feed.URL == "" {
			feed.URL = promptString(reader, "Git repository URL", true, "")
		}
		if feed.Branch == "" {
			feed.Branch = promptString(reader, "Branch", false, "main")
		}

	case feeds.FeedTypeFilesystem:
		if feed.Path == "" {
			feed.Path = promptString(reader, "Filesystem path", true, "")
		}

	case feeds.FeedTypeHTTP, feeds.FeedTypeAPI:
		if feed.URL == "" {
			feed.URL = promptString(reader, "URL", true, "")
		}
	}

	// Priority
	if feed.Priority == 0 {
		priorityStr := promptString(reader, "Priority (higher = higher precedence)", false, "100")
		if priority, err := strconv.Atoi(priorityStr); err == nil {
			feed.Priority = priority
		} else {
			feed.Priority = 100
		}
	}

	// Auto-enable rules
	autoEnable := promptYesNo(reader, "Auto-enable imported rules?", false)
	feed.AutoEnableRules = autoEnable

	// Update strategy
	fmt.Println("\nUpdate strategies:")
	fmt.Println("  1. manual    - Manual synchronization only")
	fmt.Println("  2. startup   - Sync on application startup")
	fmt.Println("  3. scheduled - Sync on schedule (cron)")

	strategyChoice := promptString(reader, "Update strategy (1-3)", false, "1")
	switch strategyChoice {
	case "1", "manual":
		feed.UpdateStrategy = feeds.UpdateManual
	case "2", "startup":
		feed.UpdateStrategy = feeds.UpdateStartup
	case "3", "scheduled":
		feed.UpdateStrategy = feeds.UpdateScheduled
		feed.UpdateSchedule = promptString(reader, "Schedule (cron format)", false, "")
	default:
		feed.UpdateStrategy = feeds.UpdateManual
	}

	// Include/Exclude paths (optional)
	if promptYesNo(reader, "Configure include/exclude paths?", false) {
		includePathsStr := promptString(reader, "Include paths (comma-separated)", false, "")
		if includePathsStr != "" {
			feed.IncludePaths = splitAndTrim(includePathsStr, ",")
		}

		excludePathsStr := promptString(reader, "Exclude paths (comma-separated)", false, "")
		if excludePathsStr != "" {
			feed.ExcludePaths = splitAndTrim(excludePathsStr, ",")
		}
	}

	// Tags (optional)
	if promptYesNo(reader, "Configure tags?", false) {
		includeTagsStr := promptString(reader, "Include tags (comma-separated)", false, "")
		if includeTagsStr != "" {
			feed.IncludeTags = splitAndTrim(includeTagsStr, ",")
		}

		excludeTagsStr := promptString(reader, "Exclude tags (comma-separated)", false, "")
		if excludeTagsStr != "" {
			feed.ExcludeTags = splitAndTrim(excludeTagsStr, ",")
		}
	}

	// Minimum severity (optional)
	if promptYesNo(reader, "Set minimum severity filter?", false) {
		fmt.Println("\nSeverity levels:")
		fmt.Println("  - informational")
		fmt.Println("  - low")
		fmt.Println("  - medium")
		fmt.Println("  - high")
		fmt.Println("  - critical")
		feed.MinSeverity = promptString(reader, "Minimum severity", false, "")
	}

	return nil
}

// promptString prompts for a string input.
func promptString(reader *bufio.Reader, prompt string, required bool, defaultValue string) string {
	for {
		if defaultValue != "" {
			fmt.Printf("%s [%s]: ", prompt, defaultValue)
		} else if required {
			fmt.Printf("%s (required): ", prompt)
		} else {
			fmt.Printf("%s: ", prompt)
		}

		// BLOCKER-2: Check error from ReadString
		input, err := reader.ReadString('\n')
		if err != nil {
			errorColor.Printf("Error reading input: %v\n", err)
			return defaultValue
		}
		input = strings.TrimSpace(input)

		if input == "" {
			if defaultValue != "" {
				return defaultValue
			}
			if !required {
				return ""
			}
			errorColor.Println("This field is required")
			continue
		}

		return input
	}
}

// promptYesNo prompts for a yes/no response.
func promptYesNo(reader *bufio.Reader, prompt string, defaultValue bool) bool {
	defaultStr := "N"
	if defaultValue {
		defaultStr = "Y"
	}

	for {
		fmt.Printf("%s [y/N] (default: %s): ", prompt, defaultStr)
		// BLOCKER-2: Check error from ReadString
		input, err := reader.ReadString('\n')
		if err != nil {
			errorColor.Printf("Error reading input: %v\n", err)
			return defaultValue
		}
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "" {
			return defaultValue
		}

		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}

		errorColor.Println("Please enter 'y' or 'n'")
	}
}

// splitAndTrim splits a string by delimiter and trims each part.
func splitAndTrim(s, delimiter string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, delimiter)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
