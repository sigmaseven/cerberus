# Task ID: 159

**Title:** Create CLI Commands for Feed Management

**Status:** done

**Dependencies:** 154 ✓

**Priority:** medium

**Description:** Implement Cobra CLI subcommands for feed management automation

**Details:**

Create cmd/feeds.go implementing Cobra CLI:

Commands structure:
cerberus feeds <subcommand> [flags]

Subcommands:
1. list [--format=table|json]
   - Display all feeds in table or JSON format
   - Table columns: ID, Name, Type, Status, Rules, Last Sync
   - JSON: full feed objects array

2. show <feed-id>
   - Display detailed feed information
   - Include stats, configuration, recent sync history

3. add --template=<name> --name=<name> OR
   add --name=<name> --type=<git|fs> --url=<url> [options]
   - Create feed from template or manual config
   - Options: --branch, --path, --min-severity, --priority, etc.
   - Validate config before creation

4. update <feed-id> [--option=value...]
   - Update feed configuration
   - Support partial updates

5. delete <feed-id> [--force]
   - Delete feed with confirmation
   - --force skips confirmation

6. sync <feed-id>
   - Trigger manual sync for single feed
   - Show progress and results

7. sync-all
   - Sync all enabled feeds
   - Display results summary

8. history <feed-id> [--limit=10]
   - Show sync history
   - Default limit 10, max 100

9. test <feed-id>
   - Test feed connectivity
   - Validate configuration without syncing

10. enable <feed-id>
    - Enable feed

11. disable <feed-id>
    - Disable feed

12. export [--output=feeds-backup.yaml]
    - Export all feeds to YAML file
    - Default: stdout

13. import <file.yaml>
    - Import feeds from YAML file
    - Merge with existing feeds

Implementation:
- Use cobra and spf13/viper for config
- Connect to same SQLite database as server
- Instantiate feedManager with same config
- Use tabwriter for table formatting
- Add progress bars for sync operations
- Colorized output using fatih/color
- Exit codes: 0 success, 1 error

Integrate into main.go:
- Add feeds command to root command
- Ensure database path resolution works in CLI context

**Test Strategy:**

Unit tests: Test each command with mock feedManager. Integration tests: Execute CLI commands against test database, verify outputs, test error cases. Manual testing: Run commands in real environment, verify usability.

## Subtasks

### 159.1. Set up Cobra CLI infrastructure and integrate with main.go

**Status:** done  
**Dependencies:** None  

Create cmd/ directory structure and set up Cobra framework with root command integration. Establish database connection pattern for CLI context.

**Details:**

Create cmd/feeds.go with Cobra command structure. Create cmd/root.go if needed for root command setup. Install required dependencies: github.com/spf13/cobra, github.com/spf13/viper. Add feeds command to main.go root command. Implement database path resolution for CLI context (handle relative vs absolute paths, config file locations). Set up shared feedManager initialization pattern. Create basic command structure with placeholder subcommands. Ensure proper exit codes (0 success, 1 error). Add basic help text and usage documentation.

### 159.2. Implement basic CRUD commands (list, show, add, update, delete)

**Status:** pending  
**Dependencies:** 159.1  

Build core feed management commands with feedManager integration and input validation.

**Details:**

Implement 'list' command with --format flag (table/json), query feedStorage.ListFeeds(), format output appropriately. Implement 'show <feed-id>' command to display detailed feed info including stats and sync history. Implement 'add' command supporting both template-based (--template) and manual (--type, --url, --branch, --path) creation modes, validate all inputs before calling feedManager.CreateFeed(). Implement 'update <feed-id>' command with partial update support for all feed options. Implement 'delete <feed-id>' command with confirmation prompt (skip with --force flag). Connect all commands to feedManager instance. Add input validation and error handling for all commands.

### 159.3. Add sync commands with progress indicators (sync, sync-all, history, test)

**Status:** pending  
**Dependencies:** 159.2  

Implement feed synchronization commands with real-time progress display and connectivity testing.

**Details:**

Install progress bar library (e.g., github.com/schollz/progressbar or github.com/cheggaaa/pb). Implement 'sync <feed-id>' command that triggers feedManager.SyncFeed() and displays progress bar with status updates. Implement 'sync-all' command that syncs all enabled feeds sequentially or in parallel, showing progress for each feed and summary results (success/failed counts, new rules imported). Implement 'history <feed-id>' command with --limit flag (default 10, max 100) to display sync history from storage. Implement 'test <feed-id>' command to validate feed connectivity and configuration without performing actual sync (test Git clone/fetch or filesystem access). Add real-time status updates during sync operations. Handle sync errors gracefully with detailed error messages.

### 159.4. Implement enable/disable commands and import/export with YAML

**Status:** pending  
**Dependencies:** 159.2  

Build feed state management commands and YAML-based backup/restore functionality.

**Details:**

Implement 'enable <feed-id>' command to set feed IsEnabled=true via feedManager. Implement 'disable <feed-id>' command to set feed IsEnabled=false. Install YAML library (gopkg.in/yaml.v3). Implement 'export' command with optional --output flag (default stdout) that serializes all feeds to YAML format including all configuration fields. Implement 'import <file.yaml>' command that reads YAML file, validates feed structures, and merges with existing feeds (handle conflicts - skip duplicates or prompt for overwrite). Add validation to ensure imported feeds have valid configuration. Support both single feed and multi-feed YAML documents. Add error handling for file I/O operations and YAML parsing errors.

### 159.5. Add table formatting, colorized output, and comprehensive error handling

**Status:** pending  
**Dependencies:** 159.2, 159.3, 159.4  

Implement polished CLI output with formatted tables, colored text, and user-friendly error messages across all commands.

**Details:**

Install formatting libraries: text/tabwriter for table formatting, github.com/fatih/color for colorized output. Implement table formatter for 'list' command with columns: ID, Name, Type, Status, Rules, Last Sync. Add color coding: green for active/success, red for errors, yellow for warnings, blue for in-progress, gray for disabled. Apply colorization to all command outputs (status badges, error messages, success confirmations). Implement consistent error message formatting with helpful context and suggested fixes. Add proper exit codes throughout all commands (0 for success, 1 for errors). Improve help text and usage examples for all commands. Add input validation messages that guide users to correct syntax. Ensure all table outputs are properly aligned and readable. Add timestamp formatting for sync history display.
