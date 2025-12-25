# Cerberus CLI Commands

This package provides command-line interface (CLI) commands for Cerberus SIEM management operations.

## Feed Management CLI

The feed management CLI provides comprehensive commands for managing SIGMA rule feeds in Cerberus.

### Command Structure

```
cerberus feeds
├── list                    # List all feeds
├── show <feed-id>         # Show detailed feed information
├── add                     # Add a new feed
├── update <feed-id>       # Update feed configuration
├── delete <feed-id>       # Delete a feed
├── sync <feed-id>         # Synchronize a feed
├── sync-all               # Synchronize all enabled feeds
├── history <feed-id>      # Show sync history
├── test <feed-id>         # Test feed connectivity
├── enable <feed-id>       # Enable a feed
├── disable <feed-id>      # Disable a feed
├── import <file>          # Import feeds from YAML
└── export [file]          # Export feeds to YAML
```

See full documentation at: https://cerberus-siem.readthedocs.io/
