# Feed Templates

## Overview

Feed templates provide pre-configured settings for popular SIGMA rule sources, simplifying feed creation and ensuring best practices. Templates eliminate the need to manually configure URLs, branches, paths, and other settings for well-known rule repositories.

## Features

- **Pre-configured Templates**: 15+ templates for popular SIGMA rule sources including SigmaHQ, SOC Prime, and community feeds
- **Easy Customization**: Override any template setting to match your requirements
- **Type Safety**: Full validation of template configurations and overrides
- **Thread-Safe**: Concurrent access to templates is safe
- **Embedded Templates**: Templates are embedded in the binary for zero-dependency deployment
- **Custom Templates**: Support for loading custom organization-specific templates

## Available Templates

### Official SigmaHQ Templates

#### sigmahq-core
Complete SIGMA rule set from SigmaHQ repository covering Windows, Linux, Network, Cloud, and Application logs.
- **Estimated Rules**: 3,000+
- **Priority**: 100
- **Tags**: official, comprehensive, production-ready

#### sigmahq-windows
Windows-specific detection rules including process creation, registry, file events, and more.
- **Estimated Rules**: 2,000+
- **Priority**: 100
- **Tags**: official, windows, endpoint

#### sigmahq-linux
Linux-specific detection rules including auditd, syslog, and system events.
- **Estimated Rules**: 400+
- **Priority**: 100
- **Tags**: official, linux, endpoint

#### sigmahq-network
Network detection rules including firewall, DNS, proxy, and Zeek logs.
- **Estimated Rules**: 200+
- **Priority**: 90
- **Tags**: official, network, infrastructure

#### sigmahq-cloud
Cloud platform detection rules for AWS, Azure, GCP, and other cloud services.
- **Estimated Rules**: 300+
- **Priority**: 95
- **Tags**: official, cloud, infrastructure

#### sigmahq-emerging-threats
Latest threat detection rules for newly discovered attack techniques and campaigns.
- **Estimated Rules**: 150+
- **Priority**: 110 (highest)
- **Tags**: official, emerging-threats, high-priority

### Community Templates

#### socprime-community
Community-contributed SIGMA rules from SOC Prime Threat Detection Marketplace.
- **Estimated Rules**: 500+
- **Priority**: 80
- **Tags**: community, socprime, threat-intelligence

#### neo23x0-sigma
High-quality detection rules from Florian Roth covering APT campaigns and malware.
- **Estimated Rules**: 400+
- **Priority**: 105
- **Tags**: community, apt, malware, high-quality

### Specialized Templates

#### sigmahq-powershell
Comprehensive PowerShell detection rules for malicious scripts and command execution.
- **Estimated Rules**: 250+
- **Priority**: 100
- **Tags**: powershell, scripting, windows

#### sigmahq-web
Detection rules for web application attacks, SQL injection, XSS, and web shells.
- **Estimated Rules**: 150+
- **Priority**: 90
- **Tags**: web-security, application, owasp

#### sigmahq-proxy
Detection rules for proxy logs, web filtering, and HTTP/HTTPS traffic analysis.
- **Estimated Rules**: 100+
- **Priority**: 85
- **Tags**: proxy, web-traffic, network

## Usage

### CLI Usage

#### List Available Templates

```bash
# List all templates
cerberus feeds templates list

# List templates with JSON output
cerberus feeds templates list --json

# Filter by tag
cerberus feeds templates list --tag=official

# Filter by type
cerberus feeds templates list --type=git
```

#### Show Template Details

```bash
# Show detailed information about a template
cerberus feeds templates show sigmahq-core

# Show with JSON output
cerberus feeds templates show sigmahq-core --json
```

#### Create Feed from Template

```bash
# Basic usage
cerberus feeds templates apply \
  --template=sigmahq-core \
  --name="SigmaHQ Main Rules"

# With customization
cerberus feeds templates apply \
  --template=sigmahq-windows \
  --name="Windows Detection Rules" \
  --enabled=true \
  --auto-enable=true \
  --priority=150 \
  --update-strategy=scheduled \
  --update-schedule="0 */6 * * *"

# Override git branch
cerberus feeds templates apply \
  --template=sigmahq-core \
  --name="SigmaHQ Development Rules" \
  --branch=develop
```

### API Usage

#### Get All Templates

```bash
GET /api/v1/feeds/templates
```

Response:
```json
[
  {
    "id": "sigmahq-core",
    "name": "SigmaHQ Core Rules",
    "description": "Official SIGMA rules from the SigmaHQ repository covering Windows, Linux, Network, Cloud, and Application logs",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/windows/", "rules/linux/", "rules/network/", "rules/cloud/", "rules/application/"],
    "recommended_priority": 100,
    "estimated_rule_count": 3000,
    "tags": ["official", "comprehensive", "production-ready"]
  }
]
```

#### Create Feed from Template (via API)

Use the template information to populate feed creation requests:

```bash
POST /api/v1/feeds
Content-Type: application/json

{
  "name": "My Custom Feed",
  "description": "Production SIGMA rules",
  "type": "git",
  "url": "https://github.com/SigmaHQ/sigma.git",
  "branch": "master",
  "include_paths": ["rules/"],
  "enabled": true,
  "auto_enable_rules": false,
  "priority": 100,
  "update_strategy": "scheduled",
  "update_schedule": "0 */6 * * *"
}
```

### Programmatic Usage

```go
import (
    "cerberus/sigma/feeds"
)

// Create template manager
tm, err := feeds.NewTemplateManager()
if err != nil {
    log.Fatal(err)
}

// List all templates
templates := tm.ListTemplates()

// Get specific template
template := tm.GetTemplate("sigmahq-core")

// Apply template with overrides
feed, err := tm.ApplyTemplate("sigmahq-core", map[string]interface{}{
    "name":              "My Production Rules",
    "enabled":           true,
    "auto_enable_rules": false,
    "priority":          150,
    "update_strategy":   "scheduled",
    "update_schedule":   "0 */6 * * *",
})

// Use the feed
feedManager.CreateFeed(ctx, feed)
```

## Customization

### Override Options

When applying templates, the following fields can be overridden:

- **id**: Custom feed ID (auto-generated if not provided)
- **name**: Feed name (required)
- **description**: Feed description
- **enabled**: Enable/disable feed
- **auto_enable_rules**: Automatically enable imported rules
- **priority**: Feed priority (higher = higher precedence)
- **update_strategy**: Update strategy (manual, startup, scheduled, webhook)
- **update_schedule**: Cron schedule for updates
- **include_paths**: Override include paths
- **exclude_paths**: Override exclude paths
- **tags**: Additional tags (appended to template tags)
- **branch**: Git branch (for git feeds)
- **url**: Override URL
- **path**: Override local path

### Custom Templates

Organizations can define custom templates in YAML format:

```yaml
templates:
  - id: custom-org-rules
    name: "Organization Custom Rules"
    description: "Internal detection rules"
    type: git
    url: https://github.com/myorg/sigma-rules.git
    branch: main
    include_paths:
      - "rules/"
    recommended_priority: 120
    estimated_rule_count: 200
    tags:
      - internal
      - custom
```

Load custom templates:

```go
tm, _ := feeds.NewTemplateManager()
err := tm.LoadTemplatesFromFile("/path/to/custom-templates.yaml")
```

## Security Considerations

### Input Validation

- All template fields are validated before use
- Override values are type-checked and validated
- URL schemes are restricted to HTTPS and Git
- File paths are sanitized to prevent traversal attacks
- Template files are size-limited to prevent memory exhaustion (5MB max)

### Best Practices

1. **Review Templates**: Review template configurations before creating feeds
2. **Override Carefully**: Only override values you understand
3. **Test First**: Test feeds in non-production before deploying
4. **Monitor Imports**: Monitor rule import statistics after feed creation
5. **Update Strategy**: Choose appropriate update strategies for your environment
6. **Priority Management**: Set priorities to ensure correct rule precedence

## Template Development

### Adding New Templates

1. Edit `sigma/feeds/templates.yaml`
2. Add new template following the structure:

```yaml
- id: unique-template-id
  name: "Human Readable Name"
  description: "Detailed description"
  type: git
  url: https://github.com/repo/path.git
  branch: main
  include_paths:
    - "rules/category/"
  exclude_paths:
    - "rules/deprecated/"
  recommended_priority: 100
  estimated_rule_count: 500
  tags:
    - category
    - source
```

3. Run tests to validate:

```bash
go test ./sigma/feeds/... -run TestLoadEmbeddedTemplates
```

### Template Validation

Templates must meet these requirements:

- **id**: Unique identifier (required)
- **name**: Human-readable name (required)
- **description**: Detailed description (required)
- **type**: Valid feed type (required)
- **url**: Valid URL for git/http/api feeds
- **recommended_priority**: Suggested priority (0-200)
- **estimated_rule_count**: Approximate number of rules
- **tags**: Array of descriptive tags

## Troubleshooting

### Template Not Found

```bash
Error: template not found: sigmahq-core
```

Solution: Verify template ID is correct. List available templates with:
```bash
cerberus feeds templates list
```

### Invalid Override Type

```bash
Error: invalid priority override: must be integer
```

Solution: Ensure override values match expected types:
- Strings: name, description, branch, url, update_strategy
- Booleans: enabled, auto_enable_rules
- Integers: priority
- Arrays: include_paths, exclude_paths, tags

### Feed Creation Failed

```bash
Error: failed to create feed: validation failed
```

Solution: Check feed validation requirements:
- Name must be non-empty
- Type must be valid (git, filesystem, http, etc.)
- Git feeds require URL
- Filesystem feeds require path

## Performance

- **Template Loading**: <10ms for embedded templates
- **Template Application**: <1ms per feed creation
- **Memory Usage**: ~500KB for all templates
- **Concurrent Access**: Lock-free reads, thread-safe

## Version Compatibility

- **Cerberus**: v1.7.0+
- **Go**: 1.21+
- **SIGMA Spec**: Compatible with current SIGMA specification

## Contributing

To contribute new templates:

1. Fork the repository
2. Add template to `templates.yaml`
3. Add tests validating the template
4. Submit pull request with:
   - Template definition
   - Test coverage
   - Documentation updates

## License

Feed templates are part of the Cerberus SIEM project and follow the same license.
Template content (SIGMA rules) from external sources retain their original licenses.
