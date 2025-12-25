# Task ID: 163

**Title:** Add Feed Templates Configuration Support

**Status:** done

**Dependencies:** 154 ✓

**Priority:** medium

**Description:** Implement feed template loading from YAML and template-based feed creation

**Details:**

The PRD references feed_templates.yaml which doesn't exist yet in the codebase.

Create sigma/feeds/templates.yaml:
```yaml
templates:
  - id: sigmahq-full
    name: "SigmaHQ Full Repository"
    description: "Complete SigmaHQ rule collection (3000+ rules)"
    type: git
    config:
      url: https://github.com/SigmaHQ/sigma.git
      branch: master
      path: rules
      min_severity: low
      auto_enable_rules: true
      priority: 100

  - id: sigmahq-windows
    name: "SigmaHQ Windows Only"
    description: "Windows-specific detection rules (1800+ rules)"
    type: git
    config:
      url: https://github.com/SigmaHQ/sigma.git
      branch: master
      path: rules
      include_paths:
        - rules/windows/**
      min_severity: medium
      auto_enable_rules: true
      priority: 100

  - id: sigmahq-linux
    name: "SigmaHQ Linux Only"
    description: "Linux-specific detection rules (400+ rules)"
    type: git
    config:
      url: https://github.com/SigmaHQ/sigma.git
      branch: master
      path: rules
      include_paths:
        - rules/linux/**
      min_severity: medium
      auto_enable_rules: true
      priority: 100

  - id: sigmahq-cloud
    name: "SigmaHQ Cloud Platforms"
    description: "AWS, Azure, GCP detection rules (300+ rules)"
    type: git
    config:
      url: https://github.com/SigmaHQ/sigma.git
      branch: master
      path: rules
      include_paths:
        - rules/cloud/**
      min_severity: medium
      auto_enable_rules: true
      priority: 100

  # ... Continue for other templates from PRD Appendix
```

Implement in sigma/feeds/templates.go:
- LoadTemplates(path string) ([]FeedTemplate, error)
- GetTemplate(id string) (*FeedTemplate, error)
- ApplyTemplate(templateID string, overrides map[string]interface{}) (*RuleFeed, error)

Integrate into manager.go:
- Add GetTemplates() method returning loaded templates
- Add CreateFeedFromTemplate(templateID, name string, overrides) method

API endpoint implementation (in task 154):
- GET /api/v1/feeds/templates uses manager.GetTemplates()
- POST /api/v1/feeds with template_id field uses CreateFeedFromTemplate()

CLI integration (in task 159):
- cerberus feeds add --template=sigmahq-windows --name="My Windows Rules"

Configuration:
- Add feeds.templates_path to config.yaml
- Default: sigma/feeds/templates.yaml
- Load templates on manager initialization

**Test Strategy:**

Unit tests: Test YAML parsing, template loading, template application with overrides. Integration tests: Create feeds from templates via API and CLI, verify correct configuration applied, test template listing endpoint.

## Subtasks

### 163.1. Create sigma/feeds/templates.yaml with SigmaHQ feed templates

**Status:** pending  
**Dependencies:** None  

Create the templates YAML file containing all SigmaHQ feed template definitions including full, windows, linux, cloud, network, and web application detection rules

**Details:**

Create sigma/feeds/templates.yaml with comprehensive template definitions:
- sigmahq-full: Complete SigmaHQ repository (3000+ rules)
- sigmahq-windows: Windows-specific rules (1800+ rules) with path filter rules/windows/**
- sigmahq-linux: Linux-specific rules (400+ rules) with path filter rules/linux/**
- sigmahq-cloud: AWS, Azure, GCP rules (300+ rules) with path filter rules/cloud/**
- sigmahq-network: Network detection rules with path filter rules/network/**
- sigmahq-web: Web application rules with path filter rules/web/**

Each template includes: id, name, description, type (git), config object with url, branch, path, optional include_paths, min_severity, auto_enable_rules, and priority fields. Use consistent structure across all templates for easy parsing.

### 163.2. Implement sigma/feeds/templates.go with template loading functions

**Status:** pending  
**Dependencies:** 163.1  

Implement the template loading infrastructure including YAML parsing, template retrieval, and template application with override support

**Details:**

Create sigma/feeds/templates.go with:

1. FeedTemplate struct matching YAML schema (ID, Name, Description, Type, Config)
2. LoadTemplates(path string) ([]FeedTemplate, error):
   - Read YAML file from path
   - Unmarshal into template structs
   - Validate required fields
   - Return parsed templates

3. GetTemplate(id string) (*FeedTemplate, error):
   - Search loaded templates by ID
   - Return error if not found

4. ApplyTemplate(templateID string, overrides map[string]interface{}) (*RuleFeed, error):
   - Load template by ID
   - Create RuleFeed from template config
   - Merge override values into config
   - Validate final configuration
   - Return configured RuleFeed

Include proper error handling, validation logic, and deep merge for nested override values.

### 163.3. Integrate template support into manager.go and API endpoints

**Status:** pending  
**Dependencies:** 163.2  

Add template methods to feed manager and expose via REST API for template listing and template-based feed creation

**Details:**

Modify sigma/feeds/manager.go:
1. Add templates []FeedTemplate field to Manager struct
2. Load templates in NewManager() using LoadTemplates()
3. Add GetTemplates() []FeedTemplate method returning loaded templates
4. Add CreateFeedFromTemplate(templateID, name string, overrides map[string]interface{}) (*RuleFeed, error):
   - Call ApplyTemplate() to create feed from template
   - Set custom name if provided
   - Apply overrides
   - Add to manager's feeds
   - Persist to storage

Modify api/feed_handlers.go:
1. Add GET /api/v1/feeds/templates handler:
   - Call manager.GetTemplates()
   - Return template list as JSON

2. Extend POST /api/v1/feeds handler:
   - Check for template_id field in request
   - If present, call CreateFeedFromTemplate()
   - Otherwise, use existing direct creation logic
   - Return created feed details

### 163.4. Add CLI support and configuration for feed templates

**Status:** pending  
**Dependencies:** 163.3  

Implement CLI command for template-based feed creation and add templates_path configuration option to config.yaml

**Details:**

Update config/config.go:
1. Add TemplatesPath field to FeedsConfig struct
2. Set default value: "sigma/feeds/templates.yaml"
3. Add validation for templates path exists

Update config.yaml:
```yaml
feeds:
  templates_path: sigma/feeds/templates.yaml
  # ... existing feed config
```

Implement CLI command (location based on existing CLI structure):
```bash
cerberus feeds add --template=<template-id> --name="Custom Name" [--override key=value ...]
```

CLI implementation:
1. Parse --template flag for template ID
2. Parse --name flag for custom feed name
3. Parse --override flags for configuration overrides
4. Convert overrides to map[string]interface{}
5. Call API endpoint POST /api/v1/feeds with template_id and overrides
6. Display created feed details
7. Handle errors with helpful messages

Ensure templates are loaded during manager initialization using configured templates_path.
