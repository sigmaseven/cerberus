# Cerberus SIEM Settings Page - Feature Plan

## 1. Overview

The Settings page provides a centralized UI for administrators to configure Cerberus SIEM system parameters without manually editing configuration files. This includes data retention policies, listener configurations, authentication settings, and system preferences.

## 2. Settings Categories

### 2.1 Data Retention
**Purpose**: Control how long data is stored before automatic cleanup

Settings:
- **Event Retention Period** (days)
  - Default: 30 days
  - Range: 1-365 days
  - Description: "How long to keep event logs before automatic deletion"
  - Impact: Affects storage usage and search results

- **Alert Retention Period** (days)
  - Default: 90 days
  - Range: 1-730 days (2 years)
  - Description: "How long to keep alerts before automatic deletion"
  - Impact: Affects storage usage and alert history

- **Retention Check Interval** (hours)
  - Default: 24 hours
  - Range: 1-168 hours (1 week)
  - Description: "How often to run data cleanup process"
  - Impact: Performance during cleanup

- **Enable Automatic Cleanup**
  - Type: Boolean toggle
  - Default: Enabled
  - Description: "Automatically delete old data based on retention periods"
  - Warning: "Disabling this may cause storage to fill up"

### 2.2 Listener Configuration
**Purpose**: Configure log ingestion endpoints

#### Syslog Listener
- **Enable Syslog Listener**
  - Type: Boolean toggle
  - Default: Enabled
  - Restart Required: Yes

- **Syslog Port**
  - Default: 514
  - Range: 1-65535
  - Validation: Check for port conflicts
  - Restart Required: Yes

- **Syslog Host**
  - Default: "0.0.0.0" (all interfaces)
  - Type: IP address or hostname
  - Restart Required: Yes

#### CEF Listener
- **Enable CEF Listener**
  - Type: Boolean toggle
  - Default: Enabled
  - Restart Required: Yes

- **CEF Port**
  - Default: 515
  - Range: 1-65535
  - Restart Required: Yes

- **CEF Host**
  - Default: "0.0.0.0"
  - Restart Required: Yes

#### JSON Listener
- **Enable JSON Listener**
  - Type: Boolean toggle
  - Default: Enabled
  - Restart Required: Yes

- **JSON Port**
  - Default: 8888
  - Range: 1-65535
  - Restart Required: Yes

- **JSON Host**
  - Default: "0.0.0.0"
  - Restart Required: Yes

- **Enable TLS for JSON**
  - Type: Boolean toggle
  - Default: Disabled
  - Restart Required: Yes

- **TLS Certificate Path**
  - Type: File path
  - Conditional: Only if TLS enabled
  - Validation: File must exist

- **TLS Key Path**
  - Type: File path
  - Conditional: Only if TLS enabled
  - Validation: File must exist

### 2.3 API Configuration
**Purpose**: Configure API server settings

- **API Port**
  - Default: 8080
  - Range: 1-65535
  - Restart Required: Yes

- **Enable TLS for API**
  - Type: Boolean toggle
  - Default: Disabled
  - Restart Required: Yes

- **API TLS Certificate**
  - Type: File path
  - Conditional: Only if TLS enabled

- **API TLS Key**
  - Type: File path
  - Conditional: Only if TLS enabled

- **API Request Timeout** (seconds)
  - Default: 30
  - Range: 5-300
  - Description: "Maximum time for API requests"
  - Hot Reload: Yes

- **Rate Limiting**
  - Type: Boolean toggle
  - Default: Enabled
  - Description: "Enable rate limiting for API requests"
  - Hot Reload: Yes

- **Rate Limit (requests/minute)**
  - Default: 100
  - Range: 10-10000
  - Conditional: Only if rate limiting enabled
  - Hot Reload: Yes

### 2.4 Authentication & Security
**Purpose**: Configure authentication and security policies

- **Enable Authentication**
  - Type: Boolean toggle
  - Default: Disabled
  - Restart Required: Yes
  - Warning: "Enabling auth requires JWT configuration"

- **JWT Secret Key**
  - Type: Password field (masked)
  - Required if auth enabled
  - Validation: Minimum 32 characters
  - Security: Never display actual value
  - Restart Required: Yes

- **JWT Token Expiry** (hours)
  - Default: 24
  - Range: 1-720 (30 days)
  - Hot Reload: Yes

- **Session Timeout** (minutes)
  - Default: 30
  - Range: 5-1440 (24 hours)
  - Description: "Inactivity timeout for user sessions"
  - Hot Reload: Yes

- **Failed Login Attempts Threshold**
  - Default: 5
  - Range: 3-20
  - Description: "Max failed login attempts before account lockout"
  - Hot Reload: Yes

- **Account Lockout Duration** (minutes)
  - Default: 30
  - Range: 5-1440
  - Hot Reload: Yes

### 2.5 Storage Configuration
**Purpose**: Configure MongoDB and storage behavior

- **Enable Deduplication**
  - Type: Boolean toggle
  - Default: Enabled
  - Description: "Prevent duplicate events from being stored"
  - Hot Reload: Yes

- **Deduplication Cache Size**
  - Default: 10000
  - Range: 1000-1000000
  - Description: "Number of event hashes to keep in memory"
  - Hot Reload: Yes

- **Deduplication Window** (seconds)
  - Default: 60
  - Range: 10-3600
  - Description: "Time window for duplicate detection"
  - Hot Reload: Yes

- **MongoDB Connection String**
  - Type: Secure text field
  - Default: "mongodb://localhost:27017"
  - Validation: Valid MongoDB URI
  - Restart Required: Yes
  - Security: Mask password in display

- **MongoDB Database Name**
  - Default: "cerberus"
  - Validation: Valid database name
  - Restart Required: Yes

### 2.6 Detection Engine
**Purpose**: Configure rule engine and correlation

- **Detection Engine Workers**
  - Default: 4
  - Range: 1-32
  - Description: "Number of concurrent rule evaluation workers"
  - Restart Required: Yes

- **Channel Buffer Size**
  - Default: 1000
  - Range: 100-100000
  - Description: "Internal event queue size"
  - Restart Required: Yes

- **Correlation Window** (seconds)
  - Default: 300 (5 minutes)
  - Range: 10-3600
  - Description: "Default time window for correlation rules"
  - Hot Reload: Yes

- **Max Correlation Cache Size**
  - Default: 10000
  - Range: 1000-1000000
  - Description: "Maximum events to track for correlation"
  - Hot Reload: Yes

### 2.7 Alerting & Notifications
**Purpose**: Configure alert behavior and notification channels

- **Enable Email Notifications**
  - Type: Boolean toggle
  - Default: Disabled
  - Hot Reload: Yes

- **SMTP Server**
  - Type: Text field
  - Example: "smtp.gmail.com:587"
  - Conditional: Only if email enabled

- **SMTP Username**
  - Type: Text field
  - Conditional: Only if email enabled

- **SMTP Password**
  - Type: Password field (masked)
  - Conditional: Only if email enabled
  - Security: Encrypted storage

- **Default Email Recipients**
  - Type: Multi-value text (comma-separated)
  - Example: "admin@company.com, security@company.com"
  - Validation: Valid email addresses

- **Enable Slack Notifications**
  - Type: Boolean toggle
  - Default: Disabled

- **Slack Webhook URL**
  - Type: Secure text field
  - Conditional: Only if Slack enabled
  - Security: Encrypted storage

- **Alert Severity Thresholds**
  - Low: Configure notification channels
  - Medium: Configure notification channels
  - High: Configure notification channels
  - Critical: Configure notification channels

### 2.8 System Information (Read-Only)
**Purpose**: Display system status and information

- **Cerberus Version**
  - Display only
  - Example: "v1.2.3"

- **Uptime**
  - Display only
  - Format: "X days, X hours, X minutes"

- **Go Version**
  - Display only

- **MongoDB Version**
  - Display only

- **Active Listeners**
  - Display status of each listener
  - Format: "Syslog: Active (Port 514)"

- **Total Events Stored**
  - Live count with refresh button

- **Total Alerts**
  - Live count with refresh button

- **Storage Usage**
  - Display database size
  - Display available disk space

- **Last Retention Cleanup**
  - Timestamp of last cleanup run
  - Number of events/alerts removed

### 2.9 Logging & Debugging
**Purpose**: Configure logging behavior

- **Log Level**
  - Options: Debug, Info, Warn, Error
  - Default: Info
  - Hot Reload: Yes

- **Log Format**
  - Options: JSON, Text
  - Default: Text
  - Hot Reload: Yes

- **Enable Request Logging**
  - Type: Boolean toggle
  - Default: Enabled
  - Description: "Log all API requests"
  - Hot Reload: Yes

- **Enable Performance Metrics**
  - Type: Boolean toggle
  - Default: Enabled
  - Hot Reload: Yes

- **Log File Path**
  - Type: File path
  - Default: "/var/log/cerberus/cerberus.log"
  - Restart Required: Yes

- **Log Rotation Size** (MB)
  - Default: 100
  - Range: 10-10000
  - Description: "Rotate log file when it reaches this size"

- **Log Retention** (days)
  - Default: 30
  - Range: 1-365
  - Description: "How long to keep old log files"

## 3. UI/UX Design

### 3.1 Page Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Settings                                                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌──────────────────────────────────────┐ │
│  │ Categories  │  │ Data Retention                        │ │
│  ├─────────────┤  │                                       │ │
│  │ ▶ Data      │  │ Event Retention Period                │ │
│  │   Retention │  │ [30        ] days                     │ │
│  │             │  │                                       │ │
│  │ ▶ Listeners │  │ Alert Retention Period                │ │
│  │             │  │ [90        ] days                     │ │
│  │ ▶ API       │  │                                       │ │
│  │   Config    │  │ Retention Check Interval              │ │
│  │             │  │ [24        ] hours                    │ │
│  │ ▶ Auth &    │  │                                       │ │
│  │   Security  │  │ [✓] Enable Automatic Cleanup          │ │
│  │             │  │                                       │ │
│  │ ▶ Storage   │  │ [Test Connection] [Save Changes]      │ │
│  │             │  │                                       │ │
│  │ ▶ Detection │  └──────────────────────────────────────┘ │
│  │   Engine    │                                           │
│  │             │                                           │
│  │ ▶ Alerting  │                                           │
│  │             │                                           │
│  │ ▶ System    │                                           │
│  │   Info      │                                           │
│  │             │                                           │
│  │ ▶ Logging   │                                           │
│  └─────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 UI Components

**Category Sidebar**
- Collapsible accordion-style categories
- Active category highlighted
- Icon for each category
- Scroll independently from main content

**Settings Panel**
- Card-based layout for each setting group
- Clear labels and descriptions
- Inline validation messages
- Help tooltips for complex settings
- "Restart Required" badges where applicable

**Form Controls**
- Number inputs with +/- buttons and validation
- Toggle switches for boolean settings
- Dropdown selects for enums
- Secure password fields with visibility toggle
- File path inputs with browse button
- Multi-value inputs with chip display

**Action Buttons**
- **Save Changes**: Primary button (top-right)
- **Reset to Defaults**: Secondary button
- **Test Connection**: For network settings
- **Apply Without Restart**: Hot-reload capable settings
- **Export Configuration**: Download current config
- **Import Configuration**: Upload config file

**Status Indicators**
- **Unsaved Changes**: Yellow warning banner
- **Restart Required**: Orange badge on affected settings
- **Last Saved**: Timestamp display
- **Validation Errors**: Red inline messages

### 3.3 User Flows

#### Modifying a Setting
1. User navigates to Settings page
2. User selects category from sidebar
3. User modifies setting value
4. System validates input immediately
5. "Save Changes" button becomes enabled
6. If restart required, badge appears
7. User clicks "Save Changes"
8. System saves to backend
9. Success notification appears
10. If restart required, prompt user to restart

#### Importing Configuration
1. User clicks "Import Configuration"
2. File upload dialog appears
3. User selects YAML/JSON config file
4. System validates configuration
5. Preview of changes shown
6. User confirms import
7. Settings updated
8. Restart prompt if needed

#### Testing Connections
1. User modifies SMTP/MongoDB settings
2. User clicks "Test Connection"
3. System attempts connection
4. Success/failure message displayed
5. Details shown if connection fails

## 4. Technical Implementation

### 4.1 Backend API Design

#### Endpoints

**GET /api/v1/settings**
- Returns current configuration
- Response includes all editable settings
- Masks sensitive values (passwords, secrets)
- Returns metadata (restart_required flags, validation rules)

```json
{
  "retention": {
    "events": 30,
    "alerts": 90,
    "check_interval": 24,
    "auto_cleanup": true
  },
  "listeners": {
    "syslog": {
      "enabled": true,
      "port": 514,
      "host": "0.0.0.0"
    },
    "cef": { ... },
    "json": { ... }
  },
  "api": { ... },
  "auth": {
    "enabled": false,
    "jwt_secret": "***MASKED***",
    "token_expiry_hours": 24
  },
  "storage": { ... },
  "engine": { ... },
  "alerting": { ... },
  "logging": { ... }
}
```

**GET /api/v1/settings/schema**
- Returns validation schema for all settings
- Includes min/max values, types, descriptions
- Used by frontend for validation

```json
{
  "retention.events": {
    "type": "integer",
    "min": 1,
    "max": 365,
    "default": 30,
    "description": "How long to keep event logs (days)",
    "restart_required": false,
    "category": "retention"
  },
  ...
}
```

**PUT /api/v1/settings**
- Updates configuration settings
- Validates all changes
- Returns which settings require restart
- Applies hot-reloadable settings immediately

Request:
```json
{
  "retention": {
    "events": 60,
    "alerts": 120
  }
}
```

Response:
```json
{
  "success": true,
  "message": "Settings updated successfully",
  "applied_immediately": ["retention.events", "retention.alerts"],
  "requires_restart": [],
  "validation_errors": []
}
```

**POST /api/v1/settings/validate**
- Validates settings without saving
- Used for real-time validation

**POST /api/v1/settings/reset**
- Resets all settings to defaults
- Requires confirmation

**POST /api/v1/settings/test-connection**
- Tests connection for specific service
- Types: mongodb, smtp, slack

Request:
```json
{
  "service": "mongodb",
  "settings": {
    "connection_string": "mongodb://localhost:27017",
    "database": "cerberus"
  }
}
```

**GET /api/v1/settings/export**
- Exports current configuration as YAML/JSON
- Used for backup and migration

**POST /api/v1/settings/import**
- Imports configuration from file
- Validates before applying
- Returns preview of changes

**GET /api/v1/system/info**
- Returns system information (read-only)
- Version, uptime, storage stats, etc.

### 4.2 Backend Implementation

#### New Package: config/settings.go

```go
package config

// SettingsManager handles runtime configuration updates
type SettingsManager struct {
    config       *Config
    configPath   string
    hotReloadCh  chan *Config
    mu           sync.RWMutex
}

// UpdateSettings validates and applies configuration changes
func (sm *SettingsManager) UpdateSettings(updates map[string]interface{}) (*UpdateResult, error)

// ValidateSettings checks if settings are valid
func (sm *SettingsManager) ValidateSettings(settings map[string]interface{}) []ValidationError

// GetSchema returns validation schema for all settings
func (sm *SettingsManager) GetSchema() map[string]SettingSchema

// ApplyHotReload applies changes that don't require restart
func (sm *SettingsManager) ApplyHotReload(settings map[string]interface{}) error

// SaveToFile persists settings to config.yaml
func (sm *SettingsManager) SaveToFile() error

// GetRestartRequired returns list of settings that need restart
func (sm *SettingsManager) GetRestartRequired(changes map[string]interface{}) []string
```

#### API Handlers: api/settings_handlers.go

```go
package api

func (a *API) getSettings(w http.ResponseWriter, r *http.Request)
func (a *API) updateSettings(w http.ResponseWriter, r *http.Request)
func (a *API) getSettingsSchema(w http.ResponseWriter, r *http.Request)
func (a *API) validateSettings(w http.ResponseWriter, r *http.Request)
func (a *API) resetSettings(w http.ResponseWriter, r *http.Request)
func (a *API) testConnection(w http.ResponseWriter, r *http.Request)
func (a *API) exportSettings(w http.ResponseWriter, r *http.Request)
func (a *API) importSettings(w http.ResponseWriter, r *http.Request)
func (a *API) getSystemInfo(w http.ResponseWriter, r *http.Request)
```

#### Sensitive Data Handling

```go
// MaskSensitiveSettings masks passwords and secrets
func MaskSensitiveSettings(config *Config) *Config {
    masked := *config
    if config.Auth.JWTSecret != "" {
        masked.Auth.JWTSecret = "***MASKED***"
    }
    if config.Alerting.SMTP.Password != "" {
        masked.Alerting.SMTP.Password = "***MASKED***"
    }
    if config.Alerting.Slack.WebhookURL != "" {
        masked.Alerting.Slack.WebhookURL = "***MASKED***"
    }
    return &masked
}
```

### 4.3 Frontend Implementation

#### Types (frontend/src/types/index.ts)

```typescript
export interface Settings {
  retention: RetentionSettings;
  listeners: ListenerSettings;
  api: APISettings;
  auth: AuthSettings;
  storage: StorageSettings;
  engine: EngineSettings;
  alerting: AlertingSettings;
  logging: LoggingSettings;
}

export interface RetentionSettings {
  events: number;
  alerts: number;
  check_interval: number;
  auto_cleanup: boolean;
}

export interface SettingSchema {
  type: 'integer' | 'string' | 'boolean' | 'password';
  min?: number;
  max?: number;
  default: any;
  description: string;
  restart_required: boolean;
  category: string;
  options?: string[]; // For enum types
  conditional?: string; // Shows only if another setting is true
}

export interface SettingsUpdateResult {
  success: boolean;
  message: string;
  applied_immediately: string[];
  requires_restart: string[];
  validation_errors: ValidationError[];
}

export interface SystemInfo {
  version: string;
  uptime: number;
  go_version: string;
  mongodb_version: string;
  total_events: number;
  total_alerts: number;
  storage_size: number;
  last_cleanup: string;
  active_listeners: ListenerStatus[];
}
```

#### API Service (frontend/src/services/api.ts)

```typescript
async getSettings(): Promise<Settings>
async updateSettings(settings: Partial<Settings>): Promise<SettingsUpdateResult>
async getSettingsSchema(): Promise<Record<string, SettingSchema>>
async validateSettings(settings: Partial<Settings>): Promise<ValidationResult>
async resetSettings(): Promise<void>
async testConnection(service: string, settings: any): Promise<ConnectionTestResult>
async exportSettings(format: 'json' | 'yaml'): Promise<Blob>
async importSettings(file: File): Promise<SettingsUpdateResult>
async getSystemInfo(): Promise<SystemInfo>
```

#### Settings Page Component (frontend/src/pages/Settings/index.tsx)

```typescript
function Settings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [schema, setSchema] = useState<Record<string, SettingSchema>>({});
  const [activeCategory, setActiveCategory] = useState('retention');
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [restartRequired, setRestartRequired] = useState<string[]>([]);

  // Components:
  // - CategorySidebar: Navigation
  // - SettingsPanel: Main content area
  // - SettingGroup: Card for each group
  // - SettingField: Individual setting input
  // - RestartWarning: Banner when restart needed
  // - UnsavedChanges: Warning banner
}
```

#### Setting Field Components

```typescript
// Reusable setting field components
- NumberField: With validation, +/- buttons
- TextField: Standard text input
- PasswordField: Masked with show/hide
- ToggleField: Switch component
- SelectField: Dropdown
- FilePathField: Input with browse
- MultiValueField: Chips for multiple values
```

## 5. Security Considerations

### 5.1 Authentication
- Settings page requires admin privileges
- JWT token validation on all endpoints
- Audit log for all settings changes

### 5.2 Sensitive Data Protection
- Never send actual passwords/secrets to frontend
- Always mask in GET responses
- Encrypt sensitive fields in config file
- Use environment variables for secrets
- Validate file paths to prevent directory traversal

### 5.3 Validation
- Server-side validation for all inputs
- Prevent injection attacks
- Validate file uploads
- Check permissions on file paths
- Validate network addresses and ports

### 5.4 Audit Trail
- Log all settings changes with timestamp
- Record user who made change
- Track old and new values (except passwords)
- Export audit log capability

## 6. Validation Rules

### Port Numbers
- Range: 1-65535
- Check for conflicts with other listeners
- Warn if using privileged ports (<1024)

### File Paths
- Must exist or be creatable
- Check permissions
- Prevent path traversal attacks
- Validate for appropriate file types

### Email Addresses
- Valid RFC 5322 format
- Support multiple recipients

### Connection Strings
- Valid MongoDB URI format
- Parse and validate components

### Retention Periods
- Minimum 1 day
- Maximum 2 years (730 days)
- Events retention ≤ Alerts retention (recommended)

### JWT Secrets
- Minimum 32 characters
- Must contain mix of characters
- Warn if weak

## 7. Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Create settings backend package
- [ ] Implement settings storage and retrieval
- [ ] Add settings API endpoints
- [ ] Create settings frontend types
- [ ] Build basic settings page layout
- [ ] Implement category navigation

### Phase 2: Core Settings (Week 2)
- [ ] Implement Data Retention settings
- [ ] Implement Listener settings
- [ ] Implement API configuration
- [ ] Add validation for all fields
- [ ] Implement save functionality
- [ ] Add unsaved changes detection

### Phase 3: Security & Auth (Week 3)
- [ ] Implement Authentication settings
- [ ] Add password masking
- [ ] Implement sensitive data encryption
- [ ] Add connection testing
- [ ] Implement audit logging
- [ ] Add admin permission checks

### Phase 4: Advanced Features (Week 4)
- [ ] Implement Storage settings
- [ ] Implement Detection Engine settings
- [ ] Implement Alerting settings
- [ ] Implement Logging settings
- [ ] Add System Info panel
- [ ] Implement hot-reload capability

### Phase 5: Import/Export (Week 5)
- [ ] Implement configuration export
- [ ] Implement configuration import
- [ ] Add import preview
- [ ] Add validation for imports
- [ ] Implement reset to defaults
- [ ] Add configuration backup/restore

### Phase 6: Polish & Testing (Week 6)
- [ ] Add comprehensive validation
- [ ] Implement error handling
- [ ] Add success/error notifications
- [ ] Create unit tests
- [ ] Create integration tests
- [ ] Add documentation
- [ ] Perform security audit

## 8. User Documentation

### 8.1 Help Text
Each setting should have:
- Clear label
- Descriptive tooltip
- Examples where applicable
- Warning for dangerous changes
- Link to documentation

### 8.2 In-App Guidance
- First-time setup wizard
- Recommended settings indicator
- "Why this matters" explanations
- Common configuration scenarios

### 8.3 Best Practices
- Retention period recommendations based on compliance
- Performance impact warnings
- Security hardening tips
- Listener configuration examples

## 9. Success Criteria

- [ ] Users can modify all configuration settings via UI
- [ ] Settings validate before saving
- [ ] Restart requirements clearly communicated
- [ ] Sensitive data properly protected
- [ ] Changes audit logged
- [ ] Configuration exportable/importable
- [ ] System information readily available
- [ ] Connection testing works reliably
- [ ] Hot-reload works for applicable settings
- [ ] UI is intuitive and well-organized

## 10. Future Enhancements

- **Multi-tenancy**: Per-tenant settings overrides
- **Role-based settings**: Different settings visible to different roles
- **Settings versioning**: Track configuration history
- **Scheduled changes**: Apply settings at specific time
- **Settings templates**: Predefined configurations for common scenarios
- **Comparison view**: Compare current vs. default vs. imported
- **Settings search**: Quick find for specific settings
- **Bulk operations**: Change multiple settings at once
- **Settings recommendations**: AI-suggested optimizations
- **Remote management**: Manage multiple Cerberus instances
