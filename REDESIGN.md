# Cerberus SIEM Frontend Development Plan

## Overview
This plan outlines a modern, responsive web frontend for the Cerberus SIEM system. The application will provide security analysts with an intuitive interface for monitoring events, managing alerts, configuring detection rules, and orchestrating automated responses. Built with React and TypeScript, it will feature a professional dark theme, real-time dashboards, and comprehensive CRUD operations for system configuration.

## Technology Stack
- **Framework**: React 18 with TypeScript
- **UI Library**: Material-UI (MUI) v6 for professional components and theming
- **State Management**: Zustand for lightweight, scalable state management
- **HTTP Client**: Axios with interceptors for API communication
- **Routing**: React Router v6 for navigation
- **Charts**: Recharts for dashboard visualizations
- **Forms**: React Hook Form with Zod validation
- **Build Tool**: Vite for fast development and optimized builds
- **Testing**: Jest for unit tests, Playwright for E2E tests
- **Styling**: Emotion (built into MUI) with custom theme system

## Application Architecture

The frontend will be developed as a separate application located in a `frontend/` directory at the root of the project, allowing for independent development, deployment, and scaling of the UI layer.

### Project Structure
```
frontend/
├── public/              # Static assets (favicon, icons, etc.)
├── src/
│   ├── components/
│   │   ├── common/      # Reusable UI components (buttons, modals, tables)
│   │   ├── layout/      # App shell, navigation, header
│   │   └── forms/       # Form components for CRUD operations
│   ├── pages/           # Route-based page components
│   │   ├── Dashboard/
│   │   ├── Alerts/
│   │   ├── Events/
│   │   ├── Rules/
│   │   ├── CorrelationRules/
│   │   ├── Actions/
│   │   └── Listeners/
│   ├── hooks/           # Custom React hooks
│   ├── services/        # API service layer
│   ├── stores/          # Zustand state stores
│   ├── types/           # TypeScript type definitions
│   ├── utils/           # Helper functions
│   └── theme/           # MUI theme configuration
├── e2e/                 # Playwright end-to-end tests
├── package.json
├── vite.config.ts
├── tsconfig.json
├── playwright.config.ts
└── tailwind.config.js   # If using Tailwind instead of Emotion
```

### State Management Strategy
- **Global State**: User authentication, theme preferences, system status
- **Page State**: Form data, table filters, pagination
- **Real-time Updates**: WebSocket connection for live alerts/events (if backend supports)
- **Caching**: React Query for API data caching and synchronization

## UI/UX Design

### Design Principles
- **Professional**: Clean, enterprise-grade interface with consistent spacing and typography
- **Intuitive**: Logical navigation, clear visual hierarchy, contextual actions
- **Responsive**: Mobile-first design that adapts to desktop, tablet, and mobile
- **Accessible**: WCAG 2.1 AA compliance with keyboard navigation and screen reader support
- **Dark Theme**: Default dark theme with high contrast for extended monitoring sessions

### Color Palette
- Primary: Deep blue (#1976d2)
- Secondary: Orange accent (#ff9800)
- Success: Green (#4caf50)
- Warning: Amber (#ff9800)
- Error: Red (#f44336)
- Background: Dark gray (#121212)
- Surface: Slightly lighter gray (#1e1e1e)

### Wireframe Descriptions

#### 1. Main Dashboard
**Layout**: Full-width grid with 4 main sections
- **Top Row**: KPI cards (Total Events, Active Alerts, Rules Fired, System Health)
- **Middle Row**: Real-time charts (Events over time, Alert severity distribution)
- **Bottom Row**: Recent alerts table and system status indicators
- **Sidebar**: Collapsible navigation menu with icons

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| +----------------+ +----------------+ +----------------+ +----------------+ |
| | Total Events   | | Active Alerts  | | Rules Fired    | | System Health  | |
| |     1,234      | |      12        | |      5         | |     Good       | |
| +----------------+ +----------------+ +----------------+ +----------------+ |
+-------------------------------------------------------------+
|                                                             |
|   Events Over Time Chart                                    |
|   [Line chart showing events per hour]                       |
|                                                             |
|   Alert Severity Distribution                                |
|   [Pie chart: Critical 20%, High 30%, Medium 35%, Low 15%]  |
|                                                             |
+-------------------------------------------------------------+
| Recent Alerts Table                                         |
| +----+--------+-------+----------+-------+--------+-------+ |
| | ID | Severity| Status| Timestamp| Rule  | Source | Action| |
| +----+--------+-------+----------+-------+--------+-------+ |
| | A1 | Critical| Pending| 12:34:56| Rule1 | Server1| [Ack] | |
| | A2 | High    | Ack'd  | 12:30:45| Rule2 | Server2| [View]| |
| +----+--------+-------+----------+-------+--------+-------+ |
|                                                             |
| System Status Indicators:                                    |
| [●] Events Ingest: 95%  [●] Rules Engine: 100%  [●] DB: OK |
+-------------------------------------------------------------+
```

**Key Features**:
- Auto-refresh every 30 seconds
- Clickable KPI cards to drill down
- Hover tooltips on charts
- Status indicators with color coding

#### 2. Alerts Management Page
**Layout**: Master-detail view
- **Left Panel**: Filterable table with columns (ID, Severity, Status, Timestamp, Rule)
- **Right Panel**: Alert details with event data, acknowledge/dismiss actions
- **Toolbar**: Bulk actions, search, severity filters, date range picker

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| [Bulk Ack] [Bulk Dismiss] [Export CSV] [Search: _________] |
| [Severity: All ▼] [Status: All ▼] [Date: ____ to ____]     |
+-------------------------------------------------------------+
| ID | Severity | Status  | Timestamp | Rule  | Source | Act |
+----+----------+---------+-----------+-------+--------+-----+
| A1 | Critical | Pending | 12:34:56  | Rule1 | Srv1   |[V] |
| A2 | High     | Ack'd   | 12:30:45  | Rule2 | Srv2   |[V] |
| A3 | Medium   | Pending | 12:25:33  | Rule3 | Srv3   |[V] |
| A4 | Low      | Dismiss | 12:20:12  | Rule4 | Srv4   |[V] |
+----+----------+---------+-----------+-------+--------+-----+
|                                                             |
|                        Alert Details                        |
| +---------------------------------------------------------+ |
| | Alert ID: A1                                            | |
| | Severity: Critical                                      | |
| | Status: Pending                                         | |
| | Timestamp: 2023-10-31 12:34:56                          | |
| | Rule: Failed Login Attempts                             | |
| | Source: 192.168.1.100                                    | |
| |                                                         | |
| | Event Data:                                             | |
| | {                                                       | |
| |   "event_type": "user_login",                           | |
| |   "fields": {                                           | |
| |     "status": "failure",                                | |
| |     "user": "admin"                                     | |
| |   }                                                     | |
| | }                                                       | |
| |                                                         | |
| | [Acknowledge] [Dismiss] [View Full Event]               | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

**Key Features**:
- Real-time status updates
- Bulk acknowledge/dismiss
- Advanced filtering and search
- Export to CSV functionality

#### 3. Rules Configuration Page
**Layout**: CRUD interface with modal forms
- **Main View**: Data table with enable/disable toggles
- **Create/Edit Modal**: Multi-step form with condition builder
- **Condition Builder**: Visual interface for adding field-operator-value conditions

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| [Create Rule] [Import] [Export] [Search: _______________]  |
+-------------------------------------------------------------+
| Name | Description | Severity | Enabled | Actions          |
+------+-------------+----------+---------+------------------+
| Failed Login | Detect failed logins | Warning | [✓] | [Edit] [Delete] |
| Admin Access | Admin user access    | Critical| [✓] | [Edit] [Delete] |
| Suspicious IP| Known bad IPs        | High    | [ ] | [Edit] [Delete] |
+------+-------------+----------+---------+------------------+
|                                                             |
|                Create/Edit Rule Modal                       |
| +---------------------------------------------------------+ |
| | Rule Name: ____________________________________________ | |
| | Description: __________________________________________ | |
| | Severity: [Warning ▼]                                   | |
| | Enabled: [✓]                                            | |
| |                                                         | |
| | Conditions:                                             | |
| | +-----------------------------------------------------+ | |
| | | Field: [event_type ▼] Op: [equals ▼] Value: login | | |
| | | [AND ▼]                                              | |
| | | Field: [fields.status ▼] Op: [equals ▼] Value: fail| | |
| | | [Add Condition] [Remove]                             | |
| | +-----------------------------------------------------+ | |
| |                                                         | |
| | Actions:                                                | |
| | +-----------------------------------------------------+ | |
| | | Type: [webhook ▼]                                    | |
| | | URL: ______________________________________________ | |
| | | [Add Action] [Remove]                                | |
| | +-----------------------------------------------------+ | |
| |                                                         | |
| | JSON Preview: [Show]                                    | |
| | [Test Rule] [Save] [Cancel]                             | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

**Key Features**:
- Drag-and-drop condition ordering
- JSON preview/validation
- Test rule against sample events
- Version history and rollback

#### 4. Correlation Rules Page
**Layout**: Similar to Rules page with sequence visualization
- **Sequence Builder**: Timeline view showing event sequence with time windows
- **Condition Editor**: Advanced multi-condition builder

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| [Create Correlation Rule] [Search: _____________________]  |
+-------------------------------------------------------------+
| Name | Sequence | Window | Actions                        |
+------+----------+--------+--------------------------------+
| Brute Force | login→login→login | 5min | [Edit] [Delete]   |
+------+----------+--------+--------------------------------+
|                                                             |
|            Sequence Builder                                 |
| +---------------------------------------------------------+ |
| | Time Window: [300 ▼] seconds                             | |
| |                                                         | |
| | Sequence:                                               | |
| | [Event 1: user_login ▼] → [Event 2: user_login ▼] → ... | |
| |                                                         | |
| | Timeline:                                               | |
| | 0s ──── 60s ──── 120s ──── 180s ──── 240s ──── 300s    | |
| | [●]     [●]     [●]                                     | |
| |                                                         | |
| | Conditions:                                             | |
| | Field: fields.status = failure                          | |
| | [Add Condition]                                         | |
| |                                                         | |
| | [Save] [Cancel]                                         | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

#### 5. Actions Configuration Page
**Layout**: Card-based grid with action type templates
- **Action Cards**: Pre-configured templates for webhook, Jira, Slack, email
- **Configuration Modal**: Type-specific form fields with validation

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| [Create Action] [Search: _______________________________]  |
+-------------------------------------------------------------+
| +----------------+ +----------------+ +----------------+   |
| |   Webhook      | |     Jira       | |    Slack       |   |
| |   [Configure]  | |   [Configure]  | |  [Configure]   |   |
| | Action ID: W1  | | Action ID: J1  | | Action ID: S1  |   |
| +----------------+ +----------------+ +----------------+   |
|                                                             |
| +----------------+                                          |
| |    Email       |                                          |
| |  [Configure]   |                                          |
| | Action ID: E1  |                                          |
| +----------------+                                          |
+-------------------------------------------------------------+
|                                                             |
|                Configure Webhook Action                     |
| +---------------------------------------------------------+ |
| | Action Name: __________________________________________ | |
| | Type: Webhook                                           | |
| | URL: https://_________________________________________ | |
| | Method: [POST ▼]                                        | |
| | Headers:                                                | |
| | Key: Authorization Value: Bearer _____________________ | |
| | [Add Header]                                            | |
| |                                                         | |
| | [Test Action] [Save] [Cancel]                           | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

#### 6. Events Viewer Page
**Layout**: Paginated table with advanced filtering
- **Filters**: Date range, event type, source IP, severity
- **Details Modal**: Full event JSON with syntax highlighting

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| Date: [____] to [____] Event Type: [All ▼] Severity: [All ▼] |
| Source IP: [___________] Search: [_______________________] |
| [Apply Filters] [Clear] [Export]                           |
+-------------------------------------------------------------+
| Timestamp | Event Type | Severity | Source IP | Raw Data   |
+-----------+------------+----------+-----------+------------+
| 12:34:56  | user_login | info     | 192.1.1.1 | {JSON...}  |
| 12:33:45  | file_access| warning  | 192.1.1.2 | {JSON...}  |
| 12:32:34  | admin_cmd  | critical | 192.1.1.3 | {JSON...}  |
+-----------+------------+----------+-----------+------------+
| [Previous] [1] [2] [3] ... [10] [Next] (1-100 of 1,234)    |
|                                                             |
|                Event Details Modal                          |
| +---------------------------------------------------------+ |
| | Event ID: evt-123                                        | |
| | Timestamp: 2023-10-31 12:34:56                           | |
| | Event Type: user_login                                   | |
| | Severity: info                                           | |
| | Source: 192.168.1.100                                    | |
| |                                                         | |
| | Raw JSON:                                               | |
| | {                                                       | |
| |   "event_id": "evt-123",                                | |
| |   "event_type": "user_login",                           | |
| |   "fields": {                                           | |
| |     "user": "john",                                     | |
| |     "status": "success"                                 | |
| |   },                                                    | |
| |   "timestamp": "2023-10-31T12:34:56Z"                   | |
| | }                                                       | |
| |                                                         | |
| | [Close]                                                 | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

#### 7. Listeners Status Page
**Layout**: Status dashboard for active listeners
- **Listener Cards**: One card per listener type showing port, status, throughput
- **Configuration View**: Read-only display of current settings

**Visual Mockup**:
```
+-------------------------------------------------------------+
| [≡] Cerberus SIEM                    [User] [Settings] [≡]  |
+-------------------------------------------------------------+
| [Dashboard] [Alerts] [Events] [Rules] [Actions] [Listeners] |
+-------------------------------------------------------------+
| Listener Status Dashboard                                   |
+-------------------------------------------------------------+
| +----------------+ +----------------+ +----------------+   |
| |   Syslog       | |     CEF        | |    JSON        |   |
| |   [●] Active   | |   [●] Active   | |  [●] Active    |   |
| | Port: 514      | | Port: 515      | | Port: 8080     |   |
| | Events/min: 45 | | Events/min: 23 | | Events/min: 67 |   |
| | Errors: 0      | | Errors: 1      | | Errors: 0      |   |
| +----------------+ +----------------+ +----------------+   |
|                                                             |
| Current Configuration:                                      |
| +---------------------------------------------------------+ |
| | listeners:                                              | |
| |   syslog:                                               | |
| |     port: 514                                           | |
| |     host: "0.0.0.0"                                     | |
| |   cef:                                                  | |
| |     port: 515                                           | |
| |     host: "0.0.0.0"                                     | |
| |   json:                                                 | |
| |     port: 8080                                          | |
| |     host: "0.0.0.0"                                     | |
| |     tls: false                                          | |
| |   skip_on_error: false                                  | |
| +---------------------------------------------------------+ |
+-------------------------------------------------------------+
```

## Functional Requirements

### FR-001: Dashboard Overview
**Description**: Display real-time system metrics and recent activity
**Acceptance Criteria**:
- KPI cards show accurate counts from /api/dashboard
- Charts render historical data from /api/dashboard/chart
- Page auto-refreshes every 30 seconds
- Responsive layout works on all screen sizes

### FR-002: Alert Management
**Description**: View, acknowledge, and dismiss security alerts
**Acceptance Criteria**:
- Table displays all alerts from /api/alerts with pagination
- Acknowledge/dismiss actions call correct endpoints
- Status updates reflect in real-time
- Bulk operations work for multiple selected alerts

### FR-003: Rule CRUD Operations
**Description**: Create, read, update, delete detection rules
**Acceptance Criteria**:
- List view shows all rules from /api/rules
- Create form validates JSON schema compliance
- Edit form pre-populates existing data
- Delete shows confirmation dialog
- Enable/disable toggle updates rule status

### FR-004: Correlation Rule Management
**Description**: Manage multi-event correlation rules
**Acceptance Criteria**:
- Sequence builder allows visual event ordering
- Time window configuration in user-friendly format
- CRUD operations match detection rules functionality
- Validation prevents invalid sequences

### FR-005: Action Configuration
**Description**: Configure automated response actions
**Acceptance Criteria**:
- Template-based creation for each action type
- Type-specific configuration forms (webhook URL, Jira credentials, etc.)
- Secure credential handling (no plain text display)
- Test action functionality before saving

### FR-006: Event Monitoring
**Description**: Browse and search security events
**Acceptance Criteria**:
- Paginated list with configurable limit (1-1000)
- Advanced filters for all event fields
- JSON viewer for raw event data
- Export functionality for filtered results

### FR-007: Listener Status
**Description**: Monitor active event listeners
**Acceptance Criteria**:
- Real-time status display for each listener type
- Throughput metrics and error counts
- Configuration details shown read-only
- Health indicators with color coding

### FR-008: Authentication & Security
**Description**: Secure access to the application
**Acceptance Criteria**:
- Login form for API key authentication
- Session management with automatic logout
- Protected routes require valid authentication
- Secure storage of credentials

### FR-009: Responsive Design
**Description**: Application works on all devices
**Acceptance Criteria**:
- Mobile navigation collapses to hamburger menu
- Tables adapt to screen size with horizontal scroll
- Touch-friendly buttons and interactions
- Readable text on all screen sizes

### FR-010: Real-time Updates
**Description**: Live data synchronization
**Acceptance Criteria**:
- WebSocket connection for real-time alerts
- Automatic UI updates without page refresh
- Connection status indicator
- Graceful fallback to polling if WebSocket fails

## Testing Strategy

### Unit Testing (Jest)
- **Coverage Target**: 80% minimum
- **Test Categories**:
  - Component rendering and props
  - Custom hooks functionality
  - Utility functions
  - API service methods
  - Form validation logic
  - State store actions

### End-to-End Testing (Playwright)
- **Test Scenarios**:
  - User authentication flow
  - Dashboard data loading and refresh
  - CRUD operations for all entities
  - Alert management workflow
  - Rule creation and validation
  - Real-time updates
  - Responsive behavior across viewports
  - Error handling and edge cases

### Playwright Configuration
```javascript
// frontend/playwright.config.ts
export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL: 'http://localhost:3000',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'Mobile Chrome', use: { ...devices['Pixel 5'] } },
  ],
});
```

### Test Structure
```
e2e/
├── auth.spec.ts          # Authentication tests
├── dashboard.spec.ts     # Dashboard functionality
├── alerts.spec.ts        # Alert management
├── rules.spec.ts         # Rule CRUD operations
├── actions.spec.ts       # Action configuration
├── events.spec.ts        # Event browsing
└── responsive.spec.ts    # Cross-device testing
```

## Implementation Plan

### Phase 1: Foundation (Week 1-2)
- Set up React + TypeScript + Vite project
- Configure MUI theme and basic layout
- Implement authentication and routing
- Create API service layer
- Set up testing frameworks

### Phase 2: Core Pages (Week 3-4)
- Build dashboard with charts and KPIs
- Implement alerts management page
- Create events viewer
- Add listeners status page

### Phase 3: CRUD Interfaces (Week 5-6)
- Rules management with form builder
- Correlation rules with sequence builder
- Actions configuration with templates
- Implement all CRUD operations

### Phase 4: Polish & Testing (Week 7-8)
- Add real-time updates
- Implement responsive design
- Write comprehensive unit tests
- Create Playwright E2E test suite
- Performance optimization and accessibility audit

### Phase 5: Deployment (Week 9)
- Build optimization and bundling
- Docker containerization
- CI/CD pipeline setup
- Documentation and handover

## Success Metrics
- **Performance**: <2s initial load, <500ms subsequent navigation
- **Accessibility**: WCAG 2.1 AA compliance score >95%
- **Test Coverage**: 80% unit test coverage, 100% critical E2E flows
- **User Satisfaction**: Intuitive navigation, responsive design, real-time updates
- **Maintainability**: Clean code structure, comprehensive documentation, type safety

This plan provides a solid foundation for building a professional SIEM frontend that meets enterprise security monitoring needs while maintaining developer productivity and user experience excellence.