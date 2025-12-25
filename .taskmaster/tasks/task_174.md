# Task ID: 174

**Title:** Update Frontend for Unified Rule Management

**Status:** in-progress

**Dependencies:** 173 ✓

**Priority:** medium

**Description:** Modify React frontend to handle unified rules table with category filter, correlation config editor, testing panel, and lifecycle controls

**Details:**

Implementation:

1. Update frontend/src/pages/Rules/index.tsx:
   - Add category filter dropdown (Detection/Correlation/All)
   - Add lifecycle status badge display
   - Add performance metrics column (avg eval time)
   - Update table columns for unified schema

2. Modify frontend/src/components/forms/RuleForm.tsx:
   - Dynamic form based on rule category
   - Show correlation config editor when category=correlation
   - Add lifecycle status selector
   - YAML editor with syntax highlighting (use react-codemirror2)
   - Real-time YAML validation

3. Create frontend/src/components/CorrelationConfigEditor.tsx:
   - Type selector (event_count, value_count, etc.)
   - Type-specific field inputs (group_by, timespan, condition)
   - Visual builder mode + raw YAML mode toggle
   - Preview generated SIGMA YAML

4. Create frontend/src/components/RuleTestPanel.tsx:
   - Event input (JSON array or file upload)
   - Test execution button
   - Results display (matched events, correlation state)
   - Evaluation time metrics

5. Create frontend/src/components/RuleLifecyclePanel.tsx:
   - State transition diagram
   - Promote/Deprecate/Archive buttons
   - Deprecation reason input
   - Sunset date picker
   - Lifecycle history timeline

6. Add frontend/src/pages/Rules/PerformanceDashboard.tsx:
   - Slow rules table (threshold configurable)
   - Evaluation time charts (Chart.js)
   - Top rules by match count
   - False positive reporting

7. Update API client frontend/src/services/api.ts:
   - Add unified rules endpoints
   - Add lifecycle endpoints
   - Add testing endpoints
   - Add performance endpoints

8. Remove deprecated CorrelationRules page after transition period

**Test Strategy:**

Create frontend/e2e/unified-rules.spec.ts:
1. Test category filtering works
2. Test creating detection rule
3. Test creating correlation rule with config
4. Test YAML editor validation
5. Test rule testing panel
6. Test lifecycle state transitions
7. Test performance dashboard loads
8. Test import/export workflow
9. Visual regression tests for new components
10. Accessibility audit (WCAG AA compliance)

## Subtasks

### 174.1. Update Rules/index.tsx with category filter, lifecycle badges, and metrics

**Status:** pending  
**Dependencies:** None  

Add category filter dropdown (Detection/Correlation/All), lifecycle status badge display, performance metrics column (avg eval time), and update table columns for unified schema

**Details:**

Modify frontend/src/pages/Rules/index.tsx to add: 1) Category filter dropdown using existing UI components with three options (Detection/Correlation/All), 2) Lifecycle status badge component displaying rule state with color coding, 3) Performance metrics column showing average evaluation time from backend, 4) Update table columns to display unified schema fields (category, logsource_category, logsource_product, logsource_service). Use existing patterns from the file for table rendering and filtering. Ensure pagination works with new filters.

### 174.2. Modify RuleForm.tsx for dynamic category-based form rendering

**Status:** pending  
**Dependencies:** 174.1  

Implement dynamic form rendering based on rule category with react-hook-form and Zod validation, add lifecycle status selector, and integrate YAML editor with syntax highlighting

**Details:**

Update frontend/src/components/forms/RuleForm.tsx to: 1) Add category selector that switches form fields dynamically, 2) Conditionally render detection fields (sigma_yaml) vs correlation fields (correlation_config), 3) Add lifecycle status dropdown (testing/production/deprecated/archived), 4) Integrate react-codemirror2 for YAML editor with YAML syntax highlighting mode, 5) Implement real-time YAML validation using js-yaml parser with error display, 6) Update Zod schema to validate based on selected category, 7) Maintain existing react-hook-form patterns. Handle form state management carefully for mode switching.

### 174.3. Create CorrelationConfigEditor.tsx with visual and YAML modes

**Status:** pending  
**Dependencies:** 174.2  

Build CorrelationConfigEditor component with type selector, type-specific field inputs for 7 correlation types, visual builder mode, raw YAML mode toggle, and YAML preview

**Details:**

Create frontend/src/components/CorrelationConfigEditor.tsx with: 1) Correlation type dropdown (event_count, value_count, temporal_proximity, value_list, rare_value, threshold, sequence), 2) Dynamic field inputs based on type (group_by, timespan, condition, threshold, etc.) using controlled components, 3) Visual builder UI with form fields for each correlation type's specific requirements, 4) Toggle switch between visual builder and raw YAML editor, 5) Live YAML preview pane showing generated correlation config, 6) Bidirectional sync between visual mode and YAML mode, 7) Validation for type-specific required fields. Use TypeScript interfaces for each correlation type's config structure.

### 174.4. Build RuleTestPanel.tsx with event input and results visualization

**Status:** pending  
**Dependencies:** 174.2  

Create RuleTestPanel component with event input (JSON array or file upload), test execution button, results display showing matched events and correlation state, and evaluation time metrics

**Details:**

Create frontend/src/components/RuleTestPanel.tsx with: 1) Event input textarea accepting JSON array format with syntax validation, 2) File upload button accepting .json files with proper parsing, 3) Test execution button that calls testing API endpoint, 4) Loading state during test execution (use polling or WebSocket if available), 5) Results section displaying: matched events count, matched event details (expandable list), correlation state for correlation rules, evaluation time in milliseconds, 6) Error handling for invalid events or test failures, 7) Clear/reset functionality. Style results with success/failure indicators. Consider using react-json-view for event display.

### 174.5. Create RuleLifecyclePanel.tsx with state diagram and transition controls

**Status:** pending  
**Dependencies:** 174.1  

Build RuleLifecyclePanel component with state transition diagram visualization, promote/deprecate/archive buttons, deprecation reason input, sunset date picker, and lifecycle history timeline

**Details:**

Create frontend/src/components/RuleLifecyclePanel.tsx with: 1) State diagram using reactflow or mermaid showing testing→production→deprecated→archived transitions, 2) Action buttons for state transitions (promote, deprecate, archive) with proper permissions checks, 3) Deprecation reason textarea (required when deprecating), 4) Sunset date picker using react-datepicker (required when deprecating), 5) Lifecycle history timeline showing all state changes with timestamps and user info, 6) Confirmation modals for destructive actions, 7) Visual indication of current state. Use existing API patterns for state mutation calls. Disable invalid transitions based on current state.

### 174.6. Add Rules/PerformanceDashboard.tsx with charts and slow rules table

**Status:** pending  
**Dependencies:** 174.1  

Create PerformanceDashboard page with slow rules table, evaluation time charts using Chart.js, top rules by match count, and false positive reporting interface

**Details:**

Create frontend/src/pages/Rules/PerformanceDashboard.tsx with: 1) Slow rules table showing rules exceeding configurable threshold (default 100ms) with sortable columns, 2) Evaluation time chart using Chart.js (line/bar chart) showing avg/min/max times over time period selector, 3) Top rules by match count table with pagination, 4) False positive reporting form (select rule, add reason, submit), 5) Dashboard filters (time range, rule category, lifecycle status), 6) Data fetching from performance metrics endpoints with loading states, 7) Responsive layout using grid/flexbox. Integrate Chart.js with react-chartjs-2 wrapper. Add export to CSV functionality for tables.

### 174.7. Update api.ts client with all unified rules endpoints

**Status:** pending  
**Dependencies:** None  

Add API client functions for unified rules CRUD, lifecycle management, rule testing, and performance metrics endpoints to frontend/src/services/api.ts

**Details:**

Update frontend/src/services/api.ts to add: 1) Unified rules endpoints: getRules(category?, status?), getRule(id), createRule(data), updateRule(id, data), deleteRule(id), 2) Lifecycle endpoints: promoteRule(id), deprecateRule(id, reason, sunsetDate), archiveRule(id), getRuleHistory(id), 3) Testing endpoints: testRule(id, events), 4) Performance endpoints: getPerformanceMetrics(timeRange?), getSlowRules(threshold?), getTopRules(limit?), reportFalsePositive(ruleId, reason), 5) Proper TypeScript types for all request/response payloads, 6) Error handling with try-catch, 7) Use existing axios instance patterns. Add JSDoc comments for all new functions.

### 174.8. Write comprehensive e2e tests with accessibility audit

**Status:** pending  
**Dependencies:** 174.1, 174.2, 174.3, 174.4, 174.5, 174.6, 174.7  

Create frontend/e2e/unified-rules.spec.ts with comprehensive Playwright tests covering all workflows, accessibility audit using axe-core, and visual regression tests

**Details:**

Create frontend/e2e/unified-rules.spec.ts with Playwright tests: 1) Category filtering test (verify filtering works for Detection/Correlation/All), 2) Create detection rule test (fill form, submit, verify creation), 3) Create correlation rule test with CorrelationConfigEditor (use visual mode, verify YAML preview, submit), 4) YAML editor validation test (enter invalid YAML, verify error display), 5) Rule testing panel test (upload events, execute test, verify results), 6) Lifecycle state transitions test (promote, deprecate, archive with reason/date), 7) Performance dashboard test (verify charts render, slow rules table loads), 8) Import/export test if applicable, 9) Accessibility audit using @axe-core/playwright on all pages (WCAG AA compliance), 10) Visual regression tests using Playwright screenshots. Use page object pattern. Ensure all tests are deterministic and clean up test data.
