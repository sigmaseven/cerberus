# Task ID: 156

**Title:** Create SIGMA Feeds Settings UI Components

**Status:** done

**Dependencies:** 155 ✓

**Priority:** high

**Description:** Build React components for feed management in the Settings page including list view, forms, and detail panels

**Details:**

Create frontend/src/pages/Settings/SigmaFeedsSettings.tsx as main component:

Components to build:
1. FeedListView - Table/card layout showing all feeds
   - Columns: Name, Type, Status badge, Rule count, Last sync, Actions
   - Status badges with colors: active (green), disabled (gray), error (red), syncing (blue)
   - Enable/disable toggle per feed
   - Quick actions: Sync button, Edit button, Delete button with confirmation
   - "Add Feed" button opens creation dialog
   - "Sync All" button triggers all enabled feeds
   - Filter dropdown by status (Active/Disabled/Error)

2. FeedFormDialog - Create/Edit modal
   - Form fields:
     * Name (required text input)
     * Description (optional textarea)
     * Type selector (Git Repository / Local Filesystem)
     * Conditional fields based on type:
       - Git: URL (required), Branch, Auth (username/password/token)
       - Filesystem: Path (required)
     * Rules Path (subdirectory)
     * Include Patterns (multi-input with add/remove)
     * Exclude Patterns (multi-input with add/remove)
     * Tag Filters (multi-input with autocomplete)
     * Min Severity (dropdown: low/medium/high/critical)
     * Priority (number input)
     * Update Strategy (dropdown: Manual/Startup/Scheduled)
     * Schedule (cron input if scheduled)
     * Auto-enable Rules (checkbox)
     * Enabled (toggle)
   - "Test Connection" button validates config
   - "Use Template" dropdown pre-populates from templates
   - Save/Cancel actions with loading states
   - Form validation using React Hook Form + Zod

3. FeedDetailModal - Detailed view
   - Tabs: Overview, Statistics, Sync History
   - Overview: Full configuration display
   - Statistics: Pie charts (rules by severity, import status)
   - Sync History: Paginated table with expand for errors
   - "Sync Now" button with progress indicator

4. SyncProgressIndicator - Shows sync status
   - Spinner during sync
   - Progress percentage if available
   - Success/error toast on completion

Integrate into Settings page (frontend/src/pages/Settings/index.tsx):
- Add new tab "SIGMA Feeds" with icon
- Mount SigmaFeedsSettings component in TabPanel

Styling:
- Use Material-UI components for consistency
- Responsive design with mobile support
- Loading skeletons during data fetch
- Error boundaries for graceful failures

**Test Strategy:**

Unit tests: Test component rendering with different feed states, form validation, user interactions. Integration tests with Playwright: Create feed via UI, edit feed, trigger sync, verify updates, delete feed, test error handling.

## Subtasks

### 156.1. Create FeedListView component with table/card layout and filtering

**Status:** pending  
**Dependencies:** None  

Build the main list view component that displays all SIGMA feeds in a Material-UI table/card layout with status badges, filters, and bulk actions

**Details:**

Create FeedListView component in frontend/src/pages/Settings/SigmaFeedsSettings.tsx:

- Implement responsive table/card layout using MUI DataGrid or Table component
- Add columns: Name, Type, Status badge, Rule count, Last sync timestamp, Actions column
- Create status badge component with color coding: active (green), disabled (gray), error (red), syncing (blue)
- Add per-feed quick actions: Enable/disable toggle, Sync button with loading state, Edit button, Delete button with confirmation dialog
- Implement toolbar with 'Add Feed' button (opens FeedFormDialog) and 'Sync All' button with confirmation
- Add filter dropdown for status (All/Active/Disabled/Error/Syncing)
- Integrate with feedsService API for fetching feeds list
- Add loading skeletons during data fetch
- Implement error boundary for graceful error handling
- Add empty state when no feeds exist
- Use React Query or similar for data fetching and caching

### 156.2. Build FeedFormDialog with dynamic fields and validation

**Status:** pending  
**Dependencies:** 156.1  

Implement create/edit modal dialog with conditional field rendering based on feed type, comprehensive validation using React Hook Form and Zod, and template selection support

**Details:**

Create FeedFormDialog component:

- Implement modal dialog using MUI Dialog component with responsive design
- Set up React Hook Form with Zod schema validation for all fields
- Add form fields: Name (required), Description (textarea), Type selector (Git/Filesystem radio/select)
- Implement conditional rendering:
  * Git type: URL (required, URL validation), Branch (default 'main'), Auth section (username/password/token with visibility toggle)
  * Filesystem type: Path (required, path validation)
- Add Rules Path field (subdirectory within repo/filesystem)
- Create multi-input components for Include Patterns and Exclude Patterns (array field with add/remove buttons)
- Add Tag Filters multi-input with autocomplete from existing tags
- Add Min Severity dropdown (low/medium/high/critical)
- Add Priority number input with validation (0-100)
- Add Update Strategy dropdown (Manual/Startup/Scheduled) with conditional Schedule cron input
- Add Auto-enable Rules checkbox and Enabled toggle
- Implement 'Test Connection' button that validates config via API
- Add 'Use Template' dropdown that pre-populates form from predefined templates
- Add Save/Cancel buttons with loading states and error handling
- Implement field-level and form-level error display

### 156.3. Implement FeedDetailModal with tabbed interface and visualizations

**Status:** pending  
**Dependencies:** 156.1  

Create detailed view modal with three tabs (Overview, Statistics, Sync History) including charts for rule statistics and paginated sync history table

**Details:**

Create FeedDetailModal component:

- Implement modal dialog with MUI Tabs component for navigation
- Tab 1 - Overview:
  * Display all feed configuration in read-only formatted layout
  * Show feed metadata (created date, updated date, last sync)
  * Display patterns and filters as chips/badges
  * Add 'Edit' button that opens FeedFormDialog in edit mode
- Tab 2 - Statistics:
  * Fetch feed statistics from API
  * Create pie chart for rules by severity using recharts or MUI X Charts
  * Create pie/bar chart for import status (imported/failed/skipped)
  * Display key metrics: Total rules, Active rules, Last sync duration
  * Show error summary if sync errors exist
- Tab 3 - Sync History:
  * Implement paginated table of sync operations (date, status, rules imported, duration, errors)
  * Add expandable rows to show error details and stack traces
  * Add 'Sync Now' button in header with SyncProgressIndicator integration
  * Show detailed sync logs with filtering options
- Add loading states for each tab's data
- Implement error handling and retry logic
- Add close button and escape key handling

### 156.4. Create SyncProgressIndicator for real-time sync status

**Status:** pending  
**Dependencies:** 156.3  

Build component that displays real-time sync progress with spinner, percentage tracking, and success/error notifications using WebSocket or polling

**Details:**

Create SyncProgressIndicator component:

- Implement progress display component that can be embedded in FeedDetailModal and FeedListView
- Add MUI CircularProgress spinner during active sync
- Display progress percentage if available from backend (e.g., '45/100 rules processed')
- Show current sync stage/status text (e.g., 'Cloning repository...', 'Parsing rules...', 'Importing to database...')
- Integrate with WebSocket connection (if available) or polling mechanism to get real-time updates
- Display success toast notification on sync completion with summary (e.g., '45 rules imported, 2 failed')
- Display error toast notification on sync failure with error message and 'View Details' action
- Implement sync cancellation button (if backend supports it)
- Add retry button on error state
- Create SyncStatusBadge sub-component for displaying current sync state in lists
- Handle multiple concurrent syncs (track by feed ID)
- Add optimistic UI updates when sync is triggered
- Implement cleanup on component unmount to prevent memory leaks

### 156.5. Integrate SIGMA Feeds components into Settings page

**Status:** pending  
**Dependencies:** 156.1, 156.2, 156.3, 156.4  

Add new 'SIGMA Feeds' tab to the Settings page and mount SigmaFeedsSettings component following existing Settings page patterns and routing structure

**Details:**

Modify frontend/src/pages/Settings/index.tsx:

- Import SigmaFeedsSettings component
- Add new tab definition to tabs array with label 'SIGMA Feeds' and appropriate MUI icon (e.g., RssFeedIcon or DynamicFeedIcon)
- Add corresponding TabPanel with SigmaFeedsSettings component mounted inside
- Ensure tab index and routing follows existing pattern in Settings page
- Add lazy loading for SigmaFeedsSettings to improve initial load performance
- Verify RBAC permissions are checked (user must have 'feeds:read' permission to view tab)
- Add mobile-responsive behavior consistent with other Settings tabs
- Ensure tab persists in URL for deep linking (if Settings page supports this)
- Add any necessary context providers for feeds management state
- Update Settings page tests to include new tab
- Verify navigation between tabs works smoothly
- Add error boundary around SigmaFeedsSettings mount point
- Update any relevant TypeScript types or interfaces
- Ensure consistent styling with other Settings tabs
