# Task ID: 160

**Title:** Implement First-Run Setup Wizard for Feed Configuration

**Status:** done

**Dependencies:** 155 ✓

**Priority:** medium

**Description:** Create an interactive setup wizard for new installations to configure SIGMA feeds

**Details:**

Create frontend/src/components/FeedSetupWizard.tsx:

Wizard flow (5 steps):

Step 1: Welcome
- Title: "Welcome to Cerberus SIEM"
- Explain SIGMA rules and feed system
- "Get Started" button → Step 2
- "Skip Setup" button → close wizard, create default feed

Step 2: Select Feed Templates
- Display available templates as cards:
  * SigmaHQ Full Repository (3000+ rules)
  * SigmaHQ Windows Only (1800+ rules)
  * SigmaHQ Linux Only (400+ rules)
  * SigmaHQ Cloud (AWS/Azure/GCP, 300+ rules)
  * SigmaHQ Network (200+ rules)
  * SigmaHQ Web Application (150+ rules)
  * Custom (configure manually)
- Multi-select checkboxes
- Show rule count and description per template
- "Next" button → Step 3

Step 3: Configure Sync Schedule
- Radio buttons:
  * Manual only (no automatic sync)
  * Daily at specific time (time picker)
  * Custom cron expression (text input with helper)
- "Next" button → Step 4

Step 4: Initial Sync
- "Start Initial Sync" button
- Progress indicator showing:
  * Current feed being synced
  * Rules imported count
  * Estimated time remaining
- Use WebSocket events from task 158
- "Skip Initial Sync" option
- Auto-advance to Step 5 on completion

Step 5: Complete
- Success message
- Summary: X feeds configured, Y rules imported
- "Go to Dashboard" button
- "Manage Feeds" button → Settings/Feeds tab

Implementation:
- Use Material-UI Stepper component
- Persist wizard state in localStorage (resume on page reload)
- Show modal dialog on first app load
- Check backend flag: GET /api/v1/system/first-run
- Set flag on completion: POST /api/v1/system/complete-setup
- Can be re-opened from Settings if needed

Backend support:
- Add storage/sqlite.go methods:
  * IsFirstRun() bool - check if any feeds exist
  * SetSetupCompleted() - set flag in metadata table
- Add API endpoints in api/handlers.go:
  * GET /api/v1/system/first-run
  * POST /api/v1/system/complete-setup

**Test Strategy:**

Unit tests: Test wizard navigation, template selection, validation. Integration tests with Playwright: Complete full wizard flow, verify feeds created, test skip options, verify wizard doesn't show on subsequent loads.

## Subtasks

### 160.1. Create backend endpoints GET /api/v1/system/first-run and POST /api/v1/system/complete-setup with SQLite metadata storage

**Status:** done  
**Dependencies:** None  

Implement backend API endpoints to detect first-run state and mark setup as completed. Add SQLite storage methods for persisting setup completion flag in metadata table.

**Details:**

1. Add to storage/sqlite.go:
   - IsFirstRun() (bool, error) - check if setup_completed flag exists in metadata table, return false if any feeds exist
   - SetSetupCompleted() error - insert/update metadata table with setup_completed=true
   - Add migration if metadata table doesn't exist

2. Create api/system_handlers.go:
   - GET /api/v1/system/first-run handler:
     * Call storage.IsFirstRun()
     * Return {"firstRun": bool}
   - POST /api/v1/system/complete-setup handler:
     * Call storage.SetSetupCompleted()
     * Return success/error
   - Add RBAC checks (admin only for POST)

3. Register routes in api/api.go setupRoutes()

4. Add unit tests for storage methods and API handlers

### 160.2. Build wizard shell component frontend/src/components/FeedSetupWizard.tsx with Stepper and state management in localStorage

**Status:** done  
**Dependencies:** 160.1  

Create the main wizard component structure using Material-UI Stepper, implement localStorage-based state persistence, and set up modal display logic triggered on first app load.

**Details:**

1. Create frontend/src/components/FeedSetupWizard.tsx:
   - Use Material-UI Stepper component (5 steps)
   - State management:
     * currentStep: number
     * selectedTemplates: string[]
     * syncSchedule: {type, time, cron}
     * syncProgress: {current, total, feed}
   - Persist state to localStorage on each step change
   - Resume from localStorage on reload

2. Modal display logic:
   - Check GET /api/v1/system/first-run on app mount
   - Show modal if firstRun=true
   - Close on completion or skip

3. Navigation methods:
   - handleNext(), handleBack(), handleSkip()
   - Validation before advancing steps

4. Integrate into frontend/src/App.tsx:
   - Add FeedSetupWizard component
   - Trigger on first load
   - Option to reopen from Settings

5. Add unit tests for state management and navigation

### 160.3. Implement Steps 1-2 (Welcome and Template Selection with multi-select and cards)

**Status:** done  
**Dependencies:** 160.2  

Build Step 1 (Welcome screen) and Step 2 (Template Selection) with card-based UI, multi-select checkboxes, and validation logic.

**Details:**

1. Step 1 - Welcome:
   - Component: WelcomeStep.tsx
   - Title: "Welcome to Cerberus SIEM"
   - Content:
     * Explanation of SIGMA rules and feed system
     * Benefits of using pre-configured feeds
   - Buttons:
     * "Get Started" → advances to Step 2
     * "Skip Setup" → closes wizard, triggers default feed creation via API

2. Step 2 - Template Selection:
   - Component: TemplateSelectionStep.tsx
   - Display feed templates as Material-UI Cards in grid:
     * SigmaHQ Full Repository (3000+ rules)
     * SigmaHQ Windows Only (1800+ rules)
     * SigmaHQ Linux Only (400+ rules)
     * SigmaHQ Cloud (AWS/Azure/GCP, 300+ rules)
     * SigmaHQ Network (200+ rules)
     * SigmaHQ Web Application (150+ rules)
     * Custom (configure manually)
   - Each card:
     * Checkbox for multi-select
     * Rule count badge
     * Description text
     * Icon/visual indicator
   - Validation: At least one template must be selected
   - "Next" button → Step 3 (disabled if no selection)

3. Add unit tests for template selection and validation

### 160.4. Implement Steps 3-4 (Schedule Configuration and Initial Sync with WebSocket progress integration from task 158)

**Status:** done  
**Dependencies:** 160.3, 160.158  

Build Step 3 (Sync Schedule Configuration) with cron support and Step 4 (Initial Sync) with real-time WebSocket progress tracking.

**Details:**

1. Step 3 - Schedule Configuration:
   - Component: ScheduleConfigurationStep.tsx
   - Radio button options:
     * Manual only (no automatic sync)
     * Daily at specific time → Material-UI TimePicker
     * Custom cron expression → TextField with helper text/validation
   - Cron expression validator
   - "Next" button → Step 4

2. Step 4 - Initial Sync:
   - Component: InitialSyncStep.tsx
   - "Start Initial Sync" button:
     * Calls POST /api/v1/feeds to create selected feeds
     * Triggers POST /api/v1/feeds/sync-all
   - WebSocket integration (task 158):
     * Subscribe to feed:sync:started, feed:sync:progress, feed:sync:completed, feed:sync:failed events
     * Display progress indicator:
       - Current feed name
       - Rules imported count (X / Y)
       - Linear progress bar
       - Estimated time remaining
   - "Skip Initial Sync" button → creates feeds without syncing, advances to Step 5
   - Auto-advance to Step 5 on sync completion
   - Error handling: Show error message if sync fails, allow retry

3. Add unit tests and Playwright integration tests

### 160.5. Implement Step 5 (Completion) and modal display logic on first app load

**Status:** done  
**Dependencies:** 160.4  

Build Step 5 (Completion screen) with summary statistics and finalize modal display logic, including POST /api/v1/system/complete-setup call.

**Details:**

1. Step 5 - Completion:
   - Component: CompletionStep.tsx
   - Success message with checkmark icon
   - Summary statistics:
     * X feeds configured (count from selectedTemplates)
     * Y rules imported (from sync results)
   - Action buttons:
     * "Go to Dashboard" → navigate to /dashboard, close wizard
     * "Manage Feeds" → navigate to /settings (Feeds tab), close wizard
   - On completion: Call POST /api/v1/system/complete-setup
   - Clear localStorage wizard state

2. Finalize modal display logic:
   - Ensure modal only shows once on first run
   - Add manual trigger from Settings page:
     * Button: "Run Setup Wizard Again"
     * Allows re-running wizard after initial setup
   - Handle edge cases:
     * User closes browser mid-wizard (resume from localStorage)
     * API errors during setup completion

3. Add comprehensive end-to-end tests:
   - Full wizard flow from Step 1 to Step 5
   - Verify feeds created in backend
   - Verify first-run flag set to false
   - Verify wizard doesn't show on subsequent app loads
   - Test reopen from Settings
