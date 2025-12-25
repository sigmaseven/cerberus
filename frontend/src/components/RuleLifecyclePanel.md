# RuleLifecyclePanel Component

## Overview

The `RuleLifecyclePanel` component provides comprehensive lifecycle management for detection rules in the Cerberus SIEM system. It enables analysts to manage rule maturity through a well-defined lifecycle process, from experimental development through stable production use to eventual deprecation and archival.

## Features

### 1. Visual State Diagram
- Interactive flowchart showing all lifecycle states
- Highlighted current state with color coding
- Clickable nodes for valid transitions
- Visual arrows indicating progression path
- Accessibility-compliant with ARIA labels

### 2. Current Status Display
- Large, prominent status badge
- Color-coded by lifecycle stage:
  - **Green**: Stable, Active (production-ready)
  - **Blue**: Test (under evaluation)
  - **Yellow**: Experimental (development)
  - **Red**: Deprecated (no longer recommended)
  - **Gray**: Archived (disabled)
- Time in current status calculation
- Clear visual hierarchy

### 3. Transition Controls
- **Promote**: Progress to next maturity level
  - Experimental → Test
  - Test → Stable
  - Stable → Active
- **Activate**: Quick transition to production
- **Deprecate**: Mark as no longer recommended
- **Archive**: Permanently disable rule
- Buttons disabled for invalid transitions
- Loading states during operations

### 4. Deprecation Dialog
- Required deprecation reason input
- Optional sunset date picker (future dates only)
- Warning about impact on active alerts
- Validation feedback
- Cancel and submit actions

### 5. Archive Confirmation
- Clear warning about permanent disabling
- Confirmation dialog
- Impact explanation
- Safe cancel option

### 6. Lifecycle History Timeline
- Vertical timeline using MUI Timeline component
- All status transitions with timestamps
- User attribution for changes
- Optional comments for context
- Expandable/collapsible view
- Color-coded status chips
- Most recent changes first

## Lifecycle States

### Experimental
- **Purpose**: Development and initial testing
- **Valid Transitions**: Test, Deprecated, Active
- **Color**: Yellow/Warning
- **Alerts**: Generated but flagged as experimental

### Test
- **Purpose**: Evaluation in test environment
- **Valid Transitions**: Stable, Experimental, Deprecated, Active
- **Color**: Blue/Primary
- **Alerts**: Generated with test flag

### Stable
- **Purpose**: Proven reliable but not yet activated
- **Valid Transitions**: Active, Deprecated
- **Color**: Green/Success
- **Alerts**: Generated normally

### Active
- **Purpose**: Production use, actively maintained
- **Valid Transitions**: Deprecated
- **Color**: Green/Success
- **Alerts**: Full production alerting

### Deprecated
- **Purpose**: No longer recommended, pending removal
- **Valid Transitions**: Active, Archived
- **Color**: Red/Error
- **Alerts**: Generated with deprecation notice
- **Metadata**: Reason and sunset date

### Archived
- **Purpose**: Permanently disabled, historical record
- **Valid Transitions**: None
- **Color**: Gray/Default
- **Alerts**: No alerts generated

## Usage

### Basic Usage

```typescript
import { RuleLifecyclePanel } from '../components/RuleLifecyclePanel';

function RuleDetailPage() {
  const [currentStatus, setCurrentStatus] = useState<LifecycleStatus>('experimental');

  return (
    <RuleLifecyclePanel
      ruleId="rule-12345"
      currentStatus={currentStatus}
      onStatusChange={(newStatus) => setCurrentStatus(newStatus)}
    />
  );
}
```

### With React Query Integration

```typescript
import { useQuery } from '@tanstack/react-query';
import { RuleLifecyclePanel } from '../components/RuleLifecyclePanel';

function RuleManagement() {
  const { data: rule } = useQuery({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getRule(ruleId),
  });

  if (!rule) return <CircularProgress />;

  return (
    <RuleLifecyclePanel
      ruleId={rule.id}
      currentStatus={rule.lifecycle_status}
      onStatusChange={() => {
        // Optionally refetch rule data
        queryClient.invalidateQueries(['rule', ruleId]);
      }}
    />
  );
}
```

### In Rule Detail Modal

```typescript
import { Dialog, DialogContent, Tabs, Tab } from '@mui/material';
import { RuleLifecyclePanel } from '../components/RuleLifecyclePanel';

function RuleDetailModal({ ruleId, open, onClose }) {
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <Tabs value={activeTab} onChange={(_, val) => setActiveTab(val)}>
        <Tab label="Overview" />
        <Tab label="Lifecycle" />
        <Tab label="History" />
      </Tabs>

      <DialogContent>
        {activeTab === 1 && (
          <RuleLifecyclePanel
            ruleId={ruleId}
            currentStatus={rule.lifecycle_status}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
```

## Props

### RuleLifecyclePanelProps

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `ruleId` | `string` | Yes | Unique identifier for the rule |
| `currentStatus` | `LifecycleStatus` | Yes | Current lifecycle status of the rule |
| `onStatusChange` | `(newStatus: LifecycleStatus) => void` | No | Callback when status changes successfully |

### LifecycleStatus Type

```typescript
type LifecycleStatus =
  | 'experimental'
  | 'test'
  | 'stable'
  | 'deprecated'
  | 'active';
```

## API Integration

The component integrates with the following backend endpoints:

### GET /api/v1/rules/{id}/lifecycle-history
Retrieves all lifecycle transitions for a rule.

**Response:**
```json
[
  {
    "timestamp": "2024-01-15T10:30:00Z",
    "from_status": "test",
    "to_status": "stable",
    "changed_by": "analyst@example.com",
    "comment": "Promoted to stable after successful testing"
  }
]
```

### POST /api/v1/rules/{id}/lifecycle
Transitions rule to a new lifecycle status.

**Request:**
```json
{
  "status": "stable",
  "comment": "Promoted after extensive testing"
}
```

**Response:**
```json
{
  "category": "detection",
  "rule": {
    "id": "rule-123",
    "lifecycle_status": "stable",
    ...
  }
}
```

## Accessibility Features

### Keyboard Navigation
- All interactive elements are keyboard accessible
- Tab order follows logical flow
- Enter/Space activates buttons and clickable chips
- Escape closes dialogs

### Screen Reader Support
- Semantic HTML structure
- ARIA labels for all interactive elements
- ARIA-current for current status
- ARIA-expanded for collapsible timeline
- Role attributes for custom components

### Visual Accessibility
- Color-coded with sufficient contrast (4.5:1 minimum)
- Status icons supplement color coding
- Clear visual hierarchy
- Focus indicators on all interactive elements

### Example ARIA Labels
```jsx
<Chip
  aria-label="Current status: Stable"
  aria-current={true}
/>

<Button
  aria-label="Promote from experimental to test"
/>

<IconButton
  aria-label="Collapse timeline"
  aria-expanded={timelineExpanded}
/>
```

## State Management

The component uses React Query for data fetching and caching:

```typescript
// Fetch lifecycle history
useQuery({
  queryKey: ['rule-lifecycle-history', ruleId],
  queryFn: () => apiService.getRuleLifecycleHistory(ruleId),
});

// Transition mutation
useMutation({
  mutationFn: (request) =>
    apiService.transitionRuleLifecycle(ruleId, request),
  onSuccess: () => {
    // Invalidate queries to refresh data
    queryClient.invalidateQueries(['rule-lifecycle-history', ruleId]);
  },
});
```

## Error Handling

### Network Errors
- Displays error alerts when API calls fail
- Provides user-friendly error messages
- Maintains UI state during errors
- Allows retry of failed operations

### Validation Errors
- Validates required fields before submission
- Shows inline validation feedback
- Prevents invalid transitions
- Clear error messaging

### Example Error States
```typescript
{actionError && (
  <Alert severity="error" sx={{ mb: 2 }}>
    {actionError}
  </Alert>
)}
```

## Performance Considerations

### Optimizations
- Lazy loading of lifecycle history
- Debounced API calls
- Memoized computations
- Conditional rendering of timeline
- React Query caching

### Loading States
- Skeleton loaders for timeline
- Button loading indicators
- Circular progress for operations
- Disabled states during transitions

## Styling

The component uses Material-UI's theming system:

```typescript
// Color coding by status
const getStatusColor = (status: LifecycleStatus) => {
  switch (status) {
    case 'stable':
    case 'active':
      return 'success';
    case 'test':
      return 'primary';
    case 'experimental':
      return 'warning';
    case 'deprecated':
      return 'error';
    default:
      return 'default';
  }
};
```

### Custom Styling
```typescript
<RuleLifecyclePanel
  ruleId={ruleId}
  currentStatus={status}
  sx={{
    '& .MuiChip-root': {
      fontSize: '1.2rem'
    }
  }}
/>
```

## Testing

The component includes comprehensive test coverage:

- Current status display
- State diagram rendering
- Transition controls
- Dialog interactions
- Timeline display
- Accessibility compliance
- Error handling
- Loading states

### Running Tests
```bash
npm test RuleLifecyclePanel.test.tsx
```

## Best Practices

### 1. Always Provide onStatusChange Callback
```typescript
<RuleLifecyclePanel
  onStatusChange={(newStatus) => {
    // Update local state
    setRuleStatus(newStatus);
    // Refresh related data
    queryClient.invalidateQueries(['rules']);
  }}
/>
```

### 2. Wrap in QueryClientProvider
```typescript
<QueryClientProvider client={queryClient}>
  <RuleLifecyclePanel {...props} />
</QueryClientProvider>
```

### 3. Handle Permissions
```typescript
const canManageLifecycle = usePermission('rules.lifecycle.manage');

{canManageLifecycle && (
  <RuleLifecyclePanel {...props} />
)}
```

### 4. Provide Context
```typescript
<Card>
  <CardHeader title={rule.name} />
  <CardContent>
    <RuleLifecyclePanel
      ruleId={rule.id}
      currentStatus={rule.lifecycle_status}
    />
  </CardContent>
</Card>
```

## Related Components

- **RuleDetailModal**: Displays full rule information with lifecycle tab
- **RuleFilterPanel**: Filters rules by lifecycle status
- **TimelineTab**: Shows alert timeline (similar pattern)

## Future Enhancements

- [ ] Bulk lifecycle transitions
- [ ] Lifecycle policy automation
- [ ] Email notifications on status changes
- [ ] Lifecycle metrics dashboard
- [ ] Custom workflow definitions
- [ ] Integration with approval workflows

## Support

For issues or questions:
- GitHub Issues: [cerberus/issues](https://github.com/org/cerberus/issues)
- Documentation: [docs/lifecycle-management](https://docs.cerberus.io/lifecycle)
- Slack: #cerberus-support

## License

Copyright © 2024 Cerberus SIEM. All rights reserved.
