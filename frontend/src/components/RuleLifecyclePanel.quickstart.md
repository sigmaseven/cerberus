# RuleLifecyclePanel Quick Start Guide

Get started with the RuleLifecyclePanel component in 5 minutes.

## Installation

No additional dependencies needed! The component uses existing MUI and React Query packages.

## Basic Usage

### Step 1: Import the Component

```tsx
import { RuleLifecyclePanel } from '@/components/RuleLifecyclePanel';
```

### Step 2: Use in Your Component

```tsx
function RuleDetailPage() {
  const ruleId = 'rule-12345';
  const currentStatus = 'experimental'; // From your rule data

  return (
    <RuleLifecyclePanel
      ruleId={ruleId}
      currentStatus={currentStatus}
      onStatusChange={(newStatus) => {
        console.log('Status changed to:', newStatus);
      }}
    />
  );
}
```

### Step 3: Ensure React Query Context

Make sure your component tree has `QueryClientProvider`:

```tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RuleDetailPage />
    </QueryClientProvider>
  );
}
```

## That's It!

The component handles:
- ✅ Fetching lifecycle history
- ✅ Displaying state diagram
- ✅ Transition controls
- ✅ Dialog management
- ✅ Loading states
- ✅ Error handling

## Common Patterns

### In a Modal

```tsx
<Dialog open={open} onClose={onClose} maxWidth="lg">
  <DialogContent>
    <RuleLifecyclePanel
      ruleId={ruleId}
      currentStatus={rule.lifecycle_status}
    />
  </DialogContent>
</Dialog>
```

### With State Management

```tsx
const [status, setStatus] = useState<LifecycleStatus>('experimental');

<RuleLifecyclePanel
  ruleId={ruleId}
  currentStatus={status}
  onStatusChange={(newStatus) => {
    setStatus(newStatus);
    // Refresh your data
  }}
/>
```

### With Permissions

```tsx
const canManageLifecycle = usePermission('rules.lifecycle.manage');

{canManageLifecycle ? (
  <RuleLifecyclePanel ruleId={ruleId} currentStatus={status} />
) : (
  <div>You don't have permission to manage lifecycle</div>
)}
```

## Lifecycle States

```
experimental → test → stable → active
                               ↓
                          deprecated → archived
```

## Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `ruleId` | `string` | Yes | Unique rule identifier |
| `currentStatus` | `LifecycleStatus` | Yes | Current lifecycle status |
| `onStatusChange` | `(newStatus: LifecycleStatus) => void` | No | Callback when status changes |

## API Requirements

Your backend must implement:

1. `GET /api/v1/rules/{id}/lifecycle-history`
2. `POST /api/v1/rules/{id}/lifecycle`

See `RuleLifecyclePanel.md` for full API documentation.

## Troubleshooting

**Component not rendering?**
- Check that QueryClientProvider is in your component tree
- Verify ruleId is a valid string
- Check browser console for errors

**Transitions not working?**
- Check network tab for API errors
- Verify backend endpoints are available
- Check CORS settings

**Lifecycle history not loading?**
- Verify GET endpoint returns array of history entries
- Check authentication/authorization
- Look for API errors in console

## Next Steps

- Read full documentation: `RuleLifecyclePanel.md`
- See usage examples: `RuleLifecyclePanel.example.tsx`
- Run tests: `npm test RuleLifecyclePanel.test.tsx`

## Need Help?

- 📖 Full Documentation: `RuleLifecyclePanel.md`
- 💡 Examples: `RuleLifecyclePanel.example.tsx`
- 🧪 Tests: `RuleLifecyclePanel.test.tsx`
- 📝 Implementation: `RULE_LIFECYCLE_IMPLEMENTATION_SUMMARY.md`
