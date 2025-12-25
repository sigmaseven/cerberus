# CorrelationConfigEditor Integration Guide

## Integration with RuleForm

The `CorrelationConfigEditor` is designed to integrate seamlessly with the `RuleForm` component for creating and editing correlation rules.

### Current Integration Status

The component is ready to be integrated into `RuleForm.tsx`. Here's how:

### Integration Steps

#### 1. Import the Component

Add to the imports section of `RuleForm.tsx`:

```typescript
import { CorrelationConfigEditor } from './CorrelationConfigEditor';
```

#### 2. Replace Inline Correlation Fields

In `RuleForm.tsx`, locate the `renderCorrelationFields()` function (around line 502) and replace the inline correlation configuration UI with:

```typescript
const renderCorrelationFields = () => {
  if (watchedCategory !== 'correlation') return null;

  return (
    <Box>
      <Typography variant="subtitle1" gutterBottom>
        Correlation Configuration
      </Typography>

      <Controller
        name="correlation_config"
        control={control}
        render={({ field, fieldState }) => (
          <CorrelationConfigEditor
            value={field.value}
            onChange={field.onChange}
            error={fieldState.error?.message}
          />
        )}
      />
    </Box>
  );
};
```

#### 3. Update Form Schema

Ensure the correlation schema in `RuleForm.tsx` matches the CorrelationConfigEditor types:

```typescript
const correlationRuleSchema = z.object({
  title: z.string().min(1, 'Rule title is required'),
  description: z.string().min(1, 'Description is required'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  enabled: z.boolean(),
  rule_category: z.literal('correlation'),
  lifecycle_status: z.enum(['experimental', 'test', 'stable', 'deprecated', 'active']).optional(),
  actions: z.array(actionSchema).optional(),
  tags: z.array(z.string()).optional(),
  // Use the same schema as CorrelationConfigEditor
  correlation_config: z.object({
    type: z.enum(['event_count', 'value_count', 'sequence', 'temporal', 'rare', 'statistical', 'chain']),
    group_by: z.array(z.string()).optional(),
    timespan: z.string().optional(),
    condition: z.object({
      operator: z.enum(['gt', 'gte', 'lt', 'lte', 'eq', 'ne']),
      value: z.number(),
    }).optional(),
    distinct_field: z.string().optional(),
    ordered: z.boolean().optional(),
    events: z.array(z.string()).optional(),
    time_pattern: z.string().optional(),
    recurrence: z.string().optional(),
    baseline_window: z.string().optional(),
    rarity_threshold: z.number().optional(),
    std_dev_threshold: z.number().optional(),
    stages: z.array(z.object({
      name: z.string().min(1, 'Stage name is required'),
      detection_ref: z.string().min(1, 'Detection reference is required'),
      timeout: z.string().optional(),
    })).optional(),
  }),
});
```

## Benefits of Using CorrelationConfigEditor

### Code Reusability

The editor can be used in multiple places:

1. **RuleForm**: Main rule creation/editing
2. **Standalone correlation editor**: Quick correlation config without full rule
3. **Template library**: Pre-configured correlation templates
4. **API testing tools**: Testing correlation endpoints

### Consistency

- Ensures consistent UI/UX across all correlation editing interfaces
- Single source of truth for correlation types and fields
- Shared validation logic

### Maintainability

- Changes to correlation logic only need to be made in one place
- Easier to add new correlation types
- Centralized testing

### Enhanced Features

Compared to inline RuleForm fields, the standalone component provides:

- **YAML Mode**: Advanced users can edit raw YAML
- **Better validation**: Real-time schema validation
- **Cleaner code**: Separates concerns
- **Reusability**: Can be used in other contexts

## Usage in Other Components

### Standalone Correlation Rule Editor

```typescript
import { CorrelationConfigEditor } from './components/forms/CorrelationConfigEditor';

function CorrelationRuleQuickCreate() {
  const [config, setConfig] = useState(null);

  const handleSave = async () => {
    if (config) {
      await api.createCorrelationRule({
        name: 'Quick Correlation',
        correlation_config: config,
        // ... other fields
      });
    }
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Quick Correlation Rule</DialogTitle>
      <DialogContent>
        <CorrelationConfigEditor
          value={config}
          onChange={setConfig}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleSave}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
```

### Correlation Template Library

```typescript
const TEMPLATES = [
  {
    name: 'Brute Force Detection',
    config: {
      type: 'event_count',
      group_by: ['source_ip'],
      timespan: '5m',
      condition: { operator: 'gt', value: 10 },
    },
  },
  {
    name: 'Privilege Escalation Chain',
    config: {
      type: 'chain',
      group_by: ['user'],
      timespan: '1h',
      stages: [
        { name: 'Login', detection_ref: 'login_event' },
        { name: 'Priv Esc', detection_ref: 'priv_esc_event' },
      ],
    },
  },
];

function CorrelationTemplates() {
  const [selected, setSelected] = useState(null);

  return (
    <Box>
      <List>
        {TEMPLATES.map((template) => (
          <ListItem key={template.name} onClick={() => setSelected(template.config)}>
            {template.name}
          </ListItem>
        ))}
      </List>

      {selected && (
        <CorrelationConfigEditor
          value={selected}
          onChange={setSelected}
        />
      )}
    </Box>
  );
}
```

### API Testing Interface

```typescript
function CorrelationAPITester() {
  const [config, setConfig] = useState(null);
  const [testResult, setTestResult] = useState(null);

  const handleTest = async () => {
    const result = await api.testCorrelation({
      correlation_config: config,
      test_events: [...],
    });
    setTestResult(result);
  };

  return (
    <Box>
      <CorrelationConfigEditor value={config} onChange={setConfig} />
      <Button onClick={handleTest}>Test Correlation</Button>
      {testResult && <Alert>{JSON.stringify(testResult)}</Alert>}
    </Box>
  );
}
```

## Migration from Inline RuleForm Fields

### Before (RuleForm.tsx with inline fields)

```typescript
// Lines 502-668 in current RuleForm.tsx
const renderCorrelationFields = () => {
  // 150+ lines of inline correlation form fields
  // Type selector
  // Timespan input
  // Group by autocomplete
  // Type-specific fields for each correlation type
  // ...
};
```

### After (RuleForm.tsx using CorrelationConfigEditor)

```typescript
const renderCorrelationFields = () => {
  if (watchedCategory !== 'correlation') return null;

  return (
    <Controller
      name="correlation_config"
      control={control}
      render={({ field, fieldState }) => (
        <CorrelationConfigEditor
          value={field.value}
          onChange={field.onChange}
          error={fieldState.error?.message}
        />
      )}
    />
  );
};
```

**Result**: ~150 lines of code reduced to ~15 lines!

## Testing Integration

When testing RuleForm with CorrelationConfigEditor:

```typescript
import { render, screen } from '@testing-library/react';
import { RuleForm } from './RuleForm';

describe('RuleForm with CorrelationConfigEditor', () => {
  it('should render correlation config editor when correlation category selected', async () => {
    const user = userEvent.setup();
    render(<RuleForm open={true} onClose={() => {}} onSubmit={() => {}} />);

    // Select correlation category
    const categorySelect = screen.getByLabelText(/rule category/i);
    await user.click(categorySelect);
    await user.click(screen.getByText(/correlation/i));

    // CorrelationConfigEditor should be rendered
    expect(screen.getByLabelText(/correlation type/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/group by fields/i)).toBeInTheDocument();
  });
});
```

## Backwards Compatibility

The component is designed to be backwards compatible with existing correlation rule data:

- Accepts `null` value for new rules
- Handles partial configurations gracefully
- Provides sensible defaults
- Validates against existing backend API

## Future Integration Opportunities

1. **Correlation Rule Import/Export**: Use CorrelationConfigEditor for previewing imported rules
2. **Correlation Analytics**: Visualize correlation effectiveness with the same editor
3. **Correlation Rule Cloning**: Quick duplication with editor
4. **Batch Correlation Creation**: Create multiple similar correlations
5. **Correlation Rule Versioning**: Compare versions side-by-side

## Performance Considerations

When integrating with RuleForm:

- **Lazy rendering**: Only renders when correlation category is selected
- **Memoized callbacks**: Prevents unnecessary re-renders
- **Controlled updates**: Uses react-hook-form's Controller for optimal performance
- **Debounced validation**: Validates without blocking UI

## Accessibility

The integration maintains RuleForm's accessibility:

- All ARIA labels preserved
- Keyboard navigation works seamlessly
- Screen reader announcements
- Focus management between RuleForm and CorrelationConfigEditor

## Summary

The `CorrelationConfigEditor` component provides a clean, reusable, and maintainable way to edit correlation configurations. Integration with RuleForm is straightforward and provides immediate benefits in code quality, maintainability, and user experience.
