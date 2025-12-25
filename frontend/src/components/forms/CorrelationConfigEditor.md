# CorrelationConfigEditor Component

## Overview

The `CorrelationConfigEditor` is a standalone, reusable component for editing correlation rule configurations in the Cerberus SIEM system. It provides both a visual form builder and a YAML editor for advanced users.

## Features

### Dual Edit Modes

- **Visual Mode**: Intuitive form-based editor with type-specific fields
- **YAML Mode**: Raw YAML editor with syntax highlighting and validation
- **Bidirectional Sync**: Changes in either mode automatically reflect in the other

### 7 Correlation Types

1. **Event Count**: Trigger when event count reaches a threshold
2. **Value Count**: Trigger on distinct value counts
3. **Sequence**: Detect ordered or unordered event sequences
4. **Temporal**: Detect time-based patterns and recurrence
5. **Rare Events**: Detect statistically rare events
6. **Statistical Anomaly**: Detect statistical anomalies using standard deviation
7. **Attack Chain**: Multi-stage correlation for complex attack patterns

### Type-Specific Fields

Each correlation type shows only relevant fields:

- **event_count**: condition (operator, value)
- **value_count**: distinct_field, condition
- **sequence**: ordered toggle, events list
- **temporal**: time_pattern, recurrence
- **rare**: baseline_window, rarity_threshold
- **statistical**: baseline_window, std_dev_threshold
- **chain**: stages array with drag-to-reorder

### Accessibility

- Keyboard navigable
- Screen reader friendly
- ARIA labels on all controls
- Focus management
- Disabled state support

### Validation

- Zod schema validation
- Real-time error checking in YAML mode
- Type-safe configuration
- Helpful error messages

## Usage

### Basic Usage

```typescript
import { useState } from 'react';
import { CorrelationConfigEditor } from './components/forms/CorrelationConfigEditor';

function MyComponent() {
  const [config, setConfig] = useState({
    type: 'event_count',
    group_by: ['source_ip'],
    timespan: '5m',
    condition: {
      operator: 'gte',
      value: 10,
    },
  });

  return (
    <CorrelationConfigEditor
      value={config}
      onChange={setConfig}
    />
  );
}
```

### With Error Handling

```typescript
function MyFormComponent() {
  const [config, setConfig] = useState(initialConfig);
  const [error, setError] = useState<string | null>(null);

  const handleChange = (newConfig) => {
    setConfig(newConfig);

    // Custom validation
    if (!newConfig.timespan) {
      setError('Timespan is required');
    } else {
      setError(null);
    }
  };

  return (
    <CorrelationConfigEditor
      value={config}
      onChange={handleChange}
      error={error}
    />
  );
}
```

### Read-Only Mode

```typescript
<CorrelationConfigEditor
  value={config}
  onChange={() => {}}
  disabled
/>
```

### Integration with RuleForm

```typescript
import { CorrelationConfigEditor } from './CorrelationConfigEditor';
import { Controller } from 'react-hook-form';

function RuleForm() {
  const { control } = useForm();

  return (
    <Controller
      name="correlation_config"
      control={control}
      render={({ field }) => (
        <CorrelationConfigEditor
          value={field.value}
          onChange={field.onChange}
        />
      )}
    />
  );
}
```

## Props

### CorrelationConfigEditorProps

| Prop | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | `CorrelationConfig \| null` | Yes | - | Current correlation configuration |
| `onChange` | `(config: CorrelationConfig) => void` | Yes | - | Callback when configuration changes |
| `disabled` | `boolean` | No | `false` | Whether the editor is disabled (read-only) |
| `error` | `string` | No | - | Error message to display |

### CorrelationConfig Type

```typescript
interface CorrelationConfig {
  // Required
  type: 'event_count' | 'value_count' | 'sequence' | 'temporal' | 'rare' | 'statistical' | 'chain';

  // Common fields (all types)
  group_by?: string[];
  timespan?: string;

  // event_count / value_count
  condition?: {
    operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
    value: number;
  };

  // value_count
  distinct_field?: string;

  // sequence
  ordered?: boolean;
  events?: string[];

  // temporal
  time_pattern?: string;
  recurrence?: string;

  // rare / statistical
  baseline_window?: string;

  // rare
  rarity_threshold?: number; // 0.1-10

  // statistical
  std_dev_threshold?: number; // 1-5

  // chain
  stages?: Array<{
    name: string;
    detection_ref: string;
    timeout?: string;
  }>;
}
```

## Configuration Examples

### Event Count

Trigger when more than 10 failed login attempts occur within 5 minutes:

```typescript
{
  type: 'event_count',
  group_by: ['source_ip'],
  timespan: '5m',
  condition: {
    operator: 'gt',
    value: 10
  }
}
```

### Value Count

Trigger when a user accesses from more than 5 different IPs in 1 hour:

```typescript
{
  type: 'value_count',
  group_by: ['user'],
  timespan: '1h',
  distinct_field: 'source_ip',
  condition: {
    operator: 'gt',
    value: 5
  }
}
```

### Sequence

Detect privilege escalation followed by file access:

```typescript
{
  type: 'sequence',
  group_by: ['user'],
  timespan: '30m',
  ordered: true,
  events: ['login', 'privilege_escalation', 'file_access']
}
```

### Attack Chain

Detect multi-stage attack:

```typescript
{
  type: 'chain',
  group_by: ['user', 'source_ip'],
  timespan: '2h',
  stages: [
    {
      name: 'Initial Access',
      detection_ref: 'rule_brute_force',
      timeout: '30m'
    },
    {
      name: 'Privilege Escalation',
      detection_ref: 'rule_priv_esc',
      timeout: '30m'
    },
    {
      name: 'Data Exfiltration',
      detection_ref: 'rule_data_exfil'
    }
  ]
}
```

## YAML Format

When using YAML mode, the configuration is serialized as:

```yaml
type: event_count
group_by:
  - source_ip
timespan: 5m
condition:
  operator: gte
  value: 10
```

## Validation

The component uses Zod schemas for validation. All configurations are validated in real-time:

- **Type checking**: Ensures correct TypeScript types
- **Required fields**: Validates required fields based on correlation type
- **Value ranges**: Validates numeric ranges (e.g., std_dev_threshold: 1-5)
- **YAML parsing**: Validates YAML syntax and structure

## Performance Considerations

- **Debounced onChange**: Form changes are debounced to prevent excessive re-renders
- **Lazy field rendering**: Only renders fields relevant to the selected correlation type
- **CodeMirror optimization**: YAML editor uses CodeMirror 6 for efficient syntax highlighting
- **Memoized callbacks**: Event handlers are memoized to prevent unnecessary re-renders

## Keyboard Shortcuts

- **Tab**: Navigate between fields
- **Arrow Keys**: Navigate within select dropdowns
- **Escape**: Close dropdowns
- **YAML Mode**: Standard code editor shortcuts (Ctrl+A, Ctrl+C, Ctrl+V, etc.)

## Browser Compatibility

- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support
- IE11: Not supported (uses modern ES6+ features)

## Dependencies

- `@mui/material`: UI components
- `react-hook-form`: Form state management
- `zod`: Schema validation
- `js-yaml`: YAML parsing/serialization
- `codemirror`: Code editor
- `@codemirror/lang-yaml`: YAML syntax highlighting

## Testing

See `CorrelationConfigEditor.test.tsx` for comprehensive test coverage:

- Visual mode rendering
- YAML mode functionality
- Type-specific field visibility
- Form validation
- Accessibility
- Keyboard navigation
- Error handling

## Related Components

- `RuleForm.tsx`: Main rule creation/editing form
- `CorrelationRuleForm.tsx`: Dedicated correlation rule form
- `SigmaDetectionEditor.tsx`: SIGMA detection editor
- `JsonEditor.tsx`: Generic JSON/YAML editor

## Future Enhancements

- [ ] Drag-and-drop for sequence events
- [ ] Visual timeline for temporal patterns
- [ ] Real-time validation against backend
- [ ] Template library for common correlations
- [ ] Import/export correlation configs
- [ ] Visual chain builder with flowchart

## License

Part of the Cerberus SIEM system.
