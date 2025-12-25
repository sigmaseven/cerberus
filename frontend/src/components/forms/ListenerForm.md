# ListenerForm Component

A production-grade form component for creating and editing event listeners in the Cerberus SIEM system.

## Features

### Core Functionality
- **Template-Based Creation**: Quick-start with pre-configured templates
- **Manual Configuration**: Full control over all listener settings
- **Type-Specific Validation**: Protocol options adapt to listener type
- **TLS/SSL Support**: Secure encrypted connections with certificate validation
- **Tag Management**: Categorize listeners with autocomplete tag input
- **Real-Time Validation**: Inline error messages with comprehensive rules

### Accessibility
- WCAG 2.1 AA compliant
- Full keyboard navigation support
- Proper ARIA labels and roles
- Screen reader friendly
- Focus management
- High contrast ratio (4.5:1+)

### Performance
- Dynamic service imports to reduce initial bundle size
- Optimized re-renders with React Hook Form
- Efficient form state management
- Minimal API calls

## Usage

### Basic Example

```tsx
import { ListenerForm } from '@/components/forms/ListenerForm';

function CreateListenerDialog() {
  const handleSubmit = async (values: ListenerFormType) => {
    const listener = await api.listeners.create(values);
    console.log('Created:', listener);
  };

  return (
    <Dialog open={isOpen}>
      <DialogContent>
        <ListenerForm
          mode="create"
          onSubmit={handleSubmit}
          onCancel={() => setIsOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
```

### Edit Mode Example

```tsx
function EditListenerDialog({ listener }: { listener: DynamicListener }) {
  const handleUpdate = async (values: ListenerFormType) => {
    await api.listeners.update(listener.id, values);
  };

  return (
    <ListenerForm
      mode="edit"
      initialValues={listener}
      onSubmit={handleUpdate}
      onCancel={onClose}
    />
  );
}
```

### With Template Selection

```tsx
// Templates are automatically loaded in create mode
<ListenerForm
  mode="create"
  onSubmit={handleSubmit}
  onCancel={onCancel}
/>
// Users can select from templates or configure manually
```

## Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `mode` | `'create' \| 'edit'` | Yes | Form mode - affects available features |
| `onSubmit` | `(values: ListenerFormType) => Promise<void>` | Yes | Called when form is submitted with valid data |
| `onCancel` | `() => void` | Yes | Called when user cancels the form |
| `initialValues` | `Partial<ListenerFormType>` | No | Pre-populate form (typically used in edit mode) |

## Form Fields

### Basic Information

#### Name (Required)
- **Type**: Text
- **Validation**: 1-100 characters
- **Description**: Unique identifier for the listener

#### Description (Optional)
- **Type**: Text (multiline)
- **Validation**: Max 500 characters
- **Description**: Human-readable description

### Configuration

#### Type (Required)
- **Options**: `syslog`, `cef`, `json`, `fluentd`, `fluentbit`
- **Disabled in**: Edit mode
- **Description**: Format of incoming events
- **Note**: Cannot be changed after creation

#### Protocol (Required)
- **Options**: Dynamically filtered based on type
- **Type-Specific Options**:
  - `syslog`: UDP, TCP
  - `cef`: UDP, TCP
  - `json`: TCP, HTTP
  - `fluentd`: TCP, HTTP
  - `fluentbit`: TCP, HTTP

#### Host (Required)
- **Type**: Text
- **Default**: `0.0.0.0`
- **Validation**: Non-empty string
- **Description**: IP address to bind to (0.0.0.0 = all interfaces)

#### Port (Required)
- **Type**: Number
- **Range**: 1-65535
- **Validation**: Integer within range
- **Common Ports**:
  - 514: Syslog/CEF
  - 8080: HTTP listeners
  - 24224: Fluentd default

#### Source (Required)
- **Type**: Text
- **Validation**: Non-empty string
- **Description**: Identifier for event attribution
- **Example**: `firewall-prod`, `app-server-01`

### Security

#### TLS Toggle
- **Type**: Switch/Checkbox
- **Default**: `false`
- **Description**: Enable TLS/SSL encryption

#### Certificate File (Required when TLS enabled)
- **Type**: Text
- **Validation**: Required if TLS is enabled
- **Description**: Path to TLS certificate file
- **Example**: `/etc/cerberus/certs/listener.crt`

#### Private Key File (Required when TLS enabled)
- **Type**: Text
- **Validation**: Required if TLS is enabled, must be provided with certificate
- **Description**: Path to TLS private key file
- **Example**: `/etc/cerberus/certs/listener.key`

### Organization

#### Tags (Optional)
- **Type**: String array (autocomplete)
- **Description**: Categorization labels
- **Features**: Free-form input, press Enter to add
- **Example**: `['production', 'firewall', 'high-priority']`

#### Field Mapping (Optional)
- **Type**: Text
- **Description**: Custom field mapping configuration name
- **Example**: `fluentd-custom-mapping`

## Validation Rules

### Port Range
```typescript
port >= 1 && port <= 65535
```

### TLS Configuration
```typescript
if (tls === true) {
  cert_file && key_file // Both required
}
```

### Protocol-Type Compatibility
```typescript
// Enforced at runtime
PROTOCOL_OPTIONS[type].includes(protocol)
```

### Field Lengths
- `name`: 1-100 characters
- `description`: 0-500 characters

## Type Definitions

```typescript
interface ListenerFormProps {
  initialValues?: Partial<ListenerFormType>;
  onSubmit: (values: ListenerFormType) => Promise<void>;
  onCancel: () => void;
  mode: 'create' | 'edit';
}

interface ListenerFormType {
  name: string;
  description: string;
  type: ListenerType;
  protocol: ListenerProtocol;
  host: string;
  port: number;
  tls: boolean;
  cert_file?: string;
  key_file?: string;
  tags?: string[];
  source: string;
  field_mapping?: string;
}

type ListenerType = 'syslog' | 'cef' | 'json' | 'fluentd' | 'fluentbit';
type ListenerProtocol = 'udp' | 'tcp' | 'http';
```

## State Management

The component uses React Hook Form for:
- Form state management
- Validation (via Zod schema)
- Error handling
- Optimized re-renders

## Error Handling

### Inline Validation Errors
- Displayed beneath each field
- Real-time validation as user types
- Clear, actionable error messages

### Submission Errors
- Caught and displayed in Alert component
- User-friendly error messages
- Non-blocking UI (can retry or cancel)

### Template Loading Errors
- Graceful fallback to manual configuration
- Error message with context
- Doesn't prevent form usage

## Accessibility Features

### Keyboard Navigation
- All fields accessible via Tab
- Logical tab order
- Escape key to cancel (when in Dialog)
- Enter key to submit (when valid)

### Screen Reader Support
- ARIA labels on all inputs
- ARIA required attributes
- ARIA invalid states
- Error announcements

### Focus Management
- Visible focus indicators (4px outline)
- Focus returns to trigger after cancel
- First error field receives focus on validation failure

### Color Contrast
- All text meets WCAG AA standards (4.5:1)
- Error states use both color and text
- Icons have text alternatives

## Performance Considerations

### Bundle Size
- Dynamic imports for ListenersService (~15KB savings)
- Lazy loading of templates (only in create mode)

### Re-render Optimization
- React Hook Form minimizes re-renders
- useEffect dependencies carefully managed
- Memoized callback functions where appropriate

### API Calls
- Templates loaded once on mount
- No polling or unnecessary requests
- Debounced validation (via onChange mode)

## Testing

Comprehensive test suite covering:
- Form rendering in both modes
- Validation rules (all edge cases)
- Protocol-type constraints
- Template selection
- Form submission
- Error handling
- Accessibility compliance
- Keyboard navigation

Run tests:
```bash
npm test -- ListenerForm.test.tsx
```

## Examples

### Syslog UDP Listener
```typescript
{
  name: "Firewall Syslog",
  description: "Receives syslog from Cisco ASA firewalls",
  type: "syslog",
  protocol: "udp",
  host: "0.0.0.0",
  port: 514,
  tls: false,
  source: "cisco-asa-firewalls",
  tags: ["firewall", "production"]
}
```

### Fluentd with TLS
```typescript
{
  name: "App Servers Fluentd",
  description: "Secure fluentd endpoint for application logs",
  type: "fluentd",
  protocol: "tcp",
  host: "0.0.0.0",
  port: 24224,
  tls: true,
  cert_file: "/etc/cerberus/certs/fluentd.crt",
  key_file: "/etc/cerberus/certs/fluentd.key",
  source: "app-servers",
  tags: ["application", "tls", "production"],
  field_mapping: "fluentd-custom"
}
```

### JSON HTTP Listener
```typescript
{
  name: "JSON API Endpoint",
  description: "HTTP endpoint for custom JSON events",
  type: "json",
  protocol: "http",
  host: "0.0.0.0",
  port: 8080,
  tls: false,
  source: "custom-api",
  tags: ["api", "json"]
}
```

## Architecture Decisions

### Why React Hook Form?
- Type-safe form management
- Excellent performance (minimal re-renders)
- Built-in validation with Zod
- Industry standard

### Why Zod for Validation?
- TypeScript-first schema validation
- Runtime type safety
- Composable validation rules
- Excellent error messages

### Why Dynamic Imports?
- Reduces initial bundle size
- Improves Time to Interactive (TTI)
- Services only loaded when needed
- Better code splitting

### Why Type-Specific Protocol Options?
- Prevents invalid configurations
- Better user experience (fewer options)
- Enforces system constraints
- Clear user intent

## Future Enhancements

- [ ] Port conflict detection (check existing listeners)
- [ ] Advanced field mapping editor UI
- [ ] Certificate file upload/validation
- [ ] Test connection button
- [ ] Import/export listener configs
- [ ] Listener health check integration
- [ ] Port recommendation based on type
- [ ] Custom validation rules per field mapping

## Related Components

- `ListenerTemplate`: Template selection UI
- `ListenerCard`: Display listener status
- `ListenerMetrics`: Show listener statistics

## Related Services

- `ListenersService`: API communication
- `api.ts`: Base API instance

## Related Types

See `frontend/src/types/index.ts`:
- `ListenerForm`
- `ListenerTemplate`
- `DynamicListener`
- `ListenerType`
- `ListenerProtocol`
