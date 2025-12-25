/**
 * ListenerTemplateSelector Component Tests
 *
 * BLOCKING-1 FIX: Comprehensive test coverage for security-sensitive component
 *
 * Tests verify:
 * - Prop validation (BLOCKING-6)
 * - Search filtering with runtime validation (BLOCKING-4)
 * - Category handling and unknown category logging (previous BLOCKING-3)
 * - Icon mapping with null guards (previous BLOCKING-2)
 * - ARIA accessibility roles (BLOCKING-5)
 * - XSS prevention via sanitization (BLOCKING-3)
 * - Selection behavior
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { ListenerTemplateSelector } from './ListenerTemplateSelector';
import type { ListenerTemplate } from '../../types';

// Mock MUI components to avoid EMFILE issues on Windows
vi.mock('@mui/material', () => ({
  Box: ({ children, sx, ...props }: any) => <div {...props}>{children}</div>,
  Card: ({ children, variant, sx, ...props }: any) => (
    <div data-testid="card" {...props}>{children}</div>
  ),
  CardActionArea: ({ children, onClick, sx, ...props }: any) => (
    <button onClick={onClick} {...props}>{children}</button>
  ),
  CardContent: ({ children, sx }: any) => <div>{children}</div>,
  Typography: ({ children, variant, color, fontWeight, gutterBottom, sx }: any) => (
    <span>{children}</span>
  ),
  Chip: ({ label, size, color, variant, sx }: any) => (
    <span data-testid="chip">{label}</span>
  ),
  Grid: ({ children, container, item, spacing, xs, sm, role, ...props }: any) => (
    <div role={role} {...props}>{children}</div>
  ),
  TextField: ({ placeholder, value, onChange, InputProps, inputProps, size, sx, fullWidth }: any) => (
    <input
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      aria-label={inputProps?.['aria-label']}
      data-testid="search-input"
    />
  ),
  InputAdornment: ({ children, position }: any) => <span>{children}</span>,
  Tabs: ({ children, value, onChange, variant, scrollButtons, sx, ...props }: any) => (
    <div role="tablist" {...props}>{children}</div>
  ),
  Tab: ({ label, value, id, ...props }: any) => (
    <button role="tab" data-value={value} {...props}>{label}</button>
  ),
  Skeleton: ({ variant, height, sx }: any) => <div data-testid="skeleton" />,
  Alert: ({ children, severity, sx }: any) => (
    <div role="alert" data-severity={severity}>{children}</div>
  ),
}));

// Mock MUI icons to avoid loading all icon files
vi.mock('@mui/icons-material', () => ({
  Search: () => <span data-testid="search-icon">Search</span>,
  Security: () => <span data-testid="security-icon">Security</span>,
  Computer: () => <span data-testid="computer-icon">Computer</span>,
  Cloud: () => <span data-testid="cloud-icon">Cloud</span>,
  Public: () => <span data-testid="public-icon">Public</span>,
  DesktopWindows: () => <span data-testid="desktop-icon">Desktop</span>,
  Settings: () => <span data-testid="settings-icon">Settings</span>,
  CheckCircle: () => <span data-testid="check-icon">Check</span>,
}));

// Mock DOMPurify
vi.mock('dompurify', () => ({
  default: {
    sanitize: (text: string, _options?: object) => {
      // Simulate stripping HTML tags
      if (typeof text !== 'string') return '';
      return text.replace(/<[^>]*>/g, '');
    },
  },
}));

// ============================================================================
// Test Fixtures
// ============================================================================

const createMockTemplate = (overrides: Partial<ListenerTemplate> = {}): ListenerTemplate => ({
  id: 'template-1',
  name: 'Test Template',
  description: 'A test template for listeners',
  category: 'Firewall',
  icon: 'security',
  tags: ['test', 'firewall', 'syslog'],
  config: {
    name: 'Test Listener',
    description: 'Test Description',
    type: 'syslog',
    protocol: 'udp',
    host: '0.0.0.0',
    port: 514,
    tls: false,
    source: 'test-source',
  },
  ...overrides,
});

const mockTemplates: ListenerTemplate[] = [
  createMockTemplate({ id: 'template-1', name: 'Palo Alto', category: 'Firewall', tags: ['palo', 'alto'] }),
  createMockTemplate({ id: 'template-2', name: 'Windows Events', category: 'Endpoint', tags: ['windows', 'endpoint'] }),
  createMockTemplate({ id: 'template-3', name: 'AWS CloudTrail', category: 'Cloud', tags: ['aws', 'cloudtrail'] }),
  createMockTemplate({ id: 'template-4', name: 'Apache Logs', category: 'Web Server', tags: ['apache', 'web'] }),
];

// ============================================================================
// Prop Validation Tests (BLOCKING-6)
// ============================================================================

describe('ListenerTemplateSelector - Prop Validation', () => {
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

  it('should show error when templates prop is not an array', () => {
    const onSelectTemplate = vi.fn();

    // @ts-expect-error - Testing invalid prop type
    render(<ListenerTemplateSelector templates={null} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Invalid component configuration: templates must be an array');
    expect(consoleError).toHaveBeenCalledWith('ListenerTemplateSelector: templates prop must be an array');
  });

  it('should show error when onSelectTemplate is not a function', () => {
    // @ts-expect-error - Testing invalid prop type
    render(<ListenerTemplateSelector templates={[]} selectedTemplateId="" onSelectTemplate="not-a-function" />);

    expect(screen.getByRole('alert')).toHaveTextContent('Invalid component configuration: callback required');
    expect(consoleError).toHaveBeenCalledWith('ListenerTemplateSelector: onSelectTemplate must be a function');
  });

  it('should render correctly with valid props', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should render without error alert (alerts are only for errors)
    const alerts = screen.queryAllByRole('alert');
    expect(alerts.some(a => a.getAttribute('data-severity') === 'error')).toBe(false);
    // Should render template cards
    expect(screen.getByText('Palo Alto')).toBeInTheDocument();
  });
});

// ============================================================================
// Search Filtering Tests (BLOCKING-4)
// ============================================================================

describe('ListenerTemplateSelector - Search Filtering', () => {
  it('should filter templates by name', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const searchInput = screen.getByTestId('search-input');
    await user.type(searchInput, 'Palo');

    // Wait for debounced search (300ms + buffer)
    await waitFor(
      () => {
        expect(screen.getByText('Palo Alto')).toBeInTheDocument();
        expect(screen.queryByText('Windows Events')).not.toBeInTheDocument();
      },
      { timeout: 500 }
    );
  });

  it('should filter templates by tags', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const searchInput = screen.getByTestId('search-input');
    await user.type(searchInput, 'cloudtrail');

    await waitFor(
      () => {
        expect(screen.getByText('AWS CloudTrail')).toBeInTheDocument();
        expect(screen.queryByText('Palo Alto')).not.toBeInTheDocument();
      },
      { timeout: 500 }
    );
  });

  it('should handle templates with non-string fields gracefully', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    const malformedTemplates = [
      createMockTemplate({
        id: 'malformed-1',
        // @ts-expect-error - Testing runtime type handling
        name: 12345,
        // @ts-expect-error - Testing runtime type handling
        description: null,
        // @ts-expect-error - Testing runtime type handling
        tags: 'not-an-array',
      }),
      createMockTemplate({ id: 'normal-1', name: 'Normal Template' }),
    ];

    render(<ListenerTemplateSelector templates={malformedTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const searchInput = screen.getByTestId('search-input');
    await user.type(searchInput, 'Normal');

    // Should not crash and should filter correctly
    await waitFor(
      () => {
        expect(screen.getByText('Normal Template')).toBeInTheDocument();
      },
      { timeout: 500 }
    );
  });
});

// ============================================================================
// Category Handling Tests (unknown category logging)
// ============================================================================

describe('ListenerTemplateSelector - Category Handling', () => {
  let consoleWarn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleWarn.mockRestore();
  });

  it('should log warning for unknown categories', () => {
    const onSelectTemplate = vi.fn();
    const templatesWithUnknownCategory = [
      createMockTemplate({ id: 'unknown-1', name: 'Unknown Category', category: 'UnknownCategory' }),
    ];

    render(
      <ListenerTemplateSelector templates={templatesWithUnknownCategory} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />
    );

    expect(consoleWarn).toHaveBeenCalledWith(expect.stringContaining('Unknown template category: "UnknownCategory"'));
  });

  it('should not log warning for known categories', () => {
    const onSelectTemplate = vi.fn();
    const knownCategoryTemplates = [
      createMockTemplate({ id: 'known-1', name: 'Firewall Template', category: 'Firewall' }),
    ];

    render(<ListenerTemplateSelector templates={knownCategoryTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should not warn for known categories
    expect(consoleWarn).not.toHaveBeenCalled();
  });

  it('should render category tabs correctly', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByRole('tab', { name: 'All' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Firewall' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Endpoint' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Cloud' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Web Server' })).toBeInTheDocument();
  });
});

// ============================================================================
// Icon Mapping Tests (null guards)
// ============================================================================

describe('ListenerTemplateSelector - Icon Mapping', () => {
  it('should render fallback icon for null iconName', () => {
    const onSelectTemplate = vi.fn();
    const templatesWithNullIcon = [
      createMockTemplate({
        id: 'null-icon',
        name: 'Null Icon Template',
        // @ts-expect-error - Testing null guard
        icon: null,
      }),
    ];

    render(<ListenerTemplateSelector templates={templatesWithNullIcon} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should render without crashing
    expect(screen.getByText('Null Icon Template')).toBeInTheDocument();
  });

  it('should render fallback icon for undefined iconName', () => {
    const onSelectTemplate = vi.fn();
    const templatesWithUndefinedIcon = [
      createMockTemplate({
        id: 'undefined-icon',
        name: 'Undefined Icon Template',
        // @ts-expect-error - Testing undefined guard
        icon: undefined,
      }),
    ];

    render(<ListenerTemplateSelector templates={templatesWithUndefinedIcon} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByText('Undefined Icon Template')).toBeInTheDocument();
  });

  it('should render fallback icon for unknown iconName', () => {
    const onSelectTemplate = vi.fn();
    const templatesWithUnknownIcon = [
      createMockTemplate({
        id: 'unknown-icon',
        name: 'Unknown Icon Template',
        icon: 'unknown_icon_name',
      }),
    ];

    render(<ListenerTemplateSelector templates={templatesWithUnknownIcon} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByText('Unknown Icon Template')).toBeInTheDocument();
  });
});

// ============================================================================
// ARIA Accessibility Tests (BLOCKING-5)
// ============================================================================

describe('ListenerTemplateSelector - Accessibility', () => {
  it('should use role="list" for template grid container', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByRole('list', { name: 'Listener templates' })).toBeInTheDocument();
  });

  it('should use role="listitem" for template cards', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const listItems = screen.getAllByRole('listitem');
    expect(listItems.length).toBe(mockTemplates.length);
  });

  it('should have accessible search input', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const searchInput = screen.getByRole('textbox', { name: 'Search listener templates' });
    expect(searchInput).toBeInTheDocument();
  });
});

// ============================================================================
// XSS Prevention Tests (BLOCKING-3)
// ============================================================================

describe('ListenerTemplateSelector - XSS Prevention', () => {
  it('should sanitize template names containing HTML', () => {
    const onSelectTemplate = vi.fn();
    const maliciousTemplates = [
      createMockTemplate({
        id: 'xss-1',
        name: '<script>alert("XSS")</script>Malicious',
        description: 'Safe description',
      }),
    ];

    render(<ListenerTemplateSelector templates={maliciousTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should render sanitized text without script tag
    expect(screen.getByText('alert("XSS")Malicious')).toBeInTheDocument();
  });

  it('should sanitize template descriptions containing HTML', () => {
    const onSelectTemplate = vi.fn();
    const maliciousTemplates = [
      createMockTemplate({
        id: 'xss-2',
        name: 'Safe Name',
        description: '<img src=x onerror=alert("XSS")>Malicious Description',
      }),
    ];

    render(<ListenerTemplateSelector templates={maliciousTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should render sanitized description
    expect(screen.getByText('Malicious Description')).toBeInTheDocument();
  });

  it('should sanitize tags containing HTML', () => {
    const onSelectTemplate = vi.fn();
    const maliciousTemplates = [
      createMockTemplate({
        id: 'xss-3',
        name: 'Safe Name',
        tags: ['<b>bold</b>', 'normal', '<script>bad</script>'],
      }),
    ];

    render(<ListenerTemplateSelector templates={maliciousTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    // Should render sanitized tags (stripped HTML)
    expect(screen.getByText('bold')).toBeInTheDocument();
    expect(screen.getByText('normal')).toBeInTheDocument();
    expect(screen.getByText('bad')).toBeInTheDocument();
  });
});

// ============================================================================
// Selection Behavior Tests
// ============================================================================

describe('ListenerTemplateSelector - Selection Behavior', () => {
  it('should call onSelectTemplate when template is clicked', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    await user.click(screen.getByText('Palo Alto'));

    expect(onSelectTemplate).toHaveBeenCalledWith('template-1');
  });

  it('should toggle selection when clicking same template', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="template-1" onSelectTemplate={onSelectTemplate} />);

    await user.click(screen.getByText('Palo Alto'));

    // Should deselect (pass empty string)
    expect(onSelectTemplate).toHaveBeenCalledWith('');
  });

  it('should change selection when clicking different template', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="template-1" onSelectTemplate={onSelectTemplate} />);

    await user.click(screen.getByText('Windows Events'));

    expect(onSelectTemplate).toHaveBeenCalledWith('template-2');
  });

  it('should select Manual Configuration when clicked', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="template-1" onSelectTemplate={onSelectTemplate} />);

    await user.click(screen.getByText('Manual Configuration'));

    expect(onSelectTemplate).toHaveBeenCalledWith('');
  });
});

// ============================================================================
// Loading and Error States
// ============================================================================

describe('ListenerTemplateSelector - Loading and Error States', () => {
  it('should show loading skeletons when loading=true', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={[]} selectedTemplateId="" onSelectTemplate={onSelectTemplate} loading={true} />);

    // Should show skeletons
    expect(screen.getAllByTestId('skeleton').length).toBeGreaterThan(0);
  });

  it('should show error alert when error prop is provided', () => {
    const onSelectTemplate = vi.fn();

    render(
      <ListenerTemplateSelector
        templates={[]}
        selectedTemplateId=""
        onSelectTemplate={onSelectTemplate}
        error="Failed to load templates"
      />
    );

    expect(screen.getByRole('alert')).toHaveTextContent('Failed to load templates');
  });

  it('should show info message when templates array is empty', () => {
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={[]} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    expect(screen.getByRole('alert')).toHaveTextContent('No templates available');
  });

  it('should show no matches message when search has no results', async () => {
    const user = userEvent.setup();
    const onSelectTemplate = vi.fn();

    render(<ListenerTemplateSelector templates={mockTemplates} selectedTemplateId="" onSelectTemplate={onSelectTemplate} />);

    const searchInput = screen.getByTestId('search-input');
    await user.type(searchInput, 'nonexistent-query-xyz');

    await waitFor(
      () => {
        expect(screen.getByRole('alert')).toHaveTextContent('No templates match your search criteria');
      },
      { timeout: 500 }
    );
  });
});
