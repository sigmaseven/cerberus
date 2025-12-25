import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../test/test-utils';
import KeyboardShortcutsHelp from './KeyboardShortcutsHelp';

describe('KeyboardShortcutsHelp', () => {
  it('should render when open', () => {
    render(<KeyboardShortcutsHelp open={true} onClose={vi.fn()} />);
    expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument();
  });

  it('should display global shortcuts', () => {
    render(<KeyboardShortcutsHelp open={true} onClose={vi.fn()} />);
    expect(screen.getByText('Open command palette')).toBeInTheDocument();
    expect(screen.getByText('Show keyboard shortcuts (this dialog)')).toBeInTheDocument();
  });

  it('should display navigation shortcuts', () => {
    render(<KeyboardShortcutsHelp open={true} onClose={vi.fn()} />);
    expect(screen.getByText('Go to Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Go to Events')).toBeInTheDocument();
    expect(screen.getByText('Go to Alerts')).toBeInTheDocument();
  });

  it('should call onClose when close button is clicked', () => {
    const onClose = vi.fn();
    render(<KeyboardShortcutsHelp open={true} onClose={onClose} />);

    const closeButton = screen.getByText('Close');
    closeButton.click();

    expect(onClose).toHaveBeenCalled();
  });
});
