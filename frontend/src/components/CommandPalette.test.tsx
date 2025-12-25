import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../test/test-utils';
import CommandPalette from './CommandPalette';

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate};
});

describe('CommandPalette', () => {
  beforeEach(() => {
    mockNavigate.mockClear();
    // Reset window.location
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { pathname: '/dashboard' }});
  });

  describe('Rendering', () => {
    it('should render when open', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.getByPlaceholderText('Type a command or search...')).toBeInTheDocument();
    });

    it('should not render when closed', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={false} onClose={onClose} />);

      // MUI Dialog renders but hidden
      expect(screen.queryByPlaceholderText('Type a command or search...')).not.toBeVisible();
    });

    it('should display all navigation commands', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.getByText('Go to Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Go to Events')).toBeInTheDocument();
      expect(screen.getByText('Go to Alerts')).toBeInTheDocument();
      expect(screen.getByText('Go to Rules')).toBeInTheDocument();
      expect(screen.getByText('Go to Correlation Rules')).toBeInTheDocument();
      expect(screen.getByText('Go to Actions')).toBeInTheDocument();
      expect(screen.getByText('Go to Listeners')).toBeInTheDocument();
      expect(screen.getByText('Go to Settings')).toBeInTheDocument();
    });
  });

  describe('Navigation', () => {
    it('should navigate to dashboard when selected', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const dashboardCommand = screen.getByText('Go to Dashboard');
      fireEvent.click(dashboardCommand);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should navigate to events when selected', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const eventsCommand = screen.getByText('Go to Events');
      fireEvent.click(eventsCommand);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/events');
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should navigate to alerts when selected', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const alertsCommand = screen.getByText('Go to Alerts');
      fireEvent.click(alertsCommand);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/alerts');
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should navigate to rules when selected', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const rulesCommand = screen.getByText('Go to Rules');
      fireEvent.click(rulesCommand);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/rules');
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should navigate to listeners when selected', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const listenersCommand = screen.getByText('Go to Listeners');
      fireEvent.click(listenersCommand);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/listeners');
        expect(onClose).toHaveBeenCalled();
      });
    });
  });

  describe('Action Commands', () => {
    it('should show refresh action when onRefresh is provided', () => {
      const onClose = vi.fn();
      const onRefresh = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} onRefresh={onRefresh} />);

      expect(screen.getByText('Refresh Current Page')).toBeInTheDocument();
    });

    it('should not show refresh action when onRefresh is not provided', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.queryByText('Refresh Current Page')).not.toBeInTheDocument();
    });

    it('should call onRefresh when refresh command is selected', async () => {
      const onClose = vi.fn();
      const onRefresh = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} onRefresh={onRefresh} />);

      const refreshCommand = screen.getByText('Refresh Current Page');
      fireEvent.click(refreshCommand);

      await waitFor(() => {
        expect(onRefresh).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should show new action when onNew is provided', () => {
      const onClose = vi.fn();
      const onNew = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} onNew={onNew} />);

      expect(screen.getByText('Create New Item')).toBeInTheDocument();
    });

    it('should call onNew when new command is selected', async () => {
      const onClose = vi.fn();
      const onNew = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} onNew={onNew} />);

      const newCommand = screen.getByText('Create New Item');
      fireEvent.click(newCommand);

      await waitFor(() => {
        expect(onNew).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });
  });

  describe('Page-Specific Commands', () => {
    it('should show listener-specific commands on listeners page', () => {
      window.location.pathname = '/listeners';
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.getByText('Import Listeners')).toBeInTheDocument();
      expect(screen.getByText('Export Listeners')).toBeInTheDocument();
    });

    it('should show rules-specific commands on rules page', () => {
      window.location.pathname = '/rules';
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.getByText('Import Rules')).toBeInTheDocument();
      expect(screen.getByText('Export Rules')).toBeInTheDocument();
    });

    it('should not show page-specific commands on other pages', () => {
      window.location.pathname = '/dashboard';
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.queryByText('Import Listeners')).not.toBeInTheDocument();
      expect(screen.queryByText('Export Listeners')).not.toBeInTheDocument();
      expect(screen.queryByText('Import Rules')).not.toBeInTheDocument();
      expect(screen.queryByText('Export Rules')).not.toBeInTheDocument();
    });
  });

  describe('Search Functionality', () => {
    it('should allow typing in search input', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const searchInput = screen.getByPlaceholderText('Type a command or search...');
      fireEvent.change(searchInput, { target: { value: 'dashboard' } });

      expect(searchInput).toHaveValue('dashboard');
    });

    it('should clear search when dialog is closed and reopened', async () => {
      const onClose = vi.fn();
      const { rerender } = render(<CommandPalette open={true} onClose={onClose} />);

      const searchInput = screen.getByPlaceholderText('Type a command or search...');
      fireEvent.change(searchInput, { target: { value: 'test search' } });

      expect(searchInput).toHaveValue('test search');

      // Close dialog
      rerender(<CommandPalette open={false} onClose={onClose} />);

      // Reopen dialog
      rerender(<CommandPalette open={true} onClose={onClose} />);

      await waitFor(() => {
        const newSearchInput = screen.getByPlaceholderText('Type a command or search...');
        expect(newSearchInput).toHaveValue('');
      });
    });
  });

  describe('Keyboard Shortcuts Display', () => {
    it('should display shortcuts for navigation commands', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      expect(screen.getByText('Ctrl+Shift+D')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+Shift+E')).toBeInTheDocument();
      expect(screen.getByText('Ctrl+Shift+A')).toBeInTheDocument();
    });

    it('should display shortcuts for action commands', () => {
      const onClose = vi.fn();
      const onRefresh = vi.fn();
      const onNew = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} onRefresh={onRefresh} onNew={onNew} />);

      expect(screen.getByText('R')).toBeInTheDocument();
      expect(screen.getByText('N')).toBeInTheDocument();
    });
  });

  describe('Dialog Behavior', () => {
    it('should call onClose when clicking outside', async () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      // MUI Dialog backdrop
      const backdrop = document.querySelector('.MuiBackdrop-root');
      if (backdrop) {
        fireEvent.click(backdrop);
        await waitFor(() => {
          expect(onClose).toHaveBeenCalled();
        });
      }
    });

    it('should autofocus search input when opened', () => {
      const onClose = vi.fn();
      render(<CommandPalette open={true} onClose={onClose} />);

      const searchInput = screen.getByPlaceholderText('Type a command or search...');
      expect(searchInput).toHaveFocus();
    });
  });
});
