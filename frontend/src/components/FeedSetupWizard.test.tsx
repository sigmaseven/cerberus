/**
 * FeedSetupWizard Tests (TASK 160.2, 160.3)
 *
 * Tests for the first-run setup wizard component.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { FeedSetupWizard, WizardState } from './FeedSetupWizard';
import api from '../services/api';
import { FeedTemplate } from '../types';

// Mock the API service
vi.mock('../services/api', () => ({
  default: {
    system: {
      checkFirstRun: vi.fn(),
      completeSetup: vi.fn(),
    },
    feeds: {
      getTemplates: vi.fn(),
    },
  },
}));

const STORAGE_KEY = 'cerberus_feed_setup_wizard';

const mockTemplates: FeedTemplate[] = [
  {
    id: 'sigma-hq',
    name: 'SigmaHQ Full Repository',
    description: 'Complete SigmaHQ rule repository with 3000+ rules',
    type: 'github',
    config: {
      url: 'https://github.com/SigmaHQ/sigma',
      branch: 'master',
    },
  },
  {
    id: 'sigma-windows',
    name: 'SigmaHQ Windows Only',
    description: 'Windows-specific rules with 1800+ rules',
    type: 'github',
    config: {
      url: 'https://github.com/SigmaHQ/sigma',
      branch: 'master',
    },
  },
  {
    id: 'sigma-linux',
    name: 'SigmaHQ Linux Only',
    description: 'Linux-specific rules with 400+ rules',
    type: 'github',
    config: {
      url: 'https://github.com/SigmaHQ/sigma',
      branch: 'master',
    },
  },
];

describe('FeedSetupWizard', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });
    localStorage.clear();
    vi.clearAllMocks();
    // Default mock implementations
    vi.mocked(api.feeds.getTemplates).mockResolvedValue(mockTemplates);
  });

  afterEach(() => {
    localStorage.clear();
  });

  const renderWizard = (props = {}) => {
    return render(
      <QueryClientProvider client={queryClient}>
        <FeedSetupWizard {...props} />
      </QueryClientProvider>
    );
  };

  describe('First Run Detection', () => {
    it('should show wizard when isFirstRun is true', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Feed Setup Wizard')).toBeInTheDocument();
      });
    });

    it('should not show wizard when isFirstRun is false', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(false);

      renderWizard();

      await waitFor(() => {
        expect(api.system.checkFirstRun).toHaveBeenCalled();
      });

      expect(screen.queryByText('Feed Setup Wizard')).not.toBeInTheDocument();
    });

    it('should show wizard when forceOpen is true', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(false);

      renderWizard({ forceOpen: true });

      await waitFor(() => {
        expect(screen.getByText('Feed Setup Wizard')).toBeInTheDocument();
      });
    });
  });

  describe('Welcome Step (Step 1)', () => {
    it('should display welcome message', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      expect(screen.getByText(/This setup wizard will help you configure/)).toBeInTheDocument();
    });

    it('should explain what Sigma Rule Feeds are', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('What are Sigma Rule Feeds?')).toBeInTheDocument();
      });
    });

    it('should list the setup steps', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText(/Select feeds/)).toBeInTheDocument();
        expect(screen.getByText(/Configure schedule/)).toBeInTheDocument();
        expect(screen.getByText(/Review & confirm/)).toBeInTheDocument();
        expect(screen.getByText(/Initial sync/)).toBeInTheDocument();
      });
    });
  });

  describe('Template Selection Step (Step 2)', () => {
    it('should load and display templates', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText('Select Rule Feed Templates')).toBeInTheDocument();
        expect(screen.getByText('SigmaHQ Full Repository')).toBeInTheDocument();
        expect(screen.getByText('SigmaHQ Windows Only')).toBeInTheDocument();
        expect(screen.getByText('SigmaHQ Linux Only')).toBeInTheDocument();
      });
    });

    it('should allow selecting and deselecting templates', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText('SigmaHQ Full Repository')).toBeInTheDocument();
      });

      // Select first template
      fireEvent.click(screen.getByText('SigmaHQ Full Repository'));

      await waitFor(() => {
        expect(screen.getByText('Selected: 1 of 3 templates')).toBeInTheDocument();
      });

      // Deselect first template
      fireEvent.click(screen.getByText('SigmaHQ Full Repository'));

      await waitFor(() => {
        expect(screen.getByText('Selected: 0 of 3 templates')).toBeInTheDocument();
      });
    });

    it('should show warning when no templates are selected', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(
          screen.getByText(/Please select at least one feed template/)
        ).toBeInTheDocument();
      });
    });

    it('should have Select All functionality', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText('Select All')).toBeInTheDocument();
      });

      // Click Select All
      fireEvent.click(screen.getByText('Select All'));

      await waitFor(() => {
        expect(screen.getByText('Selected: 3 of 3 templates')).toBeInTheDocument();
        expect(screen.getByText('Deselect All')).toBeInTheDocument();
      });
    });

    it('should handle template loading error', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);
      vi.mocked(api.feeds.getTemplates).mockRejectedValueOnce(new Error('Network error'));

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText(/Failed to load feed templates/)).toBeInTheDocument();
      });
    });
  });

  describe('localStorage Persistence', () => {
    it('should save state to localStorage on step change', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Feed Setup Wizard')).toBeInTheDocument();
      });

      // Click Next to go to step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        const stored = localStorage.getItem(STORAGE_KEY);
        expect(stored).not.toBeNull();
        if (stored) {
          const state = JSON.parse(stored) as WizardState;
          expect(state.currentStep).toBe(1);
        }
      });
    });

    it('should save selected templates to localStorage', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText('SigmaHQ Full Repository')).toBeInTheDocument();
      });

      // Select a template
      fireEvent.click(screen.getByText('SigmaHQ Full Repository'));

      await waitFor(() => {
        const stored = localStorage.getItem(STORAGE_KEY);
        expect(stored).not.toBeNull();
        if (stored) {
          const state = JSON.parse(stored) as WizardState;
          expect(state.selectedTemplates).toContain('sigma-hq');
        }
      });
    });

    it('should restore state from localStorage on reload', async () => {
      // Pre-populate localStorage with step 2 and selected template
      const savedState: WizardState = {
        currentStep: 1,
        selectedTemplates: ['sigma-hq'],
        syncSchedule: { type: 'manual' },
        syncProgress: null,
        completedSteps: [0],
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(savedState));

      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Feed Setup Wizard')).toBeInTheDocument();
      });

      // Should be on step 2 (Template Selection)
      expect(screen.getByText('Select Rule Feed Templates')).toBeInTheDocument();

      // Should have 1 template selected
      await waitFor(() => {
        expect(screen.getByText('Selected: 1 of 3 templates')).toBeInTheDocument();
      });
    });

    it('should clear localStorage on wizard completion', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);
      vi.mocked(api.system.completeSetup).mockResolvedValueOnce({
        success: true,
        message: 'Setup completed',
      });

      // Set up some stored state on the last step
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          currentStep: 4,
          selectedTemplates: ['sigma-hq'],
          syncSchedule: { type: 'manual' },
          syncProgress: null,
          completedSteps: [0, 1, 2, 3],
        })
      );

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Finish Setup')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Finish Setup'));

      await waitFor(() => {
        expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
      });
    });
  });

  describe('Navigation', () => {
    it('should navigate forward with Next button', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        expect(screen.getByText('Select Rule Feed Templates')).toBeInTheDocument();
      });
    });

    it('should navigate backward with Back button', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      // Start on step 2
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          currentStep: 1,
          selectedTemplates: [],
          syncSchedule: { type: 'manual' },
          syncProgress: null,
          completedSteps: [0],
        })
      );

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Select Rule Feed Templates')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Back'));

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });
    });

    it('should have Back button disabled on first step', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      const backButton = screen.getByText('Back');
      expect(backButton).toBeDisabled();
    });
  });

  describe('Skip Wizard', () => {
    it('should call completeSetup with skipped=true when Skip button clicked', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);
      vi.mocked(api.system.completeSetup).mockResolvedValueOnce({
        success: true,
        message: 'Setup skipped',
      });

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Skip Wizard')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Skip Wizard'));

      await waitFor(() => {
        expect(api.system.completeSetup).toHaveBeenCalledWith(true);
      });
    });

    it('should close wizard when skip is successful', async () => {
      const onClose = vi.fn();
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);
      vi.mocked(api.system.completeSetup).mockResolvedValueOnce({
        success: true,
        message: 'Setup skipped',
      });

      renderWizard({ onClose });

      await waitFor(() => {
        expect(screen.getByText('Skip Wizard')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Skip Wizard'));

      await waitFor(() => {
        expect(onClose).toHaveBeenCalled();
      });
    });
  });

  describe('Wizard Completion', () => {
    it('should call completeSetup with skipped=false on final step', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);
      vi.mocked(api.system.completeSetup).mockResolvedValueOnce({
        success: true,
        message: 'Setup completed',
      });

      // Start on last step
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          currentStep: 4,
          selectedTemplates: ['sigma-hq'],
          syncSchedule: { type: 'manual' },
          syncProgress: null,
          completedSteps: [0, 1, 2, 3],
        })
      );

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Finish Setup')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Finish Setup'));

      await waitFor(() => {
        expect(api.system.completeSetup).toHaveBeenCalledWith(false);
      });
    });
  });

  describe('Template Card Display', () => {
    it('should display rule count from description', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        // Should extract rule count from descriptions
        expect(screen.getByText('3000+ rules')).toBeInTheDocument();
        expect(screen.getByText('1800+ rules')).toBeInTheDocument();
        expect(screen.getByText('400+ rules')).toBeInTheDocument();
      });
    });

    it('should display template type', async () => {
      vi.mocked(api.system.checkFirstRun).mockResolvedValueOnce(true);

      renderWizard();

      await waitFor(() => {
        expect(screen.getByText('Welcome to Cerberus SIEM')).toBeInTheDocument();
      });

      // Navigate to Step 2
      fireEvent.click(screen.getByText('Next'));

      await waitFor(() => {
        // All templates are github type
        const githubChips = screen.getAllByText('github');
        expect(githubChips.length).toBe(3);
      });
    });
  });
});
