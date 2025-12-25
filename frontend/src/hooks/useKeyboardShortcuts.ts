import { useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

export interface KeyboardShortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  meta?: boolean;
  action: () => void;
  description?: string;
  preventDefault?: boolean;
}

interface UseKeyboardShortcutsOptions {
  shortcuts: KeyboardShortcut[];
  enabled?: boolean;
}

export const useKeyboardShortcuts = ({ shortcuts, enabled = true }: UseKeyboardShortcutsOptions) => {
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!enabled) return;

      // Don't trigger shortcuts when typing in input fields
      const target = event.target as HTMLElement;
      const isInputField = ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) ||
        target.isContentEditable;

      for (const shortcut of shortcuts) {
        const keyMatch = event.key.toLowerCase() === shortcut.key.toLowerCase();
        const ctrlMatch = shortcut.ctrl ? event.ctrlKey || event.metaKey : !event.ctrlKey && !event.metaKey;
        const shiftMatch = shortcut.shift ? event.shiftKey : !event.shiftKey;
        const altMatch = shortcut.alt ? event.altKey : !event.altKey;
        const metaMatch = shortcut.meta ? event.metaKey : true;

        if (keyMatch && ctrlMatch && shiftMatch && altMatch && metaMatch) {
          // For context-specific shortcuts (single keys like 'r', 'n'), allow only when not in input fields
          if (!shortcut.ctrl && !shortcut.shift && !shortcut.alt && !shortcut.meta && isInputField) {
            continue;
          }

          if (shortcut.preventDefault !== false) {
            event.preventDefault();
          }
          shortcut.action();
          break;
        }
      }
    },
    [shortcuts, enabled]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);
};

export const useGlobalKeyboardShortcuts = (onCommandPaletteOpen: () => void) => {
  const navigate = useNavigate();

  const shortcuts: KeyboardShortcut[] = [
    // Command palette
    {
      key: 'k',
      ctrl: true,
      action: onCommandPaletteOpen,
      description: 'Open command palette',
    },
    {
      key: 'p',
      ctrl: true,
      action: onCommandPaletteOpen,
      description: 'Open command palette',
    },
    // Navigation shortcuts
    {
      key: 'd',
      ctrl: true,
      shift: true,
      action: () => navigate('/dashboard'),
      description: 'Go to Dashboard',
    },
    {
      key: 'e',
      ctrl: true,
      shift: true,
      action: () => navigate('/events'),
      description: 'Go to Events',
    },
    {
      key: 'a',
      ctrl: true,
      shift: true,
      action: () => navigate('/alerts'),
      description: 'Go to Alerts',
    },
    {
      key: 'r',
      ctrl: true,
      shift: true,
      action: () => navigate('/rules'),
      description: 'Go to Rules',
    },
    {
      key: 'c',
      ctrl: true,
      shift: true,
      action: () => navigate('/correlation-rules'),
      description: 'Go to Correlation Rules',
    },
    {
      key: 'l',
      ctrl: true,
      shift: true,
      action: () => navigate('/listeners'),
      description: 'Go to Listeners',
    },
  ];

  useKeyboardShortcuts({ shortcuts });
};

export const usePageKeyboardShortcuts = (
  onRefresh?: () => void,
  onNew?: () => void,
  onSearch?: () => void
) => {
  const shortcuts: KeyboardShortcut[] = [];

  if (onRefresh) {
    shortcuts.push({
      key: 'r',
      action: onRefresh,
      description: 'Refresh page',
    });
  }

  if (onNew) {
    shortcuts.push({
      key: 'n',
      action: onNew,
      description: 'Create new item',
    });
  }

  if (onSearch) {
    shortcuts.push({
      key: 'f',
      ctrl: true,
      action: onSearch,
      description: 'Search',
    });
  }

  useKeyboardShortcuts({ shortcuts });
};
