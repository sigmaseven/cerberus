import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { useKeyboardShortcuts, useGlobalKeyboardShortcuts, usePageKeyboardShortcuts } from './useKeyboardShortcuts';

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate};
});

describe('useKeyboardShortcuts', () => {
  beforeEach(() => {
    mockNavigate.mockClear();
  });

  describe('Basic Functionality', () => {
    it('should trigger action when matching key is pressed', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      window.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });

    it('should trigger action with ctrl modifier', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'k', ctrl: true, action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true });
      window.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });

    it('should trigger action with shift modifier', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'd', shift: true, action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'd', shiftKey: true });
      window.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });

    it('should trigger action with ctrl+shift modifiers', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'd', ctrl: true, shift: true, action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'd', ctrlKey: true, shiftKey: true });
      window.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });

    it('should not trigger when enabled is false', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action }],
          enabled: false})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      window.dispatchEvent(event);

      expect(action).not.toHaveBeenCalled();
    });

    it('should prevent default when preventDefault is true', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action, preventDefault: true }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
      window.dispatchEvent(event);

      expect(preventDefaultSpy).toHaveBeenCalled();
      expect(action).toHaveBeenCalled();
    });

    it('should prevent default by default', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
      window.dispatchEvent(event);

      expect(preventDefaultSpy).toHaveBeenCalled();
    });

    it('should not prevent default when preventDefault is false', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action, preventDefault: false }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
      window.dispatchEvent(event);

      expect(preventDefaultSpy).not.toHaveBeenCalled();
      expect(action).toHaveBeenCalled();
    });

    it('should handle multiple shortcuts', () => {
      const action1 = vi.fn();
      const action2 = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [
            { key: 'a', action: action1 },
            { key: 'b', action: action2 },
          ]})
      );

      const eventA = new KeyboardEvent('keydown', { key: 'a' });
      window.dispatchEvent(eventA);

      const eventB = new KeyboardEvent('keydown', { key: 'b' });
      window.dispatchEvent(eventB);

      expect(action1).toHaveBeenCalledTimes(1);
      expect(action2).toHaveBeenCalledTimes(1);
    });

    it('should be case insensitive', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'A', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'a' });
      window.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });
  });

  describe('Input Field Handling', () => {
    let input: HTMLInputElement;
    let textarea: HTMLTextAreaElement;
    let contentEditableDiv: HTMLDivElement;

    beforeEach(() => {
      input = document.createElement('input');
      document.body.appendChild(input);

      textarea = document.createElement('textarea');
      document.body.appendChild(textarea);

      contentEditableDiv = document.createElement('div');
      contentEditableDiv.contentEditable = 'true';
      document.body.appendChild(contentEditableDiv);
    });

    afterEach(() => {
      document.body.removeChild(input);
      document.body.removeChild(textarea);
      document.body.removeChild(contentEditableDiv);
    });

    it('should not trigger single-key shortcuts in input fields', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'r', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'r', bubbles: true });
      Object.defineProperty(event, 'target', { value: input, writable: false });
      input.dispatchEvent(event);

      expect(action).not.toHaveBeenCalled();
    });

    it('should not trigger single-key shortcuts in textarea', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'r', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'r', bubbles: true });
      Object.defineProperty(event, 'target', { value: textarea, writable: false });
      textarea.dispatchEvent(event);

      expect(action).not.toHaveBeenCalled();
    });

    it('should not trigger single-key shortcuts in content editable elements', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'r', action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'r', bubbles: true });
      Object.defineProperty(event, 'target', { value: contentEditableDiv, writable: false });
      contentEditableDiv.dispatchEvent(event);

      expect(action).not.toHaveBeenCalled();
    });

    it('should trigger ctrl shortcuts in input fields', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'k', ctrl: true, action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true });
      Object.defineProperty(event, 'target', { value: input, writable: false });
      input.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });

    it('should trigger ctrl+shift shortcuts in input fields', () => {
      const action = vi.fn();
      renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'd', ctrl: true, shift: true, action }]})
      );

      const event = new KeyboardEvent('keydown', { key: 'd', ctrlKey: true, shiftKey: true, bubbles: true });
      Object.defineProperty(event, 'target', { value: input, writable: false });
      input.dispatchEvent(event);

      expect(action).toHaveBeenCalledTimes(1);
    });
  });

  describe('Event Listener Cleanup', () => {
    it('should cleanup event listeners on unmount', () => {
      const action = vi.fn();
      const { unmount } = renderHook(() =>
        useKeyboardShortcuts({
          shortcuts: [{ key: 'a', action }]})
      );

      unmount();

      const event = new KeyboardEvent('keydown', { key: 'a' });
      window.dispatchEvent(event);

      expect(action).not.toHaveBeenCalled();
    });
  });
});

describe('useGlobalKeyboardShortcuts', () => {
  beforeEach(() => {
    mockNavigate.mockClear();
  });

  it('should open command palette on Ctrl+K', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true });
    window.dispatchEvent(event);

    expect(onCommandPaletteOpen).toHaveBeenCalledTimes(1);
  });

  it('should open command palette on Ctrl+P', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'p', ctrlKey: true });
    window.dispatchEvent(event);

    expect(onCommandPaletteOpen).toHaveBeenCalledTimes(1);
  });

  it('should navigate to Dashboard on Ctrl+Shift+D', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'd', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });

  it('should navigate to Events on Ctrl+Shift+E', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'e', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/events');
  });

  it('should navigate to Alerts on Ctrl+Shift+A', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'a', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/alerts');
  });

  it('should navigate to Rules on Ctrl+Shift+R', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'r', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/rules');
  });

  it('should navigate to Correlation Rules on Ctrl+Shift+C', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'c', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/correlation-rules');
  });

  it('should navigate to Listeners on Ctrl+Shift+L', () => {
    const onCommandPaletteOpen = vi.fn();
    renderHook(() => useGlobalKeyboardShortcuts(onCommandPaletteOpen), {
      wrapper: BrowserRouter});

    const event = new KeyboardEvent('keydown', { key: 'l', ctrlKey: true, shiftKey: true });
    window.dispatchEvent(event);

    expect(mockNavigate).toHaveBeenCalledWith('/listeners');
  });
});

describe('usePageKeyboardShortcuts', () => {
  let input: HTMLInputElement;

  beforeEach(() => {
    input = document.createElement('input');
    document.body.appendChild(input);
  });

  afterEach(() => {
    document.body.removeChild(input);
  });

  it('should trigger onRefresh when R is pressed', () => {
    const onRefresh = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(onRefresh));

    const event = new KeyboardEvent('keydown', { key: 'r' });
    window.dispatchEvent(event);

    expect(onRefresh).toHaveBeenCalledTimes(1);
  });

  it('should trigger onNew when N is pressed', () => {
    const onNew = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(undefined, onNew));

    const event = new KeyboardEvent('keydown', { key: 'n' });
    window.dispatchEvent(event);

    expect(onNew).toHaveBeenCalledTimes(1);
  });

  it('should trigger onSearch when Ctrl+F is pressed', () => {
    const onSearch = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(undefined, undefined, onSearch));

    const event = new KeyboardEvent('keydown', { key: 'f', ctrlKey: true });
    window.dispatchEvent(event);

    expect(onSearch).toHaveBeenCalledTimes(1);
  });

  it('should handle all callbacks together', () => {
    const onRefresh = vi.fn();
    const onNew = vi.fn();
    const onSearch = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(onRefresh, onNew, onSearch));

    const refreshEvent = new KeyboardEvent('keydown', { key: 'r' });
    window.dispatchEvent(refreshEvent);

    const newEvent = new KeyboardEvent('keydown', { key: 'n' });
    window.dispatchEvent(newEvent);

    const searchEvent = new KeyboardEvent('keydown', { key: 'f', ctrlKey: true });
    window.dispatchEvent(searchEvent);

    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(onNew).toHaveBeenCalledTimes(1);
    expect(onSearch).toHaveBeenCalledTimes(1);
  });

  it('should not add shortcuts for undefined callbacks', () => {
    const onRefresh = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(onRefresh));

    // Try pressing N key (should not trigger anything since onNew is undefined)
    const event = new KeyboardEvent('keydown', { key: 'n' });
    window.dispatchEvent(event);

    // Only onRefresh should exist, so nothing should happen
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('should not trigger R shortcut in input fields', () => {
    const onRefresh = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(onRefresh));

    const event = new KeyboardEvent('keydown', { key: 'r', bubbles: true });
    Object.defineProperty(event, 'target', { value: input, writable: false });
    input.dispatchEvent(event);

    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('should not trigger N shortcut in input fields', () => {
    const onNew = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(undefined, onNew));

    const event = new KeyboardEvent('keydown', { key: 'n', bubbles: true });
    Object.defineProperty(event, 'target', { value: input, writable: false });
    input.dispatchEvent(event);

    expect(onNew).not.toHaveBeenCalled();
  });

  it('should trigger Ctrl+F shortcut in input fields', () => {
    const onSearch = vi.fn();
    renderHook(() => usePageKeyboardShortcuts(undefined, undefined, onSearch));

    const event = new KeyboardEvent('keydown', { key: 'f', ctrlKey: true, bubbles: true });
    Object.defineProperty(event, 'target', { value: input, writable: false });
    input.dispatchEvent(event);

    expect(onSearch).toHaveBeenCalledTimes(1);
  });
});
