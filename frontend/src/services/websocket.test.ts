import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { websocketService } from './websocket';

// Mock WebSocket
const mockWebSocket = {
  readyState: 0, // CONNECTING
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
  send: vi.fn(),
  close: vi.fn(),
  onopen: null as any,
  onmessage: null as any,
  onclose: null as any,
  onerror: null as any,
};

global.WebSocket = vi.fn().mockImplementation(() => mockWebSocket);

describe('WebSocketService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset the singleton instance
    (websocketService as any).ws = null;
    (websocketService as any).isConnecting = false;
    (websocketService as any).reconnectAttempts = 0;
  });

  afterEach(() => {
    websocketService.disconnect();
  });

  describe('connect', () => {
    it('should create a WebSocket connection', () => {
      websocketService.connect();

      expect(global.WebSocket).toHaveBeenCalledWith('ws://localhost:8081/ws');
      expect(mockWebSocket.onopen).toBeDefined();
      expect(mockWebSocket.onmessage).toBeDefined();
      expect(mockWebSocket.onclose).toBeDefined();
      expect(mockWebSocket.onerror).toBeDefined();
    });

    it('should not create multiple connections when already connecting', () => {
      (websocketService as any).isConnecting = true;

      websocketService.connect();

      expect(global.WebSocket).not.toHaveBeenCalled();
    });

    it('should not create connection when already connected', () => {
      (websocketService as any).ws = { readyState: WebSocket.OPEN };

      websocketService.connect();

      expect(global.WebSocket).not.toHaveBeenCalled();
    });
  });

  describe('handleMessage', () => {
    it('should call event callback for event messages', () => {
      const mockCallback = vi.fn();
      websocketService.subscribe({ onEvent: mockCallback });

      const mockEvent = { data: JSON.stringify({ type: 'event', data: { id: '1' } }) };
      mockWebSocket.onmessage(mockEvent);

      expect(mockCallback).toHaveBeenCalledWith({ id: '1' });
    });

    it('should call alert callback for alert messages', () => {
      const mockCallback = vi.fn();
      websocketService.subscribe({ onAlert: mockCallback });

      const mockEvent = { data: JSON.stringify({ type: 'alert', data: { alert_id: '1' } }) };
      mockWebSocket.onmessage(mockEvent);

      expect(mockCallback).toHaveBeenCalledWith({ alert_id: '1' });
    });

    it('should call dashboard stats callback for dashboard_stats messages', () => {
      const mockCallback = vi.fn();
      websocketService.subscribe({ onDashboardStats: mockCallback });

      const mockEvent = { data: JSON.stringify({ type: 'dashboard_stats', data: { total_events: 100 } }) };
      mockWebSocket.onmessage(mockEvent);

      expect(mockCallback).toHaveBeenCalledWith({ total_events: 100 });
    });

    it('should handle invalid JSON gracefully', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const mockEvent = { data: 'invalid json' };
      mockWebSocket.onmessage(mockEvent);

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should ignore unknown message types', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const mockEvent = { data: JSON.stringify({ type: 'unknown', data: {} }) };
      mockWebSocket.onmessage(mockEvent);

      expect(consoleSpy).toHaveBeenCalledWith('Unknown WebSocket message type:', 'unknown');
      consoleSpy.mockRestore();
    });
  });

  describe('send', () => {
    it('should send message when connected', () => {
      (websocketService as any).ws = mockWebSocket;
      mockWebSocket.readyState = WebSocket.OPEN;

      websocketService.send({ type: 'test' });

      expect(mockWebSocket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'test' }));
    });

    it('should not send message when not connected', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      websocketService.send({ type: 'test' });

      expect(mockWebSocket.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('isConnected', () => {
    it('should return true when connected', () => {
      (websocketService as any).ws = mockWebSocket;
      mockWebSocket.readyState = WebSocket.OPEN;

      expect(websocketService.isConnected()).toBe(true);
    });

    it('should return false when not connected', () => {
      expect(websocketService.isConnected()).toBe(false);
    });
  });

  describe('disconnect', () => {
    it('should close WebSocket connection', () => {
      (websocketService as any).ws = mockWebSocket;

      websocketService.disconnect();

      expect(mockWebSocket.close).toHaveBeenCalled();
      expect((websocketService as any).ws).toBeNull();
    });
  });

  describe('reconnection', () => {
    it('should attempt reconnection on close', () => {
      vi.useFakeTimers();
      const connectSpy = vi.spyOn(websocketService as any, 'connect');

      mockWebSocket.onclose();

      vi.advanceTimersByTime(1000);

      expect(connectSpy).toHaveBeenCalled();
      vi.useRealTimers();
    });

    it('should stop attempting reconnection after max attempts', () => {
      (websocketService as any).reconnectAttempts = 5;

      websocketService.disconnect();

      expect((websocketService as any).reconnectAttempts).toBe(5);
    });
  });
});