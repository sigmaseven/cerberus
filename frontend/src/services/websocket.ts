import { Event, Alert } from '../types';

export interface WebSocketMessage {
  type: 'event' | 'alert' | 'listener_status' | 'dashboard_stats';
  data: any;
  timestamp: string;
}

export interface WebSocketCallbacks {
  onEvent?: (event: Event) => void;
  onAlert?: (alert: Alert) => void;
  onListenerStatus?: (status: any) => void;
  onDashboardStats?: (stats: any) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 1000; // Start with 1 second
  private callbacks: WebSocketCallbacks = {};
  private isConnecting = false;
  private isEnabled = false; // Don't auto-connect until explicitly enabled

  constructor() {
    // Removed auto-connect - will only connect when subscribe() is called
  }

  private getWebSocketUrl(): string {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
    // Convert HTTP to WS
    const wsUrl = baseUrl.replace(/^http/, 'ws');
    return `${wsUrl}/ws`;
  }

  connect(): void {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isConnecting = true;
    const url = this.getWebSocketUrl();

    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.isConnecting = false;
        this.reconnectAttempts = 0;
        this.reconnectInterval = 1000;
        this.callbacks.onConnect?.();
      };

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          this.handleMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.isConnecting = false;
        this.callbacks.onDisconnect?.();
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        // Silently handle WebSocket errors if the endpoint doesn't exist
        // Only log if we were previously connected (indicating a real error)
        if (this.reconnectAttempts > 0) {
          console.warn('WebSocket connection lost, attempting to reconnect...');
        }
        // Don't spam console with errors on initial connection failure
        this.callbacks.onError?.(error);
      };

    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.isConnecting = false;
      this.attemptReconnect();
    }
  }

  private attemptReconnect(): void {
    // Don't attempt reconnection if WebSocket is not enabled
    if (!this.isEnabled) {
      return;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => {
      this.reconnectInterval = Math.min(this.reconnectInterval * 2, 30000); // Exponential backoff, max 30s
      this.connect();
    }, this.reconnectInterval);
  }

  private handleMessage(message: WebSocketMessage): void {
    switch (message.type) {
      case 'event':
        this.callbacks.onEvent?.(message.data);
        break;
      case 'alert':
        this.callbacks.onAlert?.(message.data);
        break;
      case 'listener_status':
        this.callbacks.onListenerStatus?.(message.data);
        break;
      case 'dashboard_stats':
        this.callbacks.onDashboardStats?.(message.data);
        break;
      default:
        console.warn('Unknown WebSocket message type:', message.type);
    }
  }

  subscribe(callbacks: WebSocketCallbacks): void {
    this.callbacks = { ...this.callbacks, ...callbacks };

    // Only enable and connect if not already enabled
    if (!this.isEnabled) {
      this.isEnabled = true;
      this.connect();
    }
  }

  unsubscribe(): void {
    this.callbacks = {};
    // Optionally disconnect when no callbacks are registered
    this.disconnect();
  }

  disconnect(): void {
    this.isEnabled = false; // Disable to prevent reconnections
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.reconnectAttempts = this.maxReconnectAttempts; // Prevent further reconnections
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  send(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected. Message not sent:', message);
    }
  }
}

// Create singleton instance
export const websocketService = new WebSocketService();
export default websocketService;