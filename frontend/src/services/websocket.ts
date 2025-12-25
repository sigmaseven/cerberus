import { Event, Alert, ListenerStatus, DashboardStats } from '../types';
import { WebSocketMessageSchema, safeValidateSchema } from '../schemas/api.schemas';

// TASK 158: Feed sync event types
export interface FeedSyncEvent {
  type: 'feed:sync:started' | 'feed:sync:progress' | 'feed:sync:completed' | 'feed:sync:failed';
  feed_id: string;
  feed_name: string;
  progress?: number; // 0-100
  message?: string;
  stats?: {
    total_rules: number;
    imported_rules: number;
    updated_rules: number;
    skipped_rules: number;
    failed_rules: number;
    last_sync_duration: number;
  };
  error?: string;
  timestamp: string;
}

export type WebSocketMessageData = Event | Alert | ListenerStatus | DashboardStats | FeedSyncEvent;

export interface WebSocketMessage {
  type: 'event' | 'alert' | 'listener_status' | 'dashboard_stats' | 'feed_sync';
  data: WebSocketMessageData;
  timestamp: string;
}

export interface WebSocketCallbacks {
  onEvent?: (event: Event) => void;
  onAlert?: (alert: Alert) => void;
  onListenerStatus?: (status: ListenerStatus) => void;
  onDashboardStats?: (stats: DashboardStats) => void;
  onFeedSync?: (event: FeedSyncEvent) => void; // TASK 158
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
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8081';
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
        this.isConnecting = false;
        this.reconnectAttempts = 0;
        this.reconnectInterval = 1000;
        this.callbacks.onConnect?.();
      };

      this.ws.onmessage = (event) => {
        try {
          const rawData = JSON.parse(event.data);

          // SECURITY: Validate WebSocket message structure
          const validatedMessage = safeValidateSchema(WebSocketMessageSchema, rawData);

          if (!validatedMessage) {
            if (import.meta.env.DEV) {
              console.error('Invalid WebSocket message format:', rawData);
            }
            // Don't process invalid messages to prevent XSS/injection
            return;
          }

          this.handleMessage(validatedMessage);
        } catch (error) {
          if (import.meta.env.DEV) {
            console.error('Failed to parse WebSocket message:', error);
          }
          // Don't crash the app, just log and continue
        }
      };

      this.ws.onclose = () => {
        this.isConnecting = false;
        this.callbacks.onDisconnect?.();
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        // Silently handle WebSocket errors if the endpoint doesn't exist
        // Only log if we were previously connected (indicating a real error)
        if (this.reconnectAttempts > 0 && import.meta.env.DEV) {
          console.warn('WebSocket connection lost, attempting to reconnect...');
        } else if (this.reconnectAttempts === 0 && import.meta.env.DEV) {
          // Silent fail on first attempt - backend may not have WebSocket endpoint
          console.debug('WebSocket not available - realtime updates disabled');
        }
        // Don't spam console with errors on initial connection failure
        this.callbacks.onError?.(error);
      };

    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to create WebSocket connection:', error);
      }
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
      return;
    }

    this.reconnectAttempts++;

    setTimeout(() => {
      this.reconnectInterval = Math.min(this.reconnectInterval * 2, 30000); // Exponential backoff, max 30s
      this.connect();
    }, this.reconnectInterval);
  }

  private handleMessage(message: { type: string; data?: unknown; timestamp?: number }): void {
    // SECURITY: Messages are already validated by WebSocketMessageSchema
    switch (message.type) {
      case 'event':
        if (message.data) {
          this.callbacks.onEvent?.(message.data as Event);
        }
        break;
      case 'alert':
        if (message.data) {
          this.callbacks.onAlert?.(message.data as Alert);
        }
        break;
      case 'stats':
        if (message.data) {
          this.callbacks.onDashboardStats?.(message.data as DashboardStats);
        }
        break;
      case 'feed_sync':
        // TASK 158: Handle feed sync events
        if (message.data) {
          this.callbacks.onFeedSync?.(message.data as FeedSyncEvent);
        }
        break;
      case 'heartbeat':
        // Heartbeat message - no action needed
        break;
      default:
        if (import.meta.env.DEV) {
          console.warn('Unknown WebSocket message type:', message.type);
        }
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

  send(message: Record<string, unknown>): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else if (import.meta.env.DEV) {
      console.warn('WebSocket is not connected. Message not sent:', message);
    }
  }
}

// Create singleton instance
export const websocketService = new WebSocketService();
export default websocketService;