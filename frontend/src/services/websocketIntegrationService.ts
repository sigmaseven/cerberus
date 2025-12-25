import { AxiosInstance } from 'axios';
import websocketService, { WebSocketCallbacks } from './websocket';

class WebSocketIntegrationService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  subscribeToRealtimeUpdates(callbacks: WebSocketCallbacks): void {
    websocketService.subscribe(callbacks);
    // Automatically connect if not already connected
    if (!websocketService.isConnected()) {
      websocketService.connect();
    }
  }

  unsubscribeFromRealtimeUpdates(): void {
    websocketService.unsubscribe();
  }

  isWebSocketConnected(): boolean {
    return websocketService.isConnected();
  }
}

export default WebSocketIntegrationService;