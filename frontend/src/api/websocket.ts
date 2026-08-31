import { Client } from '@stomp/stompjs';
import SockJS from 'sockjs-client';
import { MetricsSnapshot, OcsfEvent } from './types';

class WebSocketService {
  private client: Client | null = null;
  private metricsCallbacks: Set<(data: MetricsSnapshot) => void> = new Set();
  private eventCallbacks: Set<(data: OcsfEvent) => void> = new Set();
  private isConnected = false;

  connect() {
    if (this.client && this.isConnected) return;

    this.client = new Client({
      webSocketFactory: () => new SockJS('/ws/ulpf'),
      reconnectDelay: 3000,
      heartbeatIncoming: 4000,
      heartbeatOutgoing: 4000,
      debug: (msg) => {
        // console.debug('[STOMP]', msg);
      },
    });

    this.client.onConnect = () => {
      this.isConnected = true;
      // console.log('[STOMP] Connected to ULPF Live Broker');

      // Subscribe to metrics
      this.client?.subscribe('/topic/metrics', (message) => {
        try {
          const data: MetricsSnapshot = JSON.parse(message.body);
          this.metricsCallbacks.forEach((cb) => cb(data));
        } catch (e) {
          console.error('Failed to parse metrics message', e);
        }
      });

      // Subscribe to events
      this.client?.subscribe('/topic/events', (message) => {
        try {
          const data: OcsfEvent = JSON.parse(message.body);
          this.eventCallbacks.forEach((cb) => cb(data));
        } catch (e) {
          console.error('Failed to parse event message', e);
        }
      });
    };

    this.client.onDisconnect = () => {
      this.isConnected = false;
    };

    this.client.onStompError = (frame) => {
      console.warn('[STOMP Error]', frame.headers['message'], frame.body);
    };

    this.client.activate();
  }

  onMetrics(callback: (data: MetricsSnapshot) => void): () => void {
    this.metricsCallbacks.add(callback);
    this.connect();
    return () => {
      this.metricsCallbacks.delete(callback);
    };
  }

  onEvent(callback: (data: OcsfEvent) => void): () => void {
    this.eventCallbacks.add(callback);
    this.connect();
    return () => {
      this.eventCallbacks.delete(callback);
    };
  }

  disconnect() {
    if (this.client) {
      this.client.deactivate();
      this.client = null;
      this.isConnected = false;
    }
  }
}

export const wsService = new WebSocketService();
