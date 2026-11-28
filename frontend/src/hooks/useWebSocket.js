import { useEffect, useRef } from 'react';

const WS_URL = 'ws://127.0.0.1:8000/ws/events';
const RECONNECT_MIN_MS = 3000;
const RECONNECT_MAX_MS = 30000;

/**
 * useWebSocket — shared, auto-reconnecting WebSocket hook
 *
 * @param {function} onMessage  - called with parsed JSON payload on each message
 * @param {boolean}  enabled    - set false to skip connecting (e.g. feature-flagged pages)
 *
 * Keeps reconnecting while mounted (3 s, doubling up to 30 s): the backend's first start syncs
 * feeds before it answers, and live alerts must resume whenever it comes back.
 */
export function useWebSocket(onMessage, enabled = true) {
  const onMessageRef = useRef(onMessage);

  // Keep ref current so the open socket always calls the latest handler
  useEffect(() => { onMessageRef.current = onMessage; }, [onMessage]);

  useEffect(() => {
    if (!enabled) return undefined;
    let ws = null;
    let timer = null;
    let delay = RECONNECT_MIN_MS;
    let stopped = false;

    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => { delay = RECONNECT_MIN_MS; };
      ws.onmessage = (event) => {
        try {
          onMessageRef.current?.(JSON.parse(event.data));
        } catch (e) {
          console.warn('[WS] Failed to parse message:', event.data, e);
        }
      };
      ws.onclose = () => {
        if (stopped) return;
        timer = setTimeout(connect, delay);
        delay = Math.min(delay * 2, RECONNECT_MAX_MS);
      };
    };
    connect();

    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [enabled]);
}
