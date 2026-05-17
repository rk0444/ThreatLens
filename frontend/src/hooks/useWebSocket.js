import { useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://127.0.0.1:8000/ws/events';
const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

/**
 * useWebSocket — shared, auto-reconnecting WebSocket hook
 *
 * @param {function} onMessage  - called with parsed JSON payload on each message
 * @param {boolean}  enabled    - set false to skip connecting (e.g. feature-flagged pages)
 *
 * Usage:
 *   useWebSocket((data) => {
 *     if (data.type === 'NEW_INCIDENT') setIncidents(prev => [data.data, ...prev]);
 *   });
 */
export function useWebSocket(onMessage, enabled = true) {
  const wsRef        = useRef(null);
  const attemptsRef  = useRef(0);
  const timerRef     = useRef(null);
  const onMessageRef = useRef(onMessage);

  // Keep ref current so reconnect closure always calls latest handler
  useEffect(() => { onMessageRef.current = onMessage; }, [onMessage]);

  const connect = useCallback(() => {
    if (!enabled) return;
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        attemptsRef.current = 0;
        console.debug('[WS] Connected to', WS_URL);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessageRef.current?.(data);
        } catch (e) {
          console.warn('[WS] Failed to parse message:', event.data, e);
        }
      };

      ws.onerror = (err) => {
        console.warn('[WS] Error:', err);
      };

      ws.onclose = (event) => {
        console.debug(`[WS] Closed (code=${event.code}). Attempt ${attemptsRef.current + 1}/${MAX_RECONNECT_ATTEMPTS}`);
        if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          attemptsRef.current += 1;
          timerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
        } else {
          console.warn('[WS] Max reconnect attempts reached. Giving up.');
        }
      };
    } catch (e) {
      console.error('[WS] Failed to create WebSocket:', e);
    }
  }, [enabled]);

  useEffect(() => {
    connect();
    return () => {
      // Cleanup: close socket and cancel any pending reconnect
      clearTimeout(timerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect loop on unmount
        wsRef.current.close();
        wsRef.current = null;
      }
      attemptsRef.current = 0;
    };
  }, [connect]);
}