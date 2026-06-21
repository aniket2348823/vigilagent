import { useEffect, useRef, useCallback } from 'react';
import { websocketUrl } from '../lib/api';

/**
 * App-level singleton WebSocket manager.
 * All pages share one connection instead of each opening their own.
 *
 * Reconnect strategy: exponential backoff with jitter
 *   delay  = min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** attempts)
 *   jitter = ±25% (helps avoid thundering-herd)
 *   attempts reset to 0 on a successful `open`.
 *   After MAX_ATTEMPTS consecutive failures, dispatches a synthetic
 *   `{ type: 'WS_GIVEUP' }` event to all subscribers so the UI can show
 *   "OFFLINE — please refresh" and stops trying to reconnect.
 *
 * Auth: getWsToken() may legitimately return '' in dev (when backend WS auth
 * is OFF). websocketUrl() omits the `token` query param in that case, so the
 * connection still succeeds.
 *
 * Usage:
 *   const { subscribe, isConnected } = useWebSocket();
 *   useEffect(() => subscribe((data) => { ... }), [subscribe]);
 */

// ── Reconnect tuning ──
const BASE_DELAY_MS = 1000;       // 1s
const MAX_DELAY_MS  = 30000;      // 30s
const MAX_ATTEMPTS  = 30;         // give up after 30 tries
const JITTER_RATIO  = 0.25;       // ±25%

// ── Module-level singleton state ──
let _ws = null;
let _listeners = new Set();
let _reconnectTimer = null;
let _reconnectAttempts = 0;
let _gaveUp = false;
let _connected = false;
let _connectListeners = new Set();

function _notifyConnect(state) {
    _connected = state;
    _connectListeners.forEach(fn => fn(state));
}

function _dispatch(data) {
    _listeners.forEach(fn => {
        try { fn(data); } catch (e) { /* listener error — swallow to protect other subscribers */ }
    });
}

function _computeBackoffMs(attempts) {
    // delay = Math.min(maxDelay, base * 2 ** attempts)
    // (Math.pow is equivalent to ** — both notations kept for clarity.)
    const exp = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * (2 ** attempts));
    // jitter ±25%
    const jitter = exp * JITTER_RATIO * (Math.random() * 2 - 1);
    return Math.max(0, Math.round(exp + jitter));
}

function _connect() {
    if (_gaveUp) return; // permanent stop until manual reset
    if (_ws && (_ws.readyState === WebSocket.CONNECTING || _ws.readyState === WebSocket.OPEN)) {
        return; // already connected or connecting
    }

    try {
        // websocketUrl handles the empty-token (dev) case — token param omitted.
        _ws = new WebSocket(websocketUrl('/stream', { client_type: 'ui' }));
    } catch (e) {
        // console.error('[useWebSocket] Failed to create WebSocket', e);
        _scheduleReconnect();
        return;
    }

    _ws.onopen = () => {
        _reconnectAttempts = 0; // reset on successful connect
        _notifyConnect(true);
    };

    _ws.onmessage = (event) => {
        // Wrap JSON.parse in try/catch so a single malformed frame doesn't
        // kill the reader for every subscriber.
        let parsed;
        try {
            parsed = JSON.parse(event.data);
        } catch (e) {
            // console.error('[WS] Parse error — frame ignored', e);
            return;
        }
        try {
            if (parsed && parsed.type === 'BATCH' && Array.isArray(parsed.payload)) {
                parsed.payload.forEach(_dispatch);
            } else {
                _dispatch(parsed);
            }
        } catch (e) {
            // console.error('[WS] Dispatch error', e);
        }
    };

    _ws.onclose = () => {
        _notifyConnect(false);
        _scheduleReconnect();
    };

    _ws.onerror = () => {
        // onclose will fire after this — reconnect handled there.
    };
}

function _scheduleReconnect() {
    clearTimeout(_reconnectTimer);
    if (_gaveUp) return;

    if (_reconnectAttempts >= MAX_ATTEMPTS) {
        _gaveUp = true;
        // console.warn(`[WS] Reconnect limit reached (${MAX_ATTEMPTS} attempts) — surfacing WS_GIVEUP`);
        // Notify subscribers (e.g. LiveMonitor) so they can render an
        // "OFFLINE — please refresh" state.
        _dispatch({ type: 'WS_GIVEUP', payload: { attempts: _reconnectAttempts } });
        return;
    }

    const delay = _computeBackoffMs(_reconnectAttempts);
    _reconnectAttempts += 1;
    _reconnectTimer = setTimeout(_connect, delay);
}

function _ensureConnection() {
    if (_gaveUp) return; // user must refresh
    if (!_ws || _ws.readyState === WebSocket.CLOSED || _ws.readyState === WebSocket.CLOSING) {
        _connect();
    }
}

/**
 * React hook — subscribe to WebSocket messages.
 * The connection is opened on first subscriber and kept alive across page navigations.
 *
 * @returns {{ subscribe: (cb: Function) => () => void, isConnected: boolean }}
 */
export function useWebSocket() {
    const connectedRef = useRef(_connected);

    useEffect(() => {
        _ensureConnection();

        const onConnect = (state) => { connectedRef.current = state; };
        _connectListeners.add(onConnect);

        return () => {
            _connectListeners.delete(onConnect);
        };
    }, []);

    /**
     * Subscribe to all incoming WS messages (including synthetic `WS_GIVEUP`).
     * Returns an unsubscribe function.
     */
    const subscribe = useCallback((callback) => {
        _listeners.add(callback);
        _ensureConnection();
        return () => {
            _listeners.delete(callback);
        };
    }, []);

    return { subscribe, isConnected: connectedRef.current };
}

/**
 * Reset all module-level singleton state.
 * Only for use in tests — ensures each test starts with a clean slate.
 */
export function _resetForTesting() {
    if (_ws) {
        try { _ws.close(); } catch (_) { /* ignore */ }
    }
    _ws = null;
    _listeners = new Set();
    clearTimeout(_reconnectTimer);
    _reconnectTimer = null;
    _reconnectAttempts = 0;
    _gaveUp = false;
    _connected = false;
    _connectListeners = new Set();
}
