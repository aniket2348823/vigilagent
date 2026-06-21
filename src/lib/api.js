const normalizeBaseUrl = (value) => value.replace(/\/+$/, '');
const normalizePath = (path) => (path.startsWith('/') ? path : `/${path}`);

const getDefaultBackendHost = () => {
    const { hostname } = window.location;
    if (hostname === 'localhost') return 'localhost:8000';
    if (hostname === '127.0.0.1') return '127.0.0.1:8000';
    return `${hostname}:8000`;
};

const apiBaseFromEnv = import.meta.env.VITE_API_BASE_URL;
const wsBaseFromEnv = import.meta.env.VITE_WS_BASE_URL;

// FIX: In dev mode, use relative URLs so requests flow through Vite's proxy
// (/api → http://127.0.0.1:8000). In production, Nginx also proxies /api/ so
// relative URLs work there too. Only fall back to explicit backend host when
// VITE_API_BASE_URL is explicitly set.
export const API_BASE_URL = normalizeBaseUrl(
    apiBaseFromEnv || (import.meta.env.DEV ? '' : `${window.location.protocol}//${getDefaultBackendHost()}`)
);

export const WS_BASE_URL = normalizeBaseUrl(
    wsBaseFromEnv || (import.meta.env.DEV ? '' : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${getDefaultBackendHost()}`)
);

export const getWsToken = () => localStorage.getItem('vulagent_ws_token') || '';

export const apiUrl = (path) => `${API_BASE_URL}${normalizePath(path)}`;

// NOTE: API key auth (HIGH-43) is handled server-side by the Vite proxy
// injecting X-API-Key via proxyReq. No client-side key exposure needed.

export const websocketUrl = (path, params = {}) => {
    // FIX: new URL() requires an absolute URL. When WS_BASE_URL is empty
    // (dev mode relative URLs), derive it from the current page origin so
    // Vite can proxy the WebSocket upgrade to the backend.
    const wsBase = WS_BASE_URL
        || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;
    const url = new URL(`${wsBase}${normalizePath(path)}`);
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
            url.searchParams.set(key, value);
        }
    });

    const token = getWsToken();
    if (token && !url.searchParams.has('token')) {
        url.searchParams.set('token', token);
    }

    return url.toString();
};

// ── Hidden-scans (frontend-only "wipe history") ──
// These IDs are filtered out of the Scans view; backend storage is untouched.
const HIDDEN_SCANS_KEY = 'vigilagent.hiddenScans';

export const getHiddenScanIds = () => {
    try {
        const raw = localStorage.getItem(HIDDEN_SCANS_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string') : [];
    } catch {
        return [];
    }
};

export const setHiddenScanIds = (ids) => {
    try {
        const unique = Array.from(new Set((ids || []).filter((v) => typeof v === 'string')));
        localStorage.setItem(HIDDEN_SCANS_KEY, JSON.stringify(unique));
        return unique;
    } catch {
        return [];
    }
};

export const addHiddenScanIds = (ids) => {
    const current = getHiddenScanIds();
    return setHiddenScanIds([...current, ...(ids || [])]);
};

export const clearHiddenScanIds = () => {
    try { localStorage.removeItem(HIDDEN_SCANS_KEY); } catch { /* noop */ }
};

// ── Scan creation (POST /api/scans) ──
// Backend returns 202 with { scan_id, status }. We surface a clear error message
// on non-2xx responses so the caller can show it inline.
// ── CSRF Token Management ──
// Backend requires X-CSRF-Token on all state-changing API requests (POST/PUT/PATCH/DELETE).
// Tokens are single-use (consumed on validation), so we fetch a fresh one per request.
export const getCsrfToken = async () => {
    try {
        const res = await fetch(apiUrl('/api/dashboard/csrf-token'));
        if (res.ok) {
            const data = await res.json();
            return data.csrf_token || null;
        }
    } catch { /* ignore */ }
    return null;
};

// ── Authenticated fetch wrapper (CSRF) ──
// Automatically fetches a CSRF token for state-changing requests.
// Retries once on 403 CSRF failure with a fresh token.
export const csrfFetch = async (url, options = {}, _retried = false) => {
    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        const token = await getCsrfToken();
        const headers = { ...options.headers };
        if (token) headers['X-CSRF-Token'] = token;
        options = { ...options, headers };
    }
    const res = await fetch(url, options);
    // Retry once on CSRF 403 (stale/expired token)
    if (!_retried && res.status === 403 && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        const body = await res.clone().json().catch(() => ({}));
        if (body.detail && body.detail.includes('CSRF')) {
            return csrfFetch(url, options, true);
        }
    }
    return res;
};

export const createScan = async ({ target_url, mode = 'STANDARD', modules = [] }) => {
    const url = apiUrl('/api/scans');
    let response;
    try {
        response = await csrfFetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url, mode, modules }),
        });
    } catch (err) {
        const msg = err && err.message ? err.message : 'Network error';
        const e = new Error(`Failed to reach backend: ${msg}`);
        e.cause = err;
        throw e;
    }

    let body = null;
    try { body = await response.json(); } catch { /* keep null */ }

    if (!response.ok) {
        const detail = (body && (body.detail || body.message)) || `HTTP ${response.status}`;
        const e = new Error(`Scan creation failed: ${detail}`);
        e.status = response.status;
        e.body = body;
        throw e;
    }

    return body || {};
};
