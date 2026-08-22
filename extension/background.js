// Antigravity Spy V2 - Background Service Worker
// Modules: Synapse (Key Capture) + Traffic Interception + Aegis (Active Defense)

// ============================================================================
// CONFIGURATION
// ============================================================================

const BACKEND_URL = "http://localhost:8000";
const WS_ENDPOINT = "ws://localhost:8000/stream?client_type=spy";

// ============================================================================
// WEBSOCKET SPY REGISTRATION
// ============================================================================

let spyWs = null;
let spyReconnectTimer = null;
let spyReconnectAttempts = 0;
const SPY_BASE_DELAY_MS = 2000;
const SPY_MAX_DELAY_MS = 30000;

function connectSpyWebSocket() {
    if (spyWs && (spyWs.readyState === WebSocket.CONNECTING || spyWs.readyState === WebSocket.OPEN)) {
        return;
    }
    if (!isBackendAlive) return;
    try {
        spyWs = new WebSocket(WS_ENDPOINT);
        spyWs.onopen = () => {
            spyReconnectAttempts = 0;
            console.log("[SPY WS] Connected to backend as spy");
        };
        spyWs.onmessage = () => {
            // Inbound frames are scope/pause signals — acknowledged silently.
        };
        spyWs.onclose = () => {
            console.log("[SPY WS] Disconnected, scheduling reconnect");
            scheduleSpyReconnect();
        };
        spyWs.onerror = () => {
            // onclose fires after this — reconnect handled there.
        };
    } catch (e) {
        console.warn("[SPY WS] Failed to create WebSocket:", e.message);
        scheduleSpyReconnect();
    }
}

function scheduleSpyReconnect() {
    clearTimeout(spyReconnectTimer);
    if (!isBackendAlive) return;
    const delay = Math.min(SPY_MAX_DELAY_MS, SPY_BASE_DELAY_MS * (2 ** spyReconnectAttempts));
    spyReconnectAttempts += 1;
    spyReconnectTimer = setTimeout(connectSpyWebSocket, delay);
}

// ============================================================================
// BACKEND HEALTH GUARD (Triple-Shield)
// ============================================================================

let isBackendAlive = true;
// Adaptive health poll: 5s while healthy, exponential backoff up to 30s
// while the backend is down. A fixed 3s fetch forever hammered the backend
// from every browser with the extension installed — even when idle.
const HEALTH_CHECK_BASE_MS = 5000;
const HEALTH_CHECK_MAX_MS = 30000;
let healthCheckTimer = null;
let healthCheckAttempts = 0;
let lastHealthOk = true;

async function checkBackendHealth() {
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000); // hung backend can't block the poll
        const res = await fetch(`${BACKEND_URL}/api/health`, { method: 'GET', cache: 'no-store', signal: controller.signal });
        clearTimeout(timer);
        isBackendAlive = res.ok;
        if (res.ok) {
            healthCheckAttempts = 0;
            lastHealthOk = true;
        } else {
            lastHealthOk = false;
        }
    } catch (e) {
        clearTimeout(timer);
        isBackendAlive = false;
        lastHealthOk = false;
    }
    scheduleHealthCheck();
}

function scheduleHealthCheck() {
    clearTimeout(healthCheckTimer);
    // Healthy → fixed 5s cadence. Down → exponential backoff (5s → 30s).
    const delay = lastHealthOk
        ? HEALTH_CHECK_BASE_MS
        : Math.min(HEALTH_CHECK_MAX_MS, HEALTH_CHECK_BASE_MS * (2 ** healthCheckAttempts));
    healthCheckAttempts += 1;
    healthCheckTimer = setTimeout(checkBackendHealth, delay);
}

// Start the adaptive health polling loop
scheduleHealthCheck();

/**
 * SafeFetch: Prevents "Failed to fetch" spam by checking backend status first.
 * Silences network errors to keep the console clean in production.
 */
async function safeFetch(url, options = {}) {
    if (!isBackendAlive && !url.includes('/api/health')) {
        return { ok: false, status: 0, error: "Backend offline" };
    }

    try {
        const response = await fetch(url, options);
        if (!isBackendAlive && response.ok) isBackendAlive = true; // Recovery
        return response;
    } catch (err) {
        if (isBackendAlive) {
            console.warn("[TRAFFIC] First-contact failure. Backend might have dropped.");
            isBackendAlive = false;
        }
        return { ok: false, status: 0, error: err.message };
    }
}

// NOW Import active defense which depends on safeFetch
importScripts('background/active_defense.js');

// Filter out static assets
// Filter out common high-volume noise, but keep interesting stuff
const IGNORE_EXTENSIONS = ['.woff', '.woff2', '.ttf']; // Only ignore fonts
const IGNORE_METHODS = ['HEAD']; // Only ignore HEAD

// Synapse: Headers to capture
const SENSITIVE_HEADERS = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
    'x-csrf-token',
    'x-access-token',
    'x-session-id',
    'bearer'
];

// ============================================================================
// SYNAPSE MODULE - Auto Key Theft
// ============================================================================

function extractSensitiveHeaders(requestHeaders) {
    const captured = {};
    for (const h of requestHeaders) {
        const headerName = h.name.toLowerCase();
        if (SENSITIVE_HEADERS.includes(headerName)) {
            captured[h.name] = h.value;
        }
        // Also capture Bearer tokens in any header
        if (h.value && h.value.toLowerCase().startsWith('bearer ')) {
            captured[h.name] = h.value;
        }
    }
    return captured;
}

// ============================================================================
// OFFLINE QUEUE MECHANISM
// ============================================================================

let isFlushingQueue = false;

function enqueuePayload(url, options) {
    chrome.storage.local.get(['spyOfflineQueue'], (data) => {
        let queue = data.spyOfflineQueue || [];
        if (queue.length > 500) {
            queue.shift(); // Hard cap to prevent memory leak
        }
        queue.push({ url, options });
        chrome.storage.local.set({ spyOfflineQueue: queue }, () => {
            if (!isFlushingQueue && isBackendAlive) flushOfflineQueue();
        });
    });
}

async function flushOfflineQueue() {
    if (!isBackendAlive) {
        isFlushingQueue = false;
        return;
    }
    isFlushingQueue = true;
    chrome.storage.local.get(['spyOfflineQueue'], async (data) => {
        let queue = data.spyOfflineQueue || [];
        if (queue.length === 0) {
            isFlushingQueue = false;
            return;
        }

        const item = queue[0];
        try {
            const res = await fetch(item.url, item.options);
            if (res.ok) {
                // Success: remove item from queue
                queue.shift();
                chrome.storage.local.set({ spyOfflineQueue: queue }, () => {
                    // FLUSH FAST if we have more
                    if (queue.length > 0) {
                        setTimeout(flushOfflineQueue, 10); // 10ms instead of 100ms
                    } else {
                        isFlushingQueue = false;
                    }
                });
            } else {
                // Server returned error, backoff
                isFlushingQueue = false;
                setTimeout(flushOfflineQueue, 2000);
            }
        } catch (err) {
            // Failed: backend still offline, backoff
            isBackendAlive = false;
            isFlushingQueue = false;
            setTimeout(flushOfflineQueue, 2000); 
        }
    });
}

async function sendCapturedKeys(url, keys) {
    if (Object.keys(keys).length === 0) return;

    try {
        await safeFetch(`${BACKEND_URL}/api/recon/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: url,
                keys: keys,
                timestamp: Date.now() / 1000
            })
        });

        // Show badge notification
        chrome.action.setBadgeText({ text: '🔑' });
        chrome.action.setBadgeBackgroundColor({ color: '#8A2BE2' });

        // Clear badge after 3 seconds
        setTimeout(() => chrome.action.setBadgeText({ text: '' }), 3000);

        console.log("[SYNAPSE] Keys captured from:", url);
    } catch (err) {
        console.warn("[SYNAPSE] Backend offline, queuing keys:", err.message);
        enqueuePayload(`${BACKEND_URL}/api/recon/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, keys: keys, timestamp: Date.now() / 1000 })
        });
    }
}

// ============================================================================
// SCANNER ENGINE RELAY
// ============================================================================

async function sendScanResults(results) {
    if (!results || !results.findings || results.findings.length === 0) return;

    const payloadStr = JSON.stringify({
        url: results.meta.url,
        method: "SCAN",
        headers: { "x-scanner": "v12-engine" },
        timestamp: results.meta.timestamp / 1000,
        payload: results // Send full structure
    });

    const requestOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payloadStr
    };

    try {
        await safeFetch(`${BACKEND_URL}/api/recon/ingest`, requestOptions);
        console.log("[SPY V2] Scanner Engine results relayed.");
    } catch (err) {
        console.warn("[SPY V2] Backend offline, queuing scan results.");
        enqueuePayload(`${BACKEND_URL}/api/recon/ingest`, requestOptions);
    }
}

// Listen for messages from Content Scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_RESULTS') {
        console.log("[SPY V2] Received Scan Results from Tab:", sender.tab.id);
        sendScanResults(message.payload);
    }

    // 2. DEFENSE SHIELD (Agent Prism & Chi)
    if (message.type === "ANALYZE_THREAT" || message.type === "FORWARD_REQ") {
        const endpoint = message.type === "ANALYZE_THREAT"
            ? "http://127.0.0.1:8000/api/defense/analyze"
            : message.payload.endpoint;

        const body = message.type === "ANALYZE_THREAT"
            ? message.payload
            : message.payload.body;

        console.log(`[BACKGROUND] Relaying ${message.type} to:`, endpoint);

        safeFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        })
            .then(res => {
                if (res && res.ok && typeof res.json === 'function') {
                    return res.json();
                }
                return { success: false, error: "Backend unparseable or offline" };
            })
            .then(response => {
                if (message.type === "ANALYZE_THREAT") {
                    console.log("[BACKGROUND] Hive Verdict:", response);
                    if (response.verdict === "BLOCK") {
                        chrome.scripting.executeScript({
                            target: { tabId: sender.tab.id },
                            func: showBlockNotification,
                            args: [response.reason]
                        });
                    }
                }
                sendResponse({ success: true, data: response });
            })
            .catch(err => {
                console.warn("[BACKGROUND] Relay Failed:", err.message);
                sendResponse({ success: false, error: err.message });
            });

        return true; // Keep channel open for async response
    }
});


// ============================================================================
// TRAFFIC INTERCEPTION
// ============================================================================

function shouldCapture(details) {
    if (IGNORE_METHODS.includes(details.method)) return false;

    try {
        const url = new URL(details.url);
        const path = url.pathname.toLowerCase();

        // Ignore static assets
        for (const ext of IGNORE_EXTENSIONS) {
            if (path.endsWith(ext)) return false;
        }

        // Ignore our own backend traffic
        if (url.origin.includes("127.0.0.1:8000") || url.origin.includes("localhost:8000")) {
            return false;
        }

        return true;
    } catch (e) {
        return false;
    }
}

// ============================================================================
// WEBSOCKET CONNECTION (REMOVED: Native Uncatchable Errors / Replaced by Fetch)
// ============================================================================

// ============================================================================
// REQUEST LISTENER
// ============================================================================

chrome.webRequest.onBeforeSendHeaders.addListener(
    function (details) {
        if (!shouldCapture(details)) return;

        // Extract headers
        const headers = {};
        const capturedKeys = {};

        if (details.requestHeaders) {
            for (const h of details.requestHeaders) {
                headers[h.name] = h.value;

                // Synapse: Check for sensitive headers
                if (SENSITIVE_HEADERS.includes(h.name.toLowerCase())) {
                    capturedKeys[h.name] = h.value;
                }
            }
        }

        // Send recon packet
        const packet = {
            url: details.url,
            method: details.method,
            headers: headers,
            timestamp: Date.now() / 1000
        };

        const payloadStr = JSON.stringify(packet);
        const reqOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payloadStr
        };

        safeFetch(`${BACKEND_URL}/api/recon/ingest`, reqOptions).catch(err => {
            console.log("[SPY V2] Relay failed, queuing recon packet.");
            enqueuePayload(`${BACKEND_URL}/api/recon/ingest`, reqOptions);
        });

        // Synapse: Send captured keys
        sendCapturedKeys(details.url, capturedKeys);
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders", "extraHeaders"]
);

function showBlockNotification(reason) {
    // Inject a Toast Notification into the page
    const toast = document.createElement("div");
    toast.innerText = `🛡️ ANTIGRAVITY BLOCKED THREAT: ${reason}`;
    toast.style = "position:fixed; top:20px; right:20px; background:#ef4444; color:white; padding:15px; z-index:999999; border-radius:5px; font-family:monospace; box-shadow: 0 10px 30px rgba(0,0,0,0.5); font-weight: bold; border: 1px solid #b91c1c;";
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

console.log("[SPY V2] Antigravity Spy V2 Initialized");

// Establish WebSocket spy registration so the backend knows the extension is online
connectSpyWebSocket();

// Reconnect the spy WebSocket if backend recovers from an outage
setInterval(() => {
    if (isBackendAlive && (!spyWs || spyWs.readyState === WebSocket.CLOSED)) {
        connectSpyWebSocket();
    }
}, 5000);
