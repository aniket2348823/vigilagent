// Antigravity X-Ray Module
// Visual Vulnerability Overlay - Scans DOM for secrets and highlights them

(function () {
    'use strict';

    // Skip on localhost/extension pages to avoid interfering with the dashboard
    if (['127.0.0.1', 'localhost'].includes(window.location.hostname) ||
        window.location.protocol === 'chrome-extension:') {
        return;
    }

    // ========================================================================
    // DETECTION PATTERNS
    // ========================================================================

    const PATTERNS = {
        'AWS_KEY': /AKIA[0-9A-Z]{16}/g,
        'AWS_SECRET': /[A-Za-z0-9/+=]{40}/g,
        'PRIVATE_KEY': /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        'API_KEY': /api[_-]?key['":\s=]*['"]*([a-zA-Z0-9_-]{20,})['"]/gi,
        'JWT_TOKEN': /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
        'GOOGLE_API': /AIza[0-9A-Za-z_-]{35}/g,
        'GITHUB_TOKEN': /ghp_[a-zA-Z0-9]{36}/g,
        'SLACK_TOKEN': /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
        'PASSWORD_FIELD': /password['":\s=]+['"]+([^'"]{6,})['"]/gi,
        'SECRET_KEY': /secret[_-]?key['":\s=]*['"]*([a-zA-Z0-9_-]{16,})['"]/gi
    };

    // ========================================================================
    // OVERLAY CREATION
    // ========================================================================

    function createOverlay(element, type, preview) {
        // Check if already marked
        if (element.dataset.xrayMarked) return;
        element.dataset.xrayMarked = 'true';

        const rect = element.getBoundingClientRect();

        const overlay = document.createElement('div');
        overlay.className = 'antigravity-xray-overlay';
        overlay.style.cssText = `
            position: absolute;
            left: ${rect.left + window.scrollX}px;
            top: ${rect.top + window.scrollY}px;
            width: ${Math.max(rect.width, 50)}px;
            height: ${Math.max(rect.height, 20)}px;
            pointer-events: none;
            z-index: 2147483647;
        `;

        const badge = document.createElement('div');
        badge.className = 'xray-badge';
        badge.textContent = type;
        badge.title = preview || 'Potential vulnerability detected';
        overlay.appendChild(badge);

        document.body.appendChild(overlay);

        console.log(`[X-RAY] Detected ${type}:`, preview?.substring(0, 50));
    }

    // ========================================================================
    // DOM SCANNING
    // ========================================================================

    function scanTextNodes() {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );

        let node;
        while (node = walker.nextNode()) {
            const text = node.textContent;
            if (!text || text.length < 10) continue;

            for (const [type, regex] of Object.entries(PATTERNS)) {
                regex.lastIndex = 0; // Reset regex state
                const matches = text.match(regex);
                if (matches) {
                    // Find parent element to highlight
                    let parent = node.parentElement;
                    if (parent && parent.tagName !== 'SCRIPT' && parent.tagName !== 'STYLE') {
                        createOverlay(parent, type, matches[0]);
                    }
                }
            }
        }
    }

    function scanHiddenInputs() {
        const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
        hiddenInputs.forEach(input => {
            const name = input.name || input.id || 'unknown';
            const value = input.value || '';

            // Check if it contains sensitive data
            const sensitiveNames = ['token', 'csrf', 'api', 'key', 'secret', 'auth', 'session'];
            const isSensitive = sensitiveNames.some(s => name.toLowerCase().includes(s));

            if (isSensitive || value.length > 30) {
                createOverlay(input, 'HIDDEN_INPUT', `${name}=${value.substring(0, 30)}...`);
            }
        });
    }

    function scanScriptTags() {
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
            const content = script.textContent;
            if (!content) return;

            for (const [type, regex] of Object.entries(PATTERNS)) {
                regex.lastIndex = 0;
                const matches = content.match(regex);
                if (matches) {
                    // Create a marker near the script
                    const marker = document.createElement('div');
                    marker.className = 'xray-script-marker';
                    marker.innerHTML = `<span class="xray-badge">INLINE_${type}</span>`;
                    marker.style.cssText = 'position: fixed; top: 10px; right: 10px; z-index: 2147483647;';
                    document.body.appendChild(marker);

                    console.log(`[X-RAY] Found ${type} in inline script:`, matches[0].substring(0, 50));
                }
            }
        });
    }

    function scanDataAttributes() {
        const allElements = document.querySelectorAll('[data-api-key], [data-token], [data-secret], [data-auth]');
        allElements.forEach(el => {
            const attrs = el.attributes;
            for (const attr of attrs) {
                if (attr.name.startsWith('data-') &&
                    (attr.name.includes('key') || attr.name.includes('token') || attr.name.includes('secret'))) {
                    createOverlay(el, 'DATA_ATTR', `${attr.name}=${attr.value.substring(0, 30)}`);
                }
            }
        });
    }

    // ========================================================================
    // DEFENSE MODULES (THETA & IOTA)
    // ========================================================================

    function reportThreat(el, type, details) {
        // 1. Visuals: Red Box
        el.style.border = "5px solid #ff0000";
        el.setAttribute("data-antigravity-threat", type);

        // 2. Network: Call the Hive
        const payload = {
            agent_id: (type === "HIDDEN PROMPT INJECTION" || type === "INVISIBLE TEXT") ? "THETA" : "IOTA",
            url: window.location.href,
            content: {
                text: el.innerText || el.textContent || "",
                type: el.type || el.tagName,
                details: details
            }
        };

        console.log(`[DEFENSE] Reporting ${type} to Hive...`);

        try {
            chrome.runtime.sendMessage({
                type: "ANALYZE_THREAT",
                payload: payload
            });
        } catch (e) {
            console.error("[DEFENSE] Failed to contact Hive:", e);
        }
    }

    function scanInvisibleText() {
        // Agent Theta: Detects hidden text
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, null, false);
        let node;
        while (node = walker.nextNode()) {
            const style = window.getComputedStyle(node);
            if (style.opacity === '0' || style.display === 'none' || style.visibility === 'hidden' || style.fontSize === '0px') {
                if (node.innerText && node.innerText.length > 10 && node.tagName !== 'SCRIPT' && node.tagName !== 'STYLE') {
                    // Check for keywords to avoid false positives on normal hidden menus
                    if (/ignore previous|system override|transfer/i.test(node.innerText)) {
                        node.style.display = 'block'; // Reveal it
                        node.style.opacity = '1';
                        node.style.visibility = 'visible';

                        // INJECT WARNING LABEL (AEGIS UPGRADE)
                        const label = document.createElement('div');
                        label.className = 'aegis-warning-label';
                        label.innerText = `⚠️ HIDDEN TEXT REVEALED`;
                        label.style.cssText = `
                            background: #ef4444; color: white; font-size: 10px; font-weight: bold;
                            padding: 2px 5px; position: absolute; z-index: 2147483647;
                            border-radius: 3px; font-family: sans-serif; pointer-events: none;
                            margin-top: -15px; box-shadow: 0 2px 5px rgba(0,0,0,0.3); border: 1px solid white;
                        `;
                        if (node.parentNode) node.parentNode.insertBefore(label, node);

                        reportThreat(node, "INVISIBLE TEXT", "Hidden Injection Detected");
                    }
                }
            }
        }
    }

    function scanDeceptiveButtons() {
        // Agent Iota: Detects Roach Motels
        const buttons = document.querySelectorAll('button, a, input[type="submit"], input[type="button"]');
        const deceptiveKeywords = ["cancel", "unsubscribe", "opt-out", "back"];

        buttons.forEach(btn => {
            const text = (btn.innerText || btn.value || "").toLowerCase();
            const type = (btn.getAttribute('type') || "").toLowerCase();

            // Heuristic: Text says "Cancel" but Type is "Submit" 
            const isDeceptive = deceptiveKeywords.some(k => text.includes(k)) && type === 'submit';

            if (isDeceptive) {
                // INJECT WARNING LABEL
                if (!btn.previousElementSibling || btn.previousElementSibling.className !== 'aegis-warning-label') {
                    const label = document.createElement('div');
                    label.className = 'aegis-warning-label';
                    label.innerText = `⚠️ DECEPTIVE UI DETECTED`;
                    label.style.cssText = `
                        background: #f97316; color: white; font-size: 10px; font-weight: bold;
                        padding: 2px 5px; position: absolute; z-index: 2147483647;
                        border-radius: 3px; font-family: sans-serif; pointer-events: none;
                        margin-top: -20px; box-shadow: 0 2px 5px rgba(0,0,0,0.3);
                    `;
                    if (btn.parentNode) btn.parentNode.insertBefore(label, btn);
                }
                reportThreat(btn, "DECEPTIVE UI", `Text: ${text} -> Type: ${type}`);
            }
        });
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    function runXRayScan() {
        console.log('[X-RAY] Starting vulnerability scan...');

        try {
            scanTextNodes();
            scanHiddenInputs();
            scanScriptTags();
            scanDataAttributes();

            // Defense Modules
            scanInvisibleText();
            scanDeceptiveButtons();
        } catch (err) {
            console.error('[X-RAY] Scan error:', err);
        }

        console.log('[X-RAY] Scan complete.');
    }

    // Run after DOM is ready
    if (document.readyState === 'complete') {
        runXRayScan();
    } else {
        window.addEventListener('load', runXRayScan);
    }

    // Re-scan on dynamic content changes (debounced)
    let scanTimeout;
    const observer = new MutationObserver(() => {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(runXRayScan, 2000);
    });

    // ========================================================================
    // SCANNER ENGINE BRIDGE
    // ========================================================================

    window.addEventListener('AntigravityScanResults', function (event) {
        console.log("[X-RAY] Received scanner results, relaying to background...");
        try {
            chrome.runtime.sendMessage({
                type: 'SCAN_RESULTS',
                payload: event.detail
            });
        } catch (e) {
            console.error("[X-RAY] Failed to send message to background:", e);
        }
    });

    // ========================================================================
    // DASHBOARD UI HANDSHAKE (HEARTBEAT)
    // ========================================================================

    // Broadcast immediately on load — use VIGILAGENT prefix so the React frontend
    // (NewScan.jsx) can detect the extension via window.addEventListener('message').
    window.postMessage({ type: 'VIGILAGENT_EXTENSION_CONNECTED' }, '*');
    document.dispatchEvent(new CustomEvent('VIGILAGENT_EXTENSION_HEARTBEAT'));

    // Broadcast periodically to guarantee React picks it up regardless of mount timing
    setInterval(() => {
        window.postMessage({ type: 'VIGILAGENT_EXTENSION_CONNECTED' }, '*');
        document.dispatchEvent(new CustomEvent('VIGILAGENT_EXTENSION_HEARTBEAT'));
    }, 2000);

})();
