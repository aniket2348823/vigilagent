// Antigravity Interceptor Module
// Active Defense - Intercepts and blocks deceptive user interactions

(function () {
    'use strict';

    // Skip on localhost/extension pages to avoid interfering with the dashboard
    if (['127.0.0.1', 'localhost'].includes(window.location.hostname) ||
        window.location.protocol === 'chrome-extension:') {
        return;
    }

    console.log("[INTERCEPTOR] Active Defense Shield Initialized.");

    // DECEPTIVE PATTERNS TO BLOCK
    const DECEPTIVE_KEYWORDS = ["cancel", "unsubscribe", "opt-out", "back", "no thanks"];
    const DANGEROUS_ACTIONS = ["submit", "payment", "upgrade", "confirm"];

    function isRoachMotel(element) {
        const text = (element.innerText || element.value || "").toLowerCase();
        const type = (element.getAttribute('type') || "").toLowerCase();
        const tagName = element.tagName;

        // Pattern 1: "Cancel" button that submits a form
        if (tagName === 'BUTTON' || (tagName === 'INPUT' && (type === 'submit' || type === 'image'))) {
            const hasDeceptiveText = DECEPTIVE_KEYWORDS.some(k => text.includes(k));
            if (hasDeceptiveText) {
                return { type: "ROACH_MOTEL", reason: `Button says '${text}' but submits form` };
            }
        }

        return null;
    }

    // CAPTURE PHASE LISTENER (Runs before the page sees the click)
    document.addEventListener('click', function (e) {
        const target = e.target;
        // Traverse up to find button/link context
        const element = target.closest('button, a, input[type="submit"]');

        if (!element) return;

        const threat = isRoachMotel(element);

        if (threat) {
            console.warn(`[INTERCEPTOR] Blocked interaction on:`, element, threat);

            // 1. FREEZE THE EVENT
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();

            // 2. ASK THE HIVE (Async check, but we already blocked the default)
            const payload = {
                agent_id: "IOTA", // Agent Chi
                url: window.location.href,
                content: {
                    text: element.innerText || element.value || "",
                    tagName: element.tagName,
                    type: element.getAttribute('type'),
                    threat_type: threat.type
                }
            };

            chrome.runtime.sendMessage({
                type: "ANALYZE_THREAT",
                payload: payload
            });

            // 3. VISUAL FEEDBACK (Immediate)
            element.style.border = "5px solid red";
            element.style.cursor = "not-allowed";

            // Re-check response logic is handled by background.js notification
        }

    }, true); // USE_CAPTURE = TRUE is CRITICAL

})();
