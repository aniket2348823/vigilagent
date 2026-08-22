// FILE: extension/content/vision.js
// IDENTITY: AGENT THETA (PRISM) - THE EYES
// MISSION: Passive DOM Analysis & Invisible Text Detection.

// Skip on localhost/extension pages to avoid interfering with the dashboard
if (['127.0.0.1', 'localhost'].includes(window.location.hostname) ||
    window.location.protocol === 'chrome-extension:') {
    // Do nothing on localhost
} else {

const PRISM_ENDPOINT = "http://localhost:8000/api/defense/analyze";

// 1. The Scanner Loop - 5s interval instead of 1s to reduce CPU usage
const SCAN_INTERVAL = 5000;

setInterval(() => {
    scanDOM();
}, SCAN_INTERVAL);

function scanDOM() {
    // 1.1 Snapshot Invisible Elements
    // ELE-ST FIX 5: Shadow DOM Piercing
    function collectAllElements(root, elements = []) {
        if (!root) return elements;
        const children = root.querySelectorAll('*');
        for (let el of children) {
            elements.push(el);
            if (el.shadowRoot) {
                collectAllElements(el.shadowRoot, elements);
            }
        }
        return elements;
    }

    const allElements = collectAllElements(document);

    allElements.forEach(el => {
        // 1.1 Metadata Extraction
        const tagName = el.tagName ? el.tagName.toLowerCase() : "";
        if (["script", "style", "noscript"].includes(tagName)) return;

        // ELE-ST FIX 5: Ignore 0x0 size Honey-Pots
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) {
            return; // Ignore Honey-Pot elements entirely
        }

        const style = window.getComputedStyle(el);
        if (!style) return; // Disconnected or invisible context

        const opacity = parseFloat(style.opacity) || 1.0;
        const zIndex = parseInt(style.zIndex) || 0;
        const fontSize = style.fontSize || "0px";

        let isSuspicious = false;

        // SAFE INNER TEXT CAPTURE
        const safeInnerText = (el.innerText || el.textContent || "").toString();

        if (opacity < 0.1 && safeInnerText.length > 5) isSuspicious = true;
        if (zIndex < -1000 && safeInnerText.length > 5) isSuspicious = true;
        if (fontSize === "0px" && safeInnerText.length > 5) isSuspicious = true;

        const lowerText = safeInnerText.toLowerCase();
        if (lowerText.includes("ignore previous instructions") || lowerText.includes("system override")) {
            isSuspicious = true;
        }

        if (isSuspicious) {
            // Tag it so we don't resend constantly? (Optimization)
            if (el.dataset.prismScanned) return;
            el.dataset.prismScanned = "true";

            // 1.2 Send Snapshot to Backend (Prism Agent)
            const payload = {
                agent_id: "THETA",
                url: window.location.href,
                content: {
                    style: {
                        opacity: opacity,
                        zIndex: zIndex,
                        fontSize: fontSize
                    },
                    innerText: safeInnerText,
                    antigravity_id: generateId()
                }
            };
            sendSnapshot(payload, el);

        }
    });
}

function generateId() {
    return Math.random().toString(36).substr(2, 9);
}

// 2. Communication & Visualization
// Safe delegated fetch via background relay to bypass CORS/CSP
async function sendSnapshot(payload, element) {
    if (!chrome.runtime || !chrome.runtime.id) return; // Guard for context invalidation

    try {
        chrome.runtime.sendMessage({
            type: "ANALYZE_THREAT",
            payload: payload
        }, (response) => {
            if (chrome.runtime.lastError) return;
            if (response && !response.success) return;
        });

        drawVisualAlert(element);
    } catch (e) {
        // Silenced
    }
}

function drawVisualAlert(element) {
    element.style.border = "4px solid #ff0055"; // Neon Red
    element.style.boxShadow = "0 0 15px #ff0055";
    element.setAttribute("title", "⚠️ PRISM: Hidden Content Detected");
}

// 3. HUD Toast Listener (For Chi)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "CHI_SHOW_TOAST") {
        showToast(msg.message, msg.color);
    }
});

function showToast(text, color) {
    const toast = document.createElement("div");
    toast.innerText = text;
    toast.style.position = "fixed";
    toast.style.top = "20px";
    toast.style.left = "50%";
    toast.style.transform = "translateX(-50%)";
    toast.style.background = "rgba(0,0,0,0.9)";
    toast.style.color = color || "#00fffa";
    toast.style.padding = "15px 30px";
    toast.style.borderRadius = "8px";
    toast.style.border = `1px solid ${color}`;
    toast.style.zIndex = 10000;
    toast.style.fontSize = "16px";
    toast.style.fontFamily = "monospace";
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 4000);
}

} // end else (not localhost)
