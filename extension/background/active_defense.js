// ROLE: THE GATEKEEPER (Active Defense Interceptor)
// RESPONSIBILITY: Pause browser events -> Consult Hive -> Block/Resume

let activeTabId = null;
const HIVE_ENDPOINT = "http://localhost:8000/api/defense/analyze";

// 1. INITIALIZATION: Attach Debugger to Active Tab
// We use chrome.debugger because it creates a 'freeze' state that standard listeners cannot.
// NOTE: chrome.action.onClicked does NOT fire when a popup is configured in manifest.json.
// Instead, we listen for AEGIS_ACTIVATE messages from the popup or content scripts.
function attachToTab(tab) {
    if (activeTabId === tab.id) {
        console.log("[AEGIS] Shield already active.");
        return;
    }

    activeTabId = tab.id;
    chrome.debugger.attach({ tabId: activeTabId }, "1.3", () => {
        if (chrome.runtime.lastError) {
            console.error("[AEGIS] Attach Failed:", chrome.runtime.lastError.message);
            return;
        }
        console.log(`[AEGIS] SHIELD ACTIVE on Tab ${tab.id}`);

        // Enable domains required to intercept interactions
        chrome.debugger.sendCommand({ tabId: activeTabId }, "DOM.enable");
        chrome.debugger.sendCommand({ tabId: activeTabId }, "Runtime.enable");
        chrome.debugger.sendCommand({ tabId: activeTabId }, "Page.enable");
    });
}

// Listen for activation from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender) => {
    if (message.type === "AEGIS_ACTIVATE") {
        const tab = sender.tab || message.tab;
        if (tab && tab.id) attachToTab(tab);
    }
});

// 2. EVENT LISTENER: Catch DOM Mutations & Interactions
chrome.debugger.onEvent.addListener((source, method, params) => {
    // Only care about events on our active tab
    if (source.tabId !== activeTabId) return;

    // SCENARIO A: A Node was modified (potential Deceptive UI injection)
    if (method === "DOM.childNodeCountUpdated" || method === "DOM.attributeModified") {
        analyzeNodeRisk(params.nodeId, "DOM_MUTATION");
    }

    // SCENARIO B: Navigation Attempt (Phishing check)
    if (method === "Page.frameNavigated") {
        checkNavigationRisk(params.frame.url);
    }
});


// 3. THE "HALT & CONSULT" LOGIC
// Since chrome.debugger doesn't inherently block clicks purely via events,
// we combine it with Runtime.evaluate to inject a 'before-click' check.
// *Note: In a full production implementation, we would use 'Fetch.enable' to pause network requests.*

function analyzeNodeRisk(nodeId, eventType) {
    // Get the HTML details of the modified node to send to Agent Inspector (formerly Iota)
    chrome.debugger.sendCommand({ tabId: activeTabId }, "DOM.getOuterHTML", { nodeId: nodeId }, (result) => {
        if (chrome.runtime.lastError || !result) return;

        const payload = {
            agent_id: "IOTA", // Send to UI Inspector
            url: "active-tab-url-placeholder", // You'd fetch real URL here
            content: {
                html: result.outerHTML,
                event: eventType,
                type: "DOM_MUTATION_CHECK" // Explicit type for Inspector
            }
        };

        // Send to Hive (Backend)
        consultHive(payload);
    });
}

function checkNavigationRisk(url) {
    const payload = {
        agent_id: "IOTA", // Send to Phishing Inspector
        url: url,
        content: { type: "NAVIGATION", threat_type: "PHISHING_CHECK" }
    };
    consultHive(payload);
}

// 4. HIVE COMMUNICATION BRIDGE
function consultHive(payload) {
    // USE SAFE FETCH (from background.js context)
    safeFetch(HIVE_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
        .then(res => {
            if (res && res.ok && typeof res.json === 'function') {
                return res.json();
            }
            return { verdict: "ALLOW" }; // Default to safe if unparseable or backend offline
        })
        .then(verdict => {
            if (verdict && verdict.verdict === "BLOCK") {
                executeBlockProtocol(verdict.reason);
            }
        })
        .catch(err => {
            console.warn("[AEGIS] Hive Unreachable. Defaulting to SAFE mode.", err);
        });
}

// 5. ENFORCEMENT: THE "RED SCREEN" BLOCK
function executeBlockProtocol(reason) {
    console.log(`[AEGIS] BLOCKING ACTION. Reason: ${reason}`);

    // Inject a script to stop everything and show the overlay
    chrome.scripting.executeScript({
        target: { tabId: activeTabId },
        func: (warningText) => {
            // 1. Stop all other scripts (Approximation)
            try { window.stop(); } catch (e) { }

            // 2. Create The Red Shield Overlay
            const overlay = document.createElement('div');
            overlay.id = "antigravity-block-screen";
            overlay.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
                background: rgba(20, 0, 0, 0.95); z-index: 2147483647;
                display: flex; flex-direction: column; align-items: center; justify-content: center;
                font-family: monospace; color: #ff3333; pointer-events: all;
                border: 20px solid #ff0000;
            `;

            overlay.innerHTML = `
                <h1 style="font-size: 3rem; margin-bottom: 1rem;">🚫 AEGIS LOCKDOWN</h1>
                <h2 style="color: white; font-size: 1.5rem;">MALICIOUS INTERACTION BLOCKED</h2>
                <div style="margin-top: 2rem; padding: 1rem; border: 1px solid #ff3333; color: #ffaaaa;">
                    REASON: ${warningText}
                </div>
                <button id="aegis-override-btn" style="margin-top: 3rem; padding: 10px 20px; background: transparent; border: 1px solid white; color: white; cursor: pointer;">
                    EMERGENCY OVERRIDE (UNSAFE)
                </button>
            `;

            document.body.appendChild(overlay);

            // Allow user to dismiss if they really want to risk it
            document.getElementById('aegis-override-btn').onclick = () => {
                overlay.remove();
            };
        },
        args: [reason]
    });
}
