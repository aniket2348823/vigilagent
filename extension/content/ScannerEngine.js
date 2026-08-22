/**
 * ANTIGRAVITY V12 // SCANNER TRUTH KERNEL
 * "Zero False Positives" Philosophy
 */

// Skip on localhost/extension pages to avoid interfering with the dashboard
if (['127.0.0.1', 'localhost'].includes(window.location.hostname) ||
    window.location.protocol === 'chrome-extension:') {
    // Do nothing on localhost
} else {

class ScannerEngine {
    constructor() {
        this.results = {
            meta: {
                url: window.location.href,
                timestamp: Date.now(),
                tech_stack: {}
            },
            findings: []
        };
    }

    /**
     * MODULE 1: The Entropy Analyst
     * Finds secrets but validates context (e.g., var aws_key = ...).
     */
    scanSecrets() {
        const secretPatterns = [
            { type: "AWS Key", regex: /(AKIA[0-9A-Z]{16})/g, highValue: true },
            { type: "Stripe Key", regex: /(sk_live_[0-9a-zA-Z]{24})/g, highValue: true },
            { type: "Google API", regex: /(AIza[0-9A-Za-z_-]{35})/g, highValue: false } // AIza is often public
        ];

        // Context words that suggest a REAL secret
        const contextTriggers = ['key', 'token', 'secret', 'auth', 'password', 'cred', 'stripe', 'aws'];
        // Context words that suggest a FALSE POSITIVE
        const ignoreTriggers = ['background_image_id', 'git_commit', 'sha', 'md5', 'etag', 'image_id', 'css', 'class', 'id', 'uuid'];

        // Get text content from scripts and body
        // Note: For deep scanning we should walk the DOM, but for speed we grab common sources
        const sources = [];
        document.querySelectorAll('script:not([src])').forEach(s => sources.push({ text: s.textContent, loc: 'script' }));
        sources.push({ text: document.body.innerText, loc: 'body' });

        sources.forEach(source => {
            if (!source.text) return;

            secretPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.regex.exec(source.text)) !== null) {
                    const secret = match[0];
                    const index = match.index;

                    // Context Analysis (20 chars before)
                    const start = Math.max(0, index - 30);
                    const context = source.text.substring(start, index).toLowerCase();

                    // Verification 1: Check for Ignore Triggers (False Positives)
                    const isFalsePositive = ignoreTriggers.some(trigger => context.includes(trigger));
                    if (isFalsePositive) continue;

                    // Verification 2: Check for Confirmation Triggers (True Positives)
                    // If highEntropy is naturally rare (like AKIA), we might trust it more, 
                    // but the prompt demands context validation.
                    const hasContext = contextTriggers.some(trigger => context.includes(trigger));

                    if (hasContext) {
                        this.results.findings.push({
                            category: "HARDCODED_SECRET",
                            severity: "CRITICAL",
                            description: `Found ${pattern.type} with valid context`,
                            evidence: secret,
                            location: `${source.loc} near "...${context.trim()}..."`
                        });
                    } else if (pattern.highValue) {
                        // If it's a super distinct key like AKIA, we might flag it as MEDIUM if context is missing but not bad
                        this.results.findings.push({
                            category: "POTENTIAL_SECRET",
                            severity: "MEDIUM",
                            description: `Found ${pattern.type} (Missing context)`,
                            evidence: secret,
                            location: `${source.loc}`
                        });
                    }
                }
            });
        });
    }

    /**
     * MODULE 2: The XSS Tracer
     * Traces URL parameters into the DOM with type differentiation.
     */
    scanReflections() {
        const urlParams = new URLSearchParams(window.location.search);
        const params = [];
        for (const [key, value] of urlParams.entries()) {
            if (value.length > 2) params.push({ key, value });
        }

        if (params.length === 0) return;

        // Canary generation not needed as we are reading existing params

        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
        let node;

        while (node = walker.nextNode()) {
            params.forEach(param => {
                // Check Text Content
                if (node.nodeType === Node.TEXT_NODE && node.textContent.includes(param.value)) {
                    // Logic: Is it inside a dangerous tag?
                    const parent = node.parentElement;
                    if (parent) {
                        if (parent.tagName === 'SCRIPT') {
                            this.results.findings.push({
                                category: "DOM_XSS",
                                severity: "CRITICAL",
                                description: `URL Parameter '${param.key}' reflected inside <script>`,
                                evidence: `param: ${param.value} -> script content`,
                                location: `script`
                            });
                        } else {
                            this.results.findings.push({
                                category: "DOM_XSS",
                                severity: "LOW", // Just text reflection
                                description: `URL Parameter '${param.key}' reflected in text`,
                                evidence: `param: ${param.value} -> <${parent.tagName}>`,
                                location: `${parent.tagName.toLowerCase()}`
                            });
                        }
                    }
                }

                // Check Attributes (href, on*)
                if (node.nodeType === Node.ELEMENT_NODE) {
                    for (const attr of node.attributes) {
                        if (attr.value.includes(param.value)) {
                            // High Risk Attributes
                            if (attr.name.startsWith('on') || attr.name === 'href' || attr.name === 'src') {
                                this.results.findings.push({
                                    category: "DOM_XSS",
                                    severity: "CRITICAL",
                                    description: `URL Parameter '${param.key}' reflected in attribute '${attr.name}'`,
                                    evidence: `${attr.name}="${attr.value}"`,
                                    location: `${node.tagName.toLowerCase()}[${attr.name}]`
                                });
                            }
                        }
                    }
                }
            });
        }
    }

    /**
     * MODULE 3: The Logic Auditor
     * Checks hidden inputs for sensitive business logic controls.
     */
    scanTamperableInputs() {
        const highValueList = ['price', 'amount', 'role', 'admin', 'debug', 'cost', 'discount', 'user_id', 'account'];

        const inputs = document.querySelectorAll('input[type="hidden"]');
        inputs.forEach(input => {
            const name = (input.name || input.id || '').toLowerCase();
            const value = input.value;

            // Verification: Match against High Value Wordlist
            const match = highValueList.find(keyword => name.includes(keyword));

            if (match) {
                // Action: Ensure it's not empty
                if (value && value.trim() !== "") {
                    this.results.findings.push({
                        category: "LOGIC_BYPASS",
                        severity: "HIGH",
                        description: `Hidden input '${name}' controls critical logic`,
                        evidence: `<input name="${name}" value="${value}">`,
                        location: "input[type=hidden]"
                    });
                }
            }
        });
    }

    /**
     * MODULE 4: The Tech Profiler
     * Fingerprints frameworks with version checks.
     */
    fingerprintStack() {
        const tech = {};

        // React
        if (window.React || document.querySelector('[data-reactroot]')) {
            tech.framework = "React";
            if (window.React && window.React.version) tech.version = window.React.version;
        }

        // Angular
        if (window.angular) {
            tech.framework = "AngularJS";
            if (window.angular.version) tech.version = window.angular.version.full;
        }

        // Vue
        if (window.Vue) {
            tech.framework = "Vue.js";
            if (window.Vue.version) tech.version = window.Vue.version;
        }

        // jQuery
        if (window.jQuery) {
            tech.library = "jQuery";
            if (window.jQuery.fn && window.jQuery.fn.jquery) tech.jquery_version = window.jQuery.fn.jquery;
        }

        this.results.meta.tech_stack = tech;
    }

    /**
     * PHASE 3: REPORT GENERATION
     */
    runFullScan() {
        console.log("Antigravity Scanner Engine V12: Initiating Forensic Scan...");

        this.fingerprintStack();
        this.scanSecrets();
        this.scanReflections();
        this.scanTamperableInputs();

        // Output specific structure
        console.log("Antigravity Forensics Report:", JSON.stringify(this.results, null, 2));

        // Also fire an event for the content script/sidebar to pick up
        window.dispatchEvent(new CustomEvent('AntigravityScanResults', { detail: this.results }));

        return this.results;
    }
}

// Auto-Instantiate
const antigravityEngine = new ScannerEngine();
// Delay slightly to ensure page load
setTimeout(() => antigravityEngine.runFullScan(), 2000);

} // end else (not localhost)
