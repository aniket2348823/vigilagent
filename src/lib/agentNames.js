/**
 * Shared agent-name-to-display-name mapping.
 * Used by dashboard and live monitoring views.
 */

// All 13 agents + system roles — single source of truth for Live Monitor display.
// Order matters: more-specific matches must come first (e.g. 'network_commander' before 'network').
const AGENT_MAP = [
    // --- System Roles (check FIRST — short fixed strings) ---
    { match: 'Orchestrator', name: 'SYSTEM',            color: 'text-gray-400' },
    { match: 'VIGILAGENT',   name: 'SYSTEM',            color: 'text-gray-400' },
    { match: 'spy',          name: 'SPY',               color: 'text-slate-400' },

    // --- Network (longer match before shorter) ---
    { match: 'network_commander', name: 'NETCMDR',       color: 'text-sky-400' },
    { match: 'network',      name: 'NETCMDR',           color: 'text-sky-400' },

    // --- Reconnaissance ---
    { match: 'alpha',        name: 'ALPHA',             color: 'text-cyan-400' },
    // --- Exploitation ---
    { match: 'beta',         name: 'BETA (BREAKER)',    color: 'text-red-400' },
    { match: 'sigma',        name: 'SIGMA (SMITH)',     color: 'text-green-400' },
    // --- Analysis ---
    { match: 'gamma',        name: 'GAMMA (ANALYST)',   color: 'text-yellow-400' },
    // --- Strategy ---
    { match: 'omega',        name: 'OMEGA (STRAT)',     color: 'text-pink-400' },
    { match: 'zeta',         name: 'ZETA (CORTEX)',     color: 'text-indigo-400' },
    // --- Memory ---
    { match: 'kappa',        name: 'KAPPA (LIBRARIAN)', color: 'text-teal-400' },
    // --- Defense / Purple Team ---
    { match: 'prism',        name: 'PRISM (SENTINEL)',  color: 'text-purple-400' },
    { match: 'chi',          name: 'CHI (INSPECTOR)',   color: 'text-orange-400' },
    // --- DOM / Browser ---
    { match: 'delta',        name: 'DELTA (DOM)',       color: 'text-rose-400' },
    // --- Planning ---
    { match: 'planner',      name: 'PLANNER',           color: 'text-amber-400' },
    // --- Code Analysis ---
    { match: 'lambda',       name: 'LAMBDA (SAST)',     color: 'text-lime-400' },
];

/**
 * Resolve an agent identifier string to a display name + tailwind color class.
 * @param {string} agentId - e.g. "agent_beta", "alpha_recon", "Orchestrator"
 * @returns {{ name: string, color: string }}
 */
export function resolveAgent(agentId) {
    if (!agentId) return { name: 'UNKNOWN', color: 'text-gray-400' };
    const lower = agentId.toLowerCase();
    for (const entry of AGENT_MAP) {
        // Case-insensitive match so "Agent_Beta", "agent_beta", "BETA" all resolve
        if (lower.includes(entry.match.toLowerCase())) {
            return { name: entry.name, color: entry.color };
        }
    }
    return { name: 'UNKNOWN', color: 'text-gray-400' };
}

/**
 * All 13 agent short-ids used by the backend orchestrator awakening feed.
 * Exported so Dashboard can show the full agent roster panel.
 */
/**
 * Severity level config for the summary bar and filter UI.
 * Hoisted here as a shared constant (never changes).
 */
export const SEV_CONFIG = [
    { key: 'CRITICAL', text: 'text-red-400', barColor: 'bg-red-500' },
    { key: 'HIGH', text: 'text-orange-400', barColor: 'bg-orange-500' },
    { key: 'MEDIUM', text: 'text-yellow-400', barColor: 'bg-yellow-500' },
    { key: 'LOW', text: 'text-blue-400', barColor: 'bg-blue-400' },
    { key: 'INFO', text: 'text-gray-400', barColor: 'bg-gray-500' },
];

export const ALL_AGENTS = [
    { id: 'planner',     name: 'PLANNER',            role: 'Strategic Campaign Planning',          color: 'text-amber-400' },
    { id: 'alpha',       name: 'ALPHA',              role: 'Reconnaissance & Endpoint Discovery',   color: 'text-cyan-400' },
    { id: 'beta',        name: 'BETA (BREAKER)',     role: 'Direct Assault & Polyglot Attacks',     color: 'text-red-400' },
    { id: 'sigma',       name: 'SIGMA (SMITH)',      role: 'Exploitation Engine & Payloads',        color: 'text-green-400' },
    { id: 'gamma',       name: 'GAMMA (ANALYST)',    role: 'Forensic Audit & Vulnerability Validation', color: 'text-yellow-400' },
    { id: 'omega',       name: 'OMEGA (STRAT)',      role: 'Campaign Strategy & Attack Coordination', color: 'text-pink-400' },
    { id: 'zeta',        name: 'ZETA (CORTEX)',      role: 'Governance & Resource Throttling',      color: 'text-indigo-400' },
    { id: 'kappa',       name: 'KAPPA (LIBRARIAN)',  role: 'Memory & Contextual Intelligence',      color: 'text-teal-400' },
    { id: 'prism',       name: 'PRISM (SENTINEL)',   role: 'Safety Sentinel & Ethical Guardrails',   color: 'text-purple-400' },
    { id: 'chi',         name: 'CHI (INSPECTOR)',    role: 'Inspector & Defense Validation',         color: 'text-orange-400' },
    { id: 'delta',       name: 'DELTA (DOM)',        role: 'DOM Controller & Browser-Level Attacks', color: 'text-rose-400' },
    { id: 'lambda',      name: 'LAMBDA (SAST)',      role: 'Pre-Code Scanner (SAST/IaC/SBOM)',      color: 'text-lime-400' },
    { id: 'network',     name: 'NETCMDR',            role: 'Network Service Discovery',             color: 'text-sky-400' },
];
