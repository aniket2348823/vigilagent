/**
 * Performance Benchmark: useMemo optimization for agent event counts
 *
 * This benchmark measures the time to compute per-agent event counts
 * for the Dashboard agent roster, comparing:
 *   1. Original approach: inline .filter() on every render (13 agents × N events)
 *   2. Optimized approach: single-pass useMemo + Map lookup
 *
 * Run with: node src/test/performance-benchmark.js
 */

// ── Simulated data ──
function generateThreatFeed(eventCount) {
    const agents = [
        'alpha_recon', 'beta_scan', 'gamma_fuzz', 'delta_exploit',
        'epsilon_social', 'zeta_phish', 'eta_malware', 'theta_network',
        'iota_web', 'kappa_api', 'lambda_cloud', 'mu_endpoint', 'nu_identity'
    ];
    const events = [];
    for (let i = 0; i < eventCount; i++) {
        events.push({
            agent: agents[i % agents.length],
            type: 'EVENT',
            payload: { id: i },
        });
    }
    return events;
}

const AGENT_IDS = [
    'alpha_recon', 'beta_scan', 'gamma_fuzz', 'delta_exploit',
    'epsilon_social', 'zeta_phish', 'eta_malware', 'theta_network',
    'iota_web', 'kappa_api', 'lambda_cloud', 'mu_endpoint', 'nu_identity'
];

// ── Original approach: inline .filter() per agent ──
function computeOriginal(threatFeed) {
    const counts = {};
    for (const agentId of AGENT_IDS) {
        counts[agentId] = threatFeed.filter(t => t.agent?.toLowerCase().includes(agentId)).length;
    }
    return counts;
}

// ── Optimized approach: single-pass + Map lookup ──
function computeOptimized(threatFeed) {
    const counts = new Map();
    for (const event of threatFeed) {
        const key = event.agent?.toLowerCase() || '';
        counts.set(key, (counts.get(key) || 0) + 1);
    }
    const result = {};
    for (const agentId of AGENT_IDS) {
        result[agentId] = counts.get(agentId) || 0;
    }
    return result;
}

// ── Benchmark runner ──
function benchmark(label, fn, iterations = 1000) {
    // Warm up
    for (let i = 0; i < 10; i++) fn();

    const start = performance.now();
    for (let i = 0; i < iterations; i++) fn();
    const elapsed = performance.now() - start;
    return { label, elapsed, perIteration: elapsed / iterations };
}

// ── Run benchmarks ──
const SIZES = [100, 500, 1000, 5000];

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║  Performance Benchmark: agentEventCounts useMemo           ║');
console.log('╠══════════════════════════════════════════════════════════════╣');
console.log('║  Agents: 13 | Iterations per run: 1,000                    ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');

for (const size of SIZES) {
    const feed = generateThreatFeed(size);
    const original = benchmark('Inline .filter() (original)', () => computeOriginal(feed));
    const optimized = benchmark('useMemo + Map (optimized)', () => computeOptimized(feed));
    const speedup = (original.elapsed / optimized.elapsed).toFixed(1);

    console.log(`── Feed size: ${size} events ──`);
    console.log(`  Original:  ${original.elapsed.toFixed(2)}ms total (${original.perIteration.toFixed(4)}ms/iter)`);
    console.log(`  Optimized: ${optimized.elapsed.toFixed(2)}ms total (${optimized.perIteration.toFixed(4)}ms/iter)`);
    console.log(`  Speedup:   ${speedup}x faster\n`);
}

// ── Verify correctness ──
const testFeed = generateThreatFeed(500);
const originalResult = computeOriginal(testFeed);
const optimizedResult = computeOptimized(testFeed);

let correct = true;
for (const agentId of AGENT_IDS) {
    if (originalResult[agentId] !== optimizedResult[agentId]) {
        console.error(`MISMATCH: ${agentId} — original=${originalResult[agentId]}, optimized=${optimizedResult[agentId]}`);
        correct = false;
    }
}
console.log(`Correctness check: ${correct ? '✓ PASS — results match' : '✗ FAIL — results differ'}`);
