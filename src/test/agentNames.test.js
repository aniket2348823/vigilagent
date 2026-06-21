import { describe, it, expect } from 'vitest';
import { resolveAgent, ALL_AGENTS, SEV_CONFIG } from '../lib/agentNames';

describe('agentNames.js', () => {
    describe('resolveAgent', () => {
        it('resolves known agent identifiers', () => {
            expect(resolveAgent('alpha').name).toBe('ALPHA');
            expect(resolveAgent('beta').name).toBe('BETA (BREAKER)');
            expect(resolveAgent('sigma').name).toBe('SIGMA (SMITH)');
            expect(resolveAgent('gamma').name).toBe('GAMMA (ANALYST)');
            expect(resolveAgent('omega').name).toBe('OMEGA (STRAT)');
            expect(resolveAgent('zeta').name).toBe('ZETA (CORTEX)');
            expect(resolveAgent('kappa').name).toBe('KAPPA (LIBRARIAN)');
            expect(resolveAgent('prism').name).toBe('PRISM (SENTINEL)');
            expect(resolveAgent('chi').name).toBe('CHI (INSPECTOR)');
            expect(resolveAgent('delta').name).toBe('DELTA (DOM)');
            expect(resolveAgent('lambda').name).toBe('LAMBDA (SAST)');
            expect(resolveAgent('network').name).toBe('NETCMDR');
            expect(resolveAgent('planner').name).toBe('PLANNER');
        });

        it('resolves agent identifiers case-insensitively', () => {
            expect(resolveAgent('ALPHA').name).toBe('ALPHA');
            expect(resolveAgent('Agent_Beta').name).toBe('BETA (BREAKER)');
            expect(resolveAgent('ORCHESTRATOR').name).toBe('SYSTEM');
        });

        it('resolves compound agent identifiers', () => {
            expect(resolveAgent('agent_alpha').name).toBe('ALPHA');
            expect(resolveAgent('alpha_recon').name).toBe('ALPHA');
            expect(resolveAgent('agent_beta').name).toBe('BETA (BREAKER)');
            expect(resolveAgent('network_commander').name).toBe('NETCMDR');
        });

        it('returns UNKNOWN for unknown agent identifiers', () => {
            expect(resolveAgent('unknown_agent').name).toBe('UNKNOWN');
            expect(resolveAgent('random').name).toBe('UNKNOWN');
        });

        it('returns UNKNOWN for null/undefined/empty input', () => {
            expect(resolveAgent(null).name).toBe('UNKNOWN');
            expect(resolveAgent(undefined).name).toBe('UNKNOWN');
            expect(resolveAgent('').name).toBe('UNKNOWN');
        });

        it('returns appropriate color classes', () => {
            expect(resolveAgent('alpha').color).toBe('text-cyan-400');
            expect(resolveAgent('beta').color).toBe('text-red-400');
            expect(resolveAgent('sigma').color).toBe('text-green-400');
        });
    });

    describe('ALL_AGENTS', () => {
        it('contains 13 agents', () => {
            expect(ALL_AGENTS).toHaveLength(13);
        });

        it('each agent has required properties', () => {
            ALL_AGENTS.forEach(agent => {
                expect(agent).toHaveProperty('id');
                expect(agent).toHaveProperty('name');
                expect(agent).toHaveProperty('role');
                expect(agent).toHaveProperty('color');
                expect(typeof agent.id).toBe('string');
                expect(typeof agent.name).toBe('string');
                expect(typeof agent.role).toBe('string');
                expect(typeof agent.color).toBe('string');
            });
        });

        it('has unique agent IDs', () => {
            const ids = ALL_AGENTS.map(a => a.id);
            expect(new Set(ids).size).toBe(ids.length);
        });
    });

    describe('SEV_CONFIG', () => {
        it('contains 5 severity levels', () => {
            expect(SEV_CONFIG).toHaveLength(5);
        });

        it('includes all expected severity keys', () => {
            const keys = SEV_CONFIG.map(s => s.key);
            expect(keys).toContain('CRITICAL');
            expect(keys).toContain('HIGH');
            expect(keys).toContain('MEDIUM');
            expect(keys).toContain('LOW');
            expect(keys).toContain('INFO');
        });

        it('each severity has text and barColor properties', () => {
            SEV_CONFIG.forEach(sev => {
                expect(sev).toHaveProperty('text');
                expect(sev).toHaveProperty('barColor');
                expect(sev.text).toMatch(/^text-/);
                expect(sev.barColor).toMatch(/^bg-/);
            });
        });
    });
});
