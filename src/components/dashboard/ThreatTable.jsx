import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LIQUID_SPRING } from '../../lib/constants';
import { resolveAgent, ALL_AGENTS, SEV_CONFIG } from '../../lib/agentNames';
import { isWithinRange } from '../../lib/timestamps';

const ThreatTable = ({ persistentState, filterAgent, setFilterAgent, filterTimeRange, setFilterTimeRange, filterSeverity, setFilterSeverity, selectedRowIndex, setSelectedRowIndex, selectedEvent, setSelectedEvent, rowRefs, scanActive, currentPhase, completedPhases, showExportMenu, setShowExportMenu, exportData }) => {
    const tableBodyRef = useRef(null);

    const totalFeedCount = (persistentState.threat_feed || []).length;
    const { sevCounts, filteredFeedTotal } = useMemo(() => {
        const feed = (persistentState.threat_feed || []).filter(t => {
            if (filterAgent && (!t.agent || !t.agent.toLowerCase().includes(filterAgent))) return false;
            if (filterSeverity && (t.severity || 'INFO').toUpperCase() !== filterSeverity) return false;
            return true;
        });
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        feed.forEach(t => {
            const sev = (t.severity || 'INFO').toUpperCase();
            if (counts[sev] !== undefined) counts[sev]++;
            else counts.INFO++;
        });
        return { sevCounts: counts, filteredFeedTotal: feed.length };
    }, [persistentState?.threat_feed, filterAgent, filterSeverity]);

    return (
        <div className="grid grid-cols-1 gap-6">
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ ...LIQUID_SPRING, delay: 0.3 }}
                className="glass-panel-dash rounded-2xl p-0 relative overflow-hidden flex flex-col"
                style={{ minHeight: '520px' }}
            >
                <div className="h-full flex flex-col">
                    <div className="px-5 py-3 border-b border-white/5">
                        <div className="flex justify-between items-center">
                            <h2 className="text-sm font-medium text-gray-200 flex items-center gap-2">
                                <span className="material-symbols-outlined text-base text-purple-400">monitoring</span>
                                Live Threat Monitor
                            </h2>
                            <div className="flex items-center gap-3">
                                {scanActive && (
                                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-green-400">
                                        <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse"></span>
                                        SCANNING
                                    </span>
                                )}
                                <select
                                    value={filterAgent}
                                    onChange={(e) => {
                                        setFilterAgent(e.target.value);
                                        const p = new URLSearchParams(window.location.search);
                                        if (e.target.value) p.set('agent', e.target.value); else p.delete('agent');
                                        window.history.replaceState(null, '', `${window.location.pathname}?${p.toString()}`);
                                    }}
                                    className="text-[10px] font-mono bg-white/5 border border-white/10 text-gray-400 rounded-lg px-2 py-1 focus:outline-none focus:border-purple-500/50 cursor-pointer"
                                >
                                    <option value="">All Agents</option>
                                    {ALL_AGENTS.map((a) => (
                                        <option key={a.id} value={a.id}>{a.name}</option>
                                    ))}
                                </select>
                                <select
                                    value={filterTimeRange}
                                    onChange={(e) => {
                                        setFilterTimeRange(e.target.value);
                                        const p = new URLSearchParams(window.location.search);
                                        if (e.target.value) p.set('timerange', e.target.value); else p.delete('timerange');
                                        window.history.replaceState(null, '', `${window.location.pathname}?${p.toString()}`);
                                    }}
                                    className="text-[10px] font-mono bg-white/5 border border-white/10 text-gray-400 rounded-lg px-2 py-1 focus:outline-none focus:border-purple-500/50 cursor-pointer"
                                >
                                    <option value="">All Time</option>
                                    <option value="30">Last 30s</option>
                                    <option value="60">Last 1m</option>
                                    <option value="300">Last 5m</option>
                                    <option value="900">Last 15m</option>
                                </select>
                                <select
                                    value={filterSeverity}
                                    onChange={(e) => {
                                        setFilterSeverity(e.target.value);
                                        const p = new URLSearchParams(window.location.search);
                                        if (e.target.value) p.set('severity', e.target.value); else p.delete('severity');
                                        window.history.replaceState(null, '', `${window.location.pathname}?${p.toString()}`);
                                    }}
                                    className="text-[10px] font-mono bg-white/5 border border-white/10 text-gray-400 rounded-lg px-2 py-1 focus:outline-none focus:border-purple-500/50 cursor-pointer"
                                >
                                    <option value="">All Severity</option>
                                    <option value="CRITICAL">CRITICAL</option>
                                    <option value="HIGH">HIGH</option>
                                    <option value="MEDIUM">MEDIUM</option>
                                    <option value="LOW">LOW</option>
                                    <option value="INFO">INFO</option>
                                </select>
                                {(filterAgent || filterTimeRange || filterSeverity) && (
                                    <button
                                        onClick={() => {
                                            setFilterAgent('');
                                            setFilterTimeRange('');
                                            setFilterSeverity('');
                                            window.history.replaceState(null, '', window.location.pathname);
                                        }}
                                        className="text-[10px] font-mono bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-2 py-1 hover:bg-red-500/20 transition-colors cursor-pointer flex items-center gap-1"
                                    >
                                        <span className="material-symbols-outlined text-[12px]">filter_alt_off</span>
                                        Clear
                                    </button>
                                )}
                                {/* Export Button */}
                                <div className="relative">
                                    <button
                                        onClick={() => setShowExportMenu(!showExportMenu)}
                                        className="text-[10px] font-mono bg-white/5 border border-white/10 text-gray-400 rounded-lg px-2 py-1 hover:bg-white/10 transition-colors cursor-pointer flex items-center gap-1"
                                    >
                                        <span className="material-symbols-outlined text-[12px]">download</span>
                                        Export
                                    </button>
                                    {showExportMenu && (
                                        <div className="absolute right-0 top-full mt-1 bg-[#0a0a1a] border border-white/10 rounded-lg shadow-xl z-50 overflow-hidden">
                                            <button onClick={() => exportData('json')} className="block w-full text-left px-4 py-2 text-[10px] font-mono text-gray-400 hover:bg-white/5 hover:text-white transition-colors">JSON</button>
                                            <button onClick={() => exportData('csv')} className="block w-full text-left px-4 py-2 text-[10px] font-mono text-gray-400 hover:bg-white/5 hover:text-white transition-colors border-t border-white/5">CSV</button>
                                        </div>
                                    )}
                                </div>
                                <span className="text-[10px] font-mono text-gray-500">
                                    {filteredFeedTotal} events
                                </span>
                            </div>
                        </div>
                        {/* Scan Phase Indicator */}
                        {scanActive && (
                            <div className="flex items-center gap-2 mt-2">
                                {['Recon', 'Exploit', 'Report'].map((phase, i) => {
                                    const isActive = currentPhase?.toLowerCase().includes(phase.toLowerCase());
                                    const isDone = completedPhases.some(cp => cp.toLowerCase().includes(phase.toLowerCase()));
                                    return (
                                        <div key={phase} className="flex items-center gap-1.5">
                                            <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold ${
                                                isActive ? 'bg-purple-500 text-white shadow-[0_0_8px_rgba(168,85,247,0.5)]' :
                                                isDone ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                                                'bg-white/5 text-gray-500 border border-white/10'
                                            }`}>
                                                {isDone ? '\u2713' : i + 1}
                                            </div>
                                            <span className={`text-[10px] font-mono ${
                                                isActive ? 'text-purple-300' :
                                                isDone ? 'text-green-400' :
                                                'text-gray-500'
                                            }`}>{phase}</span>
                                            {i < 2 && (
                                                <div className={`w-6 h-[1px] ${isDone ? 'bg-green-500/30' : 'bg-white/10'}`}></div>
                                            )}
                                        </div>
                                    );
                                })}
                                {currentPhase && (
                                    <span className="text-[9px] font-mono text-purple-300 ml-2 animate-pulse">
                                        {currentPhase}
                                    </span>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Severity Summary Bar */}
                    {filteredFeedTotal > 0 && (
                        <div className="px-4 py-2 border-b border-white/5">
                            <div className="flex items-center gap-4">
                                <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider">Severity</span>
                                <span className="text-[9px] font-mono text-gray-500">
                                    {filteredFeedTotal}{filteredFeedTotal < totalFeedCount && !filterTimeRange ? ` / ${totalFeedCount}` : ''}
                                </span>
                                <div className="flex-1 flex items-center gap-1 h-2 rounded-full overflow-hidden bg-white/5">
                                    {SEV_CONFIG.map(({ key, barColor }) => {
                                        const pct = filteredFeedTotal > 0 ? (sevCounts[key] / filteredFeedTotal) * 100 : 0;
                                        return pct > 0 ? (
                                            <div
                                                key={key}
                                                className={`${barColor} h-full transition-all duration-500 ease-out first:rounded-l-full last:rounded-r-full`}
                                                style={{ width: `${pct}%`, minWidth: pct > 0 ? '2px' : '0' }}
                                                title={`${key}: ${sevCounts[key]}`}
                                            ></div>
                                        ) : null;
                                    })}
                                </div>
                                <div className="flex items-center gap-2">
                                    {SEV_CONFIG.map(({ key, text }) => (
                                        sevCounts[key] > 0 && (
                                            <span key={key} className={`text-[9px] font-mono ${text} flex items-center gap-0.5`}>
                                                <span className={`w-1.5 h-1.5 rounded-full ${text.replace('text-', 'bg-')}`}></span>
                                                {sevCounts[key]}
                                            </span>
                                        )
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    <div className="flex-grow overflow-y-auto overflow-x-auto scrollbar-thin px-1" ref={tableBodyRef}>
                        {(persistentState.threat_feed || []).length === 0 ? (
                            <div className="flex items-center justify-center h-full text-gray-600 opacity-40">
                                <div className="text-center">
                                    <span className="material-symbols-outlined text-3xl block mb-2">graphic_eq</span>
                                    <p className="text-xs font-mono">Waiting for agent activity…</p>
                                </div>
                            </div>
                        ) : (
                            <table className="w-full text-xs">
                                <thead className="sticky top-0 bg-[#0a0a1a]/90 backdrop-blur z-10">
                                    <tr className="text-gray-500 text-left">
                                        <th className="px-3 py-2 font-medium">Time</th>
                                        <th className="px-3 py-2 font-medium">Agent</th>
                                        <th className="px-3 py-2 font-medium">Event</th>
                                        <th className="px-3 py-2 font-medium">Target / URL</th>
                                        <th className="px-3 py-2 font-medium">Method</th>
                                        <th className="px-3 py-2 font-medium">Status</th>
                                        <th className="px-3 py-2 font-medium">CVSS</th>
                                        <th className="px-3 py-2 font-medium">Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {(persistentState.threat_feed || []).filter(t => {
                                        if (filterAgent && (!t.agent || !t.agent.toLowerCase().includes(filterAgent))) return false;
                                        if (filterSeverity && (t.severity || 'INFO').toUpperCase() !== filterSeverity) return false;
                                        if (filterTimeRange && t.timestamp && !isWithinRange(t.timestamp, parseInt(filterTimeRange, 10))) return false;
                                        return true;
                                    }).slice(0, 500).map((t, i) => {
                                        const agent = resolveAgent(t.agent);
                                        const sevColors = {
                                            CRITICAL: 'text-red-400 bg-red-500/10',
                                            HIGH: 'text-orange-400 bg-orange-500/10',
                                            MEDIUM: 'text-yellow-400 bg-yellow-500/10',
                                            LOW: 'text-blue-400 bg-blue-500/10',
                                            INFO: 'text-gray-400 bg-gray-500/10',
                                        };
                                        const sevClass = sevColors[t.severity?.toUpperCase()] || sevColors.INFO;
                                        const anomaly = t.anomaly || t.threat_type?.includes('INJECTION') || t.threat_type?.includes('BYPASS');
                                        const sevAccent = {
                                            CRITICAL: 'border-l-[3px] border-l-red-500 animate-severity-pulse-red',
                                            HIGH: 'border-l-[3px] border-l-orange-500 animate-severity-pulse-orange',
                                            MEDIUM: 'border-l-[3px] border-l-yellow-500',
                                            LOW: 'border-l-[3px] border-l-blue-400',
                                            INFO: '',
                                        };
                                        const rowAccent = sevAccent[t.severity?.toUpperCase()] || sevAccent.INFO;
                                        return (
                                            <tr key={i} ref={el => { rowRefs.current[i] = el; }} className={`border-b border-white/[0.03] hover:bg-white/[0.02] transition-all duration-300 cursor-pointer ${selectedRowIndex === i ? 'bg-purple-500/10 ring-1 ring-purple-500/30' : ''} ${rowAccent}`} style={{ animationDelay: `${i * 20}ms` }} onClick={() => { setSelectedRowIndex(i); setSelectedEvent(t); }}>
                                                <td className="px-3 py-2 text-gray-500 font-mono whitespace-nowrap">{t.timestamp}</td>
                                                <td className="px-3 py-2 font-mono whitespace-nowrap">
                                                    <span className={agent.color} title={t.agent}>{agent.name}</span>
                                                </td>
                                                <td className="px-3 py-2 font-mono whitespace-nowrap">
                                                    <span className={`text-gray-300 ${anomaly ? 'text-orange-300 font-bold' : ''}`}>{t.threat_type}</span>
                                                </td>
                                                <td className="px-3 py-2 text-gray-400 font-mono truncate max-w-[220px]" title={t.url}>{t.url}</td>
                                                <td className="px-3 py-2 text-gray-500 font-mono whitespace-nowrap">{t.method || '—'}</td>
                                                <td className="px-3 py-2 font-mono whitespace-nowrap">
                                                    {t.status ? (
                                                        <span className={t.status >= 400 ? 'text-red-400' : t.status >= 300 ? 'text-yellow-400' : 'text-green-400'}>
                                                            {t.status}
                                                        </span>
                                                    ) : '—'}
                                                </td>
                                                <td className="px-3 py-2 w-[100px]">
                                                    {t.cvss_score != null ? (
                                                        <span className="text-[10px] font-bold text-white">{Number(t.cvss_score).toFixed(1)}</span>
                                                    ) : '—'}
                                                </td>
                                                <td className="px-3 py-2">
                                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${sevClass}`}>
                                                        {t.severity || 'INFO'}
                                                    </span>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>
            </motion.div>
        </div>
    );
};

export default React.memo(ThreatTable);
