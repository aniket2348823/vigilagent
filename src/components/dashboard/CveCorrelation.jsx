import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LIQUID_SPRING } from '../../lib/constants';
import { apiUrl } from '../../lib/api';

const SEVERITY_BADGE = {
    CRITICAL: 'text-red-400 bg-red-500/15 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
    MEDIUM: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
    LOW: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
    UNKNOWN: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
};

const SOURCE_BADGES = {
    ghsa: { label: 'GHSA', color: 'bg-blue-500/15 text-blue-300 border-blue-500/20' },
    osv: { label: 'OSV', color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/20' },
    nvd: { label: 'NVD', color: 'bg-purple-500/15 text-purple-300 border-purple-500/20' },
    registry_lookup: { label: 'Registry', color: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/20' },
};

function ConfidenceBar({ value }) {
    const pct = Math.round(value * 100);
    const color = pct >= 90 ? 'bg-emerald-500' : pct >= 70 ? 'bg-yellow-500' : pct >= 40 ? 'bg-orange-500' : 'bg-red-500';
    return (
        <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-500 ${color}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-[10px] font-mono text-gray-400">{pct}%</span>
        </div>
    );
}

export default function CveCorrelation() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [expandedRow, setExpandedRow] = useState(null);
    const [filterSeverity, setFilterSeverity] = useState('');
    const [filterConfidence, setFilterConfidence] = useState(0);

    useEffect(() => { fetchData(); }, []);

    const fetchData = async () => {
        try {
            const res = await fetch(apiUrl('/api/dashboard/api/cve/correlate'));
            const json = await res.json();
            if (json.success) {
                setData(json);
            } else {
                setError(json.error || 'Failed to load CVE correlation');
            }
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="glass-panel-dash rounded-2xl p-6">
                <div className="flex items-center gap-2 mb-4">
                    <span className="material-symbols-outlined text-purple-400 text-lg">hub</span>
                    <h3 className="text-sm font-medium text-gray-200">CVE Correlation</h3>
                </div>
                <div className="space-y-2">
                    {[1, 2, 3].map(i => <div key={i} className="h-12 bg-white/5 rounded-lg animate-pulse" />)}
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="glass-panel-dash rounded-2xl p-6">
                <div className="flex items-center gap-2 mb-3">
                    <span className="material-symbols-outlined text-red-400 text-lg">error</span>
                    <h3 className="text-sm font-medium text-gray-200">CVE Correlation</h3>
                </div>
                <p className="text-xs text-red-400">{error}</p>
            </div>
        );
    }

    const cves = (data?.correlated_cves || []).filter(c => {
        if (filterSeverity && c.overall_severity !== filterSeverity) return false;
        if (filterConfidence > 0 && c.confidence < filterConfidence) return false;
        return true;
    });
    const summary = data?.summary || {};

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...LIQUID_SPRING, delay: 0.4 }}
            className="glass-panel-dash rounded-2xl p-6 relative overflow-hidden"
        >
            <div className="absolute inset-0 card-glow-red opacity-20 pointer-events-none" />
            <div className="relative z-10">
                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-purple-400 text-lg">hub</span>
                        <h3 className="text-sm font-medium text-gray-200">CVE Correlation</h3>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-gray-500">
                            {summary.total_cves || 0} CVEs
                        </span>
                        <span className="text-[10px] font-mono text-emerald-300 bg-emerald-500/10 px-2 py-0.5 rounded">
                            {summary.high_confidence || 0} high-confidence
                        </span>
                        {/* Export buttons */}
                        <button
                            onClick={() => window.open(apiUrl('/api/dashboard/api/cve/correlate/export?format=json'), '_blank')}
                            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-gray-300 hover:bg-white/10 hover:text-white transition-all"
                        >
                            <span className="material-symbols-outlined text-xs">download</span>
                            JSON
                        </button>
                        <button
                            onClick={() => window.open(apiUrl('/api/dashboard/api/cve/correlate/export?format=csv'), '_blank')}
                            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-300 hover:bg-purple-500/20 hover:text-white transition-all"
                        >
                            <span className="material-symbols-outlined text-xs">table_chart</span>
                            CSV
                        </button>
                    </div>
                </div>

                {/* Summary Cards */}
                <div className="grid grid-cols-4 gap-2 mb-4">
                    {[
                        { label: 'Critical', value: summary.critical || 0, color: 'text-red-400', bg: 'bg-red-500/10' },
                        { label: 'High', value: summary.high || 0, color: 'text-orange-400', bg: 'bg-orange-500/10' },
                        { label: 'Multi-Source', value: summary.multi_source || 0, color: 'text-purple-400', bg: 'bg-purple-500/10' },
                        { label: 'Total', value: summary.total_cves || 0, color: 'text-white', bg: 'bg-white/5' },
                    ].map((s, i) => (
                        <div key={i} className={`${s.bg} rounded-lg p-2 text-center`}>
                            <p className={`text-lg font-bold ${s.color}`}>{s.value}</p>
                            <p className="text-[9px] text-gray-500 uppercase">{s.label}</p>
                        </div>
                    ))}
                </div>

                {/* Filters */}
                <div className="flex items-center gap-2 mb-3">
                    <select
                        value={filterSeverity}
                        onChange={e => setFilterSeverity(e.target.value)}
                        className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                    >
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                    <select
                        value={filterConfidence}
                        onChange={e => setFilterConfidence(Number(e.target.value))}
                        className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                    >
                        <option value={0}>Any Confidence</option>
                        <option value={0.7}>≥ 70%</option>
                        <option value={0.9}>≥ 90%</option>
                    </select>
                    <span className="text-[10px] text-gray-500 ml-auto">{cves.length} results</span>
                </div>

                {/* CVE List */}
                <div className="space-y-1.5 max-h-[400px] overflow-y-auto scrollbar-thin">
                    {cves.length === 0 ? (
                        <div className="text-center py-8 text-gray-500">
                            <span className="material-symbols-outlined text-2xl block mb-2">check_circle</span>
                            <p className="text-xs">No correlated CVEs found</p>
                        </div>
                    ) : (
                        cves.map((cve, i) => {
                            const isExpanded = expandedRow === cve.cve_id;
                            const sevClass = SEVERITY_BADGE[cve.overall_severity] || SEVERITY_BADGE.UNKNOWN;
                            return (
                                <motion.div
                                    key={cve.cve_id}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: i * 0.02 }}
                                    className="bg-white/[0.03] rounded-xl border border-white/5 hover:border-white/10 transition-all"
                                >
                                    <div
                                        className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                                        onClick={() => setExpandedRow(isExpanded ? null : cve.cve_id)}
                                    >
                                        {/* Severity Badge */}
                                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${sevClass}`}>
                                            {cve.overall_severity}
                                        </span>
                                        {/* CVE ID */}
                                        <span className="text-xs font-mono text-white font-medium min-w-[110px]">
                                            {cve.cve_id}
                                        </span>
                                        {/* Package */}
                                        <span className="text-xs text-gray-400 truncate flex-1">
                                            {cve.package} {cve.version ? `@ ${cve.version}` : ''}
                                        </span>
                                        {/* Source Count */}
                                        <div className="flex items-center gap-1">
                                            {cve.sources.map(src => {
                                                const badge = SOURCE_BADGES[src] || { label: src, color: 'bg-gray-500/15 text-gray-300' };
                                                return (
                                                    <span key={src} className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${badge.color}`}>
                                                        {badge.label}
                                                    </span>
                                                );
                                            })}
                                        </div>
                                        {/* Confidence */}
                                        <ConfidenceBar value={cve.confidence} />
                                        {/* CVSS */}
                                        {cve.cvss_score > 0 && (
                                            <span className="text-[10px] font-mono text-gray-400">
                                                CVSS {cve.cvss_score.toFixed(1)}
                                            </span>
                                        )}
                                        {/* Expand Arrow */}
                                        <span className={`material-symbols-outlined text-gray-500 text-sm transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                                            expand_more
                                        </span>
                                    </div>

                                    {/* Expanded Details */}
                                    <AnimatePresence>
                                        {isExpanded && (
                                            <motion.div
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: 'auto', opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                className="overflow-hidden"
                                            >
                                                <div className="px-4 pb-3 border-t border-white/5 pt-3 space-y-2">
                                                    {cve.summary && (
                                                        <p className="text-xs text-gray-300 leading-relaxed">{cve.summary}</p>
                                                    )}
                                                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                                                        <div>
                                                            <span className="text-gray-500">Package:</span>
                                                            <span className="text-gray-300 ml-1 font-mono">{cve.package}</span>
                                                        </div>
                                                        <div>
                                                            <span className="text-gray-500">Version:</span>
                                                            <span className="text-gray-300 ml-1 font-mono">{cve.version || 'unpinned'}</span>
                                                        </div>
                                                        <div>
                                                            <span className="text-gray-500">First Seen:</span>
                                                            <span className="text-gray-300 ml-1 font-mono">{cve.first_seen || '—'}</span>
                                                        </div>
                                                        <div>
                                                            <span className="text-gray-500">Scan Count:</span>
                                                            <span className="text-gray-300 ml-1 font-mono">{cve.scan_count}</span>
                                                        </div>
                                                    </div>
                                                    {Object.keys(cve.source_severities || {}).length > 0 && (
                                                        <div>
                                                            <span className="text-[10px] text-gray-500 block mb-1">Source Severities:</span>
                                                            <div className="flex flex-wrap gap-1">
                                                                {Object.entries(cve.source_severities).map(([src, sev]) => (
                                                                    <span key={src} className="text-[9px] font-mono px-1.5 py-0.5 bg-white/5 rounded">
                                                                        {src}: {sev}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                    {cve.url && (
                                                        <a
                                                            href={cve.url}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="inline-flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors"
                                                        >
                                                            <span className="material-symbols-outlined text-xs">open_in_new</span>
                                                            View on NVD
                                                        </a>
                                                    )}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </div>
        </motion.div>
    );
}
