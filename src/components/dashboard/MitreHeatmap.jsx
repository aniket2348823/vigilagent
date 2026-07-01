import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { LIQUID_SPRING } from '../../lib/constants';
import { apiUrl } from '../../lib/api';

const SEVERITY_COLORS = {
    green: { bg: 'bg-emerald-500/20', border: 'border-emerald-500/30', text: 'text-emerald-400', fill: '#10b981' },
    yellow: { bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', text: 'text-yellow-400', fill: '#eab308' },
    red: { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400', fill: '#ef4444' },
};

const TACTIC_ICONS = {
    reconnaissance: 'search',
    'resource-development': 'build',
    'initial-access': 'login',
    execution: 'play_arrow',
    persistence: 'lock',
    'privilege-escalation': 'admin_panel_settings',
    'defense-evasion': 'shield',
    'credential-access': 'key',
    discovery: 'explore',
    'lateral-movement': 'swap_horiz',
    collection: 'inventory_2',
    'command-and-control': 'cloud',
    exfiltration: 'upload',
    impact: 'warning',
};

export default function MitreHeatmap() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [hoveredTactic, setHoveredTactic] = useState(null);
    const [selectedTactic, setSelectedTactic] = useState(null);

    useEffect(() => {
        fetchHeatmap();
    }, []);

    const fetchHeatmap = async () => {
        try {
            const res = await fetch(apiUrl('/api/dashboard/api/mitre/heatmap'));
            const json = await res.json();
            if (json.success) {
                setData(json);
            } else {
                setError(json.error || 'Failed to load heatmap');
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
                    <span className="material-symbols-outlined text-purple-400 text-lg">grid_view</span>
                    <h3 className="text-sm font-medium text-gray-200">MITRE ATT&CK Coverage</h3>
                </div>
                <div className="grid grid-cols-7 gap-2">
                    {Array.from({ length: 14 }).map((_, i) => (
                        <div key={i} className="h-16 bg-white/5 rounded-lg animate-pulse" />
                    ))}
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="glass-panel-dash rounded-2xl p-6">
                <div className="flex items-center gap-2 mb-3">
                    <span className="material-symbols-outlined text-red-400 text-lg">error</span>
                    <h3 className="text-sm font-medium text-gray-200">MITRE ATT&CK Coverage</h3>
                </div>
                <p className="text-xs text-red-400">{error}</p>
            </div>
        );
    }

    const heatmap = data?.heatmap || [];
    const summary = data?.summary || {};

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...LIQUID_SPRING, delay: 0.2 }}
            className="glass-panel-dash rounded-2xl p-6 relative overflow-hidden"
        >
            <div className="absolute inset-0 card-glow-purple opacity-20 pointer-events-none" />
            <div className="relative z-10">
                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-purple-400 text-lg">grid_view</span>
                        <h3 className="text-sm font-medium text-gray-200">MITRE ATT&CK Coverage</h3>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className="text-[10px] font-mono text-gray-500">
                            {summary.total_unique_techniques || 0} techniques mapped
                        </span>
                        <span className="text-[10px] font-mono text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded">
                            {summary.coverage_percentage || 0}% coverage
                        </span>
                    </div>
                </div>

                {/* Summary Badges */}
                <div className="flex items-center gap-2 mb-4">
                    <div className="flex items-center gap-1.5 px-2 py-1 bg-emerald-500/10 rounded-lg">
                        <span className="w-2 h-2 bg-emerald-500 rounded-full" />
                        <span className="text-[10px] text-emerald-400">
                            {summary.tactics_with_coverage || 0} tactics covered
                        </span>
                    </div>
                    <div className="flex items-center gap-1.5 px-2 py-1 bg-white/5 rounded-lg">
                        <span className="text-[10px] text-gray-400">
                            {summary.total_tactics || 14} total tactics
                        </span>
                    </div>
                </div>

                {/* Heatmap Grid */}
                <div className="grid grid-cols-7 gap-2 mb-4">
                    {heatmap.map((tactic, i) => {
                        const color = SEVERITY_COLORS[tactic.coverage_color] || SEVERITY_COLORS.red;
                        const isSelected = selectedTactic?.tactic_id === tactic.tactic_id;
                        const isHovered = hoveredTactic === tactic.tactic_id;
                        return (
                            <motion.div
                                key={tactic.tactic_id}
                                initial={{ opacity: 0, scale: 0.8 }}
                                animate={{ opacity: 1, scale: 1 }}
                                transition={{ ...LIQUID_SPRING, delay: i * 0.03 }}
                                whileHover={{ scale: 1.05, y: -3 }}
                                onMouseEnter={() => setHoveredTactic(tactic.tactic_id)}
                                onMouseLeave={() => setHoveredTactic(null)}
                                onClick={() => setSelectedTactic(isSelected ? null : tactic)}
                                className={`relative cursor-pointer rounded-xl p-3 border transition-all duration-200 ${
                                    isSelected
                                        ? `${color.bg} ${color.border} shadow-lg`
                                        : isHovered
                                        ? `${color.bg} border-white/10`
                                        : 'bg-white/[0.03] border-white/5 hover:border-white/10'
                                }`}
                            >
                                <div className="flex flex-col items-center text-center">
                                    <span className={`material-symbols-outlined text-lg mb-1 ${
                                        isSelected || isHovered ? color.text : 'text-gray-500'
                                    }`}>
                                        {TACTIC_ICONS[tactic.tactic_short] || 'help'}
                                    </span>
                                    <span className={`text-[8px] font-mono leading-tight ${
                                        isSelected ? 'text-white' : 'text-gray-400'
                                    }`}>
                                        {tactic.tactic_name.length > 12
                                            ? tactic.tactic_name.substring(0, 12) + '…'
                                            : tactic.tactic_name}
                                    </span>
                                    <span className={`text-[10px] font-bold mt-1 ${
                                        isSelected ? color.text : 'text-gray-500'
                                    }`}>
                                        {tactic.covered_count}
                                    </span>
                                </div>
                                {/* Coverage bar */}
                                <div className="absolute bottom-0 left-2 right-2 h-1 bg-white/5 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full rounded-full transition-all duration-500 ${
                                            tactic.coverage_color === 'green' ? 'bg-emerald-500' :
                                            tactic.coverage_color === 'yellow' ? 'bg-yellow-500' : 'bg-red-500'
                                        }`}
                                        style={{ width: `${Math.min(tactic.covered_count * 25, 100)}%` }}
                                    />
                                </div>
                            </motion.div>
                        );
                    })}
                </div>

                {/* Selected Tactic Details */}
                {selectedTactic && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-white/[0.03] rounded-xl p-4 border border-white/5"
                    >
                        <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                                <span className={`material-symbols-outlined text-base ${
                                    SEVERITY_COLORS[selectedTactic.coverage_color]?.text || 'text-gray-400'
                                }`}>
                                    {TACTIC_ICONS[selectedTactic.tactic_short] || 'help'}
                                </span>
                                <span className="text-sm font-medium text-white">{selectedTactic.tactic_name}</span>
                                <span className="text-[10px] font-mono text-gray-500">{selectedTactic.tactic_id}</span>
                            </div>
                            <button
                                onClick={() => setSelectedTactic(null)}
                                className="text-gray-500 hover:text-white transition-colors"
                            >
                                <span className="material-symbols-outlined text-sm">close</span>
                            </button>
                        </div>
                        {selectedTactic.techniques?.length > 0 ? (
                            <div className="flex flex-wrap gap-1.5">
                                {selectedTactic.techniques.map((tech, i) => (
                                    <span
                                        key={i}
                                        className="text-[10px] font-mono px-2 py-1 bg-purple-500/10 text-purple-300 rounded-lg border border-purple-500/20"
                                    >
                                        {tech.technique_id}: {tech.technique_name}
                                    </span>
                                ))}
                            </div>
                        ) : (
                            <p className="text-xs text-gray-500 italic">No techniques mapped for this tactic</p>
                        )}
                    </motion.div>
                )}
            </div>
        </motion.div>
    );
}
