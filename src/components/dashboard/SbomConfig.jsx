import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { LIQUID_SPRING } from '../../lib/constants';
import { apiUrl } from '../../lib/api';

const ToggleSwitch = ({ enabled, label, description, onToggle, saving }) => (
    <div className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
        <div className="flex-1 min-w-0 mr-4">
            <p className="text-sm font-medium text-white">{label}</p>
            {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
        </div>
        <button
            onClick={onToggle}
            disabled={saving}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500/50 ${
                enabled
                    ? 'bg-emerald-500/80'
                    : 'bg-gray-600'
            } ${saving ? 'opacity-50 cursor-wait' : 'cursor-pointer'}`}
            role="switch"
            aria-checked={enabled}
        >
            <span
                className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform duration-200 ${
                    enabled ? 'translate-x-[18px]' : 'translate-x-[3px]'
                }`}
            />
        </button>
    </div>
);

const TtlDisplay = ({ label, value }) => (
    <div className="flex items-center justify-between py-2">
        <span className="text-xs text-gray-400">{label}</span>
        <span className="text-xs font-mono text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded">
            {value}s
        </span>
    </div>
);

export default function SbomConfig() {
    const [config, setConfig] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const [saveMsg, setSaveMsg] = useState('');

    useEffect(() => {
        fetchConfig();
    }, []);

    const fetchConfig = async () => {
        try {
            const res = await fetch(apiUrl('/api/dashboard/api/sbom/config'));
            const data = await res.json();
            if (data.success) {
                setConfig(data.config);
            } else {
                setError(data.error || 'Failed to load config');
            }
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const updateConfig = useCallback(async (key, value) => {
        setSaving(true);
        setSaveMsg('');
        try {
            const res = await fetch(apiUrl('/api/dashboard/api/sbom/config'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [key]: value }),
            });
            const data = await res.json();
            if (data.success) {
                setConfig(data.config);
                setSaveMsg('Saved');
                setTimeout(() => setSaveMsg(''), 2000);
            } else {
                setSaveMsg(data.error || 'Failed to save');
            }
        } catch (e) {
            setSaveMsg(e.message);
        } finally {
            setSaving(false);
        }
    }, []);

    if (loading) {
        return (
            <div className="glass-panel-dash rounded-2xl p-6">
                <div className="flex items-center gap-2 mb-4">
                    <span className="material-symbols-outlined text-purple-400 text-lg">tune</span>
                    <h3 className="text-sm font-medium text-gray-200">SBOM Scanner Config</h3>
                </div>
                <div className="space-y-3">
                    {[1, 2, 3, 4].map(i => (
                        <div key={i} className="h-10 bg-white/5 rounded-lg animate-pulse" />
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
                    <h3 className="text-sm font-medium text-gray-200">SBOM Scanner Config</h3>
                </div>
                <p className="text-xs text-red-400">{error}</p>
            </div>
        );
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...LIQUID_SPRING, delay: 0.3 }}
            className="glass-panel-dash rounded-2xl p-6 relative overflow-hidden"
        >
            <div className="absolute inset-0 card-glow-purple opacity-30 pointer-events-none" />
            <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-purple-400 text-lg">tune</span>
                        <h3 className="text-sm font-medium text-gray-200">SBOM Scanner Config</h3>
                    </div>
                    <span className="text-[10px] font-mono text-gray-500 bg-white/5 px-2 py-0.5 rounded">
                        {config?.config_source || 'engagement.yaml'}
                    </span>
                </div>

                {/* Lookup Source Toggles */}
                <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                        <p className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Lookup Sources</p>
                        {saveMsg && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                saveMsg === 'Saved' ? 'text-emerald-400 bg-emerald-500/10' : 'text-red-400 bg-red-500/10'
                            }`}>{saveMsg}</span>
                        )}
                    </div>
                    <ToggleSwitch
                        enabled={config?.ghsa_enabled ?? true}
                        label="GitHub Advisory Database"
                        description="GHSA advisories with ecosystem detection"
                        onToggle={() => updateConfig('ghsa_enabled', !(config?.ghsa_enabled ?? true))}
                        saving={saving}
                    />
                    <ToggleSwitch
                        enabled={config?.osv_enabled ?? true}
                        label="Open Source Vulnerabilities"
                        description="OSV (osv.dev) aggregated advisories"
                        onToggle={() => updateConfig('osv_enabled', !(config?.osv_enabled ?? true))}
                        saving={saving}
                    />
                    <ToggleSwitch
                        enabled={config?.nvd_enabled ?? true}
                        label="NIST NVD"
                        description="National Vulnerability Database (rate-limited)"
                        onToggle={() => updateConfig('nvd_enabled', !(config?.nvd_enabled ?? true))}
                        saving={saving}
                    />
                    <ToggleSwitch
                        enabled={config?.registry_enabled ?? true}
                        label="Registry Lookup"
                        description="npm + PyPI package existence checks"
                        onToggle={() => updateConfig('registry_enabled', !(config?.registry_enabled ?? true))}
                        saving={saving}
                    />
                </div>

                {/* Cache TTLs */}
                <div className="mb-4">
                    <p className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">Cache TTL</p>
                    <div className="bg-white/[0.03] rounded-lg p-3">
                        <TtlDisplay label="Registry Cache" value={config?.registry_cache_ttl_seconds ?? 3600} />
                        <TtlDisplay label="GHSA Cache" value={config?.ghsa_cache_ttl_seconds ?? 3600} />
                        <TtlDisplay label="OSV Cache" value={config?.osv_cache_ttl_seconds ?? 3600} />
                        <TtlDisplay label="NVD Cache" value={config?.nvd_cache_ttl_seconds ?? 3600} />
                    </div>
                </div>

                {/* Advisory Limit */}
                <div className="flex items-center justify-between py-2 px-3 bg-white/[0.03] rounded-lg">
                    <span className="text-xs text-gray-400">Max Advisories / Package</span>
                    <span className="text-sm font-bold text-white">{config?.max_advisories_per_package ?? 10}</span>
                </div>

                {/* NVD API Key Status */}
                <div className="flex items-center gap-2 mt-3 py-2 px-3 bg-white/[0.03] rounded-lg">
                    <span className={`w-2 h-2 rounded-full ${config?.nvd_api_key_configured ? 'bg-green-400' : 'bg-yellow-400'}`} />
                    <span className="text-xs text-gray-400">
                        NVD API Key: {config?.nvd_api_key_configured ? 'Configured' : 'Not set (rate-limited)'}
                    </span>
                </div>
            </div>
        </motion.div>
    );
}
