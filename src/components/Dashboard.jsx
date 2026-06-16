import React, { useState, useEffect, useRef, useMemo } from 'react';
import Navigation from './Navigation';
import { motion } from 'framer-motion';
import { LIQUID_SPRING } from '../lib/constants';
import { apiUrl } from '../lib/api';
import { handleAutoDownload } from '../lib/downloadReport';
import { useWebSocket } from '../hooks/useWebSocket';
import LiveMonitor from './LiveMonitor';


const Dashboard = ({ navigate, persistentState, setPersistentState }) => {
    // [V7] Local sync refs to track the active scan ID and cooldown status for the flushBuffer closure
    const activeScanIdRef = useRef(persistentState?.activeScanId);
    const isCooldownRef = useRef(persistentState?.isCooldown);
    const isStartDelayRef = useRef(persistentState?.isStartDelay);

    const [latestThreat, setLatestThreat] = useState(null);
    const [scanActive, setScanActive] = useState(false);
    const [scanTargetUrl, setScanTargetUrl] = useState('');

    const scanActiveRef = useRef(false);
    const scanTargetUrlRef = useRef('');

    // Keep refs in sync with props and local state
    useEffect(() => { scanActiveRef.current = scanActive; }, [scanActive]);
    useEffect(() => { scanTargetUrlRef.current = scanTargetUrl; }, [scanTargetUrl]);
    useEffect(() => { activeScanIdRef.current = persistentState?.activeScanId; }, [persistentState?.activeScanId]);
    useEffect(() => { isCooldownRef.current = persistentState?.isCooldown; }, [persistentState?.isCooldown]);
    useEffect(() => { isStartDelayRef.current = persistentState?.isStartDelay; }, [persistentState?.isStartDelay]);

    const statsBuffer = useRef([]);
    const bufferTimer = useRef(null);
    const requestCountRef = useRef(0);

    // ── Shared WebSocket (singleton — no more per-page connections) ──
    const { subscribe } = useWebSocket();

    const flushBuffer = () => {
        const events = statsBuffer.current;
        if (events.length === 0) return;
        statsBuffer.current = [];

        setPersistentState(prev => {
            let nextState = { ...prev };
            events.forEach(data => {
                // SCAN LIFECYCLE: Start populating on scan start, clear on complete
                if (data.type === 'SCAN_UPDATE') {
                    const status = data.payload?.status;
                    const incomingScanId = data.payload?.id;

                    if (status === 'Running' || status === 'Initializing') {
                        const isNewScan = activeScanIdRef.current !== incomingScanId;

                        setScanActive(true);
                        scanActiveRef.current = true;
                        nextState.activeScanId = incomingScanId;
                        activeScanIdRef.current = incomingScanId;
                        nextState.isCooldown = false;
                        isCooldownRef.current = false;

                        // [V7] Real-time Start Suppression: Empty data and wait 2 seconds
                        if (isNewScan) {
                            nextState.threat_feed = [];
                            nextState.graph_data = [];
                            requestCountRef.current = 0;

                            nextState.isStartDelay = true;
                            isStartDelayRef.current = true;
                            setTimeout(() => {
                                setPersistentState(p => ({ ...p, isStartDelay: false }));
                                isStartDelayRef.current = false;
                            }, 2000);
                        }

                        // Store target URL for filtering
                        if (data.payload?.target_url) {
                            setScanTargetUrl(data.payload.target_url);
                            scanTargetUrlRef.current = data.payload.target_url;
                        }
                    } else if (status === 'Completed' || status === 'Finalizing') {
                        setScanActive(false);
                        scanActiveRef.current = false;
                        setScanTargetUrl('');
                        scanTargetUrlRef.current = '';

                        // [V8 FIX] Keep threat_feed and graph_data so the user can see results!
                        // Only clear the scan tracking state, not the visible data.
                        nextState.activeScanId = null;
                        activeScanIdRef.current = null;

                        // Start 2-second cooldown (prevents stale events from next scan)
                        nextState.isCooldown = true;
                        isCooldownRef.current = true;
                        setTimeout(() => {
                            setPersistentState(p => ({ ...p, isCooldown: false }));
                            isCooldownRef.current = false;
                        }, 2000);
                    }
                }

                if (data.type === 'VULN_UPDATE') {
                    nextState.metrics = data.payload.metrics || data.payload;
                    // [V7] Sync real-time performance counters from authoritative backend
                    if (nextState.metrics.total_requests !== undefined) {
                        requestCountRef.current = nextState.metrics.total_requests;
                    }
                    if (nextState.metrics.rps !== undefined) {
                        nextState.rps = nextState.metrics.rps;
                        // Map RPS spike to graph if scan is active
                        if (scanActiveRef.current) {
                            nextState.graph_data = [...(nextState.graph_data || []), nextState.metrics.rps].slice(-60);
                        }
                    }
                }
                else if (['LIVE_THREAT_LOG', 'ATTACK_HIT', 'VULN_CONFIRMED', 'LOG', 'JOB_ASSIGNED', 'RECON_PACKET', 'KEY_CAPTURE', 'LIVE_ATTACK_FEED', 'GI5_LOG'].includes(data.type)) {

                    // [V7] ISOLATION PRISM: 
                    // If we are in COOLDOWN or START DELAY, don't show ANYTHING.
                    if (isCooldownRef.current || isStartDelayRef.current) return;

                    // If a scan is active, ONLY show events belonging to that scan.
                    if (activeScanIdRef.current && data.scan_id !== activeScanIdRef.current) {
                        return;
                    }

                    if (data.type === 'LIVE_THREAT_LOG') {
                        setLatestThreat(data.payload);
                    }
                    const defaultV6 = { injections_blocked: 0, deceptive_ui_blocked: 0, risk_score: 0 };
                    const currentV6 = nextState.v6_metrics || defaultV6;
                    const newMetrics = { ...currentV6 };

                    const severityToRisk = (sev) => {
                        const map = { 'CRITICAL': 95, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10 };
                        return map[sev?.toUpperCase()] || 30;
                    };

                    let threat = data.payload;
                    if (data.type === 'ATTACK_HIT' || data.type === 'JOB_ASSIGNED') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: data.source || 'agent_beta',
                            threat_type: data.type === 'JOB_ASSIGNED' ? 'JOB DISPATCHED' : 'ATTACK GENERATED',
                            url: data.payload?.url || data.payload?.target || (typeof data.payload === 'string' ? data.payload.substring(0, 40) : 'System Action'),
                            severity: 'INFO',
                            risk_score: severityToRisk('INFO')
                        };
                    } else if (data.type === 'VULN_CONFIRMED') {
                        const confirmedSev = data.payload?.severity || 'CRITICAL';
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: data.source || 'agent_gamma',
                            threat_type: data.payload?.type || 'VULNERABILITY',
                            url: data.payload?.url || data.payload?.id || 'Confirmed Exploit',
                            severity: confirmedSev,
                            risk_score: severityToRisk(confirmedSev),
                            cvss_score: data.payload?.cvss_score || null,
                            cvss_vector: data.payload?.cvss_vector || '',
                            cwe: data.payload?.cwe || '',
                        };
                    } else if (data.type === 'LOG') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: data.source || 'system',
                            threat_type: 'SYSTEM LOG',
                            url: typeof data.payload === 'string' ? data.payload.substring(0, 60) : 'Log Entry',
                            severity: 'LOW',
                            risk_score: severityToRisk('LOW')
                        };
                    } else if (data.type === 'RECON_PACKET') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: 'spy_v2',
                            threat_type: 'TRAFFIC INTERCEPTED',
                            url: data.payload?.url || 'Unknown Endpoint',
                            severity: data.payload?.severity || 'INFO',
                            risk_score: data.payload?.risk_score || severityToRisk(data.payload?.severity || 'INFO')
                        };
                    } else if (data.type === 'KEY_CAPTURE') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: 'synapse_v2',
                            threat_type: 'CREDENTIAL LEAK',
                            url: data.payload?.url || 'Sensitive Header',
                            severity: 'HIGH',
                            risk_score: severityToRisk('HIGH')
                        };
                    } else if (data.type === 'LIVE_ATTACK_FEED') {
                        const attackPayload = data.payload || {};
                        // Map orchestrator lifecycle events to descriptive types
                        const lifecycleTypes = ['INITIALIZATION', 'PLANNING', 'ACTIVATION', 'AGENT_ONLINE', 'PHASE_TRANSITION', 'MONITORING', 'TERMINATION'];
                        const isLifecycle = lifecycleTypes.includes(attackPayload.threat_type);
                        const attackSev = attackPayload.severity || (isLifecycle ? 'INFO' : 'HIGH');
                        const displayType = isLifecycle
                            ? attackPayload.threat_type
                            : `[ATTACK] ${attackPayload.arsenal?.toUpperCase() || attackPayload.threat_type || 'GENERAL'}`;
                        threat = {
                            timestamp: attackPayload.timestamp || new Date().toLocaleTimeString(),
                            agent: attackPayload.agent || 'agent_sigma',
                            threat_type: displayType,
                            url: attackPayload.result || attackPayload.url || 'Target Endpoint',
                            severity: attackSev,
                            risk_score: attackPayload.risk_score || severityToRisk(attackSev),
                            action: attackPayload.action,
                            payload_data: attackPayload.payload
                        };
                    } else if (data.type === 'GI5_LOG') {
                        const logMsg = typeof data.payload === 'string' ? data.payload : data.payload?.message || 'System Event';
                        threat = {
                            timestamp: new Date().toLocaleTimeString(),
                            agent: 'Orchestrator',
                            threat_type: 'SYSTEM LOG',
                            url: logMsg.substring(0, 80),
                            severity: 'INFO',
                            risk_score: severityToRisk('INFO')
                        };
                    }

                    if (['PROMPT_INJECTION', 'INVISIBLE_TEXT', 'HIDDEN_TEXT'].includes(threat.threat_type)) {
                        newMetrics.injections_blocked += 1;
                    } else if (['DECEPTIVE_UI', 'PHISHING', 'ROACH_MOTEL', 'DARK_PATTERN_BLOCK'].includes(threat.threat_type)) {
                        newMetrics.deceptive_ui_blocked += 1;
                    }

                    let incomingScore = threat.risk_score || severityToRisk(threat.severity);
                    let prevScore = newMetrics.risk_score || 0;
                    newMetrics.risk_score = prevScore === 0 ? incomingScore : Math.round(0.45 * incomingScore + 0.55 * prevScore);

                    nextState.v6_metrics = newMetrics;

                    // Cap threat_feed at 500 entries to prevent unbounded memory growth
                    const MAX_THREAT_FEED = 500;
                    const updatedFeed = [threat, ...(nextState.threat_feed || [])];
                    nextState.threat_feed = updatedFeed.length > MAX_THREAT_FEED
                        ? updatedFeed.slice(0, MAX_THREAT_FEED)
                        : updatedFeed;

                    // Sync graph with request count (Request Activity)
                    if (scanActiveRef.current) {
                        requestCountRef.current += 1;
                    }
                }
            });
            return nextState;
        });
    };

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const res = await fetch(apiUrl('/api/dashboard/stats'));
                const data = await res.json();

                setPersistentState(prev => ({
                    ...prev,
                    ...data,
                    // Preserve live threat_feed and graph_data if they are already populated from websocket
                    threat_feed: prev.threat_feed.length > 0 ? prev.threat_feed : (data.threat_feed || []),
                    graph_data: prev.graph_data.length > 0 ? prev.graph_data : (data.graph_data || []),
                    v6_metrics: data.v6_metrics || { injections_blocked: 0, deceptive_ui_blocked: 0, risk_score: 0 }
                }));

                // Detect if there's an active scan to set local flags
                if (data.metrics?.active_scans > 0) {
                    setScanActive(true);
                    scanActiveRef.current = true;
                }
            } catch (e) {
                // console.error("Failed to fetch dashboard stats", e);
            }
        };

        fetchStats();
        const interval = setInterval(fetchStats, 5000);

        // Subscribe to shared WS instead of opening a new connection
        const unsub = subscribe((data) => {
            // Handle BATCH envelopes from optimized socket_manager
            const events = data.type === 'BATCH' && Array.isArray(data.payload)
                ? data.payload
                : [data];

            events.forEach(event => {
                statsBuffer.current.push(event);
                // Auto-download generated PDF report (shared utility)
                handleAutoDownload(event);
            });

            if (!bufferTimer.current) {
                bufferTimer.current = requestAnimationFrame(() => {
                    flushBuffer();
                    bufferTimer.current = null;
                });
            }
        });

        return () => {
            clearInterval(interval);
            unsub();
            if (bufferTimer.current) {
                cancelAnimationFrame(bufferTimer.current);
                bufferTimer.current = null;
            }
        };
    }, []);

    // ── Memoized graph path generators ──
    const graphPath = useMemo(() => {
        const data = persistentState?.graph_data;
        if (!data || data.length === 0) return "";
        const maxVal = Math.max(...data, 1);
        const width = 1000;
        const height = 300;
        const pointWidth = width / Math.max(data.length - 1, 1);
        let path = `M0,${height} `;
        data.forEach((val, i) => {
            const x = i * pointWidth;
            const y = height - (val / maxVal) * (height * 0.8);
            path += `L${x},${y} `;
        });
        path += `L${width},${height} Z`;
        return path;
    }, [persistentState?.graph_data]);

    const linePath = useMemo(() => {
        const data = persistentState?.graph_data;
        if (!data || data.length === 0) return "";
        const maxVal = Math.max(...data, 1);
        const width = 1000;
        const height = 300;
        const pointWidth = width / Math.max(data.length - 1, 1);
        let d = "";
        data.forEach((val, i) => {
            const x = i * pointWidth;
            const y = height - (val / maxVal) * (height * 0.8);
            if (i === 0) d += `M${x},${y}`;
            else d += ` L${x},${y}`;
        });
        return d;
    }, [persistentState?.graph_data]);

    return (
        <div className="min-h-screen relative overflow-x-hidden" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            <div className="relative z-10 flex flex-col min-h-screen">
                <Navigation navigate={navigate} activePage="dashboard" />

                <main className="flex-grow px-6 pb-6 w-full max-w-7xl mx-auto space-y-6">
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...LIQUID_SPRING, duration: 0.5 }}
                        className="mt-4 mb-6"
                    >
                        <h1 className="text-3xl font-bold mb-1 text-white">Dashboard</h1>
                        <p className="text-gray-400 text-sm">View and manage your security assessments overview.</p>
                    </motion.div>

                    {persistentState && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            {[
                                { title: 'Injections Blocked', value: persistentState?.v6_metrics?.injections_blocked || 0, icon: 'shield', color: 'purple', glow: 'card-glow-purple', bgIcon: 'bg-purple-500/20 text-purple-300', trend: 0 },
                                { title: 'Deceptive UI', value: persistentState?.v6_metrics?.deceptive_ui_blocked || 0, icon: 'visibility_off', color: 'orange', glow: 'card-glow-orange', bgIcon: 'bg-orange-500/20 text-orange-300', trend: 0 },
                                {
                                    title: 'Live Risk Score',
                                    value: (persistentState?.v6_metrics?.risk_score || 0) + '%',
                                    icon: 'speed',
                                    color: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'red' : 'green',
                                    glow: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'card-glow-red' : 'card-glow-green',
                                    bgIcon: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300',
                                    trend: 0
                                },
                                { title: 'Active Scans', value: persistentState?.metrics?.active_scans || 0, icon: 'sensors', color: 'blue', glow: 'card-glow-blue', bgIcon: 'bg-blue-500/20 text-blue-300', isLive: true, trend: 0 }
                            ].map((item, i) => (
                                <motion.div
                                    key={i}
                                    initial={{ opacity: 0, scale: 0.9 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    transition={{ ...LIQUID_SPRING, delay: i * 0.1 }}
                                    whileHover={{ scale: 1.02, y: -5, transition: { duration: 0.2 } }}
                                    className="glass-panel-dash p-5 rounded-2xl relative overflow-hidden group"
                                >
                                    <div className={`absolute inset-0 ${item.glow} transition-opacity duration-300 opacity-60 group-hover:opacity-100`}></div>
                                    <div className="flex justify-between items-start mb-4 relative z-10">
                                        <div className={`p-2 rounded-lg ${item.bgIcon}`}>
                                            <span className="material-symbols-outlined text-xl">{item.icon}</span>
                                        </div>
                                        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-green-500/20 text-green-400">
                                            LIVE
                                        </span>
                                    </div>
                                    <div className="relative z-10">
                                        <h3 className="text-gray-400 text-sm font-medium">{item.title}</h3>
                                        <p className="text-2xl font-bold text-white mt-1">{item.value}</p>
                                    </div>
                                </motion.div>
                            ))}
                        </div>
                    )}

                    {/* REQUEST ACTIVITY GRAPH — Synced with Live Threat Monitor */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...LIQUID_SPRING, delay: 0.2 }}
                        className="glass-panel-dash rounded-2xl p-6 relative overflow-hidden flex flex-col h-[380px]"
                    >
                        <div className="flex justify-between items-center mb-4 relative z-10">
                            <h2 className="text-sm font-medium text-gray-200">Request Activity</h2>
                            <div className="flex items-center gap-3">
                                {scanActive && (
                                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-green-400">
                                        <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse shadow-[0_0_6px_rgba(74,222,128,0.6)]"></span>
                                        SCANNING
                                    </span>
                                )}
                                <span className="text-[10px] font-mono text-gray-500">
                                    {persistentState.graph_data.length > 0 ? `${requestCountRef.current} requests` : 'Idle'}
                                </span>
                            </div>
                        </div>
                        <div className="flex-grow w-full h-full relative z-0 mt-2">
                            {graphPath ? (
                                <svg className="w-full h-full drop-shadow-[0_0_15px_rgba(139,92,246,0.3)]" preserveAspectRatio="none" viewBox="0 0 1000 300">
                                    <defs>
                                        <linearGradient id="lineGradient" x1="0%" x2="100%" y1="0%" y2="0%">
                                            <stop offset="0%" stopColor="#d946ef"></stop>
                                            <stop offset="50%" stopColor="#8b5cf6"></stop>
                                            <stop offset="100%" stopColor="#06b6d4"></stop>
                                        </linearGradient>
                                        <linearGradient id="areaGradient" x1="0%" x2="0%" y1="0%" y2="100%">
                                            <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.4"></stop>
                                            <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0"></stop>
                                        </linearGradient>
                                    </defs>
                                    <path
                                        className="transition-all duration-300 ease-in-out"
                                        d={graphPath}
                                        fill="url(#areaGradient)"
                                        opacity="0.8"
                                    ></path>
                                    <path
                                        className="transition-all duration-300 ease-in-out"
                                        d={linePath}
                                        fill="none"
                                        stroke="url(#lineGradient)"
                                        strokeLinecap="round"
                                        strokeWidth="3"
                                    ></path>
                                </svg>
                            ) : (
                                <div className="flex items-center justify-center h-full text-gray-600 opacity-40">
                                    <div className="text-center">
                                        <span className="material-symbols-outlined text-3xl block mb-2">show_chart</span>
                                        <p className="text-xs font-mono">Waiting for scan to start...</p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </motion.div>

                    {/* REQUEST MONITORING — Adaptive 500-row rolling window */}
                    <div className="grid grid-cols-1 gap-6 h-[500px]">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ ...LIQUID_SPRING, delay: 0.3 }}
                            className="glass-panel-dash rounded-2xl p-0 relative overflow-hidden flex flex-col h-full"
                        >
                            <div className="h-full flex flex-col">
                                <div className="flex justify-between items-center px-5 py-3 border-b border-white/5">
                                    <h2 className="text-sm font-medium text-gray-200 flex items-center gap-2">
                                        <span className="material-symbols-outlined text-base text-purple-400">monitoring</span>
                                        Live Threat Monitor
                                    </h2>
                                    {scanActive && (
                                        <span className="flex items-center gap-1.5 text-[10px] font-mono text-green-400">
                                            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse"></span>
                                            MONITORING
                                        </span>
                                    )}
                                </div>
                                <div className="flex-grow overflow-y-auto overflow-x-auto scrollbar-thin px-1">
                                    {(persistentState.threat_feed || []).length === 0 ? (
                                        <div className="flex items-center justify-center h-full text-gray-600 opacity-40">
                                            <div className="text-center">
                                                <span className="material-symbols-outlined text-3xl block mb-2">security</span>
                                                <p className="text-xs font-mono">No threats detected yet</p>
                                            </div>
                                        </div>
                                    ) : (
                                        <table className="w-full text-xs">
                                            <thead className="sticky top-0 bg-[#0a0a1a]/90 backdrop-blur z-10">
                                                <tr className="text-gray-500 text-left">
                                                    <th className="px-4 py-2 font-medium">Time</th>
                                                    <th className="px-4 py-2 font-medium">Agent</th>
                                                    <th className="px-4 py-2 font-medium">Type</th>
                                                    <th className="px-4 py-2 font-medium">Target</th>
                                                    <th className="px-4 py-2 font-medium">CVSS 4.0</th>
                                                    <th className="px-4 py-2 font-medium">Severity</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(persistentState.threat_feed || []).slice(0, 500).map((t, i) => {
                                                    const sevColors = {
                                                        CRITICAL: 'text-red-400 bg-red-500/10',
                                                        HIGH: 'text-orange-400 bg-orange-500/10',
                                                        MEDIUM: 'text-yellow-400 bg-yellow-500/10',
                                                        LOW: 'text-blue-400 bg-blue-500/10',
                                                        INFO: 'text-gray-400 bg-gray-500/10',
                                                    };
                                                    const sevClass = sevColors[t.severity?.toUpperCase()] || sevColors.INFO;
                                                    return (
                                                        <tr key={i} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors">
                                                            <td className="px-4 py-2 text-gray-500 font-mono">{t.timestamp}</td>
                                                            <td className="px-4 py-2 text-purple-300 font-mono">{t.agent}</td>
                                                            <td className="px-4 py-2 text-gray-300 font-mono">{t.threat_type}</td>
                                                            <td className="px-4 py-2 text-gray-400 font-mono truncate max-w-[200px]" title={t.url}>{t.url}</td>
                                                            <td className="px-4 py-2 w-[140px]">
                                                                {t.cvss_score != null ? (
                                                                    <div className="flex flex-col">
                                                                        <span className="text-[10px] font-bold text-white">{Number(t.cvss_score).toFixed(1)}</span>
                                                                        {t.cvss_vector && (
                                                                            <span className="text-[8px] text-gray-500 font-mono truncate" title={t.cvss_vector}>
                                                                                {t.cvss_vector}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                ) : (
                                                                    <span className="text-gray-600 text-[10px]">—</span>
                                                                )}
                                                            </td>
                                                            <td className="px-4 py-2">
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

                    {/* LIVE AGENT FEED — Real-time backend orchestration events */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...LIQUID_SPRING, delay: 0.4 }}
                    >
                        <LiveMonitor />
                    </motion.div>
                </main>

                <footer className="w-full text-center py-6 text-xs text-gray-600 relative z-10">
                    Vulagent Scanner Intelligence Backbone © 2024
                </footer>
            </div>
        </div>
    );
};

export default Dashboard;
