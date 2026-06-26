import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import Navigation from './Navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { LIQUID_SPRING } from '../lib/constants';
import { apiUrl } from '../lib/api';
import { handleAutoDownload } from '../lib/downloadReport';
import { useWebSocket } from '../hooks/useWebSocket';
import { resolveAgent, ALL_AGENTS } from '../lib/agentNames';
import { now24h, timestampAgeMs } from '../lib/timestamps';
import AnimatedCounter from './dashboard/AnimatedCounter';
import HealthIndicator from './dashboard/HealthIndicator';
import ThreatTable from './dashboard/ThreatTable';
import RpsGauge from './dashboard/RpsGauge';


const Dashboard = ({ navigate, persistentState, setPersistentState }) => {
    // [V7] Local sync refs to track the active scan ID and cooldown status for the flushBuffer closure
    const activeScanIdRef = useRef(persistentState?.activeScanId);
    const isCooldownRef = useRef(persistentState?.isCooldown);
    const isStartDelayRef = useRef(persistentState?.isStartDelay);

    const [latestThreat, setLatestThreat] = useState(null);
    const [scanActive, setScanActive] = useState(false);
    const [scanTargetUrl, setScanTargetUrl] = useState('');
    const [currentPhase, setCurrentPhase] = useState(null);
    const [completedPhases, setCompletedPhases] = useState([]);
    // Initialize filters from URL query string for persistence across navigation
    const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
    const [filterAgent, setFilterAgent] = useState(() => urlParams?.get('agent') || '');
    const [filterTimeRange, setFilterTimeRange] = useState(() => urlParams?.get('timerange') || '');
    const [filterSeverity, setFilterSeverity] = useState(() => urlParams?.get('severity') || '');

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
    const [selectedRowIndex, setSelectedRowIndex] = useState(-1);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [showExportMenu, setShowExportMenu] = useState(false);
    const rowRefs = useRef([]);


    // ── Shared WebSocket (singleton — no more per-page connections) ──
    const { subscribe } = useWebSocket();

    const flushBuffer = () => {
        const events = statsBuffer.current;
        if (events.length === 0) return;
        statsBuffer.current = [];

        // Batch size IS the delta — each event increments requestCountRef by 1
        const graphDelta = events.length;

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
                        setCurrentPhase(null);
                        setCompletedPhases([]);

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
                    }
                }
                else if (['LIVE_THREAT_LOG', 'ATTACK_HIT', 'VULN_CONFIRMED', 'LOG', 'JOB_ASSIGNED', 'RECON_PACKET', 'KEY_CAPTURE', 'LIVE_ATTACK_FEED', 'GI5_LOG', 'PHASE_STARTED', 'PHASE_COMPLETED', 'RECON_PROGRESS', 'EXPLOIT_PROGRESS', 'AGENT_HEARTBEAT'].includes(data.type)) {

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
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'beta',
                            threat_type: data.type === 'JOB_ASSIGNED' ? 'JOB DISPATCHED' : 'ATTACK GENERATED',
                            url: data.payload?.url || data.payload?.target || (typeof data.payload === 'string' ? data.payload.substring(0, 40) : 'System Action'),
                            severity: 'INFO',
                            risk_score: severityToRisk('INFO'),
                            method: data.payload?.method || null,
                            status: data.payload?.status || null
                        };
                    } else if (data.type === 'VULN_CONFIRMED') {
                        const confirmedSev = data.payload?.severity || 'CRITICAL';
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
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
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'alpha',
                            threat_type: 'SYSTEM LOG',
                            url: typeof data.payload === 'string' ? data.payload.substring(0, 60) : 'Log Entry',
                            severity: 'LOW',
                            risk_score: severityToRisk('LOW')
                        };
                    } else if (data.type === 'RECON_PACKET') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'alpha',
                            threat_type: 'TRAFFIC INTERCEPTED',
                            url: data.payload?.url || 'Unknown Endpoint',
                            severity: data.payload?.severity || 'INFO',
                            risk_score: data.payload?.risk_score || severityToRisk(data.payload?.severity || 'INFO')
                        };
                    } else if (data.type === 'KEY_CAPTURE') {
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'kappa',
                            threat_type: 'CREDENTIAL LEAK',
                            url: data.payload?.url || 'Sensitive Header',
                            severity: 'HIGH',
                            risk_score: severityToRisk('HIGH')
                        };
                    } else if (data.type === 'LIVE_ATTACK_FEED') {
                        const attackPayload = data.payload || {};
                        const lifecycleTypes = ['INITIALIZATION', 'PLANNING', 'ACTIVATION', 'AGENT_ONLINE', 'PHASE_TRANSITION', 'MONITORING', 'TERMINATION'];
                        const isLifecycle = lifecycleTypes.includes(attackPayload.threat_type);
                        const attackSev = attackPayload.severity || (isLifecycle ? 'INFO' : 'HIGH');
                        const displayType = isLifecycle
                            ? attackPayload.threat_type
                            : `[ATTACK] ${attackPayload.arsenal?.toUpperCase() || attackPayload.threat_type || 'GENERAL'}`;
                        threat = {
                            timestamp: attackPayload.timestamp || now24h(),
                            agent: attackPayload.agent || 'agent_sigma',
                            threat_type: displayType,
                            url: attackPayload.result || attackPayload.url || 'Target Endpoint',
                            severity: attackSev,
                            risk_score: attackPayload.risk_score || severityToRisk(attackSev),
                            method: attackPayload.method || null,
                            status: attackPayload.status || null,
                            anomaly: attackPayload.anomaly || false,
                            action: attackPayload.action,
                            payload_data: attackPayload.payload
                        };
                    } else if (data.type === 'GI5_LOG') {
                        const logMsg = typeof data.payload === 'string' ? data.payload : data.payload?.message || 'System Event';
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'alpha',
                            threat_type: 'SYSTEM LOG',
                            url: logMsg.substring(0, 80),
                            severity: 'INFO',
                            risk_score: severityToRisk('INFO')
                        };
                    } else if (data.type === 'PHASE_STARTED') {
                        const p = data.payload || {};
                        const phaseName = p.phase || p.name || 'Unknown';
                        setCurrentPhase(phaseName);
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'alpha',
                            threat_type: `PHASE: ${phaseName}`,
                            url: `Starting phase ${phaseName}`,
                            severity: 'INFO',
                            risk_score: 10
                        };
                    } else if (data.type === 'PHASE_COMPLETED') {
                        const p = data.payload || {};
                        const phaseName = p.phase || p.name || 'Unknown';
                        setCompletedPhases(prev => [...new Set([...prev, phaseName])]);
                        setCurrentPhase(null);
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || 'alpha',
                            threat_type: `PHASE DONE: ${phaseName}`,
                            url: `Completed phase ${phaseName}`,
                            severity: 'INFO',
                            risk_score: 10
                        };
                    } else if (data.type === 'RECON_PROGRESS') {
                        const p = data.payload || {};
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || p.agent || 'alpha',
                            threat_type: 'RECON PROGRESS',
                            url: p.detail || p.url || 'Scanning targets',
                            severity: 'INFO',
                            risk_score: 10
                        };
                    } else if (data.type === 'EXPLOIT_PROGRESS') {
                        const p = data.payload || {};
                        threat = {
                            timestamp: new Date().toLocaleTimeString('en-GB'),
                            agent: data.source || p.agent || 'beta',
                            threat_type: 'EXPLOIT PROGRESS',
                            url: p.detail || p.url || 'Testing exploits',
                            severity: 'MEDIUM',
                            risk_score: 50
                        };
                    } else if (data.type === 'AGENT_HEARTBEAT') {
                        // Don't push heartbeats to threat_feed — they'd flood the monitor.
                        return;
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
                        // Push pre-computed delta to graph_data for Request Activity chart
                        if (graphDelta > 0) {
                            nextState.graph_data = [...(nextState.graph_data || []), graphDelta].slice(-60);
                        }
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

    // ── Approximate filtered feed count for keyboard navigation ──
    const filteredFeedTotal = useMemo(() => {
        return (persistentState.threat_feed || []).filter(t => {
            if (filterAgent && (!t.agent || !t.agent.toLowerCase().includes(filterAgent))) return false;
            if (filterSeverity && (t.severity || 'INFO').toUpperCase() !== filterSeverity) return false;
            return true;
        }).length;
    }, [persistentState?.threat_feed, filterAgent, filterSeverity]);

    // ── Reset selection + modal when filters/feed change ──
    useEffect(() => { setSelectedRowIndex(-1); setSelectedEvent(null); }, [filterAgent, filterTimeRange, filterSeverity]);
    useEffect(() => { setSelectedRowIndex(-1); setSelectedEvent(null); }, [persistentState?.threat_feed?.length]);

    // Use refs for values accessed in keyboard useEffect to avoid re-subscribing
    const filteredFeedTotalRef = useRef(filteredFeedTotal);
    useEffect(() => { filteredFeedTotalRef.current = filteredFeedTotal; }, [filteredFeedTotal]);
    const showExportMenuRef = useRef(showExportMenu);
    useEffect(() => { showExportMenuRef.current = showExportMenu; }, [showExportMenu]);
    const selectedEventRef = useRef(selectedEvent);
    useEffect(() => { selectedEventRef.current = selectedEvent; }, [selectedEvent]);

    // Close export dropdown on outside click
    useEffect(() => {
        if (!showExportMenu) return;
        const handleClick = () => setShowExportMenu(false);
        // Use setTimeout to avoid closing on the same click that opened it
        const timer = setTimeout(() => document.addEventListener('click', handleClick), 0);
        return () => { clearTimeout(timer); document.removeEventListener('click', handleClick); };
    }, [showExportMenu]);

    // ── Keyboard shortcuts ──
    useEffect(() => {
        const handleKeyDown = (e) => {
            // Escape closes modal first, then export menu, then clears filters
            if (e.key === 'Escape') {
                if (selectedEventRef.current) { setSelectedEvent(null); return; }
                if (showExportMenuRef.current) { setShowExportMenu(false); return; }
                if (filterAgent || filterTimeRange || filterSeverity) {
                    setFilterAgent('');
                    setFilterTimeRange('');
                    setFilterSeverity('');
                    setSelectedRowIndex(-1);
                    window.history.replaceState(null, '', window.location.pathname);
                }
                return;
            }
            // Arrow keys navigate table rows (only when not focused on inputs)
            const tag = document.activeElement?.tagName?.toLowerCase();
            if (tag === 'input' || tag === 'select' || tag === 'textarea') return;
            // Use ref to avoid stale closure and reduce re-subscription churn
            const visibleCount = Math.min(filteredFeedTotalRef.current, 500);
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setSelectedRowIndex(prev => Math.min(prev + 1, visibleCount - 1));
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setSelectedRowIndex(prev => Math.max(prev - 1, 0));
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [filterAgent, filterTimeRange, filterSeverity]);

    // ── Scroll selected row into view ──
    useEffect(() => {
        if (selectedRowIndex >= 0 && rowRefs.current[selectedRowIndex]) {
            rowRefs.current[selectedRowIndex].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }, [selectedRowIndex]);

    // ── Memoized agent event counts (avoids re-filtering per agent on every render) ──
    const agentEventCounts = useMemo(() => {
        const feed = persistentState?.threat_feed || [];
        const counts = {};
        ALL_AGENTS.forEach(a => { counts[a.id] = 0; });
        feed.forEach(t => {
            if (!t.agent) return;
            const lower = t.agent.toLowerCase();
            const matchedId = ALL_AGENTS.find(a => lower.includes(a.id))?.id;
            if (matchedId) counts[matchedId]++;
        });
        return counts;
    }, [persistentState?.threat_feed]);

    // ── Per-agent sparkline data (last 20 time buckets) ──
    const agentSparklines = useMemo(() => {
        const feed = persistentState?.threat_feed || [];
        const BUCKETS = 20;
        const bucketWidth = 30000; // 30s per bucket → 10 min total
        const sparkData = {};
        ALL_AGENTS.forEach(a => { sparkData[a.id] = new Array(BUCKETS).fill(0); });
        feed.forEach(t => {
            if (!t.agent || !t.timestamp) return;
            const lower = t.agent.toLowerCase();
            const matchedId = ALL_AGENTS.find(a => lower.includes(a.id))?.id;
            if (!matchedId) return;
            const age = timestampAgeMs(t.timestamp);
            if (age === null) return;
            const bucket = BUCKETS - 1 - Math.floor(age / bucketWidth);
            if (bucket >= 0 && bucket < BUCKETS) sparkData[matchedId][bucket]++;
        });
        return sparkData;
    }, [persistentState?.threat_feed]);

    // ── Export dashboard data ──
    const exportData = useCallback((format) => {
        const feed = (persistentState?.threat_feed || []);
        const timestamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
        let content, filename, mime;
        if (format === 'json') {
            content = JSON.stringify(feed, null, 2);
            filename = `threat-feed-${timestamp}.json`;
            mime = 'application/json';
        } else {
            const headers = ['timestamp', 'agent', 'threat_type', 'url', 'method', 'status', 'cvss_score', 'severity', 'risk_score', 'anomaly'];
            const rows = feed.map(t => headers.map(h => {
                let val = t[h];
                if (h === 'anomaly') val = val ? 'true' : 'false';
                if (h === 'status') val = val || '';
                val = String(val ?? '');
                return val.includes(',') || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
            }).join(','));
            content = [headers.join(','), ...rows].join('\n');
            filename = `threat-feed-${timestamp}.csv`;
            mime = 'text/csv';
        }
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
        setShowExportMenu(false);
    }, [persistentState?.threat_feed]);

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

                    {/* Health Indicator */}
                    <HealthIndicator scanActive={scanActive} feedLength={(persistentState?.threat_feed || []).length} rps={persistentState?.rps || 0} />

                    {persistentState && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            {[
                                { title: 'Injections Blocked', rawValue: persistentState?.v6_metrics?.injections_blocked || 0, value: <AnimatedCounter value={persistentState?.v6_metrics?.injections_blocked || 0} />, icon: 'shield', color: 'purple', glow: 'card-glow-purple', bgIcon: 'bg-purple-500/20 text-purple-300', trend: 0 },
                                { title: 'Deceptive UI', rawValue: persistentState?.v6_metrics?.deceptive_ui_blocked || 0, value: <AnimatedCounter value={persistentState?.v6_metrics?.deceptive_ui_blocked || 0} />, icon: 'visibility_off', color: 'orange', glow: 'card-glow-orange', bgIcon: 'bg-orange-500/20 text-orange-300', trend: 0 },
                                {
                                    title: 'Live Risk Score',
                                    rawValue: persistentState?.v6_metrics?.risk_score || 0,
                                    value: <AnimatedCounter value={persistentState?.v6_metrics?.risk_score || 0} suffix="%" />, icon: 'speed',
                                    color: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'red' : 'green',
                                    glow: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'card-glow-red' : 'card-glow-green',
                                    bgIcon: (persistentState?.v6_metrics?.risk_score || 0) > 80 ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300',
                                    trend: 0
                                },
                                { title: 'Active Scans', rawValue: persistentState?.metrics?.active_scans || 0, value: <AnimatedCounter value={persistentState?.metrics?.active_scans || 0} />, icon: 'sensors', color: 'blue', glow: 'card-glow-blue', bgIcon: 'bg-blue-500/20 text-blue-300', isLive: true, trend: 0 }
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

                    {/* RPS Gauge + Request Activity Graph row */}
                    <div className="grid grid-cols-1 lg:grid-cols-[140px_1fr] gap-4">
                        <RpsGauge rps={persistentState?.rps || 0} maxRps={100} />

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
                    </div>

                    {/* AGENT ROSTER — All 13 agents displayed as status chips */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...LIQUID_SPRING, delay: 0.25 }}
                        className="glass-panel-dash rounded-2xl p-4 relative overflow-hidden"
                    >
                        <div className="flex items-center justify-between mb-3">
                            <h2 className="text-sm font-medium text-gray-200 flex items-center gap-2">
                                <span className="material-symbols-outlined text-base text-purple-400">group</span>
                                Agent Roster ({ALL_AGENTS.length} Active)
                            </h2>
                            {scanActive && (
                                <span className="flex items-center gap-1.5 text-[10px] font-mono text-green-400">
                                    <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse shadow-[0_0_6px_rgba(74,222,128,0.6)]"></span>
                                    ALL ONLINE
                                </span>
                            )}
                        </div>
                        <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-7 gap-2">
                            {ALL_AGENTS.map((agent) => {
                                const agentEventCount = agentEventCounts[agent.id] || 0;
                                const isAgentActive = agentEventCount > 0;
                                return (
                                    <motion.div
                                        key={agent.id}
                                        whileHover={{ scale: 1.05, y: -2 }}
                                        className={`flex flex-col items-center p-2 rounded-xl border transition-all duration-300 ${
                                            isAgentActive
                                                ? 'border-white/10 bg-white/[0.03] shadow-[0_0_10px_rgba(168,85,247,0.1)]'
                                                : 'border-white/[0.04] bg-white/[0.01] opacity-60'
                                        }`}
                                    >
                                        <div className="relative">
                                            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold ${
                                                isAgentActive ? 'bg-white/10' : 'bg-white/5'
                                            }`}>
                                                <span className={agent.color}>{agent.name.charAt(0)}</span>
                                            </div>
                                            {isAgentActive && (
                                                <span className="absolute -top-1.5 -right-1.5 min-w-[14px] h-[14px] rounded-full bg-purple-500/80 text-white text-[7px] font-bold flex items-center justify-center px-0.5">
                                                    {agentEventCount > 99 ? '99+' : agentEventCount}
                                                </span>
                                            )}
                                        </div>
                                        {/* Mini sparkline */}
                                        {isAgentActive && (
                                            <svg className={`w-full h-2 mt-1 max-w-[48px] ${agent.color}`} viewBox="0 0 20 4" preserveAspectRatio="none">
                                                {(() => {
                                                    const sparkBars = agentSparklines[agent.id] || [];
                                                    const maxSpark = Math.max(...sparkBars, 1);
                                                    return sparkBars.map((val, bi) => {
                                                    const barH = val > 0 ? Math.max((val / maxSpark) * 4, 0.5) : 0;
                                                    return (
                                                        <rect
                                                            key={bi}
                                                            x={bi}
                                                            y={4 - barH}
                                                            width="0.8"
                                                            height={barH}
                                                            className="fill-current opacity-60"
                                                        />
                                                    );
                                                    });
                                                })()}
                                            </svg>
                                        )}
                                        <span className={`text-[9px] font-mono font-medium mt-1 ${agent.color} ${isAgentActive ? '' : 'opacity-50'}`}>
                                            {agent.name}
                                        </span>
                                        <span className="text-[7px] text-gray-600 text-center leading-tight mt-0.5">
                                            {agent.role.split(' ')[0]}
                                        </span>
                                    </motion.div>
                                );
                            })}
                        </div>
                    </motion.div>

                    {/* LIVE MONITOR — Extracted ThreatTable component */}
                    <ThreatTable
                        persistentState={persistentState}
                        filterAgent={filterAgent}
                        setFilterAgent={setFilterAgent}
                        filterTimeRange={filterTimeRange}
                        setFilterTimeRange={setFilterTimeRange}
                        filterSeverity={filterSeverity}
                        setFilterSeverity={setFilterSeverity}
                        selectedRowIndex={selectedRowIndex}
                        setSelectedRowIndex={setSelectedRowIndex}
                        selectedEvent={selectedEvent}
                        setSelectedEvent={setSelectedEvent}
                        rowRefs={rowRefs}
                        scanActive={scanActive}
                        currentPhase={currentPhase}
                        completedPhases={completedPhases}
                        showExportMenu={showExportMenu}
                        setShowExportMenu={setShowExportMenu}
                        exportData={exportData}
                    />

                </main>

                {/* ── Event Detail Modal ── */}
                <AnimatePresence>
                    {selectedEvent && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
                            onClick={() => setSelectedEvent(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                transition={{ type: 'spring', damping: 25, stiffness: 300 }}
                                className="glass-panel-dash rounded-2xl p-6 max-w-lg w-full max-h-[80vh] overflow-y-auto scrollbar-thin"
                                onClick={(e) => e.stopPropagation()}
                            >
                                {/* Header */}
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                        <span className="material-symbols-outlined text-base text-purple-400">info</span>
                                        Event Details
                                    </h3>
                                    <button onClick={() => setSelectedEvent(null)} className="text-gray-500 hover:text-white transition-colors cursor-pointer">
                                        <span className="material-symbols-outlined text-lg">close</span>
                                    </button>
                                </div>
                                {/* Severity Badge */}
                                <div className="mb-4">
                                    {(() => {
                                        const sev = (selectedEvent.severity || 'INFO').toUpperCase();
                                        const badgeClass = {
                                            CRITICAL: 'text-red-400 bg-red-500/15 border-red-500/30',
                                            HIGH: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
                                            MEDIUM: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
                                            LOW: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
                                            INFO: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
                                        };
                                        return (
                                            <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border ${badgeClass[sev] || badgeClass.INFO}`}>
                                                {sev}
                                            </span>
                                        );
                                    })()}
                                </div>
                                {/* Detail Grid */}
                                <div className="space-y-3">
                                    {[
                                        ['Timestamp', selectedEvent.timestamp],
                                        ['Agent', selectedEvent.agent ? `${resolveAgent(selectedEvent.agent).name} (${selectedEvent.agent})` : '—'],
                                        ['Event Type', selectedEvent.threat_type],
                                        ['Target', selectedEvent.url],
                                        ['Method', selectedEvent.method],
                                        ['Status', selectedEvent.status != null ? String(selectedEvent.status) : null],
                                        ['Risk Score', selectedEvent.risk_score != null ? `${selectedEvent.risk_score}%` : null],
                                        ['CVSS Score', selectedEvent.cvss_score != null ? Number(selectedEvent.cvss_score).toFixed(1) : null],
                                        ['CVSS Vector', selectedEvent.cvss_vector || null],
                                        ['CWE', selectedEvent.cwe || null],
                                        ['Anomaly Detected', selectedEvent.anomaly ? 'Yes' : null],
                                        ['Action', selectedEvent.action || null],
                                    ].filter(([, val]) => val != null && val !== '').map(([label, val]) => (
                                        <div key={label} className="flex justify-between items-start gap-4">
                                            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider shrink-0">{label}</span>
                                            <span className="text-[11px] font-mono text-gray-300 text-right break-all">{val}</span>
                                        </div>
                                    ))}
                                </div>
                                {/* Payload Data */}
                                {selectedEvent.payload_data && (
                                    <div className="mt-4 pt-3 border-t border-white/5">
                                        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block mb-2">Payload Data</span>
                                        <pre className="text-[10px] font-mono text-gray-400 bg-white/[0.03] rounded-lg p-3 overflow-x-auto max-h-40 overflow-y-auto scrollbar-thin">
                                            {typeof selectedEvent.payload_data === 'string'
                                                ? selectedEvent.payload_data
                                                : JSON.stringify(selectedEvent.payload_data, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>

                <footer className="w-full text-center py-6 text-xs text-gray-600 relative z-10">
                    Vigilagent Intelligence Backbone © 2025-2026
                </footer>
            </div>
        </div>
    );
};

export default Dashboard;
