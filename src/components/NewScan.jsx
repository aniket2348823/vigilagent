import React, { useState, useEffect, useRef } from 'react';
import Navigation from './Navigation';
import AnimationWrapper from './AnimationWrapper';
import { motion } from 'framer-motion';
import { apiUrl, createScan } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';

const NewScan = ({ navigate }) => {
    // ... [STATE] ...
    const [authType, setAuthType] = useState('Bearer');
    const [activeScanModules, setActiveScanModules] = useState([
        { name: 'The Tycoon', desc: 'Financial logic flaws & parameter tampering', selected: true },
        { name: 'The Escalator', desc: 'Mass Assignment & Privilege Escalation', selected: true },
        { name: 'The Skipper', desc: 'Workflow bypass & multi-step sequence skipping', selected: true },
        { name: 'Doppelganger (IDOR)', desc: 'Insecure Direct Object Reference detection', selected: false },
        { name: 'Chronomancer', desc: 'Race Condition testing for transactional APIs', selected: false },
        { name: 'SQL Injection Probe', desc: 'Deep injection testing for SQL, NoSQL, GraphQL', selected: false },
        { name: 'JWT Token Cracker', desc: 'Cryptographic analysis of JSON Web Tokens', selected: false },
        { name: 'API Fuzzer (REST)', desc: 'High-velocity fuzzing for RESTful endpoints', selected: false },
        { name: 'Auth Bypass Tester', desc: 'Systematic testing of authentication gates', selected: false },
        { name: 'Hybrid DOM Extraction', desc: 'Headless browser execution via PinchTab Engine', selected: false }
    ]);
    const [isConnected, setIsConnected] = useState(false);
    const localConnectedRef = useRef(false);
    const [requestRate, setRequestRate] = useState(450);
    const [concurrency, setConcurrency] = useState(50);
    const [estimatedDuration, setEstimatedDuration] = useState(45);

    // [NEW] Interception Filters
    const [interceptionFilters, setInterceptionFilters] = useState([
        { name: 'Financial Logic', desc: 'Financial logic flaws & tampering', selected: true },
        { name: 'Privilege Escalation', desc: 'Mass Assignment & role elevation', selected: true },
        { name: 'PII Data', desc: 'Detects exposed Personally Identifiable Information (PII) in API responses', selected: true },
        { name: 'Workflow Integrity', desc: 'Workflow bypass & sequence skipping', selected: true },
        { name: 'Object References (IDOR)', desc: 'Insecure resource access & enumeration', selected: false },
        { name: 'Concurrency & Timing', desc: 'Race conditions & timing attacks', selected: false },
        { name: 'Injection & Fuzzing', desc: 'Injection vectors & input fuzzing', selected: false },
        { name: 'Authentication Gates', desc: 'Auth bypass & token tampering', selected: false }
    ]);

    // Backend Integration State
    const [targets, setTargets] = useState("");
    const [authContent, setAuthContent] = useState("");
    const [scanTitle, setScanTitle] = useState("Ultimate Precision Blueprint");
    const { subscribe } = useWebSocket();

    const [isExtensionEnabled, setIsExtensionEnabled] = useState(false);
    const [isLaunching, setIsLaunching] = useState(false);
    const [launchError, setLaunchError] = useState(null);
    const [launchedScanId, setLaunchedScanId] = useState(null);

    // --- Extension Handshake ---
    useEffect(() => {
        if (!isExtensionEnabled) {
            setIsConnected(false);
            localConnectedRef.current = false;
            return;
        }

        const handleMessage = (event) => {
            if (event.data?.type === 'VIGILAGENT_EXTENSION_CONNECTED') {
                setIsConnected(true);
                localConnectedRef.current = true;
            }
        };

        const handleCustomEvent = () => {
            setIsConnected(true);
            localConnectedRef.current = true;
        };

        window.addEventListener('message', handleMessage);
        document.addEventListener('VIGILAGENT_EXTENSION_HEARTBEAT', handleCustomEvent);

        // Backend health-poll fallback: the Chrome extension sends traffic to
        // the backend via HTTP (not postMessage), and the HUD content script
        // skips injection on localhost.  Poll /api/health to detect the spy.
        const pollId = setInterval(async () => {
            if (localConnectedRef.current) return; // already connected
            try {
                const res = await fetch(apiUrl('/api/health'), { cache: 'no-store' });
                if (res.ok) {
                    const data = await res.json();
                    if (data.spy_connected || data.extensions_active > 0) {
                        setIsConnected(true);
                        localConnectedRef.current = true;
                    }
                }
            } catch { /* backend offline, ignore */ }
        }, 3000);

        return () => {
            window.removeEventListener('message', handleMessage);
            document.removeEventListener('VIGILAGENT_EXTENSION_HEARTBEAT', handleCustomEvent);
            clearInterval(pollId);
        };
    }, [isExtensionEnabled]);

    const isExtensionEnabledRef = useRef(isExtensionEnabled);
    useEffect(() => { isExtensionEnabledRef.current = isExtensionEnabled; }, [isExtensionEnabled]);

    // --- Shared WebSocket Subscription (replaces per-page connection) ---
    useEffect(() => {
        const unsub = subscribe((data) => {
            if (data.type === 'RECON_PACKET') {
                const url = data.payload.url || "";
                const isBackendTraffic = url.includes('127.0.0.1:8000') ||
                    url.includes('localhost:8000') ||
                    url.includes('127.0.0.1:5173') ||
                    url.includes('localhost:5173') ||
                    url.includes('/api/recon') ||
                    url.includes('/stream');
                if (!isBackendTraffic) {
                    if (isExtensionEnabledRef.current && !localConnectedRef.current) {
                        setIsConnected(true);
                        localConnectedRef.current = true;
                    }
                }
            } else if (data.type === 'ATTACK_HIT') {
                // Attack hit received
            } else if (data.type === 'SPY_STATUS') {
                if (isExtensionEnabledRef.current) {
                    if (data.payload.connected) {
                        setIsConnected(true);
                    } else if (!localConnectedRef.current) {
                        setIsConnected(false);
                    }
                }
            }
        });

        return () => { unsub(); };
    }, [subscribe]);

    // Recalculate duration whenever relevant state changes
    useEffect(() => {
        const durationSeconds = 600;
        setEstimatedDuration(Math.ceil(durationSeconds / 60));
    }, [activeScanModules]);


    const toggleModule = (index) => {
        const updated = [...activeScanModules];
        updated[index].selected = !updated[index].selected;
        setActiveScanModules(updated);
    };

    const toggleSwitch = (e, index) => {
        e.stopPropagation();
        const updated = [...activeScanModules];
        updated[index].switchState = !updated[index].switchState;
        setActiveScanModules(updated);
    };

    const getAuthBtnClass = (type) =>
        `rounded-md py-1.5 text-sm font-medium transition-all ${authType === type
            ? 'bg-[#9b61ff] text-white text-glow shadow-[0_0_10px_rgba(155,97,255,0.4)]'
            : 'text-gray-400 hover:text-white hover:bg-white/5'
        }`;

    const getPlaceholder = () => {
        if (authType === 'API Key') return 'Enter X-API-KEY or similar...';
        if (authType === 'Basic') return 'username:password base64 string...';
        return 'Paste your Bearer token...';
    };

    // --- Launch Action ---
    const handleLaunch = async () => {
        setLaunchError(null);

        // Trim whitespace and pull the first non-empty target line.
        const targetUrl = (targets.split('\n').find((line) => line.trim().length > 0) || '').trim();
        if (!targetUrl) {
            setLaunchError("Please specify a target URL.");
            return;
        }

        // Must start with http:// or https:// (per spec) before deeper URL parsing.
        if (!/^https?:\/\//i.test(targetUrl)) {
            setLaunchError("Target URL must start with http:// or https://");
            return;
        }

        // URL validation — prevent invalid targets from reaching backend
        try {
            const parsed = new URL(targetUrl);
            if (!['http:', 'https:'].includes(parsed.protocol)) {
                setLaunchError("Invalid protocol. Only http:// and https:// targets are supported.");
                return;
            }
            if (!parsed.hostname || parsed.hostname.length < 3) {
                setLaunchError("Invalid hostname. Please enter a valid domain or IP address.");
                return;
            }
        } catch {
            setLaunchError("Invalid URL format. Please enter a valid URL (e.g., https://example.com).");
            return;
        }

        const selectedModules = activeScanModules.filter((m) => m.selected).map((m) => m.name);

        setIsLaunching(true);

        try {
            const result = await createScan({
                target_url: targetUrl,
                // AGGRESSIVE = full recon power: every applicable arsenal tool
                // runs (all 39 when available) and every selected attack module
                // fires against the recon-discovered endpoints.
                mode: "AGGRESSIVE",
                modules: selectedModules,
            });

            const scanId = result?.scan_id || null;
            setLaunchedScanId(scanId);

            // Brief pause so the backend can register the new scan record before the
            // Scans page re-fetches /api/dashboard/scans.
            await new Promise((resolve) => setTimeout(resolve, 800));
            navigate('scans');
        } catch (err) {
            // console.error("Launch failed:", err);
            const msg = err && err.message ? err.message : 'Unknown error';
            const friendly = msg.includes('Failed to reach backend')
                ? "Backend is offline. Please ensure the Vigilagent Terminal is running on port 8000."
                : msg;
            setLaunchError(friendly);
        } finally {
            setIsLaunching(false);
        }
    };

    return (
        <AnimationWrapper className="text-white min-h-screen w-full overflow-x-hidden relative" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            {/* Background is now global */}

            <div className="relative z-10 flex flex-col min-h-screen">

                <Navigation navigate={navigate} activePage="scans" />

                {/* Main Content Wrapper */}
                <div className="flex-grow mx-auto max-w-7xl px-6 lg:px-8 w-full">
                    <div className="my-12 flex flex-wrap items-center justify-between gap-6">
                        <div>
                            <h2 className="text-4xl font-bold tracking-tighter">New Scan Configuration</h2>
                            <p className="mt-2 text-base text-gray-300">Configure target scope, modules, and performance parameters for a new security assessment.</p>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                            <motion.button
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={handleLaunch}
                                disabled={isLaunching}
                                className={`glow-element flex h-11 items-center justify-center gap-2 rounded-lg bg-[#9b61ff] px-5 text-base font-semibold text-white transition-opacity hover:opacity-90 ${isLaunching ? 'opacity-70 cursor-wait' : ''}`}
                            >
                                <span className="material-symbols-outlined text-xl">rocket_launch</span>
                                {isLaunching ? 'Launching...' : 'Launch Scan'}
                            </motion.button>
                            {launchError && (
                                <div
                                    role="alert"
                                    className="max-w-sm rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300"
                                >
                                    {launchError}
                                </div>
                            )}
                            {launchedScanId && !launchError && (
                                <div className="max-w-sm rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-xs text-green-300">
                                    Scan launched: <span className="font-mono">{launchedScanId}</span>
                                </div>
                            )}
                        </div>
                    </div>

                    <main className="grid grid-cols-1 gap-8 lg:grid-cols-3">
                        <div className="flex flex-col gap-8 lg:col-span-2">
                            <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
                                <div className="glassmorphism-card rounded-xl p-6">
                                    <div className="mb-4 flex items-center gap-3">
                                        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/20"><span className="material-symbols-outlined text-gray-400">settings</span></div>
                                        <h3 className="text-lg font-semibold">General Information</h3>
                                    </div>
                                    <div className="space-y-4">
                                        <label className="block">
                                            <span className="text-sm font-medium text-gray-300">SCAN TITLE</span>
                                            <input
                                                className="relative z-10 mt-1 block w-full rounded-lg border-0 bg-[#3E425E]/70 p-3 text-white placeholder-gray-400 focus:ring-2 focus:ring-[#9b61ff]"
                                                placeholder="Ultimate Precision Blueprint"
                                                type="text"
                                                value={scanTitle}
                                                onChange={(e) => setScanTitle(e.target.value)}
                                            />
                                        </label>
                                        <button className="w-full rounded-lg bg-[#3E425E]/70 py-2.5 text-sm font-medium transition-colors hover:bg-[#3E425E]/90">LOAD PRESET</button>
                                    </div>
                                </div>
                                <div className="glassmorphism-card rounded-xl p-6">
                                    <div className="mb-4 flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/20"><span className="material-symbols-outlined text-gray-400">target</span></div>
                                            <h3 className="text-lg font-semibold">Target Scope</h3>
                                        </div>
                                    </div>
                                    <textarea
                                        className="relative z-10 block w-full rounded-lg border-0 bg-[#3E425E]/70 p-3 text-white placeholder-gray-400 focus:ring-2 focus:ring-[#9b61ff]"
                                        placeholder="Enter IPs, Domains, or CIDR blocks (one per line)..."
                                        rows="4"
                                        value={targets || ""}
                                        onChange={(e) => setTargets(e.target.value)}
                                    ></textarea>
                                    <div className="mt-3 flex items-center justify-between">
                                        <span className="rounded-md bg-[#3E425E]/70 px-2 py-1 text-xs font-medium">{targets.split('\n').filter(t => t.trim()).length} targets defined</span>
                                    </div>
                                </div>
                            </div>
                            <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
                                <div className="space-y-4">
                                    <h4 className="text-xl font-semibold">Interception Filters</h4>
                                    <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2">
                                        {interceptionFilters.map((item, i) => (
                                            <div key={i} className="glassmorphism-card flex items-start gap-4 rounded-xl p-4">
                                                <input
                                                    checked={item.selected}
                                                    onChange={() => {
                                                        const updated = [...interceptionFilters];
                                                        updated[i].selected = !updated[i].selected;
                                                        setInterceptionFilters(updated);
                                                    }}
                                                    className="mt-1 h-5 w-5 shrink-0 appearance-none rounded-md border-2 border-gray-500 bg-transparent checked:border-[#9b61ff] checked:bg-[#9b61ff] cursor-pointer"
                                                    type="checkbox"
                                                />
                                                <div><h5 className="font-semibold">{item.name}</h5><p className="text-sm text-gray-400">{item.desc}</p></div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <h4 className="text-xl font-semibold">Logic Attack Vectors</h4>
                                    <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2">
                                        {activeScanModules.map((item, i) => (
                                            <div key={i} className="glassmorphism-card flex items-start gap-4 rounded-xl p-4">
                                                <input
                                                    checked={item.selected}
                                                    onChange={() => toggleModule(i)}
                                                    className="mt-1 h-5 w-5 shrink-0 appearance-none rounded-md border-2 border-gray-500 bg-transparent checked:border-[#9b61ff] checked:bg-[#9b61ff] cursor-pointer"
                                                    type="checkbox"
                                                />
                                                <div className="flex-grow">
                                                    <div className="flex items-center justify-between">
                                                        <h5 className="font-semibold">{item.name}</h5>
                                                        {item.hasSwitch && (
                                                            <div className="relative inline-block w-8 h-4 align-middle select-none transition duration-200 ease-in ml-2">
                                                                <div
                                                                    onClick={(e) => toggleSwitch(e, i)}
                                                                    className={`w-8 h-4 rounded-full cursor-pointer transition-colors duration-300 ${item.switchState ? 'bg-[#8B5CF6]' : 'bg-gray-600'}`}
                                                                >
                                                                    <div className={`absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full transition-transform duration-300 ${item.switchState ? 'translate-x-4' : 'translate-x-0'}`}></div>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <p className="text-sm text-gray-400">{item.desc}</p>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                            {/* Interception */}
                            <div className="col-span-1 md:col-span-2">
                                <div className="glassmorphism-card rounded-xl p-6">
                                    <div className="mb-4 flex items-center gap-3">
                                        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/20"><span className="material-symbols-outlined text-gray-400 text-sm">wifi_tethering</span></div>
                                        <h3 className="text-lg font-semibold">Interception Source</h3>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <div className="flex flex-1 items-center justify-between rounded-lg bg-[#3E425E]/70 px-4 py-3 cursor-default">
                                            <div className="flex items-center gap-3">
                                                <div className="relative inline-block w-10 h-6 align-middle select-none transition duration-200 ease-in">
                                                    <div
                                                        onClick={() => setIsExtensionEnabled(!isExtensionEnabled)}
                                                        className={`w-10 h-6 rounded-full cursor-pointer transition-colors duration-300 ${isExtensionEnabled ? 'bg-[#8B5CF6]' : 'bg-gray-600'}`}
                                                    >
                                                        <div className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform duration-300 ${isExtensionEnabled ? 'translate-x-4' : 'translate-x-0'}`}></div>
                                                    </div>
                                                </div>
                                                <span className="text-sm font-medium text-white">Live Browser Feed (Chrome Ext)</span>
                                            </div>

                                            <div className="flex items-center gap-2">
                                                <span className={`text-sm font-medium ${isConnected ? 'text-green-400' : 'text-red-400'}`}>
                                                    {isExtensionEnabled ? (isConnected ? 'Connected' : 'Waiting...') : 'Disabled'}
                                                </span>
                                                <span className={`h-2 w-2 rounded-full shadow-[0_0_8px_rgba(0,0,0,0.6)] ${isExtensionEnabled && isConnected ? 'bg-green-400 shadow-[0_0_8px_rgba(74,222,128,0.6)]' : 'bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.6)]'}`}></span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="flex flex-col gap-8 lg:col-span-1">
                            <div className="glassmorphism-card rounded-xl p-6">
                                <div className="mb-4 flex items-center gap-3">
                                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/20"><span className="material-symbols-outlined text-[#9b61ff] icon-glow">speed</span></div>
                                    <h3 className="text-lg font-semibold">Performance</h3>
                                </div>
                                <div className="space-y-6">
                                    <div className="space-y-2">
                                        <div className="flex justify-between text-sm"><span>Request Rate</span> <span className="rounded-md bg-[#3E425E]/70 px-2 py-0.5 text-xs font-medium">{requestRate} req/s</span></div>
                                        <input className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-[#3E425E]/70 accent-[#9b61ff]" max="1000" min="0" type="range" value={requestRate} onChange={(e) => setRequestRate(e.target.value)} />
                                    </div>
                                    <div className="space-y-2">
                                        <div className="flex justify-between text-sm"><span>Concurrency</span> <span className="rounded-md bg-[#3E425E]/70 px-2 py-0.5 text-xs font-medium">{concurrency} threads</span></div>
                                        <input className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-[#3E425E]/70 accent-[#9b61ff]" max="100" min="1" type="range" value={concurrency} onChange={(e) => setConcurrency(e.target.value)} />
                                    </div>
                                </div>
                            </div>

                            <div className="glassmorphism-card rounded-xl p-6">
                                <div className="mb-4 flex items-center gap-3">
                                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/20"><span className="material-symbols-outlined text-[#9b61ff] icon-glow">key</span></div>
                                    <h3 className="text-lg font-semibold">Authentication</h3>
                                </div>
                                <div className="grid grid-cols-3 gap-1 rounded-lg bg-[#3E425E]/70 p-1">
                                    <button onClick={() => setAuthType('Bearer')} className={getAuthBtnClass('Bearer')}>Bearer</button>
                                    <button onClick={() => setAuthType('API Key')} className={getAuthBtnClass('API Key')}>API Key</button>
                                    <button onClick={() => setAuthType('Basic')} className={getAuthBtnClass('Basic')}>Basic</button>
                                </div>
                                <textarea
                                    className="mt-4 block w-full rounded-lg border-0 bg-[#3E425E]/70 p-3 text-white placeholder-gray-400 focus:ring-2 focus:ring-[#9b61ff]"
                                    placeholder={getPlaceholder()}
                                    rows="3"
                                    value={authContent}
                                    onChange={(e) => setAuthContent(e.target.value)}
                                ></textarea>
                            </div>

                            <div className="glassmorphism-card rounded-xl p-6 text-center">
                                <p className="text-lg">ESTIMATED DURATION</p>
                                <p className="my-2 text-4xl font-bold">~<span className="text-[#9b61ff] text-glow">{estimatedDuration}</span> minutes</p>
                                <div className="my-4 h-2 w-full rounded-full bg-[#3E425E]/70">
                                    <div className="h-2 w-3/4 rounded-full bg-[#9b61ff] glow-element"></div>
                                </div>
                                <p className="text-sm text-gray-400">Based on {concurrency} threads scanning Active Modules.</p>
                            </div>
                        </div>
                    </main>

                    <footer className="py-8 text-center text-sm text-gray-500">
                        Vigilagent Intelligence Backbone © 2024
                    </footer>
                </div>
            </div>
        </AnimationWrapper>
    );
};

export default NewScan;
