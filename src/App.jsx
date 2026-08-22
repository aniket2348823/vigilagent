import React, { useState, useEffect, useCallback, useRef, lazy, Suspense } from 'react';
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import SmoothScroll from './components/SmoothScroll';
import GlobalBackground from './components/GlobalBackground';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ui';
import { AnimatePresence, motion } from 'framer-motion';
import { apiUrl } from './lib/api';

// Secondary pages are lazy-loaded so the initial Dashboard bundle stays small;
// each chunk is cached by the browser after the first visit. The Suspense
// fallback matches the app background so navigation never flashes white.
const Scans = lazy(() => import('./components/Scans'));
const NewScan = lazy(() => import('./components/NewScan'));
const Settings = lazy(() => import('./components/Settings'));
const Library = lazy(() => import('./components/Library'));
const Vulnerabilities = lazy(() => import('./components/Vulnerabilities'));

// Preload every secondary page chunk immediately (fire-and-forget). Without
// this, the first switch to a page whose chunk isn't in the module cache yet
// suspends React and shows the loading fallback mid-transition — the "loading
// screen" flash between tabs. Once these resolve, lazy() reads the modules
// from the cache synchronously, so tab switches are a pure fade, never a
// Suspense fallback. The small extra fetch happens in parallel at startup and
// keeps the initial render bundle unchanged.
[
    import('./components/Scans'),
    import('./components/NewScan'),
    import('./components/Settings'),
    import('./components/Library'),
    import('./components/Vulnerabilities'),
].forEach((p) => p.catch(() => { /* chunk load failure — lazy() will retry on navigation */ }));

export default function App() {
    const [currentPage, setCurrentPage] = useState('dashboard');
    // Auth gate: 'checking' | 'ok' | 'locked'. The 'checking' state renders a
    // branded loading screen (NOT a black void) while the session check runs,
    // with a hard timeout so a slow or down backend can never leave the app
    // stuck on a blank page.
    const [authState, setAuthState] = useState('checking');

    // [V7] Persistent Dashboard State (Lifted from components/Dashboard.jsx)
    const [dashboardState, setDashboardState] = useState({
        metrics: {
            total_scans: 0,
            active_scans: 0,
            vulnerabilities: 0,
            critical: 0
        },
        graph_data: [],
        threat_feed: [],
        recent_activity: [],
        activeScanId: null, // Tracks currently focused scan for isolation
        isCooldown: false,  // Dashboard cleanup cooldown
        isStartDelay: false // Suppression delay for new scans
    });

    // -- Font & Icon Loader --
    // One combined CSS2 request (was 6 separate stylesheets) — Google Fonts
    // supports multiple families per URL. Material Icons (regular) is kept for
    // Login's icon; Outlined/Round variants are unused and were dropped.
    useEffect(() => {
        const links = [
            "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&family=Material+Icons&family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
        ];

        links.forEach(href => {
            if (!document.querySelector(`link[href="${href}"]`)) {
                const link = document.createElement('link');
                link.href = href;
                link.rel = 'stylesheet';
                document.head.appendChild(link);
            }
        });
    }, []);

    // -- Stable setter ref to avoid setState-during-render warning --
    // Dashboard calls setPersistentState from effects; wrapping in a ref
    // ensures the setter identity never changes and avoids the React warning
    // "Cannot update a component (Dashboard) while rendering a different component (App)".
    const dashboardStateRef = useRef(dashboardState);
    dashboardStateRef.current = dashboardState;

    const setDashboardStateStable = useCallback((valueOrFn) => {
        setDashboardState(prev => {
            const next = typeof valueOrFn === 'function' ? valueOrFn(prev) : valueOrFn;
            return next;
        });
    }, []);

    // -- Auth Check --
    // LOAD-TIME ROOT-CAUSE FIX: the old gate rendered an empty <div> until
    // /api/dashboard/auth/status returned, with NO timeout — a cold or slow
    // backend left the app as a black void (and with the backend down, a
    // long hang before the Login fallback). Now the check runs with a 6s
    // AbortController ceiling, the branded loading screen shows instantly,
    // and the result resolves to a definitive state in bounded time.
    // Fail-CLOSED on error/timeout preserves FIX-002 semantics.
    const AUTH_CHECK_TIMEOUT_MS = 6000;

    useEffect(() => {
        checkAuth();
    }, []);

    const checkAuth = () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), AUTH_CHECK_TIMEOUT_MS);
        fetch(apiUrl('/api/dashboard/auth/status'), { signal: controller.signal })
            .then(res => res.json())
            .then(data => {
                if (data['2fa_required'] && !data.authenticated) {
                    setAuthState('locked');
                } else {
                    setAuthState('ok');
                }
            })
            .catch(() => {
                // FIX-002: Fail CLOSED on auth check failure or timeout
                setAuthState('locked');
            })
            .finally(() => clearTimeout(timer));
    };

    // -- Navigation Helper --
    const navigate = useCallback((page) => {
        setCurrentPage(page);
        window.scrollTo(0, 0);
    }, []);

    if (authState === 'locked') {
        return <Login onLoginSuccess={() => setAuthState('ok')} />;
    }

    if (authState === 'checking') {
        // Instant visual feedback while the session check runs (replaces the
        // blank black <div>). Resolves to the dashboard or login in <= 6s.
        return (
            <div className="min-h-screen bg-[#06070B] flex items-center justify-center">
                <div className="text-center">
                    <div
                        className="mx-auto mb-4 h-8 w-8 rounded-full border-2 border-purple-500 border-t-transparent"
                        style={{ animation: 'spin 0.8s linear infinite' }}
                        role="status"
                        aria-label="Loading"
                    ></div>
                    <p className="text-sm text-gray-400">Vigilagent · establishing secure session…</p>
                </div>
            </div>
        );
    }

    return (
        <ErrorBoundary>
            <ToastProvider>
                <SmoothScroll>
                    {/* Transparent Star Overlay */}
                    <GlobalBackground />

                    {/* Shared Background for all pages to ensure continuity */}
                    <div className="nebula-background"></div>

                    {/* All CSS is now in index.css — no inline <style> block */}

                    {/* Render the specific page component based on state.
                        Each page is wrapped in a motion transition layer so
                        AnimatePresence can cross-fade — without it the pages'
                        plain roots mount/unmount instantly and the dark theme
                        flashes a full black screen between tabs. */}
                    <Suspense fallback={
                        <div className="min-h-screen bg-[#06070B] flex items-center justify-center">
                            <div className="text-center">
                                <div
                                    className="mx-auto mb-4 h-8 w-8 rounded-full border-2 border-purple-500 border-t-transparent"
                                    style={{ animation: 'spin 0.8s linear infinite' }}
                                    role="status"
                                    aria-label="Loading"
                                ></div>
                                <p className="text-sm text-gray-400">Vigilagent · loading…</p>
                            </div>
                        </div>
                    }>
                        <AnimatePresence mode="wait" initial={false}>
                            <motion.div
                                key={currentPage}
                                initial={{ opacity: 0, y: 14 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -14 }}
                                transition={{ duration: 0.22, ease: 'easeOut' }}
                            >
                                {currentPage === 'dashboard' && (
                                    <Dashboard
                                        navigate={navigate}
                                        persistentState={dashboardState}
                                        setPersistentState={setDashboardStateStable}
                                    />
                                )}
                                {currentPage === 'scans' && <Scans navigate={navigate} />}
                                {currentPage === 'newscan' && <NewScan navigate={navigate} />}
                                {currentPage === 'vulnerabilities' && <Vulnerabilities navigate={navigate} />}
                                {currentPage === 'settings' && <Settings navigate={navigate} />}
                                {currentPage === 'library' && <Library navigate={navigate} />}
                            </motion.div>
                        </AnimatePresence>
                    </Suspense>
                </SmoothScroll>
            </ToastProvider>
        </ErrorBoundary>
    );
}
