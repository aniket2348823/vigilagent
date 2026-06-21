import React, { useState, useEffect, useCallback, useRef } from 'react';
import Dashboard from './components/Dashboard';
import Scans from './components/Scans';
import NewScan from './components/NewScan';
import Settings from './components/Settings';
import Library from './components/Library';
import Login from './components/Login';
import SmoothScroll from './components/SmoothScroll';
import GlobalBackground from './components/GlobalBackground';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ui';
import { AnimatePresence } from 'framer-motion';
import { apiUrl } from './lib/api';

export default function App() {
    const [currentPage, setCurrentPage] = useState('dashboard');
    const [isLocked, setIsLocked] = useState(true); // Default to locked while checking
    const [checkingAuth, setCheckingAuth] = useState(true);

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
    useEffect(() => {
        const links = [
            "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap",
            "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap",
            "https://fonts.googleapis.com/icon?family=Material+Icons+Outlined",
            "https://fonts.googleapis.com/icon?family=Material+Icons",
            "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap",
            "https://fonts.googleapis.com/icon?family=Material+Icons+Round"
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
    useEffect(() => {
        checkAuth();
    }, []);

    const checkAuth = () => {
        fetch(apiUrl('/api/dashboard/auth/status'))
            .then(res => res.json())
            .then(data => {
                if (data['2fa_required'] && !data.authenticated) {
                    setIsLocked(true);
                } else {
                    setIsLocked(false);
                }
                setCheckingAuth(false);
            })
            .catch(err => {
                // console.error("Auth check failed", err);
                // FIX-002: Fail CLOSED on auth check failure
                setIsLocked(true);
                setCheckingAuth(false);
            });
    };

    // -- Navigation Helper --
    const navigate = useCallback((page) => {
        setCurrentPage(page);
        window.scrollTo(0, 0);
    }, []);

    if (checkingAuth) {
        return <div className="min-h-screen bg-[#06070B]"></div>;
    }

    if (isLocked) {
        return <Login onLoginSuccess={() => setIsLocked(false)} />;
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

                    {/* Render the specific page component based on state */}
                    <AnimatePresence mode="wait">
                        {currentPage === 'dashboard' && (
                            <Dashboard
                                key="dashboard"
                                navigate={navigate}
                                persistentState={dashboardState}
                                setPersistentState={setDashboardStateStable}
                            />
                        )}
                        {currentPage === 'scans' && <Scans key="scans" navigate={navigate} />}
                        {currentPage === 'newscan' && <NewScan key="newscan" navigate={navigate} />}
                        {currentPage === 'settings' && <Settings key="settings" navigate={navigate} />}
                        {currentPage === 'library' && <Library key="library" navigate={navigate} />}
                    </AnimatePresence>
                </SmoothScroll>
            </ToastProvider>
        </ErrorBoundary>
    );
}
