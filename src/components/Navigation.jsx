import React, { useState } from 'react';
import { motion, LayoutGroup, AnimatePresence } from 'framer-motion';
import { LIQUID_SPRING } from '../lib/constants';

const Navigation = ({ navigate, activePage }) => {
    const [mobileOpen, setMobileOpen] = useState(false);

    const goTo = (page) => navigate(page);

    // Activate a clickable item on Enter or Space (matches native <button> behaviour
    // and makes the LayoutGroup-wrapped logo discoverable to keyboard users).
    const onActivateKey = (handler) => (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handler();
        }
    };

    return (
        <nav className="relative z-10 w-full pt-6 pb-2" aria-label="Primary">
            <div className="max-w-7xl mx-auto px-6 lg:px-8">
                <LayoutGroup>
                    <div className="flex items-center justify-between h-16">
                        {/* Logo Section — keyboard-accessible link to dashboard */}
                        <div
                            className="flex items-center gap-3 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded"
                            onClick={() => goTo('dashboard')}
                            onKeyDown={onActivateKey(() => goTo('dashboard'))}
                            role="link"
                            tabIndex={0}
                            aria-label="Vigilagent — go to dashboard"
                        >
                            <motion.div layout to="position" className="text-purple-400">
                                <span className="material-symbols-outlined text-2xl" aria-hidden="true">auto_awesome</span>
                            </motion.div>
                            {/* Enforce Space Grotesk specifically for the logo to maintain branding symmetry across all pages */}
                            <span className="font-medium text-lg text-white tracking-wide" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Vigilagent</span>
                        </div>

                        {/* Desktop Links */}
                        <div className="hidden md:flex items-center space-x-1" role="menubar">
                            {['dashboard', 'scans', 'vulnerabilities', 'library', 'settings'].map((page) => {
                                const isActive = activePage === page;
                                return (
                                    <div key={page} className="relative flex flex-col items-center">
                                        <button
                                            type="button"
                                            role="menuitem"
                                            onClick={() => goTo(page)}
                                            aria-current={isActive ? 'page' : undefined}
                                            aria-label={`Navigate to ${page}`}
                                            className={`${isActive ? 'text-white' : 'text-gray-400 hover:text-white'} px-4 py-2 text-sm font-medium transition-colors capitalize focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded`}
                                        >
                                            {page}
                                        </button>
                                        {isActive && (
                                            <motion.div
                                                layoutId="nav-pill"
                                                className="h-0.5 w-6 bg-[#8A2BE2] rounded-full shadow-[0_0_10px_#8A2BE2] mt-[-2px] absolute bottom-0"
                                                transition={LIQUID_SPRING}
                                                aria-hidden="true"
                                            />
                                        )}
                                    </div>
                                );
                            })}
                        </div>

                        {/* Icons + Mobile Hamburger */}
                        <div className="flex items-center gap-5">
                            <button
                                type="button"
                                aria-label="Notifications"
                                className="text-gray-400 hover:text-white transition-colors hidden md:block focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded"
                            >
                                <span className="material-symbols-outlined text-[22px]" aria-hidden="true">notifications</span>
                            </button>
                            <button
                                type="button"
                                aria-label="Account"
                                className="text-gray-400 hover:text-white transition-colors hidden md:block focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded"
                            >
                                <span className="material-symbols-outlined text-[22px]" aria-hidden="true">account_circle</span>
                            </button>
                            {/* Mobile hamburger */}
                            <button
                                type="button"
                                className="md:hidden text-gray-300 hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded"
                                onClick={() => setMobileOpen(prev => !prev)}
                                aria-label={mobileOpen ? 'Close mobile menu' : 'Open mobile menu'}
                                aria-expanded={mobileOpen}
                                aria-controls="mobile-nav-drawer"
                            >
                                <span className="material-symbols-outlined text-[26px]" aria-hidden="true">
                                    {mobileOpen ? 'close' : 'menu'}
                                </span>
                            </button>
                        </div>
                    </div>
                </LayoutGroup>

                {/* Mobile Drawer */}
                <AnimatePresence>
                    {mobileOpen && (
                        <motion.div
                            id="mobile-nav-drawer"
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: 0.2 }}
                            className="md:hidden overflow-hidden border-t border-white/10 mt-2"
                            role="menu"
                            aria-label="Mobile navigation"
                        >
                            <div className="flex flex-col py-3 gap-1">
                                {['dashboard', 'scans', 'vulnerabilities', 'library', 'settings'].map((page) => {
                                    const isActive = activePage === page;
                                    return (
                                        <button
                                            key={page}
                                            type="button"
                                            role="menuitem"
                                            onClick={() => { goTo(page); setMobileOpen(false); }}
                                            aria-current={isActive ? 'page' : undefined}
                                            aria-label={`Navigate to ${page}`}
                                            className={`${isActive ? 'text-white bg-purple-600/20' : 'text-gray-400 hover:text-white hover:bg-white/5'} px-4 py-3 text-sm font-medium transition-colors capitalize rounded-lg text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500`}
                                        >
                                            {page}
                                        </button>
                                    );
                                })}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </nav>
    );
};

export default Navigation;
