import React, { useState, useEffect } from 'react';
import Navigation from './Navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { LIQUID_SPRING } from '../lib/constants';
import { apiUrl, csrfFetch } from '../lib/api';

const Settings = ({ navigate }) => {
    const [toggles, setToggles] = useState({
        'email-alerts': true,
        'in-app': true,
        'weekly-reports': true,
        '2fa': false
    });
    const [isLoading, setIsLoading] = useState(false);

    // 2FA State
    const [qrCode, setQrCode] = useState(null);
    const [verifyCode, setVerifyCode] = useState('');
    const [show2FAModal, setShow2FAModal] = useState(false);

    // Fetch Settings on Load
    useEffect(() => {
        fetch(apiUrl('/api/dashboard/settings'))
            .then(res => res.json())
            .then(data => {
                if (data['2fa_enabled']) {
                    setToggles(prev => ({ ...prev, '2fa': true }));
                }
            })
            .catch(err => { /* settings fetch failed — user sees empty state */ });
    }, []);

    const handleToggle = async (id) => {
        if (id === '2fa') {
            if (!toggles['2fa']) {
                // User wants to ENABLE 2FA -> Show QR
                handleGenerate2FA();
            } else {
                // Disable 2FA — call backend to persist
                try {
                    const res = await csrfFetch(apiUrl('/api/dashboard/settings/2fa/disable'), { method: 'POST' });
                    if (res.ok) {
                        setToggles(prev => ({ ...prev, '2fa': false }));
                    } else {
                        alert('Failed to disable 2FA');
                    }
                } catch (e) {
                    // console.error('Error disabling 2FA:', e);
                    setToggles(prev => ({ ...prev, '2fa': false }));
                }
            }
        } else {
            setToggles(prev => ({
                ...prev,
                [id]: !prev[id]
            }));
        }
    };

    const handleGenerate2FA = async () => {
        setIsLoading(true);
        try {
            const res = await csrfFetch(apiUrl('/api/dashboard/settings/2fa/generate'), { method: 'POST' });
            const data = await res.json();
            setQrCode(data.qr_code);
            setShow2FAModal(true);
        } catch (e) {
            alert("Failed to generate 2FA QR Code");
        } finally {
            setIsLoading(false);
        }
    };

    const verify2FA = async () => {
        if (!verifyCode) return;
        setIsLoading(true);
        try {
            const res = await csrfFetch(apiUrl('/api/dashboard/settings/2fa/verify'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ totp_code: verifyCode })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                setToggles(prev => ({ ...prev, '2fa': true }));
                setShow2FAModal(false);
                setVerifyCode('');
                setQrCode(null);
                alert("2FA Secured. Agent Omega is watching.");
            } else {
                alert("Verification Failed: " + data.message);
            }
        } catch (e) {
            alert("Error verifying code");
        } finally {
            setIsLoading(false);
        }
    };

    const saveSettings = async () => {
        setIsLoading(true);
        try {
            const res = await csrfFetch(apiUrl('/api/dashboard/settings'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(toggles)
            });
            if (res.ok) {
                alert('Settings Updated');
            } else {
                alert('Failed to save settings');
            }
        } catch (e) {
            // console.error('Error saving settings:', e);
            alert('Error saving settings');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="font-[Inter] min-h-screen relative overflow-x-hidden flex flex-col" style={{ fontFamily: "'Inter', sans-serif" }}>
            {/* Background is now global */}
            <div className="noise-overlay"></div>

            <div className="relative z-10 flex flex-col min-h-screen">
                <Navigation navigate={navigate} activePage="settings" />

                <main className="relative z-10 flex-grow px-6 py-8 max-w-7xl mx-auto w-full">
                    <h1 className="text-3xl font-bold text-white mb-8">Settings</h1>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

                        {/* Account Settings */}
                        <motion.section
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ ...LIQUID_SPRING, delay: 0.1 }}
                            className="glass-panel-settings rounded-xl p-8 flex flex-col gap-6"
                        >
                            <h2 className="text-lg font-semibold text-gray-200">Account Settings</h2>
                            <div className="space-y-4">
                                <div className="flex flex-col gap-2">
                                    <label htmlFor="settings-username" className="text-xs text-gray-400 uppercase tracking-widest font-semibold pl-1">Username</label>
                                    <input id="settings-username" name="username" aria-label="Username" className="w-full bg-black/40 border border-white/10 focus:border-purple-500/50 rounded-lg px-4 py-3 text-gray-200 text-sm transition-all outline-none placeholder-gray-600" type="text" defaultValue="username" />
                                </div>
                                <div className="flex flex-col gap-2">
                                    <label htmlFor="settings-email" className="text-xs text-gray-400 uppercase tracking-widest font-semibold pl-1">Email</label>
                                    <input id="settings-email" name="email" aria-label="Email address" className="w-full bg-black/40 border border-white/10 focus:border-purple-500/50 rounded-lg px-4 py-3 text-gray-200 text-sm transition-all outline-none placeholder-gray-600" type="email" defaultValue="target.om@apluvi.com" />
                                </div>
                            </div>
                            <motion.button
                                whileHover={{ scale: 1.01 }}
                                whileTap={{ scale: 0.99 }}
                                className="w-full bg-purple-600 hover:bg-purple-500 text-white font-medium py-3 rounded-lg shadow-[0_0_20px_rgba(139,92,246,0.2)] transition-all text-sm mt-2"
                            >
                                Save Account Info
                            </motion.button>
                        </motion.section>

                        {/* Notifications */}
                        <motion.section
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ ...LIQUID_SPRING, delay: 0.2 }}
                            className="glass-panel-settings rounded-xl p-8 flex flex-col gap-6"
                        >
                            <h2 className="text-lg font-semibold text-gray-200">Notifications</h2>
                            <div className="flex flex-col gap-6 mt-2">
                                {[
                                    { id: 'email-alerts', label: 'Email Alerts' },
                                    { id: 'in-app', label: 'In-App Notifications' },
                                    { id: 'weekly-reports', label: 'Weekly Reports' }
                                ].map(item => (
                                    <div key={item.id} className="flex items-center justify-between pb-4 border-b border-white/5">
                                        <span id={`toggle-label-${item.id}`} className="text-sm text-gray-300 font-light">{item.label}</span>
                                        <div className="relative inline-block w-10 h-6 align-middle select-none transition duration-200 ease-in">
                                            <button
                                                type="button"
                                                role="switch"
                                                aria-checked={!!toggles[item.id]}
                                                aria-labelledby={`toggle-label-${item.id}`}
                                                onClick={() => handleToggle(item.id)}
                                                className={`w-10 h-6 rounded-full cursor-pointer transition-colors duration-300 relative focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 ${toggles[item.id] ? 'bg-purple-600' : 'bg-gray-700'}`}
                                            >
                                                <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform duration-300 ${toggles[item.id] ? 'translate-x-4' : 'translate-x-0'}`} aria-hidden="true"></span>
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.section>

                        {/* Security Section (Renamed from API & Security) */}
                        <motion.section
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ ...LIQUID_SPRING, delay: 0.3 }}
                            className="glass-panel-settings rounded-xl p-8 flex flex-col gap-6 lg:col-span-2"
                        >
                            <h2 className="text-lg font-semibold text-gray-200">Security</h2>

                            {/* Removed Gemini API Key Section */}

                            <div className="flex items-center justify-between pt-2">
                                <div>
                                    <span id="toggle-label-2fa" className="text-sm text-gray-200 block mb-1">Two-Factor Authentication (2FA)</span>
                                    <span className="text-xs text-gray-500 font-light">Secure your account with TOTP (Google Authenticator).</span>
                                </div>
                                <div className="relative inline-block w-10 h-6 align-middle select-none transition duration-200 ease-in">
                                    <button
                                        type="button"
                                        role="switch"
                                        aria-checked={!!toggles['2fa']}
                                        aria-labelledby="toggle-label-2fa"
                                        onClick={() => handleToggle('2fa')}
                                        className={`w-10 h-6 rounded-full cursor-pointer transition-colors duration-300 relative focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 ${toggles['2fa'] ? 'bg-purple-600' : 'bg-gray-700'}`}
                                    >
                                        <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform duration-300 ${toggles['2fa'] ? 'translate-x-4' : 'translate-x-0'}`} aria-hidden="true"></span>
                                    </button>
                                </div>
                            </div>
                        </motion.section>
                    </div>
                </main>

                <footer className="relative z-10 w-full py-6 text-center">
                    <p className="text-xs text-gray-600 font-light tracking-wide">VigilAgent API Endpoint Scanning System</p>
                </footer>
            </div>

            {/* 2FA Modal */}
            <AnimatePresence>
                {show2FAModal && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm px-4"
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="settings-2fa-title"
                            className="bg-[#0f1115] border border-purple-500/30 rounded-xl p-8 max-w-md w-full shadow-[0_0_50px_rgba(139,92,246,0.1)] relative"
                        >
                            <button
                                onClick={() => setShow2FAModal(false)}
                                aria-label="Close 2FA setup dialog"
                                className="absolute top-4 right-4 text-gray-500 hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 rounded"
                            >
                                ✕
                            </button>

                            <h3 id="settings-2fa-title" className="text-xl font-bold text-white mb-2 text-center">Setup 2FA</h3>
                            <p className="text-sm text-gray-400 text-center mb-6">Scan this QR code with your authenticator app.</p>

                            <div className="flex justify-center mb-6 bg-white p-4 rounded-lg w-fit mx-auto">
                                {qrCode && <img src={qrCode} alt="Scan to register VigilAgent in your authenticator app" className="w-48 h-48" />}
                            </div>

                            <div className="flex flex-col gap-3">
                                <label htmlFor="settings-2fa-code" className="text-xs text-gray-400 uppercase tracking-widest font-semibold pl-1">Verification Code</label>
                                <div className="flex gap-2">
                                    <input
                                        id="settings-2fa-code"
                                        name="totp_code"
                                        type="text"
                                        inputMode="numeric"
                                        pattern="[0-9]*"
                                        autoComplete="one-time-code"
                                        aria-label="Six-digit verification code"
                                        value={verifyCode}
                                        onChange={(e) => setVerifyCode(e.target.value)}
                                        placeholder="000000"
                                        maxLength={6}
                                        className="w-full bg-black/50 border border-white/20 focus:border-purple-500 rounded-lg px-4 py-3 text-center text-xl tracking-[0.5em] font-mono text-white transition-all outline-none"
                                    />
                                </div>
                                <button
                                    onClick={verify2FA}
                                    disabled={isLoading || verifyCode.length < 6}
                                    className="w-full mt-4 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-3 rounded-lg shadow-lg transition-all"
                                >
                                    {isLoading ? 'Verifying...' : 'Verify & Enable'}
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default Settings;
