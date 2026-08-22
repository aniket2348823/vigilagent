import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

/**
 * Dashboard health indicator showing real-time connection status.
 * Tracks WebSocket health, last event timestamp, and overall system status.
 */
export default React.memo(function HealthIndicator({ scanActive, feedLength, rps }) {
    const [wsStatus, setWsStatus] = useState('connecting');
    const [lastEventAge, setLastEventAge] = useState(null);
    const lastEventTimeRef = useRef(null);
    const lastAgeRef = useRef(null); // Last rendered age — skip identical ticks

    // Track last event time from threat_feed length changes
    useEffect(() => {
        if (feedLength > 0) {
            lastEventTimeRef.current = Date.now();
            setWsStatus('connected');
        }
    }, [feedLength]);

    // Poll last event age every second
    useEffect(() => {
        const interval = setInterval(() => {
            if (lastEventTimeRef.current) {
                const age = Math.floor((Date.now() - lastEventTimeRef.current) / 1000);
                // setState with an unchanged value still re-renders the component;
                // skip identical ticks so an idle dashboard doesn't churn every second.
                if (age !== lastAgeRef.current) {
                    lastAgeRef.current = age;
                    setLastEventAge(age);
                    // If no events for 30s+ during active scan, show warning
                    if (age > 30 && scanActive) {
                        setWsStatus('stale');
                    } else if (age > 60) {
                        setWsStatus('idle');
                    }
                }
            }
        }, 1000);
        return () => clearInterval(interval);
    }, [scanActive]);

    // Reset to connecting on scan start
    useEffect(() => {
        if (scanActive) {
            setWsStatus('connected');
            lastEventTimeRef.current = Date.now();
        }
    }, [scanActive]);

    const statusConfig = {
        connected: { color: 'bg-green-400', text: 'text-green-400', label: 'LIVE', shadow: 'shadow-[0_0_6px_rgba(74,222,128,0.6)]' },
        stale: { color: 'bg-yellow-400', text: 'text-yellow-400', label: 'STALE', shadow: 'shadow-[0_0_6px_rgba(250,204,21,0.4)]' },
        idle: { color: 'bg-gray-500', text: 'text-gray-500', label: 'IDLE', shadow: '' },
        connecting: { color: 'bg-blue-400', text: 'text-blue-400', label: 'CONNECTING', shadow: '' },
    };

    const status = statusConfig[wsStatus] || statusConfig.idle;

    const formatAge = (secs) => {
        if (secs == null) return '—';
        if (secs < 60) return `${secs}s ago`;
        return `${Math.floor(secs / 60)}m ${secs % 60}s ago`;
    };

    const feedCount = feedLength || 0;

    return (
        <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-4 px-4 py-2 glass-panel-dash rounded-xl"
        >
            {/* WebSocket Status */}
            <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${status.color} ${status.shadow} ${wsStatus === 'connected' ? 'animate-pulse' : ''}`}></span>
                <span className={`text-[10px] font-mono font-medium ${status.text}`}>{status.label}</span>
            </div>

            <div className="w-px h-3 bg-white/10"></div>

            {/* Last Event */}
            <div className="flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[12px] text-gray-500">schedule</span>
                <span className="text-[10px] font-mono text-gray-500">
                    {scanActive ? formatAge(lastEventAge) : 'No active scan'}
                </span>
            </div>

            <div className="w-px h-3 bg-white/10"></div>

            {/* Feed Stats */}
            <div className="flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[12px] text-gray-500">database</span>
                <span className="text-[10px] font-mono text-gray-500">
                    {feedCount} events{rps > 0 ? ` · ${rps} rps` : ''}
                </span>
            </div>

            <div className="w-px h-3 bg-white/10"></div>

            {/* Data Source Indicator */}
            <div className="flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[12px] text-purple-400">hub</span>
                <span className="text-[10px] font-mono text-gray-500">WebSocket + REST</span>
            </div>
        </motion.div>
    );
});
