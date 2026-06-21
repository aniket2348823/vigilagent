import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { LIQUID_SPRING } from '../../lib/constants';

const RpsGauge = ({ rps = 0, maxRps = 100 }) => {
    const [animatedRps, setAnimatedRps] = useState(rps);
    const prevRpsRef = useRef(rps);
    const animFrameRef = useRef(null);

    useEffect(() => {
        const start = prevRpsRef.current;
        const end = rps;
        const duration = 400;
        const startTime = performance.now();

        const animate = (now) => {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease-out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = start + (end - start) * eased;
            setAnimatedRps(current);

            if (progress < 1) {
                animFrameRef.current = requestAnimationFrame(animate);
            } else {
                prevRpsRef.current = end;
            }
        };

        animFrameRef.current = requestAnimationFrame(animate);
        return () => {
            if (animFrameRef.current && typeof cancelAnimationFrame !== 'undefined') cancelAnimationFrame(animFrameRef.current);
        };
    }, [rps]);

    // SVG semi-circular gauge
    const size = 120;
    const strokeWidth = 8;
    const radius = (size - strokeWidth) / 2;
    const circumference = Math.PI * radius; // Half circle
    const normalizedValue = Math.min(animatedRps / maxRps, 1);
    const dashOffset = circumference * (1 - normalizedValue);

    // Color based on RPS level
    const getColor = (val) => {
        if (val < 0.3) return { stroke: '#22c55e', glow: 'rgba(34,197,94,0.4)', text: 'text-green-400' };
        if (val < 0.7) return { stroke: '#eab308', glow: 'rgba(234,179,8,0.4)', text: 'text-yellow-400' };
        return { stroke: '#ef4444', glow: 'rgba(239,68,68,0.4)', text: 'text-red-400' };
    };

    const color = getColor(normalizedValue);

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ ...LIQUID_SPRING, delay: 0.15 }}
            className="glass-panel-dash p-4 rounded-2xl relative overflow-hidden flex flex-col items-center"
        >
            <div className="absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent pointer-events-none" />
            
            <div className="relative z-10 flex flex-col items-center">
                <svg width={size} height={size / 2 + 12} viewBox={`0 0 ${size} ${size / 2 + 12}`}>
                    <defs>
                        <filter id="gaugeGlow">
                            <feGaussianBlur stdDeviation="3" result="blur" />
                            <feComposite in="SourceGraphic" in2="blur" operator="over" />
                        </filter>
                    </defs>
                    {/* Background arc */}
                    <path
                        d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
                        fill="none"
                        stroke="rgba(255,255,255,0.05)"
                        strokeWidth={strokeWidth}
                        strokeLinecap="round"
                    />
                    {/* Active arc */}
                    <path
                        d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
                        fill="none"
                        stroke={color.stroke}
                        strokeWidth={strokeWidth}
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        strokeDashoffset={dashOffset}
                        filter="url(#gaugeGlow)"
                        style={{ transition: 'stroke-dashoffset 0.4s ease-out' }}
                    />
                    {/* RPS value */}
                    <text
                        x={size / 2}
                        y={size / 2 - 4}
                        textAnchor="middle"
                        className="fill-white font-bold"
                        fontSize="22"
                        fontFamily="'Space Grotesk', sans-serif"
                    >
                        {Math.round(animatedRps)}
                    </text>
                    <text
                        x={size / 2}
                        y={size / 2 + 14}
                        textAnchor="middle"
                        className="fill-gray-500"
                        fontSize="9"
                        fontFamily="'Space Grotesk', sans-serif"
                    >
                        req/s
                    </text>
                </svg>
            </div>
        </motion.div>
    );
};

export default React.memo(RpsGauge);
