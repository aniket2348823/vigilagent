import React, { useState, useEffect, useRef } from 'react';

/**
 * Animated counter that smoothly transitions from old value to new value.
 * Uses requestAnimationFrame with ease-out cubic easing for natural feel.
 * @param {number} value - Target value to animate to
 * @param {string} prefix - Text before the number (e.g. '$')
 * @param {string} suffix - Text after the number (e.g. '%')
 * @param {number} duration - Animation duration in ms (default 600)
 */
export default React.memo(function AnimatedCounter({ value, prefix = '', suffix = '', duration = 600 }) {
    const [display, setDisplay] = useState(value ?? 0);
    const prevRef = useRef(value ?? 0);
    const rafRef = useRef(null);

    useEffect(() => {
        const from = prevRef.current;
        const to = value;
        if (from === to) return;
        const start = performance.now();
        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(from + (to - from) * eased);
            setDisplay(current);
            if (progress < 1) {
                rafRef.current = requestAnimationFrame(animate);
            }
        };
        rafRef.current = requestAnimationFrame(animate);
        return () => { if (rafRef.current && typeof cancelAnimationFrame !== 'undefined') cancelAnimationFrame(rafRef.current); };
    }, [value, duration]);

    useEffect(() => { prevRef.current = display; }, [display]);

    return <span>{prefix}{display}{suffix}</span>;
});
