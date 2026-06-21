import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import AnimatedCounter from '../components/dashboard/AnimatedCounter';

// Mock requestAnimationFrame for testing
beforeEach(() => {
    vi.useFakeTimers();
    let rafId = 0;
    global.requestAnimationFrame = vi.fn((cb) => {
        return setTimeout(() => cb(performance.now()), 16);
    });
    global.cancelAnimationFrame = vi.fn((id) => clearTimeout(id));
    // Mock performance.now to advance deterministically with fake timers
    vi.spyOn(performance, 'now').mockReturnValue(0);
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('AnimatedCounter', () => {
    it('renders the initial value', () => {
        render(<AnimatedCounter value={42} />);
        expect(screen.getByText('42')).toBeTruthy();
    });

    it('renders zero value', () => {
        render(<AnimatedCounter value={0} />);
        expect(screen.getByText('0')).toBeTruthy();
    });

    it('renders suffix when provided', () => {
        render(<AnimatedCounter value={75} suffix="%" />);
        expect(screen.getByText('75%')).toBeTruthy();
    });

    it('renders without suffix by default', () => {
        const { container } = render(<AnimatedCounter value={100} />);
        expect(container.textContent).toBe('100');
    });

    it('handles null/undefined value gracefully', () => {
        render(<AnimatedCounter value={null} />);
        expect(screen.getByText('0')).toBeTruthy();
    });

    it('animates to new value when value prop changes', () => {
        const { rerender } = render(<AnimatedCounter value={0} />);
        expect(screen.getByText('0')).toBeTruthy();

        rerender(<AnimatedCounter value={100} />);
        
        // Set performance.now past animation duration (600ms)
        performance.now.mockReturnValue(650);
        
        // Advance timers to trigger requestAnimationFrame callbacks
        act(() => {
            vi.advanceTimersByTime(700);
        });

        // After animation completes, should show final value
        expect(screen.getByText('100')).toBeTruthy();
    });

    it('does not animate when value does not change', () => {
        const { rerender } = render(<AnimatedCounter value={50} />);
        expect(screen.getByText('50')).toBeTruthy();

        rerender(<AnimatedCounter value={50} />);
        expect(screen.getByText('50')).toBeTruthy();
    });
});
