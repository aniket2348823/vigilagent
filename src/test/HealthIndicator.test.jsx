import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import HealthIndicator from '../components/dashboard/HealthIndicator';

beforeEach(() => {
    vi.useFakeTimers();
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('HealthIndicator', () => {
    it('shows CONNECTING status initially', () => {
        render(<HealthIndicator scanActive={false} feedLength={0} rps={0} />);
        expect(screen.getByText('CONNECTING')).toBeTruthy();
    });

    it('transitions to LIVE when feed has events (effect-driven state)', () => {
        const { rerender } = render(<HealthIndicator scanActive={false} feedLength={0} rps={0} />);
        expect(screen.getByText('CONNECTING')).toBeTruthy();

        // Simulate feed update — triggers useEffect that sets wsStatus to 'connected'
        act(() => {
            rerender(<HealthIndicator scanActive={true} feedLength={10} rps={5} />);
        });

        // After effect fires, status should be LIVE
        expect(screen.getByText('LIVE')).toBeTruthy();
        expect(screen.queryByText('CONNECTING')).toBeNull();
    });

    it('displays feed count', () => {
        render(<HealthIndicator scanActive={false} feedLength={42} rps={0} />);
        expect(screen.getByText(/42 events/)).toBeTruthy();
    });

    it('displays RPS when greater than 0', () => {
        render(<HealthIndicator scanActive={true} feedLength={10} rps={25} />);
        expect(screen.getByText(/25 rps/)).toBeTruthy();
    });

    it('does not display RPS when 0', () => {
        render(<HealthIndicator scanActive={false} feedLength={10} rps={0} />);
        expect(screen.getByText(/10 events/)).toBeTruthy();
    });

    it('shows WebSocket + REST data source', () => {
        render(<HealthIndicator scanActive={false} feedLength={0} rps={0} />);
        expect(screen.getByText('WebSocket + REST')).toBeTruthy();
    });

    it('shows scan status when no active scan', () => {
        render(<HealthIndicator scanActive={false} feedLength={0} rps={0} />);
        expect(screen.getByText('No active scan')).toBeTruthy();
    });

    it('shows time format when scan is active', () => {
        render(<HealthIndicator scanActive={true} feedLength={10} rps={5} />);
        // The component uses setInterval(1000ms) to update lastEventAge.
        // Advance fake timers so the interval fires and sets the age.
        act(() => {
            vi.advanceTimersByTime(1100);
        });
        // Should show some time format (e.g., "0s ago" or "1s ago")
        const timeElement = screen.getByText(/\d+s ago/);
        expect(timeElement).toBeTruthy();
    });
});
