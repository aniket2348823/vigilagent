import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import RpsGauge from '../components/dashboard/RpsGauge';

beforeEach(() => {
    vi.useFakeTimers();
    global.requestAnimationFrame = vi.fn((cb) => {
        return setTimeout(() => cb(Date.now()), 16);
    });
    global.cancelAnimationFrame = vi.fn((id) => clearTimeout(id));
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('RpsGauge', () => {
    it('renders the RPS value', () => {
        render(<RpsGauge rps={42} />);
        expect(screen.getByText('42')).toBeTruthy();
    });

    it('renders the req/s label', () => {
        render(<RpsGauge rps={10} />);
        expect(screen.getByText('req/s')).toBeTruthy();
    });

    it('renders zero RPS', () => {
        render(<RpsGauge rps={0} />);
        expect(screen.getByText('0')).toBeTruthy();
    });

    it('renders high RPS value', () => {
        render(<RpsGauge rps={999} />);
        expect(screen.getByText('999')).toBeTruthy();
    });

    it('renders with custom maxRps', () => {
        const { container } = render(<RpsGauge rps={50} maxRps={200} />);
        expect(container.querySelector('svg')).toBeTruthy();
    });

    it('renders SVG gauge arc', () => {
        const { container } = render(<RpsGauge rps={25} />);
        const svg = container.querySelector('svg');
        expect(svg).toBeTruthy();
        const paths = container.querySelectorAll('path');
        expect(paths.length).toBe(2); // background arc + active arc
    });

    it('defaults to 0 RPS when not provided', () => {
        render(<RpsGauge />);
        expect(screen.getByText('0')).toBeTruthy();
    });
});
