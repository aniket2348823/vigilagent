import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ThreatTable from '../components/dashboard/ThreatTable';

// Minimal mock of rowRefs
const createRowRefs = () => ({ current: [] });

const baseProps = {
    persistentState: {
        threat_feed: [
            { timestamp: '14:30:00', agent: 'alpha', threat_type: 'RECON COMPLETE', url: 'http://target.com', severity: 'INFO', risk_score: 10 },
            { timestamp: '14:29:30', agent: 'beta', threat_type: 'SQL INJECTION', url: 'http://target.com/login', severity: 'CRITICAL', risk_score: 95, cvss_score: 9.8 },
            { timestamp: '14:29:00', agent: 'gamma', threat_type: 'XSS FOUND', url: 'http://target.com/search', severity: 'HIGH', risk_score: 75, anomaly: true },
            { timestamp: '14:28:00', agent: 'alpha', threat_type: 'TRAFFIC INTERCEPTED', url: 'http://target.com/api', severity: 'MEDIUM', risk_score: 50 },
            { timestamp: '14:27:00', agent: 'delta', threat_type: 'DOM MANIPULATION', url: 'http://target.com/app', severity: 'LOW', risk_score: 25 },
        ],
    },
    filterAgent: '',
    setFilterAgent: vi.fn(),
    filterTimeRange: '',
    setFilterTimeRange: vi.fn(),
    filterSeverity: '',
    setFilterSeverity: vi.fn(),
    selectedRowIndex: -1,
    setSelectedRowIndex: vi.fn(),
    selectedEvent: null,
    setSelectedEvent: vi.fn(),
    rowRefs: createRowRefs(),
    scanActive: false,
    currentPhase: null,
    completedPhases: [],
    showExportMenu: false,
    setShowExportMenu: vi.fn(),
    exportData: vi.fn(),
};

describe('ThreatTable', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('rendering', () => {
        it('renders the Live Threat Monitor header', () => {
            render(<ThreatTable {...baseProps} />);
            expect(screen.getByText('Live Threat Monitor')).toBeTruthy();
        });

        it('renders all 5 threat feed events', () => {
            render(<ThreatTable {...baseProps} />);
            expect(screen.getByText('RECON COMPLETE')).toBeTruthy();
            expect(screen.getByText('SQL INJECTION')).toBeTruthy();
            expect(screen.getByText('XSS FOUND')).toBeTruthy();
            expect(screen.getByText('TRAFFIC INTERCEPTED')).toBeTruthy();
            expect(screen.getByText('DOM MANIPULATION')).toBeTruthy();
        });

        it('shows empty state when no events', () => {
            render(<ThreatTable {...baseProps} persistentState={{ threat_feed: [] }} />);
            expect(screen.getByText('Waiting for agent activity…')).toBeTruthy();
        });

        it('displays event count', () => {
            render(<ThreatTable {...baseProps} />);
            expect(screen.getByText('5 events')).toBeTruthy();
        });
    });

    describe('severity filtering', () => {
        it('filters by CRITICAL severity', () => {
            render(<ThreatTable {...baseProps} filterSeverity="CRITICAL" />);
            expect(screen.getByText('SQL INJECTION')).toBeTruthy();
            expect(screen.queryByText('RECON COMPLETE')).toBeNull();
            expect(screen.queryByText('XSS FOUND')).toBeNull();
        });

        it('filters by HIGH severity', () => {
            render(<ThreatTable {...baseProps} filterSeverity="HIGH" />);
            expect(screen.getByText('XSS FOUND')).toBeTruthy();
            expect(screen.queryByText('SQL INJECTION')).toBeNull();
        });

        it('filters by INFO severity', () => {
            render(<ThreatTable {...baseProps} filterSeverity="INFO" />);
            expect(screen.getByText('RECON COMPLETE')).toBeTruthy();
            expect(screen.queryByText('SQL INJECTION')).toBeNull();
        });

        it('shows all when no severity filter', () => {
            render(<ThreatTable {...baseProps} filterSeverity="" />);
            expect(screen.getByText('RECON COMPLETE')).toBeTruthy();
            expect(screen.getByText('SQL INJECTION')).toBeTruthy();
            expect(screen.getByText('XSS FOUND')).toBeTruthy();
        });
    });

    describe('agent filtering', () => {
        it('filters by agent name', () => {
            render(<ThreatTable {...baseProps} filterAgent="alpha" />);
            expect(screen.getByText('RECON COMPLETE')).toBeTruthy();
            expect(screen.getByText('TRAFFIC INTERCEPTED')).toBeTruthy();
            expect(screen.queryByText('SQL INJECTION')).toBeNull();
        });

        it('filters by agent id partial match', () => {
            render(<ThreatTable {...baseProps} filterAgent="beta" />);
            expect(screen.getByText('SQL INJECTION')).toBeTruthy();
            expect(screen.queryByText('RECON COMPLETE')).toBeNull();
        });

        it('shows all when no agent filter', () => {
            render(<ThreatTable {...baseProps} filterAgent="" />);
            expect(screen.getByText('RECON COMPLETE')).toBeTruthy();
            expect(screen.getByText('SQL INJECTION')).toBeTruthy();
        });
    });

    describe('time range filtering', () => {
        it('calls setFilterTimeRange when time filter changes', () => {
            render(<ThreatTable {...baseProps} />);
            const select = screen.getAllByRole('combobox')[1]; // Second select is time range
            fireEvent.change(select, { target: { value: '30' } });
            expect(baseProps.setFilterTimeRange).toHaveBeenCalledWith('30');
        });

        it('shows Clear button when any filter is active', () => {
            render(<ThreatTable {...baseProps} filterTimeRange="30" />);
            expect(screen.getByText('Clear')).toBeTruthy();
        });
    });

    describe('severity bar', () => {
        it('shows severity bar when events exist', () => {
            render(<ThreatTable {...baseProps} />);
            // 'Severity' appears in both the summary bar and table header
            const elements = screen.getAllByText('Severity');
            expect(elements.length).toBeGreaterThanOrEqual(1);
        });

        it('displays correct severity count labels', () => {
            render(<ThreatTable {...baseProps} />);
            // Feed has: 1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW, 1 INFO
            // All 5 severity counts should show "1" in the legend
            const ones = screen.getAllByText('1');
            expect(ones.length).toBeGreaterThanOrEqual(5);
        });

        it('hides severity bar when no events', () => {
            render(<ThreatTable {...baseProps} persistentState={{ threat_feed: [] }} />);
            expect(screen.queryByText('Severity')).toBeNull();
        });
    });

    describe('scan phase indicator', () => {
        it('shows phase indicator when scan is active', () => {
            render(<ThreatTable {...baseProps} scanActive={true} currentPhase="recon" />);
            expect(screen.getByText('Recon')).toBeTruthy();
            expect(screen.getByText('Exploit')).toBeTruthy();
            expect(screen.getByText('Report')).toBeTruthy();
        });

        it('hides phase indicator when scan is not active', () => {
            render(<ThreatTable {...baseProps} scanActive={false} />);
            expect(screen.queryByText('Recon')).toBeNull();
        });
    });

    describe('CVSS display', () => {
        it('displays CVSS score when present', () => {
            render(<ThreatTable {...baseProps} />);
            expect(screen.getByText('9.8')).toBeTruthy();
        });

        it('shows dash when no CVSS score', () => {
            render(<ThreatTable {...baseProps} />);
            // INFO events don't have CVSS — should show em dash
            const cells = screen.getAllByText('—');
            expect(cells.length).toBeGreaterThan(0);
        });
    });

    describe('export button', () => {
        it('renders export button', () => {
            render(<ThreatTable {...baseProps} />);
            expect(screen.getByText('Export')).toBeTruthy();
        });

        it('toggles export menu on click', () => {
            render(<ThreatTable {...baseProps} />);
            fireEvent.click(screen.getByText('Export'));
            expect(baseProps.setShowExportMenu).toHaveBeenCalledWith(true);
        });
    });

    describe('row click', () => {
        it('calls setSelectedEvent when row is clicked', () => {
            render(<ThreatTable {...baseProps} />);
            fireEvent.click(screen.getByText('SQL INJECTION'));
            expect(baseProps.setSelectedEvent).toHaveBeenCalledWith(
                expect.objectContaining({ threat_type: 'SQL INJECTION' })
            );
        });
    });
});
