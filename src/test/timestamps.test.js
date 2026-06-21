import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { now24h, parseTimestamp, isWithinRange, timestampAgeMs } from '../lib/timestamps';

describe('timestamps.js', () => {
    describe('now24h', () => {
        it('returns a string in HH:MM:SS format', () => {
            const result = now24h();
            expect(result).toMatch(/^\d{1,2}:\d{2}:\d{2}$/);
        });

        it('returns 24-hour format (no AM/PM)', () => {
            const result = now24h();
            expect(result).not.toMatch(/AM|PM/i);
        });
    });

    describe('parseTimestamp', () => {
        it('parses a valid HH:MM:SS timestamp', () => {
            const result = parseTimestamp('14:30:45');
            expect(result).toBeInstanceOf(Date);
            expect(result.getHours()).toBe(14);
            expect(result.getMinutes()).toBe(30);
            expect(result.getSeconds()).toBe(45);
        });

        it('parses a single-digit hour timestamp', () => {
            const result = parseTimestamp('9:05:30');
            expect(result).toBeInstanceOf(Date);
            expect(result.getHours()).toBe(9);
            expect(result.getMinutes()).toBe(5);
        });

        it('returns null for null/undefined input', () => {
            expect(parseTimestamp(null)).toBeNull();
            expect(parseTimestamp(undefined)).toBeNull();
            expect(parseTimestamp('')).toBeNull();
        });

        it('returns null for invalid timestamp strings', () => {
            expect(parseTimestamp('invalid')).toBeNull();
            expect(parseTimestamp('abc:def:ghi')).toBeNull();
        });

        it('handles midnight rollover (future time → yesterday)', () => {
            const futureTime = '23:59:59';
            const result = parseTimestamp(futureTime);
            // If current time is before 23:59:59, the result should be adjusted
            const now = new Date();
            if (now.getHours() < 23) {
                expect(result.getDate()).toBe(now.getDate() - 1);
            }
        });

        it('handles timestamps with AM/PM format', () => {
            const result = parseTimestamp('2:30:45 PM');
            expect(result).toBeInstanceOf(Date);
        });
    });

    describe('isWithinRange', () => {
        beforeEach(() => {
            vi.useFakeTimers();
            vi.setSystemTime(new Date('2026-06-21T14:30:00'));
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it('returns true for a timestamp within range', () => {
            // 10 seconds ago
            expect(isWithinRange('14:29:50', 30)).toBe(true);
        });

        it('returns false for a timestamp outside range', () => {
            // 5 minutes ago
            expect(isWithinRange('14:25:00', 60)).toBe(false);
        });

        it('returns true for unparseable timestamps (kept by default)', () => {
            expect(isWithinRange('invalid', 30)).toBe(true);
        });

        it('returns true for exact boundary', () => {
            // Exactly 60 seconds ago
            expect(isWithinRange('14:29:00', 60)).toBe(true);
        });
    });

    describe('timestampAgeMs', () => {
        beforeEach(() => {
            vi.useFakeTimers();
            vi.setSystemTime(new Date('2026-06-21T14:30:00'));
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it('returns age in milliseconds for a valid timestamp', () => {
            // 30 seconds ago
            const age = timestampAgeMs('14:29:30');
            expect(age).toBe(30000);
        });

        it('returns null for unparseable timestamps', () => {
            expect(timestampAgeMs('invalid')).toBeNull();
        });

        it('returns 0 for current time', () => {
            const age = timestampAgeMs('14:30:00');
            expect(age).toBe(0);
        });

        it('returns positive value for past events', () => {
            const age = timestampAgeMs('14:28:00');
            expect(age).toBe(120000); // 2 minutes = 120000ms
        });
    });
});
