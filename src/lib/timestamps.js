/**
 * Shared timestamp utilities for the dashboard.
 * Eliminates duplicated HH:MM:SS parsing across sparklines, table filters, etc.
 */

/**
 * Generate a current timestamp in 24h format (HH:MM:SS).
 * Uses en-GB locale for consistent 24h output matching the backend's strftime("%H:%M:%S").
 * @returns {string} e.g. "14:30:45"
 */
export function now24h() {
    return new Date().toLocaleTimeString('en-GB');
}

/**
 * Parse an "HH:MM:SS" timestamp string into a Date object set to today.
 * Handles midnight rollover: if the parsed time appears to be in the future,
 * it's assumed to have crossed midnight and is adjusted to yesterday.
 * @param {string} timestamp - e.g. "14:30:45" or "2:30:45 PM"
 * @returns {Date|null} Date object set to today at the parsed time, or null if unparseable
 */
export function parseTimestamp(timestamp) {
    if (!timestamp) return null;
    try {
        const parts = timestamp.split(/[:\s]/);
        const th = parseInt(parts[0], 10);
        const tm = parseInt(parts[1], 10);
        const ts = parseInt(parts[2], 10) || 0;
        if (isNaN(th) || isNaN(tm)) return null;
        const now = new Date();
        const result = new Date(now);
        result.setHours(th, tm, ts, 0);
        // Handle midnight rollover: if event time is in the future, it crossed midnight
        if (result > now) {
            result.setDate(result.getDate() - 1);
        }
        return result;
    } catch (e) {
        return null;
    }
}

/**
 * Check if a timestamp string is within the last N seconds from now.
 * @param {string} timestamp - e.g. "14:30:45"
 * @param {number} rangeSec - seconds to check against
 * @returns {boolean} true if within range (or unparseable — kept by default)
 */
export function isWithinRange(timestamp, rangeSec) {
    const eventTime = parseTimestamp(timestamp);
    if (!eventTime) return true; // Keep unparseable timestamps
    const diffSec = (Date.now() - eventTime.getTime()) / 1000;
    return diffSec <= rangeSec;
}

/**
 * Compute age in milliseconds from a timestamp string to now.
 * @param {string} timestamp - e.g. "14:30:45"
 * @returns {number|null} age in ms, or null if unparseable
 */
export function timestampAgeMs(timestamp) {
    const eventTime = parseTimestamp(timestamp);
    if (!eventTime) return null;
    return Date.now() - eventTime.getTime();
}
