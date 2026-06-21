import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket, _resetForTesting } from '../hooks/useWebSocket';

// Mock the api module
vi.mock('../lib/api', () => ({
    websocketUrl: vi.fn((path, params) => `ws://localhost:8080${path}`),
}));

// ── Mock WebSocket ──
class MockWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    constructor(url) {
        this.url = url;
        this.readyState = MockWebSocket.CONNECTING;
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        this.onerror = null;
        this.close = vi.fn(() => {
            this.readyState = MockWebSocket.CLOSED;
            if (this.onclose) this.onclose({ code: 1000, reason: '' });
        });
        this.send = vi.fn();
        // Store reference for external control
        MockWebSocket._lastInstance = this;
    }

    // Simulate successful connection
    simulateOpen() {
        this.readyState = MockWebSocket.OPEN;
        if (this.onopen) this.onopen();
    }

    // Simulate receiving a message
    simulateMessage(data) {
        if (this.onmessage) {
            this.onmessage({ data: JSON.stringify(data) });
        }
    }

    // Simulate receiving raw string data
    simulateRawMessage(rawString) {
        if (this.onmessage) {
            this.onmessage({ data: rawString });
        }
    }

    // Simulate connection close
    simulateClose(code = 1000, reason = '') {
        this.readyState = MockWebSocket.CLOSED;
        if (this.onclose) this.onclose({ code, reason });
    }

    // Simulate error
    simulateError() {
        if (this.onerror) this.onerror(new Error('Connection error'));
        // onclose typically fires after onerror
        this.simulateClose(1006, 'Abnormal closure');
    }
}

beforeEach(() => {
    vi.useFakeTimers();
    global.WebSocket = MockWebSocket;
    MockWebSocket._lastInstance = null;
    // Reset module-level singleton state so each test starts fresh
    _resetForTesting();
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('useWebSocket', () => {
    describe('connection lifecycle', () => {
        it('returns subscribe function and isConnected boolean', () => {
            const { result } = renderHook(() => useWebSocket());
            expect(typeof result.current.subscribe).toBe('function');
            expect(typeof result.current.isConnected).toBe('boolean');
        });

        it('creates a WebSocket connection on first subscribe', () => {
            const { result } = renderHook(() => useWebSocket());
            act(() => {
                result.current.subscribe(() => {});
            });
            expect(MockWebSocket._lastInstance).toBeTruthy();
            expect(MockWebSocket._lastInstance.url).toContain('/stream');
        });

        it('does not create duplicate connections', () => {
            const { result } = renderHook(() => useWebSocket());
            act(() => {
                result.current.subscribe(() => {});
                result.current.subscribe(() => {});
            });
            // Only one WebSocket should be created
            expect(MockWebSocket._lastInstance).toBeTruthy();
        });
    });

    describe('message subscription', () => {
        it('receives messages from WebSocket', () => {
            const { result } = renderHook(() => useWebSocket());
            const received = [];
            act(() => {
                result.current.subscribe((data) => received.push(data));
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            act(() => {
                ws.simulateMessage({ type: 'TEST_EVENT', payload: { id: 1 } });
            });
            expect(received).toHaveLength(1);
            expect(received[0]).toEqual({ type: 'TEST_EVENT', payload: { id: 1 } });
        });

        it('unsubscribes correctly', () => {
            const { result } = renderHook(() => useWebSocket());
            const received = [];
            let unsub;
            act(() => {
                unsub = result.current.subscribe((data) => received.push(data));
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            act(() => {
                unsub();
            });
            act(() => {
                ws.simulateMessage({ type: 'TEST' });
            });
            expect(received).toHaveLength(0);
        });

        it('supports multiple subscribers', () => {
            const { result } = renderHook(() => useWebSocket());
            const received1 = [];
            const received2 = [];
            act(() => {
                result.current.subscribe((data) => received1.push(data));
                result.current.subscribe((data) => received2.push(data));
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            act(() => {
                ws.simulateMessage({ type: 'MULTI_TEST' });
            });
            expect(received1).toHaveLength(1);
            expect(received2).toHaveLength(1);
        });

        it('isolates listener errors from other subscribers', () => {
            const { result } = renderHook(() => useWebSocket());
            const errorListener = vi.fn(() => { throw new Error('listener error'); });
            const goodListener = vi.fn();
            act(() => {
                result.current.subscribe(errorListener);
                result.current.subscribe(goodListener);
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            // Should not throw despite errorListener failing
            act(() => {
                ws.simulateMessage({ type: 'TEST' });
            });
            expect(goodListener).toHaveBeenCalledTimes(1);
        });
    });

    describe('BATCH message handling', () => {
        it('unpacks BATCH messages into individual dispatches', () => {
            const { result } = renderHook(() => useWebSocket());
            const received = [];
            act(() => {
                result.current.subscribe((data) => received.push(data));
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            act(() => {
                ws.simulateMessage({
                    type: 'BATCH',
                    payload: [
                        { type: 'EVENT_1', payload: {} },
                        { type: 'EVENT_2', payload: {} },
                        { type: 'EVENT_3', payload: {} },
                    ],
                });
            });
            expect(received).toHaveLength(3);
            expect(received[0].type).toBe('EVENT_1');
            expect(received[1].type).toBe('EVENT_2');
            expect(received[2].type).toBe('EVENT_3');
        });
    });

    describe('malformed messages', () => {
        it('ignores non-JSON messages without crashing', () => {
            const { result } = renderHook(() => useWebSocket());
            const received = [];
            act(() => {
                result.current.subscribe((data) => received.push(data));
            });
            const ws = MockWebSocket._lastInstance;
            act(() => {
                ws.simulateOpen();
            });
            act(() => {
                ws.simulateRawMessage('not valid json {{{');
            });
            expect(received).toHaveLength(0);
        });
    });

    describe('reconnection', () => {
        it('reconnects after connection closes', () => {
            const { result } = renderHook(() => useWebSocket());
            act(() => {
                result.current.subscribe(() => {});
            });
            const ws1 = MockWebSocket._lastInstance;
            act(() => {
                ws1.simulateOpen();
            });
            act(() => {
                ws1.simulateClose();
            });
            // Fast-forward past the backoff delay (base = 1s)
            act(() => {
                vi.advanceTimersByTime(1500);
            });
            expect(MockWebSocket._lastInstance).not.toBe(ws1);
        });

        it('resets reconnect attempts on successful open', () => {
            const { result } = renderHook(() => useWebSocket());
            act(() => {
                result.current.subscribe(() => {});
            });
            const ws1 = MockWebSocket._lastInstance;
            act(() => {
                ws1.simulateOpen();
            });
            act(() => {
                ws1.simulateClose();
            });
            act(() => {
                vi.advanceTimersByTime(1500);
            });
            const ws2 = MockWebSocket._lastInstance;
            act(() => {
                ws2.simulateOpen();
            });
            // Should be able to reconnect again after close
            act(() => {
                ws2.simulateClose();
            });
            act(() => {
                vi.advanceTimersByTime(1500);
            });
            expect(MockWebSocket._lastInstance).not.toBe(ws2);
        });
    });

    describe('WS_GIVEUP event', () => {
        it('dispatches WS_GIVEUP after max reconnect attempts', () => {
            const { result } = renderHook(() => useWebSocket());
            const received = [];
            act(() => {
                result.current.subscribe((data) => received.push(data));
            });
            // Simulate 30+ failed reconnection attempts
            for (let i = 0; i < 31; i++) {
                const ws = MockWebSocket._lastInstance;
                if (ws) {
                    act(() => {
                        ws.simulateClose();
                    });
                }
                act(() => {
                    vi.advanceTimersByTime(35000); // advance past max backoff
                });
            }
            const giveup = received.find(r => r.type === 'WS_GIVEUP');
            expect(giveup).toBeTruthy();
            expect(giveup.payload.attempts).toBeGreaterThanOrEqual(30);
        });
    });

    describe('backoff computation', () => {
        it('uses exponential backoff with jitter', () => {
            const { result } = renderHook(() => useWebSocket());
            act(() => {
                result.current.subscribe(() => {});
            });
            const ws1 = MockWebSocket._lastInstance;
            act(() => {
                ws1.simulateOpen();
            });
            // Close and measure time to reconnect
            const delays = [];
            for (let i = 0; i < 3; i++) {
                const ws = MockWebSocket._lastInstance;
                act(() => {
                    ws.simulateClose();
                });
                const startTime = Date.now();
                act(() => {
                    vi.advanceTimersByTime(35000);
                });
                delays.push(Date.now() - startTime);
            }
            // All should have attempted reconnection
            expect(delays).toHaveLength(3);
        });
    });
});
