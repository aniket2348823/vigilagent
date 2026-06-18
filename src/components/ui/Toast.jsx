import React, {
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState,
} from 'react';
import ToastContext from './ToastContext';

/**
 * Toast — accessible, stacking notification system.
 *
 * Wrap your app with <ToastProvider> and call useToast() to dispatch.
 *
 * @typedef {'info'|'success'|'warning'|'error'} ToastType
 * @typedef {Object} ToastInput
 * @property {ToastType} [type]      Default 'info'.
 * @property {string}    [title]     Optional title (bolded).
 * @property {string}    message     Required body text.
 * @property {number}    [duration]  Auto-dismiss ms. 0 = sticky. Default 4000.
 *
 * @typedef {Object} ToastApi
 * @property {(t: ToastInput) => string} toast        Dispatch a toast. Returns id.
 * @property {(id: string) => void}      dismiss      Manually close a toast by id.
 * @property {() => void}                clear        Close all visible toasts.
 */

const MAX_VISIBLE = 3;
const DEFAULT_DURATION = 4000;



const TYPE_STYLES = {
    info:    { bar: 'bg-[#9b61ff]', icon: 'info',           iconColor: 'text-[#9b61ff]' },
    success: { bar: 'bg-[#27AE60]', icon: 'check_circle',   iconColor: 'text-[#27AE60]' },
    warning: { bar: 'bg-[#F1C40F]', icon: 'warning',        iconColor: 'text-[#F1C40F]' },
    error:   { bar: 'bg-[#C0392B]', icon: 'error',          iconColor: 'text-[#C0392B]' },
};

let __toastSeq = 0;
const nextId = () => `toast-${Date.now()}-${++__toastSeq}`;

/**
 * Single toast item. Internal — exported for tests / advanced reuse.
 * @param {{toast: any, onDismiss: (id: string) => void}} props
 */
function Toast({ toast, onDismiss }) {
    const { id, type = 'info', title, message } = toast;
    const styles = TYPE_STYLES[type] || TYPE_STYLES.info;

    return (
        <div
            role={type === 'error' ? 'alert' : 'status'}
            className="
                pointer-events-auto relative w-full sm:w-[360px]
                bg-[#3E425E]/70 backdrop-blur-md
                border border-white/10 rounded-lg shadow-[0_8px_32px_rgba(0,0,0,0.4)]
                flex gap-3 p-3 pr-2 overflow-hidden
                animate-[toastIn_180ms_ease-out]
                motion-reduce:animate-none
            "
        >
            <span className={`absolute left-0 top-0 bottom-0 w-1 ${styles.bar}`} aria-hidden="true" />
            <span
                className={`material-symbols-outlined text-xl ${styles.iconColor} flex-shrink-0 mt-0.5`}
                aria-hidden="true"
            >
                {styles.icon}
            </span>
            <div className="flex-1 min-w-0">
                {title && (
                    <p className="text-sm font-semibold text-white leading-tight mb-0.5 truncate">
                        {title}
                    </p>
                )}
                <p className="text-xs text-gray-300 leading-snug break-words">{message}</p>
            </div>
            <button
                type="button"
                onClick={() => onDismiss(id)}
                aria-label="Dismiss notification"
                className="
                    flex-shrink-0 self-start text-gray-400 hover:text-white
                    rounded p-1 transition-colors
                    focus:outline-none focus-visible:ring-2 focus-visible:ring-[#9b61ff]
                "
            >
                <span className="material-symbols-outlined text-base" aria-hidden="true">close</span>
            </button>
        </div>
    );
}

/**
 * ToastProvider — mounts the live region and exposes the toast() API via context.
 * Place once near the App root.
 *
 * @param {{children: React.ReactNode}} props
 */
export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([]);
    const timersRef = useRef(new Map());

    const dismiss = useCallback((id) => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
        const timer = timersRef.current.get(id);
        if (timer) {
            clearTimeout(timer);
            timersRef.current.delete(id);
        }
    }, []);

    const toast = useCallback(
        ({ type = 'info', title, message, duration = DEFAULT_DURATION } = {}) => {
            const id = nextId();
            const item = { id, type, title, message };

            setToasts((prev) => {
                const next = [...prev, item];
                // Stack max MAX_VISIBLE: oldest gets dropped (along with its timer).
                if (next.length > MAX_VISIBLE) {
                    const dropped = next.slice(0, next.length - MAX_VISIBLE);
                    dropped.forEach((d) => {
                        const t = timersRef.current.get(d.id);
                        if (t) {
                            clearTimeout(t);
                            timersRef.current.delete(d.id);
                        }
                    });
                    return next.slice(-MAX_VISIBLE);
                }
                return next;
            });

            if (duration > 0) {
                const timer = setTimeout(() => dismiss(id), duration);
                timersRef.current.set(id, timer);
            }
            return id;
        },
        [dismiss]
    );

    const clear = useCallback(() => {
        timersRef.current.forEach((t) => clearTimeout(t));
        timersRef.current.clear();
        setToasts([]);
    }, []);

    useEffect(() => {
        const timers = timersRef.current;
        return () => {
            timers.forEach((t) => clearTimeout(t));
            timers.clear();
        };
    }, []);

    const api = useMemo(() => ({ toast, dismiss, clear }), [toast, dismiss, clear]);

    return (
        <ToastContext.Provider value={api}>
            {children}

            {/* Live region — keyboard users / SR users hear updates here */}
            <div
                role="status"
                aria-live="polite"
                aria-relevant="additions text"
                className="
                    fixed z-[1000] bottom-4 right-4 left-4 sm:left-auto
                    flex flex-col items-stretch sm:items-end gap-2
                    pointer-events-none
                "
            >
                {toasts.map((t) => (
                    <Toast key={t.id} toast={t} onDismiss={dismiss} />
                ))}
            </div>

            {/* Inject the entry keyframe once, scoped to this region */}
            <style>{`
                @keyframes toastIn {
                    0%   { opacity: 0; transform: translateY(8px) scale(0.98); }
                    100% { opacity: 1; transform: translateY(0)   scale(1);    }
                }
            `}</style>
        </ToastContext.Provider>
    );
}

export { Toast };
export default ToastProvider;
