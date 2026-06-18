import { useContext } from 'react';
import ToastContext from '../components/ui/ToastContext';

/**
 * Public hook. Throws if used outside <ToastProvider>.
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
export function useToast() {
    const ctx = useContext(ToastContext);
    if (!ctx) {
        throw new Error('useToast must be used within a <ToastProvider>');
    }
    return ctx;
}
