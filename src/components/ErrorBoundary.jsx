import React from 'react';
import EmptyState from './ui/EmptyState';
import Button from './ui/Button';

/**
 * ErrorBoundary — production-grade React error boundary.
 *
 * Catches render errors from descendants and shows a recovery UI built on the
 * shared EmptyState + Button primitives. Props-compatible with the previous
 * implementation (just wraps `children`). Optional `onReset` callback fires
 * when the user clicks "Try Again".
 *
 * @typedef {Object} ErrorBoundaryProps
 * @property {React.ReactNode}                                  children
 * @property {(error: Error, info: React.ErrorInfo) => void}    [onError]   Logging hook.
 * @property {() => void}                                       [onReset]   Optional post-reset side effect.
 * @property {React.ReactNode | ((args: { error: Error|null, reset: () => void }) => React.ReactNode)} [fallback]
 *           Optional custom fallback. If a function, receives { error, reset }.
 */
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('[ErrorBoundary] Caught render error:', error, errorInfo);
        if (typeof this.props.onError === 'function') {
            try {
                this.props.onError(error, errorInfo);
            } catch (_) {
                /* swallow secondary errors */
            }
        }
    }

    handleReset = () => {
        this.setState({ hasError: false, error: null });
        if (typeof this.props.onReset === 'function') {
            try {
                this.props.onReset();
            } catch (_) {
                /* user callback errors should not re-trigger the boundary */
            }
        }
    };

    handleReload = () => {
        if (typeof window !== 'undefined' && window.location) {
            window.location.reload();
        }
    };

    render() {
        if (!this.state.hasError) return this.props.children;

        // Custom fallback support.
        const { fallback } = this.props;
        if (typeof fallback === 'function') {
            return fallback({ error: this.state.error, reset: this.handleReset });
        }
        if (fallback !== undefined) {
            return fallback;
        }

        return (
            <div
                role="alert"
                className="min-h-screen flex items-center justify-center bg-[#06070B] px-4"
                style={{ fontFamily: "'Inter', sans-serif" }}
            >
                <div className="w-full max-w-lg">
                    <EmptyState
                        icon="error"
                        size="lg"
                        title="Something went wrong"
                        description="An unexpected error occurred in the UI. Your data is safe — try again, or reload the page."
                        action={{
                            label: 'Try Again',
                            onClick: this.handleReset,
                            icon: 'refresh',
                        }}
                        secondaryAction={
                            <Button variant="ghost" size="sm" onClick={this.handleReload}>
                                Reload Page
                            </Button>
                        }
                    />
                </div>
            </div>
        );
    }
}

export default ErrorBoundary;
