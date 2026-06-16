import React from 'react';
import Modal from './ui/Modal';

/**
 * FindingDetailModal — full detail view for a single finding.
 *
 * Uses the shared Modal component (focus trap, ESC, backdrop dismiss).
 * Severity styles are injected via the `severityStyles` prop to stay in
 * sync with the parent component and avoid duplication.
 *
 * @typedef {Object} FindingDetailModalProps
 * @property {boolean}       open            Controls visibility.
 * @property {() => void}     onClose         Fires on ESC / backdrop / close button.
 * @property {Object|null}    finding         The finding object to display.
 * @property {Object}         severityStyles  Severity class map from parent.
 */

function kv(label, value, mono = false) {
    return (
        <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">{label}</span>
            <span className={`text-sm text-gray-200 break-all ${mono ? 'font-mono text-xs' : ''}`}>
                {value ?? '—'}
            </span>
        </div>
    );
}

function FindingDetailModal({ open, onClose, finding, severityStyles = {} }) {
    if (!finding) return null;

    const sev = (finding.cvss_severity || finding.severity || 'INFO').toUpperCase();
    const sevClass = severityStyles[sev] || severityStyles.LOW || 'bg-blue-500/20 text-blue-400';

    return (
        <Modal
            open={open}
            onClose={onClose}
            title={finding.type || finding.name || 'Finding Detail'}
            size="lg"
        >
            <div className="space-y-5">
                {/* Severity + Score header */}
                <div className="flex items-center gap-3 flex-wrap">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${sevClass}`}>
                        <span className="w-1.5 h-1.5 rounded-full bg-current" />
                        {sev}
                    </span>
                    {finding.cvss_score != null && (
                        <span className="text-lg font-bold text-white">
                            CVSS {Number(finding.cvss_score).toFixed(1)}
                        </span>
                    )}
                    {finding.cwe && (
                        <span className="text-xs font-mono text-gray-400 bg-white/5 px-2 py-0.5 rounded">
                            {finding.cwe}
                        </span>
                    )}
                </div>

                {/* Key / Value grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-white/[0.02] rounded-lg p-4 border border-white/5">
                    {kv('Type', finding.type || finding.name)}
                    {kv('Target', finding.url || finding.affected_target, true)}
                    {kv('Scope', finding.scope_status || finding.scope)}
                    {kv('State', finding.state)}
                </div>

                {/* CVSS 4.0 Vector */}
                {finding.cvss_vector && (
                    <div className="space-y-1">
                        <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">CVSS 4.0 Vector</span>
                        <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                            <code className="text-xs text-purple-300 font-mono break-all leading-relaxed">
                                {finding.cvss_vector}
                            </code>
                        </div>
                        <p className="text-[10px] text-gray-500">
                            {finding.cvss_vector.split('/').length - 1} metrics · CVSS Version 4.0
                        </p>
                    </div>
                )}

                {/* Evidence / Description */}
                {(finding.evidence || finding.description) && (
                    <div className="space-y-1">
                        <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">Evidence</span>
                        <div className="bg-black/30 rounded-lg p-3 border border-white/5 max-h-48 overflow-y-auto scrollbar-thin">
                            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed">
                                {finding.evidence || finding.description}
                            </pre>
                        </div>
                    </div>
                )}

                {/* Raw payload (collapsible) */}
                {finding.raw && (
                    <details className="group">
                        <summary className="text-[10px] uppercase tracking-wider text-gray-500 font-medium cursor-pointer select-none hover:text-gray-400 transition-colors">
                            Raw Payload
                        </summary>
                        <div className="mt-2 bg-black/30 rounded-lg p-3 border border-white/5 max-h-40 overflow-y-auto scrollbar-thin">
                            <pre className="text-[10px] text-gray-400 font-mono whitespace-pre-wrap">
                                {typeof finding.raw === 'string' ? finding.raw : JSON.stringify(finding.raw, null, 2)}
                            </pre>
                        </div>
                    </details>
                )}
            </div>
        </Modal>
    );
}

export default React.memo(FindingDetailModal);
