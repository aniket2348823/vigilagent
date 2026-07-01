import React from 'react';
import { motion } from 'framer-motion';
import { LIQUID_SPRING } from '../lib/constants';
import Navigation from './Navigation';
import MitreHeatmap from './dashboard/MitreHeatmap';
import CveCorrelation from './dashboard/CveCorrelation';
import SbomConfig from './dashboard/SbomConfig';

export default function Vulnerabilities({ navigate }) {
    return (
        <div className="min-h-screen relative overflow-x-hidden" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            <div className="relative z-10 flex flex-col min-h-screen">
                <Navigation navigate={navigate} activePage="vulnerabilities" />

                <main className="flex-grow px-6 pb-6 w-full max-w-7xl mx-auto space-y-6">
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...LIQUID_SPRING, duration: 0.5 }}
                        className="mt-4 mb-6"
                    >
                        <h1 className="text-3xl font-bold mb-1 text-white">Vulnerabilities</h1>
                        <p className="text-gray-400 text-sm">
                            CVE correlation, MITRE ATT&CK coverage, and SBOM scanner configuration.
                        </p>
                    </motion.div>

                    {/* MITRE ATT&CK Heatmap */}
                    <MitreHeatmap />

                    {/* CVE Correlation */}
                    <CveCorrelation />

                    {/* SBOM Config */}
                    <SbomConfig />
                </main>

                <footer className="w-full text-center py-6 text-xs text-gray-600 relative z-10">
                    Vigilagent Intelligence Backbone © 2025-2026
                </footer>
            </div>
        </div>
    );
}
