import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Single source of truth for dev API key — must match docker-compose.yml default.
// In production, Nginx reads API_AUTH_KEY from the container environment.
// SECURITY: API_AUTH_KEY must be set in .env or shell for dev mode.
// The Vite dev proxy injects this server-side so it never reaches the browser.
const DEV_API_KEY = process.env.API_AUTH_KEY;
if (!DEV_API_KEY) {
    console.warn('[SECURITY] API_AUTH_KEY not set — Vite proxy will send empty key. Set it in your shell or .env file.');
}

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './src/test/setup.js',
        css: true,
        pool: 'vmThreads',
        exclude: [
            '**/node_modules/**',
            '**/dist/**',
            '**/data/scans/**',
            '**/extension/**',
        ],
    },
    server: {
        host: "0.0.0.0",
        proxy: {
            "/api": {
                target: "http://127.0.0.1:8000",
                changeOrigin: true,
                secure: false,
                configure: (proxy) => {
                    // Inject X-API-Key server-side so the key never reaches the browser.
                    proxy.on('proxyReq', (proxyReq) => {
                        proxyReq.setHeader('X-API-Key', DEV_API_KEY);
                    });
                }
            },
            "/stream": {
                target: "ws://127.0.0.1:8000",
                ws: true
            },
            "/ws/live": {
                target: "ws://127.0.0.1:8000",
                ws: true
            }
        }
    }
})

