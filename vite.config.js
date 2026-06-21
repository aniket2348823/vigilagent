import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Single source of truth for dev API key — must match docker-compose.yml default.
// In production, Nginx reads API_AUTH_KEY from the container environment.
const DEV_API_KEY = process.env.API_AUTH_KEY || 'dev-test-key-12345678901234567890';

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './src/test/setup.js',
        css: true,
        pool: 'vmThreads',
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

