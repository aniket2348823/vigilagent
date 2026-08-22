import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Resolve the directory that actually holds .env. Vite may bundle this config
// to a temp file before loading it, which makes import.meta.url point at a
// temp dir with no .env — loadEnv then returns nothing and the proxy silently
// falls back to a stale shell API_AUTH_KEY (every /api call 401s). So we probe
// each candidate and only trust a directory that demonstrably contains .env.
function resolveEnvDir() {
    const candidates = [
        fileURLToPath(new URL('.', import.meta.url)),
        process.cwd(),
    ];
    for (const dir of candidates) {
        try {
            if (fs.existsSync(path.join(dir, '.env'))) return dir;
        } catch { /* ignore unreadable candidate */ }
    }
    return candidates[0];
}

// Single source of truth for dev API key — must match docker-compose.yml default.
// In production, Nginx reads API_AUTH_KEY from the container environment.
// SECURITY: API_AUTH_KEY must be set in .env or shell for dev mode.
// The Vite dev proxy injects this server-side so it never reaches the browser.
//
// FIX: read the key through loadEnv() and PREFER the .env value over the shell
// env. The backend also loads API_AUTH_KEY from .env, so .env is the single
// source of truth for local dev. Before this fix a stale key exported in the
// shell env (e.g. an older API_AUTH_KEY) won over .env, the proxy injected the
// wrong X-API-Key, and every /api request returned 401 (key_present=True).
//
// FIX 2: resolve the env dir from THIS config file's own directory, not
// process.cwd(). Vite launched as a bare `node .../vite.js` from another
// directory (IDE action, shortcut, script) has a different CWD, loadEnv then
// missed .env entirely and silently fell back to a stale shell API_AUTH_KEY —
// the proxy kept injecting a wrong key and every /api call 401'd again.
export default defineConfig(({ mode }) => {
    const envDir = resolveEnvDir();
    const env = loadEnv(mode, envDir, '');
    const DEV_API_KEY = env.API_AUTH_KEY || process.env.API_AUTH_KEY;
    if (!DEV_API_KEY) {
        console.warn('[SECURITY] API_AUTH_KEY not set — Vite proxy will send empty key. Set it in your shell or .env file.');
    } else {
        // Same sha256-prefix fingerprint the backend logs at startup — compare
        // the two to spot a key mismatch in seconds (never prints the key).
        const fp = createHash('sha256').update(DEV_API_KEY).digest('hex').slice(0, 12);
        console.log(`[SECURITY] Vite proxy API key fingerprint: sha256:${fp}`);
    }

    return {
        plugins: [react()],
        test: {
            globals: true,
            environment: 'jsdom',
            setupFiles: ['./src/test/setup.js'],
            css: true,
            pool: 'vmThreads',
            include: ['src/test/**/*.test.{js,jsx}'],
            exclude: [
                '**/node_modules/**',
                '**/dist/**',
                '**/data/scans/**',
                '**/extension/**',
            ],
            // Use modern Rolldown instead of deprecated esbuild
            // oxc is now the default in Vite 5.2+
        },
        build: {
            rollupOptions: {
                output: {
                    // Stable vendor chunks → long-term browser cache hits across
                    // redeploys (only app code changes hash, not the vendors).
                    manualChunks: {
                        'vendor-react': ['react', 'react-dom'],
                        'vendor-motion': ['framer-motion'],
                        'vendor-lenis': ['lenis'],
                    },
                },
            },
        },
        server: {
            host: "0.0.0.0",
            // Dev first-load speed: pre-transform the entry graph when the dev
            // server starts, so the first browser request doesn't pay the full
            // on-demand JSX/CSS transform cost (cold-start blanking).
            warmup: {
                clientFiles: [
                    'src/main.jsx',
                    'src/App.jsx',
                    'src/components/Dashboard.jsx',
                    'src/index.css',
                ],
            },
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
    };
});
