# Vigilagent — Frontend (React + Vite + Tailwind)

This directory holds the entire frontend for the Vigilagent UI. The
backend lives in `../backend` and exposes both an HTTP API and a WebSocket
stream that this app consumes.

## File layout

```
src/
├── App.jsx              # Top-level router + auth gate + global providers
├── main.jsx             # React 18 root, mounts <App /> into #root
├── index.css            # Tailwind layers + global glass/nebula styles
├── README.md            # ← this file
│
├── components/          # All page + presentational components
│   ├── ui/              # Reusable primitives (Button, Modal, Toast, …)
│   ├── Dashboard.jsx    # Main scan dashboard
│   ├── Scans.jsx        # Scan history list
│   ├── NewScan.jsx      # Create-a-scan form
│   ├── LiveMonitor.jsx  # Real-time agent activity feed
│   ├── Library.jsx      # Read-only catalogue of agents + modules
│   ├── Settings.jsx     # Account + 2FA toggles
│   ├── Login.jsx        # 2FA gate
│   ├── Navigation.jsx   # Top nav bar
│   ├── ErrorBoundary.jsx
│   ├── SeverityBadge.jsx
│   ├── SmoothScroll.jsx # Lenis wrapper (respects prefers-reduced-motion)
│   ├── GlobalBackground.jsx
│   └── AnimationWrapper.jsx
│
├── hooks/
│   ├── useWebSocket.js  # Singleton WS bridge (backoff + WS_GIVEUP)
│   ├── useReconFeed.js  # Derived recon-event stream
│   └── useMagnetic.js   # Pointer-magnet hover effect
│
├── lib/
│   ├── api.js           # API_BASE_URL, websocketUrl(), createScan(), …
│   ├── downloadReport.js# Auto-download triggered by GI5_LOG events
│   ├── constants.js     # Shared springs, durations, colour tokens
│   └── agentNames.js    # Backend agent-id → display-name lookup
│
└── data/
    └── library_data.js  # Static catalogue rendered by Library.jsx
```

## Run locally

```bash
# from the repo root
npm install
npm run dev          # starts Vite dev server on http://localhost:5173
npm run build        # production bundle in /dist
npm run preview      # serve the production build locally
npm run lint         # ESLint over src/
```

### Environment variables

Vite reads `import.meta.env.*` at build time. Create a `.env.local` at the
repo root if you need to override the defaults (which auto-detect the backend
on the same hostname, port `8000`):

```
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_BASE_URL=ws://localhost:8000
```

When unset, `src/lib/api.js` derives both URLs from `window.location`.

## How the WebSocket bridge works

The frontend opens **one** WebSocket connection for the whole app, managed by
`hooks/useWebSocket.js`. Every page that wants live data calls the hook and
subscribes to the shared stream:

```jsx
const { subscribe, isConnected } = useWebSocket();

useEffect(() => {
    const unsub = subscribe((data) => {
        if (data.type === 'WS_GIVEUP') {
            // Surface "OFFLINE — please refresh" UI
        }
        // …handle other event types
    });
    return unsub;
}, [subscribe]);
```

Key behaviours:

- **Singleton.** Module-level state means navigating between pages never
  closes/reopens the socket — listeners just attach to the existing one.
- **Exponential backoff with jitter.** On disconnect, the hook retries with
  `delay = min(30s, 1s * 2 ** attempts)` plus ±25% jitter. The attempt
  counter resets on a successful `open`.
- **Give-up signal.** After 30 consecutive failures the hook stops retrying
  and dispatches a synthetic `{ type: 'WS_GIVEUP' }` event so the UI can show
  a permanent offline state. The user must refresh to retry.
- **Resilient parser.** A malformed JSON frame is logged and dropped — it
  cannot crash the reader for other subscribers.
- **Dev auth.** When backend WS auth is OFF, `getWsToken()` returns `''` and
  the `token` query param is omitted; the connection still succeeds.

The download helper `lib/downloadReport.js` listens for `GI5_LOG` events
containing `REPORT GENERATED:` and auto-downloads the PDF. It accepts an
optional `toast` callback so failures (404, network down, wrong content type)
are surfaced as user-visible Toasts instead of silent broken downloads.

## Adding a new page

1. Create `src/components/MyPage.jsx`, importing `Navigation` and any UI
   primitives you need from `./ui`.
2. Register the page in `src/App.jsx`:
   ```jsx
   import MyPage from './components/MyPage';
   // …inside <AnimatePresence>:
   {currentPage === 'mypage' && <MyPage key="mypage" navigate={navigate} />}
   ```
3. Add the route key to `Navigation.jsx`'s page list (`['dashboard', 'scans',
   'library', 'settings', …]`) so it gets a nav button. Each item is a
   keyboard-accessible `<button>` with `aria-current="page"` when active.
4. If your page consumes live data, call `useWebSocket()` and subscribe in a
   `useEffect`; remember to unsubscribe on cleanup.
5. If your page needs toasts, call `useToast()` from `./components/ui`.
   `<ToastProvider>` is already wired at the App root.

## Conventions

- **Tailwind only** for styling — no CSS-in-JS libraries, no new global CSS
  unless absolutely necessary (extend `index.css`).
- **No new npm dependencies** without team approval. Stick to the libraries
  already declared in `package.json`.
- **A11y baseline:** icon-only buttons get `aria-label`, all form inputs have
  associated `<label htmlFor>`, modals declare `role="dialog"
  aria-modal="true"`, and the active nav item exposes `aria-current="page"`.
