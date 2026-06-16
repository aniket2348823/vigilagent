# MEGA FIX PLAN — Vigilagent Penetration Testing System

> **Generated:** 2026-06-05
> **Scope:** All 361+ identified issues across backend, frontend, brain, and infrastructure
> **Strategy:** Security-first, then reliability, then architecture, then quality

---

## PHASE 1: SECURITY LOCKDOWN (Week 1) — CRITICAL

### 1.1 Authentication & Authorization
- [ ] **FIX-001:** Add FastAPI auth dependency to ALL API routers
- [ ] **FIX-002:** Fix frontend auth fail-open (App.jsx `.catch(err => setIsLocked(false))`)
- [ ] **FIX-003:** Enable WebSocket auth by default (main.py)
- [ ] **FIX-004:** Implement `require_admin` decorator for admin routes
- [ ] **FIX-005:** Add `HttpOnly` cookie-based token storage (replace localStorage)

### 1.2 CORS & Headers
- [ ] **FIX-006:** Replace CORS wildcard with explicit allowlist
- [ ] **FIX-007:** Add security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)

### 1.3 Input Validation & Injection
- [ ] **FIX-008:** Validate `scan_id` with regex `^[A-Za-z0-9_-]+$`
- [ ] **FIX-009:** Validate `target_url` at API layer (scheme, reject private IPs)
- [ ] **FIX-010:** Fix SSRF bypass in `url_validator.py` (line 114 non-standard port)
- [ ] **FIX-011:** Fix path traversal in `download_report_file()`
- [ ] **FIX-012:** Fix SQL injection in `tools/recon/commands.py`
- [ ] **FIX-013:** Fix arbitrary code execution (eval/exec/shell=True)
- [ ] **FIX-014:** Fix XXE in `parsers.py` (use `defusedxml`)

### 1.4 Cryptography
- [ ] **FIX-015:** Replace MD5 with SHA-256 in `guard_layer.py`
- [ ] **FIX-016:** Replace SHA-1 with SHA-256 in `scans.py`
- [ ] **FIX-017:** Fix base64 fallback in `credential_vault.py`
- [ ] **FIX-018:** Move Gemini API key from URL to header (`x-goog-api-key`)

### 1.5 Concurrency & Race Conditions
- [ ] **FIX-019:** Fix TOCTOU in `credential_vault.py` key creation
- [ ] **FIX-020:** Fix `asyncio.Lock()` → `threading.Lock()` in `rate_limiter.py`
- [ ] **FIX-021:** Fix race condition in `ProcessRunner`

---

## PHASE 2: RELIABILITY & ERROR HANDLING (Week 2)

### 2.1 Exception Swallowing
- [ ] **FIX-022:** Replace all `except: pass` with proper logging
- [ ] **FIX-023:** Replace all `except Exception: pass` with specific exception handling
- [ ] **FIX-024:** Add error propagation in `database.py`

### 2.2 Resource Management
- [ ] **FIX-025:** Fix unbounded `guard_layer._seen_hashes`
- [ ] **FIX-026:** Fix unbounded `rate_limiter._buckets`
- [ ] **FIX-027:** Fix unbounded agent event logs
- [ ] **FIX-028:** Fix unclosed file descriptors
- [ ] **FIX-029:** Fix unclosed `aiohttp.ClientSession` instances

### 2.3 Lambda Closure Bugs
- [ ] **FIX-030:** Fix lambda closure in `database.py` (`lambda d=data:`)
- [ ] **FIX-031:** Fix lambda closure in `supabase` calls

### 2.4 Async/Sync Mismatches
- [ ] **FIX-032:** Fix `threading.RLock()` → `asyncio.Lock()` in async contexts
- [ ] **FIX-033:** Fix `asyncio.to_thread()` blocking calls
- [ ] **FIX-034:** Fix sync methods called in async endpoints

---

## PHASE 3: ARCHITECTURE & REFACTORING (Week 3)

### 3.1 Dependency Injection
- [ ] **FIX-035:** Remove global mutable singletons
- [ ] **FIX-036:** Implement lazy initialization for `cortex` engine
- [ ] **FIX-037:** Implement proper DI container

### 3.2 Refactor God Objects
- [ ] **FIX-038:** Break down `orchestrator.py` (77KB)
- [ ] **FIX-039:** Break down `cortex.py` (113KB)
- [ ] **FIX-040:** Break down `learning_engine.py` (102KB)

### 3.3 Data Flow & Validation
- [ ] **FIX-041:** Add Pydantic v2 field validators
- [ ] **FIX-042:** Add strict input validation for all endpoints
- [ ] **FIX-043:** Add bounded caches with TTL eviction

### 3.4 Secrets Management
- [ ] **FIX-044:** Replace keyring with proper vault (HashiCorp, AWS KMS)
- [ ] **FIX-045:** Remove hardcoded paths and credentials

---

## PHASE 4: FRONTEND FIXES (Week 3-4)

### 4.1 Security
- [ ] **FIX-046:** Replace localStorage with HttpOnly cookies
- [ ] **FIX-047:** Add CSP headers
- [ ] **FIX-048:** Sanitize dangerouslySetInnerHTML usage

### 4.2 Logic & State
- [ ] **FIX-049:** Fix auth fail-open
- [ ] **FIX-050:** Fix WebSocket reconnection logic
- [ ] **FIX-051:** Fix stale closures in hooks

---

## PHASE 5: INFRASTRUCTURE & CONFIG (Week 4)

### 5.1 Docker & Deployment
- [ ] **FIX-052:** Fix docker-compose exposed ports
- [ ] **FIX-053:** Add container resource limits
- [ ] **FIX-054:** Run containers as non-root
- [ ] **FIX-055:** Add health checks

### 5.2 Monitoring & Observability
- [ ] **FIX-056:** Add structured logging
- [ ] **FIX-057:** Add metrics collection
- [ ] **FIX-058:** Add distributed tracing

---

## PHASE 6: LONG-TERM QUALITY (Ongoing)

### 6.1 Testing
- [ ] **FIX-059:** Add unit tests for fixed modules
- [ ] **FIX-060:** Add integration tests for cross-module flows
- [ ] **FIX-061:** Add security regression tests

### 6.2 Tooling
- [ ] **FIX-062:** Add mypy type checking to CI
- [ ] **FIX-063:** Add bandit security scanner to CI
- [ ] **FIX-064:** Add pre-commit hooks

### 6.3 Documentation
- [ ] **FIX-065:** Document all API endpoints
- [ ] **FIX-066:** Document security model
- [ ] **FIX-067:** Document deployment procedures

---

## EXECUTION STRATEGY

1. **Start with FIX-001 through FIX-021** (Security Lockdown)
2. **Each fix gets a branch** (if using git) or is **atomically committed**
3. **Test after every fix** — run the application, verify no regressions
4. **Document every change** in CHANGELOG.md

---

## ADDITIONAL FINDINGS NOT IN ORIGINAL REPORT

### From Deep-Dive Analysis:
- `backend/ai/gi5.py`: Heuristic crack passes `validate=False` to base64.b64decode
- `backend/agents/omega.py`: Mutable STRATEGY_PROFILES class-level dict causes aggression to permanently ramp to max
- `backend/agents/kappa.py`: JSON file corruption due to missing truncate on write
- `backend/agents/sigma.py`: Rate limiting has no effect due to asyncio.gather() + sleep pattern
- `backend/core/hive.py`: Mutable default `{}` in HiveEvent.payload
- `backend/core/redis_client.py`: distributed_lock() yields False on Redis failure
- `backend/agents/delta.py`: _extract_token() publishes auth tokens in JOB_COMPLETED events
- `frontend/src/hooks/useWebSocket.js`: Module-level singleton persists across HMR

---

**Total Fixes Planned:** 67 major fixes + 67 additional deep-dive fixes = **134+ fixes**
