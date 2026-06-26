# Vigilagent - API Reference

**Last Updated**: May 25, 2026  
**Version**: 5.0  
**Status**: Production Ready

---

## Table of Contents

1. [Core Components](#core-components)
   - [StateManager](#statemanager)
   - [BrowserOrchestrator](#browserorchestrator)
   - [TaskManager](#taskmanager)
2. [Security Components](#security-components)
   - [RateLimiter](#ratelimiter)
   - [URLValidator](#urlvalidator)
   - [CSRFProtection](#csrfprotection)
3. [Browser Engines](#browser-engines)
   - [OpenClawEngine](#openclawengine)
   - [PinchTabEngine](#pinchtabengine)
4. [Session & Forensics](#session--forensics)
   - [HybridSessionManager](#hybridsessionmanager)
   - [ForensicCollector](#forensiccollector)
5. [Agents](#agents)
   - [AlphaAgent](#alphaagent)
   - [BetaAgent](#betaagent)
   - [GammaAgent](#gammaagent)

---

## Core Components

### StateManager

**Location**: `backend/core/state.py`

Manages application state, scan records, and vulnerability findings with async-safe operations.

#### Key Methods

##### `async register_scan(scan_data: Dict[str, Any])`
Register a new scan in the system.

**Parameters**:
- `scan_data`: Dictionary containing scan configuration
  - `id` (str): Unique scan identifier
  - `status` (str): Initial status (e.g., "Initializing")
  - `name` (str): Scan name/target
  - `scope` (str): Target URL or scope
  - `modules` (List[str]): Modules to run
  - `timestamp` (str): Start timestamp

**Example**:
```python
scan_data = {
    "id": "scan-001",
    "status": "Initializing",
    "name": "https://example.com",
    "scope": "https://example.com",
    "modules": ["Alpha", "Beta"],
    "timestamp": "2026-05-25 10:00:00"
}
await state_manager.register_scan(scan_data)
```

##### `async record_finding(scan_id: str, severity: str, signature_data: Dict[str, Any])`
Record a vulnerability finding with automatic deduplication.

**Parameters**:
- `scan_id` (str): Scan identifier
- `severity` (str): Severity level ("Critical", "High", "Medium", "Low")
- `signature_data` (Dict): Vulnerability signature for deduplication
  - `url` (str): Affected URL
  - `type` (str): Vulnerability type (e.g., "XSS", "SQLI")
  - `data` (str): Payload or evidence

**Example**:
```python
signature = {
    "url": "https://example.com/search",
    "type": "XSS",
    "data": "<script>alert(1)</script>"
}
await state_manager.record_finding("scan-001", "High", signature)
```

##### `async read_scan_state(scan_id: str) -> Dict[str, Any]`
Read the current state of a scan.

**Returns**: Dictionary containing scan state or empty dict if not found

**Example**:
```python
scan_state = await state_manager.read_scan_state("scan-001")
print(f"Status: {scan_state.get('status')}")
```

##### `async write_scan_state(scan_id: str, data: dict)`
Write/update scan state to persistent storage.

**Parameters**:
- `scan_id` (str): Scan identifier
- `data` (dict): Complete scan state data

**Example**:
```python
scan_state = await state_manager.read_scan_state("scan-001")
scan_state["status"] = "Running"
scan_state["progress"] = 50
await state_manager.write_scan_state("scan-001", scan_state)
```

##### `sync_complete_scan(scan_id: str, status: str = "Completed", report_ready: bool = True)`
Atomically mark a scan as complete.

**Parameters**:
- `scan_id` (str): Scan identifier
- `status` (str): Final status (default: "Completed")
- `report_ready` (bool): Whether report is ready (default: True)

**Example**:
```python
state_manager.sync_complete_scan("scan-001", status="Completed", report_ready=True)
```

---

### BrowserOrchestrator

**Location**: `backend/core/browser_orchestrator.py`

Manages browser contexts, engines, and resource pooling for efficient browser automation.

#### Key Methods

##### `async initialize(lazy: bool = False)`
Initialize the browser orchestrator and engines.

**Parameters**:
- `lazy` (bool): If True, delay engine initialization until first use

**Example**:
```python
orchestrator = BrowserOrchestrator()
await orchestrator.initialize(lazy=True)
```

##### `async get_context(scan_id: str) -> BrowserContext`
Get or create a browser context for a scan.

**Parameters**:
- `scan_id` (str): Scan identifier

**Returns**: Playwright BrowserContext object

**Example**:
```python
context = await orchestrator.get_context("scan-001")
page = await context.new_page()
await page.goto("https://example.com")
```

##### `async release_context(scan_id: str)`
Release a browser context back to the pool.

**Parameters**:
- `scan_id` (str): Scan identifier

**Example**:
```python
await orchestrator.release_context("scan-001")
```

##### `get_resource_stats() -> Dict[str, Any]`
Get current resource usage statistics.

**Returns**: Dictionary with resource metrics
- `active_contexts` (int): Number of active contexts
- `pooled_contexts` (int): Number of pooled contexts
- `memory_mb` (float): Current memory usage in MB

**Example**:
```python
stats = orchestrator.get_resource_stats()
print(f"Active contexts: {stats['active_contexts']}")
print(f"Memory usage: {stats['memory_mb']} MB")
```

##### `async cleanup()`
Clean up all browser resources.

**Example**:
```python
await orchestrator.cleanup()
```

---

### TaskManager

**Location**: `backend/core/task_manager.py`

Manages async tasks with proper lifecycle tracking and cleanup.

#### Key Methods

##### `create_task(coro, name: str = None) -> asyncio.Task`
Create and track an async task.

**Parameters**:
- `coro`: Coroutine to execute
- `name` (str): Optional task name for debugging

**Returns**: asyncio.Task object

**Example**:
```python
task_manager = TaskManager("MyComponent")

async def my_background_task():
    while True:
        await asyncio.sleep(1)
        print("Running...")

task = task_manager.create_task(my_background_task(), name="background_worker")
```

##### `async cancel_all()`
Cancel all tracked tasks.

**Example**:
```python
await task_manager.cancel_all()
```

##### `get_active_tasks() -> List[asyncio.Task]`
Get list of currently active tasks.

**Returns**: List of active Task objects

**Example**:
```python
active = task_manager.get_active_tasks()
print(f"Active tasks: {len(active)}")
```

---

## Security Components

### RateLimiter

**Location**: `backend/core/rate_limiter.py`

Token bucket rate limiter for API endpoint protection.

#### Key Methods

##### `configure_limit(endpoint: str, requests_per_minute: int)`
Configure rate limit for an endpoint.

**Parameters**:
- `endpoint` (str): Endpoint path (e.g., "/api/scan")
- `requests_per_minute` (int): Maximum requests per minute

**Example**:
```python
rate_limiter = RateLimiter()
rate_limiter.configure_limit("/api/scan", 10)  # 10 requests/minute
```

##### `async check_rate_limit(endpoint: str, client_ip: str)`
Check if request is within rate limit.

**Parameters**:
- `endpoint` (str): Endpoint path
- `client_ip` (str): Client IP address

**Raises**: `HTTPException` with status 429 if rate limit exceeded

**Example**:
```python
try:
    await rate_limiter.check_rate_limit("/api/scan", "192.168.1.1")
    # Process request
except HTTPException as e:
    # Rate limit exceeded
    return {"error": "Too many requests"}
```

---

### URLValidator

**Location**: `backend/core/url_validator.py`

Validates URLs to prevent SSRF attacks.

#### Key Methods

##### `validate(url: str) -> Tuple[bool, str]`
Validate a URL for security issues.

**Parameters**:
- `url` (str): URL to validate

**Returns**: Tuple of (is_valid, reason)
- `is_valid` (bool): True if URL is safe
- `reason` (str): Reason for rejection if invalid

**Example**:
```python
validator = URLValidator()

is_valid, reason = validator.validate("https://example.com")
if is_valid:
    # Proceed with request
    pass
else:
    print(f"Invalid URL: {reason}")
```

**Blocked Patterns**:
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Localhost/private IPs
- Dangerous protocols (file://, gopher://)
- SQL injection characters

---

### CSRFProtection

**Location**: `backend/core/csrf_protection.py`

Token-based CSRF protection for state-changing operations.

#### Key Methods

##### `generate_token(session_id: str) -> str`
Generate a CSRF token for a session.

**Parameters**:
- `session_id` (str): Session identifier

**Returns**: CSRF token string

**Example**:
```python
csrf = CSRFProtection()
token = csrf.generate_token("session-123")
# Return token to client
```

##### `validate_token(token: str, session_id: str) -> bool`
Validate a CSRF token.

**Parameters**:
- `token` (str): CSRF token from client
- `session_id` (str): Session identifier

**Returns**: True if token is valid

**Example**:
```python
is_valid = csrf.validate_token(client_token, "session-123")
if not is_valid:
    raise HTTPException(status_code=403, detail="Invalid CSRF token")
```

---

## Browser Engines

### OpenClawEngine

**Location**: `backend/core/openclaw_engine.py`

Playwright-based browser engine for reconnaissance and endpoint discovery.

#### Key Methods

##### `async navigate(url: str) -> Dict[str, Any]`
Navigate to a URL and extract information.

**Parameters**:
- `url` (str): Target URL

**Returns**: Dictionary with navigation results
- `success` (bool): Whether navigation succeeded
- `endpoints` (List[str]): Discovered endpoints
- `forms` (List[Dict]): Discovered forms

**Example**:
```python
engine = OpenClawEngine()
await engine.initialize()

result = await engine.navigate("https://example.com")
print(f"Found {len(result['endpoints'])} endpoints")
```

---

### PinchTabEngine

**Location**: `backend/core/pinchtab_engine.py`

Advanced browser engine for token extraction and injection testing.

#### Key Methods

##### `async extract_tokens(url: str) -> List[str]`
Extract authentication tokens from a page.

**Parameters**:
- `url` (str): Target URL

**Returns**: List of extracted tokens

**Example**:
```python
engine = PinchTabEngine()
await engine.initialize()

tokens = await engine.extract_tokens("https://example.com/login")
print(f"Found {len(tokens)} tokens")
```

---

## Session & Forensics

### HybridSessionManager

**Location**: `backend/core/hybrid_session_manager.py`

Manages browser sessions with automatic sanitization of sensitive data.

#### Key Methods

##### `async save_session(scan_id: str, session_data: Dict[str, Any])`
Save session data with automatic sanitization.

**Parameters**:
- `scan_id` (str): Scan identifier
- `session_data` (Dict): Session data to save

**Example**:
```python
session_manager = HybridSessionManager()

session_data = {
    "cookies": [...],
    "localStorage": {...},
    "sessionStorage": {...}
}

await session_manager.save_session("scan-001", session_data)
```

##### `async load_session(scan_id: str) -> Dict[str, Any]`
Load sanitized session data.

**Parameters**:
- `scan_id` (str): Scan identifier

**Returns**: Sanitized session data

**Example**:
```python
session_data = await session_manager.load_session("scan-001")
```

---

### ForensicCollector

**Location**: `backend/core/forensic_collector.py`

Collects and encrypts forensic evidence during scans.

#### Key Methods

##### `async capture_screenshot(scan_id: str, page: Page, name: str)`
Capture and encrypt a screenshot.

**Parameters**:
- `scan_id` (str): Scan identifier
- `page` (Page): Playwright page object
- `name` (str): Screenshot name

**Example**:
```python
collector = ForensicCollector()

await collector.capture_screenshot("scan-001", page, "login_page")
```

##### `async collect_evidence(scan_id: str, evidence_type: str, data: Any)`
Collect and encrypt evidence.

**Parameters**:
- `scan_id` (str): Scan identifier
- `evidence_type` (str): Type of evidence
- `data` (Any): Evidence data

**Example**:
```python
await collector.collect_evidence("scan-001", "network_log", network_data)
```

---

## Agents

### AlphaAgent

**Location**: `backend/agents/alpha.py`

Reconnaissance agent for endpoint discovery and API classification.

#### Key Methods

##### `async discover_endpoints(url: str) -> List[str]`
Discover API endpoints on a target.

**Parameters**:
- `url` (str): Target URL

**Returns**: List of discovered endpoints

**Example**:
```python
alpha = AlphaAgent(event_bus)
await alpha.start()

endpoints = await alpha.discover_endpoints("https://api.example.com")
```

---

### BetaAgent

**Location**: `backend/agents/beta.py`

Attack agent for vulnerability testing and exploitation.

#### Key Methods

##### `async test_csrf_bypass(url: str) -> Dict[str, Any]`
Test CSRF protection bypass techniques.

**Parameters**:
- `url` (str): Target URL

**Returns**: Dictionary with test results

**Example**:
```python
beta = BetaAgent(event_bus)
await beta.start()

result = await beta.test_csrf_bypass("https://example.com/api/update")
```

---

### GammaAgent

**Location**: `backend/agents/gamma.py`

Forensic analysis agent for network traffic monitoring.

#### Key Methods

##### `async analyze_network_traffic(scan_id: str) -> Dict[str, Any]`
Analyze network traffic for suspicious patterns.

**Parameters**:
- `scan_id` (str): Scan identifier

**Returns**: Dictionary with analysis results

**Example**:
```python
gamma = GammaAgent(event_bus)
await gamma.start()

analysis = await gamma.analyze_network_traffic("scan-001")
```

---

## Best Practices

### Error Handling

Always use specific exception types and log errors:

```python
try:
    result = await some_operation()
except ValueError as e:
    logger.error(f"Invalid value: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise
```

### Async Task Management

Always use TaskManager for background tasks:

```python
task_manager = TaskManager("MyComponent")

# Create task
task = task_manager.create_task(background_work(), name="worker")

# Cleanup on shutdown
await task_manager.cancel_all()
```

### Resource Cleanup

Always clean up resources in finally blocks:

```python
context = None
try:
    context = await orchestrator.get_context("scan-001")
    # Use context
finally:
    if context:
        await orchestrator.release_context("scan-001")
```

### Security

Always validate user input:

```python
# Validate URLs
is_valid, reason = url_validator.validate(user_url)
if not is_valid:
    raise ValueError(f"Invalid URL: {reason}")

# Check rate limits
await rate_limiter.check_rate_limit(endpoint, client_ip)

# Validate CSRF tokens
if not csrf.validate_token(token, session_id):
    raise HTTPException(status_code=403)
```

---

## See Also

- [Architecture Documentation](ARCHITECTURE.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)
- [Performance Tuning Guide](PERFORMANCE.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Last Updated**: May 25, 2026  
**Maintainer**: Vigilagent Team  
**Status**: Production Ready
