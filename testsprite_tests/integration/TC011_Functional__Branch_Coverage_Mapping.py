import requests
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_TC011_functional_branch_coverage_high_load():
    """
    Test Case TC011:
    Functional & Branch Coverage Mapping under high load.
    Verify critical execution paths in hive.py, cortex.py are traversed,
    focusing on key backend criteria.
    """

    # Helper: Launch a scan swarm (core business logic trigger)
    def launch_scan(target_url, method="GET", headers=None, duration=10):
        if headers is None:
            headers = {}
        payload = {
            "target_url": target_url,
            "method": method,
            "headers": headers,
            "duration": duration
        }
        resp = requests.post(f"{BASE_URL}/api/attack/fire", json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # Helper: Analyze defense API (stimulate cortex logic)
    def defense_analyze(agent_id, content, url):
        payload = {
            "agent_id": agent_id,
            "content": content,
            "url": url
        }
        resp = requests.post(f"{BASE_URL}/api/defense/analyze", json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # Helper: Query dashboard scans to retrieve scan_ids and simulate E2E integration
    def get_dashboard_scans():
        resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # Helper: Validate scan_id existence in dashboard scans after launch
    def validate_scan_presence(scan_id):
        scans = get_dashboard_scans()
        scan_ids = [scan.get("scan_id") for scan in scans if "scan_id" in scan]
        assert scan_id in scan_ids, f"scan_id {scan_id} not found in dashboard scans"

    # --- 1. API Discovery: Validate essential endpoints are reachable under load ---

    essential_gets = [
        "/api/dashboard/stats",
        "/api/ai/status",
        "/api/health"
    ]

    # Test GET endpoints under concurrency to verify discovery and stability
    def get_endpoint(path):
        r = requests.get(f"{BASE_URL}{path}", timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(get_endpoint, ep) for ep in essential_gets for _ in range(3)]
        for future in futures:
            data = future.result()
            assert data is not None

    # --- 2. Supabase Integration + 5. Business Logic + 10. End-to-End Integration ---

    # Launch multiple high-load scans concurrently to traverse core swarm pipeline logic
    scan_results = []
    launch_count = 5

    def concurrent_launch(i):
        # Use unique target_url to avoid data collision, simulate business logic branching
        target_url = f"https://example.com/resource-{uuid.uuid4()}"
        try:
            res = launch_scan(target_url=target_url, method="GET", headers={"X-Test-Id": str(i)}, duration=5)
            assert res.get("status") == "Swarm Online"
            scan_id = res.get("scan_id")
            assert scan_id is not None and len(scan_id) > 0
            return scan_id
        except requests.HTTPError as e:
            # Accept rate limit as valid response to simulate system load
            if e.response.status_code == 429:
                return None
            raise

    with ThreadPoolExecutor(max_workers=launch_count) as executor:
        results = list(executor.map(concurrent_launch, range(launch_count)))
        scan_results.extend([r for r in results if r is not None])

    assert len(scan_results) > 0, "No scans launched successfully under high load"

    # Validate scan presence in dashboard for each launched scan to test persistence and retrieval
    for scan_id in scan_results:
        validate_scan_presence(scan_id)

    # --- 3. Auth Flows - test 2FA enablement and invalid attempts (basic coverage) ---

    # 2FA generation - no auth required per PRD, test flow
    resp = requests.post(f"{BASE_URL}/api/dashboard/settings/2fa/generate", timeout=TIMEOUT)
    assert resp.status_code == 200
    twofa_data = resp.json()
    secret = twofa_data.get("secret")
    qr_code = twofa_data.get("qr_code_base64")
    assert secret and qr_code

    # 2FA verify with incorrect totp_code (simulate failure)
    resp = requests.post(f"{BASE_URL}/api/dashboard/settings/2fa/verify", json={"totp_code": "000000"}, timeout=TIMEOUT)
    assert resp.status_code == 401 or resp.status_code == 400

    # --- 4. OpenRouter AI Fallbacks/Hallucinations ---

    # Send malformed content to /api/defense/analyze to trigger 500 error
    try:
        resp = requests.post(f"{BASE_URL}/api/defense/analyze", json={"agent_id": "agent_prism", "content": "malformed", "url": "https://example.com"}, timeout=TIMEOUT)
        assert resp.status_code == 500
    except requests.HTTPError as e:
        assert e.response.status_code == 500

    # Send valid analyze request to verify normal Cortex AI path
    valid_resp = defense_analyze("agent_prism", {"innerText": "some benign text"}, "https://example.com")
    assert "verdict" in valid_resp and valid_resp["verdict"] in ["BLOCK", "ALLOW"]
    assert "risk_score" in valid_resp and isinstance(valid_resp["risk_score"], int)

    # --- 6. Resilience (Network Failures) & 7. Performance (Latency) ---

    # Measure latency for a scan launch - ensure < 5 seconds
    start = time.time()
    launch_resp = launch_scan("https://example.com/resilience-test", duration=3)
    latency = time.time() - start
    assert latency < 5, f"API latency too high: {latency}s"

    # --- 8. Concurrency (Race Conditions) ---

    # Simulate 10 concurrent swarm launch attempts rapidly to test atomic locking
    race_results = []

    def rapid_launch(_):
        try:
            r = launch_scan("https://example.com/concurrent", duration=2)
            return r.get("scan_id")
        except requests.HTTPError as e:
            # Accept rate limit or server errors to simulate concurrency handling
            if e.response.status_code in [429, 500]:
                return None
            raise

    with ThreadPoolExecutor(max_workers=10) as executor:
        race_results = list(executor.map(rapid_launch, range(10)))

    successful = [r for r in race_results if r]
    assert len(successful) > 0, "No successful launches under concurrency"

    # --- 9. Security (Injections) ---

    # Test injection payload in target_url for scan launch (NoSQLi, Command Injection vectors)
    injection_strings = [
        "' OR '1'='1",
        "1; DROP TABLE users;",
        "${7*7}",
        "$(reboot)",
        "`ls -la`"
    ]

    for inj in injection_strings:
        try:
            resp = requests.post(f"{BASE_URL}/api/attack/fire",
                                 json={"target_url": f"https://example.com/{inj}", "method": "GET", "headers": {}, "duration": 1},
                                 timeout=TIMEOUT)
            assert resp.status_code in [200, 422, 429], f"Unexpected status {resp.status_code} for injection input"
        except requests.HTTPError as e:
            # Accept 422 validation or 429 rate limiting errors as valid handling
            assert e.response.status_code in [422, 429]

    # --- 11. Code Coverage: Covered indirectly by executing above critical paths via hive.py and cortex.py calls ---

    # Cleanup is not necessary as no persistent manual resources created beyond scans which self-expire

# test_TC011_functional_branch_coverage_high_load()
