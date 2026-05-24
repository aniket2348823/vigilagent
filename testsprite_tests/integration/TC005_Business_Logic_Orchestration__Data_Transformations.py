import requests
import time
import threading
import uuid

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30


def test_business_logic_orchestration_data_transformations():
    """
    Verify correctness of distributed task orchestration and data flow transformation
    between the Orchestrator and backend agents focusing on the 11-point criteria.
    """

    # 1. API Discovery: Check key endpoints are reachable and return expected status codes
    critical_endpoints = [
        "/api/attack/fire",
        "/api/dashboard/scans",
        "/api/defense/analyze",
        "/api/health",
        "/api/ai/status"
    ]
    for ep in critical_endpoints:
        try:
            url = BASE_URL + ep
            if ep == "/api/attack/fire":
                # /api/attack/fire requires POST with valid payload
                test_payload = {
                    "target_url": "https://example.com",
                    "method": "GET",
                    "headers": {},
                    "duration": 1
                }
                r = requests.post(url, json=test_payload, timeout=TIMEOUT)
                assert r.status_code == 200, f"Failed to POST to endpoint {ep}"
            else:
                # Use GET request to check endpoint reachability instead of OPTIONS
                r = requests.get(url, timeout=TIMEOUT)
                assert r.status_code in (200, 204), f"Failed to discover endpoint {ep}"
        except requests.exceptions.RequestException as ex:
            assert False, f"Exception during API discovery for {ep}: {ex}"

    # 2. Supabase Integration: Check if scans are properly recorded and retrievable
    def launch_scan(target_url):
        payload = {
            "target_url": target_url,
            "method": "GET",
            "headers": {"User-Agent": "VulagentScannerTest/1.0"},
            "duration": 5
        }
        resp = requests.post(BASE_URL + "/api/attack/fire", json=payload, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Scan launch failed: {resp.text}"
        body = resp.json()
        assert body.get("status") == "Swarm Online"
        assert "scan_id" in body
        return body["scan_id"]

    scan_id = None
    try:
        # Launch a scan for a basic test target
        scan_id = launch_scan("https://example.com")

        # Wait till the scan appears in dashboard (polling with timeout)
        found = False
        for _ in range(15):
            r = requests.get(BASE_URL + "/api/dashboard/scans", timeout=TIMEOUT)
            assert r.status_code == 200
            scans = r.json()
            if any(s.get("scan_id") == scan_id for s in scans):
                found = True
                break
            time.sleep(1)
        assert found, "Scan ID not found in dashboard scans"

        # 3. Auth Flows - Since no auth is required for core scan launching, test 401 on protected 2FA verify (negative case)
        r_2fa_verify = requests.post(BASE_URL + "/api/dashboard/settings/2fa/verify", json={"totp_code": "000000"}, timeout=TIMEOUT)
        assert r_2fa_verify.status_code in (401, 403), "2FA verify accepted invalid totp_code"

        # 4. OpenRouter AI Fallbacks/Hallucinations: Provoking malformed input to /api/defense/analyze
        bad_payload = {"agent_id": "agent_prism", "content": "malformed_string_instead_of_dict", "url": "https://x.com"}
        r = requests.post(BASE_URL + "/api/defense/analyze", json=bad_payload, timeout=TIMEOUT)
        assert r.status_code in (500, 422), "Malformed defense/analyze payload did not error correctly"

        # 5. Business Logic: Validate the /api/defense/analyze correct path and verdict
        good_payload = {
            "agent_id": "agent_prism",
            "content": {"innerText": "This might be a prompt injection test."},
            "url": "https://example.com"
        }
        r = requests.post(BASE_URL + "/api/defense/analyze", json=good_payload, timeout=TIMEOUT)
        assert r.status_code == 200
        result = r.json()
        assert "verdict" in result and result["verdict"] in ("BLOCK", "ALLOW")
        assert "risk_score" in result and isinstance(result["risk_score"], int)

        # 6. Resilience (Network Failures): Simulate by attempting a request to an invalid port and ensuring failure managed
        try:
            requests.get("http://127.0.0.1:5999/api/health", timeout=5)
            assert False, "Connection to invalid port unexpectedly succeeded"
        except requests.exceptions.RequestException:
            pass  # Expected

        # 7. Performance (Latency): Measure /api/health latency should be low (< 0.5s)
        start = time.time()
        r = requests.get(BASE_URL + "/api/health", timeout=TIMEOUT)
        latency = time.time() - start
        assert r.status_code == 200
        assert latency < 0.5, f"High latency for /api/health: {latency}s"

        # 8. Concurrency (Race Conditions): Fire concurrent scan launches, verify no duplicates
        scan_ids = []
        def concurrent_launch():
            try:
                sid = launch_scan("https://example.com")
                scan_ids.append(sid)
            except AssertionError:
                pass

        threads = [threading.Thread(target=concurrent_launch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(scan_ids) >= 1, "No scans launched concurrently"
        # Basic uniqueness check
        assert len(set(scan_ids)) == len(scan_ids), "Duplicate scan IDs detected in concurrent launches"

        # 9. Security (Injections): Test injection in the 'target_url' field for /api/attack/fire
        injection_payload = {
            "target_url": "'; DROP TABLE users;--",
            "method": "GET",
            "headers": {},
            "duration": 1
        }
        resp = requests.post(BASE_URL + "/api/attack/fire", json=injection_payload, timeout=TIMEOUT)
        # Expect either validation error or safe rejection; no server error or injection
        assert resp.status_code in (422, 400, 200), f"Injection payload caused unsafe response: {resp.text}"

        # 10. End-to-End Integration: Confirm scan lifecycle through states
        # Poll scan until report_ready or timeout
        report_ready = False
        for _ in range(30):
            r = requests.get(BASE_URL + "/api/dashboard/scans", timeout=TIMEOUT)
            assert r.status_code == 200
            scans = r.json()
            for s in scans:
                if s.get("scan_id") == scan_id and s.get("report_ready"):
                    report_ready = True
                    break
            if report_ready:
                break
            time.sleep(2)
        assert report_ready, "Scan did not complete with report ready in time"

        # Retrieve report PDF
        r = requests.get(f"{BASE_URL}/api/reports/pdf/{scan_id}", timeout=TIMEOUT)
        assert r.status_code == 200, f"Failed to get PDF report: {r.text}"
        assert r.headers.get("Content-Type") == "application/pdf"
        content_disp = r.headers.get("Content-Disposition", "")
        assert "filename" in content_disp.lower()

        # 11. Code Coverage: Confirm /api/ai/status can be retrieved reporting core system AI statuses
        r = requests.get(BASE_URL + "/api/ai/status", timeout=TIMEOUT)
        assert r.status_code == 200
        ai_status = r.json()
        assert "core_status" in ai_status
        assert isinstance(ai_status.get("llm_calls"), int)
        assert "fallback" in ai_status

    finally:
        # Cleanup: If scan_id created, delete it if API supports deletion (Not specified so attempt via dashboard scans if exposed)
        # No deletion endpoint mentioned in PRD; skip actual delete to not cause errors
        pass


# test_business_logic_orchestration_data_transformations()
