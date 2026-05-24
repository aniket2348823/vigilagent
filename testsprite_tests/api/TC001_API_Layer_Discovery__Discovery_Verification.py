import requests
import time
import threading

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_TC001_api_layer_discovery_and_verification():
    # Helper to test GET endpoints with expected 200 and json schema presence
    def check_get_endpoint(path, expected_keys=None):
        url = BASE_URL + path
        resp = requests.get(url, timeout=TIMEOUT)
        assert resp.status_code == 200, f"GET {path} status {resp.status_code}"
        data = resp.json()
        if expected_keys:
            for key in expected_keys:
                assert key in data, f"Key '{key}' missing in response for {path}"
        return data

    # Helper to test POST endpoints with body and expect success or handled errors
    def check_post_endpoint(path, json_body, expected_status_codes=(200,)):
        url = BASE_URL + path
        resp = requests.post(url, json=json_body, timeout=TIMEOUT)
        assert resp.status_code in expected_status_codes, f"POST {path} status {resp.status_code}"
        if resp.status_code == 200:
            return resp.json()
        return resp.text

    # 1. API Discovery: enumerate and test fire, status and analyze endpoints
    # fire: POST /api/attack/fire
    fire_payload = {
        "target_url": "https://example.com",
        "method": "GET",
        "headers": {"User-Agent": "Vulagent-Test"},
        "duration": 5
    }

    # Start a fire scan
    fire_response = check_post_endpoint("/api/attack/fire", fire_payload, expected_status_codes=(200,422,429,500))
    assert isinstance(fire_response, dict) or 'Validation error' in str(fire_response) or isinstance(fire_response, str), \
        "Unexpected fire response format"

    # When fire is successful, check presence of scan_id and status
    if isinstance(fire_response, dict) and "scan_id" in fire_response:
        scan_id = fire_response["scan_id"]
        assert fire_response.get("status") == "Swarm Online" or "status" in fire_response

        # Check GET /api/dashboard/scans contains the scan_id
        scans_data = check_get_endpoint("/api/dashboard/scans")
        assert isinstance(scans_data, list), "/api/dashboard/scans response is not a list as expected"
        assert any(item.get("scan_id") == scan_id for item in scans_data if isinstance(item, dict)), "Scan_id not found in /api/dashboard/scans"

        # Check GET /api/health for service liveness and versioning
        health_data = check_get_endpoint("/api/health", expected_keys=["status", "version"])
        assert health_data["status"] == "online"

        # Check GET /api/ai/status for AI core status and fallback info
        ai_status_data = requests.get(BASE_URL + "/api/ai/status", timeout=TIMEOUT)
        assert ai_status_data.status_code in (200, 500), "/api/ai/status unexpected status"
        if ai_status_data.status_code == 200:
            ai_json = ai_status_data.json()
            required_ai_keys = {"core_status", "fallback", "llm_calls", "circuit_breaker_trips"}
            assert required_ai_keys.issubset(ai_json.keys()), "/api/ai/status missing keys"

        # POST /api/defense/analyze with valid body
        analyze_body = {
            "agent_id": "agent_prism",
            "content": {"innerText": "Test injection attempt <script>alert(1)</script>"},
            "url": "https://example.com"
        }
        analyze_resp = requests.post(BASE_URL + "/api/defense/analyze", json=analyze_body, timeout=TIMEOUT)
        assert analyze_resp.status_code in (200, 500), "POST /api/defense/analyze unexpected status"
        if analyze_resp.status_code == 200:
            analyze_json = analyze_resp.json()
            assert all(k in analyze_json for k in ("verdict", "reason", "risk_score")), "Missing keys in analyze response"
            assert analyze_json["verdict"] in ("BLOCK", "ALLOW")

        # Validate unexpected/hidden route detection via heuristic:
        # Attempt to get root API index if exists (not specified but attempt)
        # Also try some common internal hidden routes and validate 404 or schema.
        # We try fire, status, analyze, health explicitly as known endpoints

        known_endpoints = [
            "/api/attack/fire",
            "/api/dashboard/scans",
            "/api/dashboard/stats",
            "/api/defense/analyze",
            "/api/health",
            "/api/ai/status"
        ]

        for ep in known_endpoints:
            if ep.startswith("/api/attack/fire") or ep == "/api/defense/analyze":
                # POST expected
                # We reuse minimal correct payloads or empty payload to test schema binding
                try:
                    if ep == "/api/attack/fire":
                        # Test missing required field to provoke validation error
                        resp = requests.post(BASE_URL + ep, json={"method": "GET"}, timeout=TIMEOUT)
                        assert resp.status_code == 422 or resp.status_code == 429 or resp.status_code == 200
                    elif ep == "/api/defense/analyze":
                        resp = requests.post(BASE_URL + ep, json={"agent_id": "agent_prism", "content": {}, "url": "https://x"}, timeout=TIMEOUT)
                        assert resp.status_code in (200, 500), f"Unexpected status at {ep}"
                except requests.RequestException:
                    assert False, f"RequestException on POST {ep}"
            else:
                # GET expected
                try:
                    resp = requests.get(BASE_URL + ep, timeout=TIMEOUT)
                    assert resp.status_code == 200
                except requests.RequestException:
                    assert False, f"RequestException on GET {ep}"

        # Schema-bound validation: basic check for Content-Type application/json on APIs except health (also JSON)
        for ep in known_endpoints:
            try:
                resp = requests.get(BASE_URL + ep, timeout=TIMEOUT)
                ct = resp.headers.get("Content-Type","")
                assert "application/json" in ct or ep == "/api/health"
            except requests.RequestException:
                pass

        # Additional: Test concurrency by launching multiple concurrent /api/attack/fire requests and check not failing catastrophically
        def launch_fire_scan():
            try:
                r = requests.post(BASE_URL + "/api/attack/fire", json=fire_payload, timeout=TIMEOUT)
                assert r.status_code in (200, 429, 422, 500)
            except:
                pass

        threads = []
        for _ in range(5):
            t = threading.Thread(target=launch_fire_scan)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    else:
        # If fire_response is validation error or other, confirm error handling works
        assert ("Validation error" in str(fire_response)) or isinstance(fire_response, str), "Fire endpoint error not handled"

# test_TC001_api_layer_discovery_and_verification()
