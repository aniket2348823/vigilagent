import requests
import time
import threading

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30


def test_api_latency_and_core_bottleneck_identification():
    results = {"fire_post": None, "dashboard_scans": None, "defense_analyze": None, "ai_status": None}
    latencies = {}

    # 1. API Discovery: Check core endpoints /api/attack/fire (POST), /api/dashboard/scans (GET), /api/defense/analyze (POST), /api/ai/status (GET)
    try:
        # Prepare payload for /api/attack/fire
        fire_payload = {
            "target_url": "https://example.com/api/v1/resource",
            "method": "GET",
            "headers": {"User-Agent": "LatencyTest/1.0"},
            "duration": 5
        }

        start_fire = time.perf_counter()
        fire_resp = requests.post(f"{BASE_URL}/api/attack/fire", json=fire_payload, timeout=TIMEOUT)
        end_fire = time.perf_counter()
        latencies["/api/attack/fire POST"] = end_fire - start_fire
        assert fire_resp.status_code == 200, f"/api/attack/fire failed with status {fire_resp.status_code}"
        fire_json = fire_resp.json()
        assert "scan_id" in fire_json and "status" in fire_json and fire_json["status"] == "Swarm Online"
        scan_id = fire_json["scan_id"]
        results["fire_post"] = scan_id

        # Retry fetching scans to ensure scan_id appears (handle async registration delay)
        scans_list = []
        found_scan = False
        for _ in range(10):  # retry up to 10 times with 1 second delay
            start_scans = time.perf_counter()
            scans_resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
            end_scans = time.perf_counter()
            latencies["/api/dashboard/scans GET"] = end_scans - start_scans
            assert scans_resp.status_code == 200, f"/api/dashboard/scans failed with status {scans_resp.status_code}"
            scans_list = scans_resp.json()
            assert isinstance(scans_list, list), "/api/dashboard/scans response not a list"
            if any(scan.get("scan_id") == scan_id for scan in scans_list):
                found_scan = True
                break
            time.sleep(1)
        assert found_scan, "Launched scan_id not found in scans list after retries"
        results["dashboard_scans"] = scans_list

        # 4. OpenRouter AI Fallbacks/Hallucinations: Test /api/defense/analyze normal and error path
        analyze_payload = {
            "agent_id": "agent_prism",
            "content": {"innerText": "Potential prompt injection test text"},
            "url": "https://example.com"
        }
        start_defense = time.perf_counter()
        defense_resp = requests.post(f"{BASE_URL}/api/defense/analyze", json=analyze_payload, timeout=TIMEOUT)
        end_defense = time.perf_counter()
        latencies["/api/defense/analyze POST"] = end_defense - start_defense
        assert defense_resp.status_code == 200, f"/api/defense/analyze failed normal case with {defense_resp.status_code}"
        defense_json = defense_resp.json()
        assert defense_json.get("verdict") in ["BLOCK","ALLOW"]
        results["defense_analyze"] = defense_json

        # Malformed payload to induce 500 server error, test fallback
        malformed_payload = {
            "agent_id": None,  # invalid
            "content": "invalid_string_instead_of_dict",
            "url": ""
        }
        malformed_resp = requests.post(f"{BASE_URL}/api/defense/analyze", json=malformed_payload, timeout=TIMEOUT)
        assert malformed_resp.status_code == 500, "Malformed payload did not cause 500 error as expected"

        # 7. Performance (Latency) & 6. Resilience (Network Failures)
        # Already measured latencies above.
        # Simulate network failure for a known endpoint (simulate by timeout very short)
        try:
            requests.get(f"{BASE_URL}/api/dashboard/stats", timeout=0.001)
        except requests.exceptions.ReadTimeout:
            pass
        else:
            # If no timeout forced, acceptable as resilience test
            pass

        # 11. Code Coverage - invoke /api/ai/status to check AI engine statuses and fallbacks
        start_ai_status = time.perf_counter()
        ai_status_resp = requests.get(f"{BASE_URL}/api/ai/status", timeout=TIMEOUT)
        end_ai_status = time.perf_counter()
        latencies["/api/ai/status GET"] = end_ai_status - start_ai_status
        assert ai_status_resp.status_code == 200, f"/api/ai/status failed with status {ai_status_resp.status_code}"
        ai_status_json = ai_status_resp.json()
        assert "core_status" in ai_status_json and isinstance(ai_status_json["core_status"], dict)
        results["ai_status"] = ai_status_json

    finally:
        # Cleanup: If scan was started, no explicit delete endpoint shown, cleanup not possible here
        # Leaving resource for backend auto-cleanup or further tests given lack of delete endpoint
        pass

    # Output performance summary assertions
    for endpoint, latency in latencies.items():
        assert latency < 10.0, f"Latency too high for {endpoint}: {latency:.3f}s (threshold 10s)"

    # Concurrency and race condition tests
    # Launch multiple /api/attack/fire requests concurrently to observe latency and race effects
    concurrency_results = []
    def launch_attack():
        try:
            r = requests.post(f"{BASE_URL}/api/attack/fire", json=fire_payload, timeout=TIMEOUT)
            concurrency_results.append((r.status_code, r.elapsed.total_seconds()))
        except Exception as e:
            concurrency_results.append((str(e), None))

    threads = [threading.Thread(target=launch_attack) for _ in range(5)]
    start_concurrency = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    end_concurrency = time.perf_counter()
    concurrency_duration = end_concurrency - start_concurrency

    # Assert all launched without error and within acceptable latency
    for status, elapsed in concurrency_results:
        assert status == 200, f"Concurrent fire request failed with status/error: {status}"
        assert elapsed is not None and elapsed < 15, f"Concurrent fire request latency too high: {elapsed}"

    assert concurrency_duration < 20, f"Overall concurrency test too slow: {concurrency_duration:.2f}s"


# test_api_latency_and_core_bottleneck_identification()
