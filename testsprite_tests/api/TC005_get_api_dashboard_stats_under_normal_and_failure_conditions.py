import requests
import threading
import time
import base64
import urllib.parse

BASE_URL = "http://localhost:8000"
API_PATH = "/api/dashboard/stats"
FULL_URL = BASE_URL + API_PATH
TIMEOUT = 30

def double_url_encode(data: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(data, safe=''), safe='')

def base64_rot13_encode(data: str) -> str:
    base64_encoded = base64.b64encode(data.encode()).decode()
    rot13_trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )
    return base64_encoded.translate(rot13_trans)

def invisible_unicode_injection(data: str) -> str:
    # Inject zero-width space and zero-width non-joiner at random positions
    zwspace = '\u200b'
    zwnj = '\u200c'
    pieces = [data[:len(data)//2], zwspace, data[len(data)//2:], zwnj]
    return "".join(pieces)

def stress_request(session, results, index):
    try:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Vulagent-Scanner-Test-Agent"
        }
        # Prepare heavy obfuscated query parameters to stress sanitizer
        # Dashboard stats endpoint is GET with no required query params, but we add dummy obfuscated param to test sanitization
        payload = "testPayload/\\?&="
        obf_payload = invisible_unicode_injection(base64_rot13_encode(double_url_encode(payload)))
        params = {"stress": obf_payload}

        resp = session.get(FULL_URL, headers=headers, params=params, timeout=TIMEOUT)
        # Acceptable status codes: 200 (normal), 503 (service unavailable), 500 (server error)
        # Validate according to status code
        status = resp.status_code
        if status == 200:
            # Validate JSON structure for aggregated metrics, graph_data, recent_activity
            json_data = resp.json()
            assert "metrics" in json_data and isinstance(json_data["metrics"], dict), "Missing or invalid 'metrics'"
            assert "total_scans" in json_data["metrics"], "Missing 'total_scans' in metrics"
            assert "active_scans" in json_data["metrics"], "Missing 'active_scans' in metrics"
            assert "vulnerabilities" in json_data["metrics"], "Missing 'vulnerabilities' in metrics"
            assert "critical" in json_data["metrics"], "Missing 'critical' in metrics"
            assert "graph_data" in json_data and isinstance(json_data["graph_data"], list), "Missing or invalid 'graph_data'"
            assert "recent_activity" in json_data and isinstance(json_data["recent_activity"], list), "Missing or invalid 'recent_activity'"
            results[index] = "PASS_200"
        elif status in (503, 500):
            # Check error message presence and UI fallbacks cannot be tested via API, but response must have error message
            json_data = None
            try:
                json_data = resp.json()
            except Exception:
                pass
            assert json_data is not None, "Expected JSON error message on 503/500"
            assert "error" in json_data or "message" in json_data, "Expected 'error' or 'message' key in error response"
            results[index] = f"PASS_{status}"
        else:
            results[index] = f"FAIL_UNEXPECTED_STATUS_{status}"
    except Exception as e:
        results[index] = f"FAIL_EXCEPTION_{str(e)}"

def test_get_api_dashboard_stats_under_normal_and_failure_conditions():
    # We simulate normal and failure conditions by sending many parallel requests to trigger load
    # and rely on the backend behavior to return 503/500 when under stress.
    session = requests.Session()
    threads = []
    # To achieve stress, we spawn 100 concurrent threads (adjustable as needed)
    CONCURRENT_REQUESTS = 100
    results = [None] * CONCURRENT_REQUESTS

    for i in range(CONCURRENT_REQUESTS):
        t = threading.Thread(target=stress_request, args=(session, results, i))
        threads.append(t)
        t.start()
        # Slight stagger to not flood all at once, simulating load ramp-up
        time.sleep(0.01)

    for t in threads:
        t.join()

    # Analyze results
    passed_200 = sum(1 for r in results if r == "PASS_200")
    passed_503 = sum(1 for r in results if r == "PASS_503")
    passed_500 = sum(1 for r in results if r == "PASS_500")
    failed = [r for r in results if r and r.startswith("FAIL")]

    # Assertions
    # At least some requests should succeed with 200
    assert passed_200 > 0, "No successful 200 responses received under normal conditions"

    # No unexpected failures allowed
    assert len(failed) == 0, f"Failures occurred during load test: {failed}"

    # If the backend returns 503/500, it must include error message in JSON
    # Already asserted in stress_request

test_get_api_dashboard_stats_under_normal_and_failure_conditions()
