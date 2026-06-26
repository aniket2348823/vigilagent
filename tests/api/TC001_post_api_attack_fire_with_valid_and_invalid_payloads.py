import requests
import base64
import threading
import time
import urllib.parse

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

def base64_rot13_encode(s: str) -> str:
    b64 = base64.b64encode(s.encode()).decode()
    # ROT13 implemented only for ASCII letters
    def rot13(c):
        if 'a' <= c <= 'z':
            return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        if 'A' <= c <= 'Z':
            return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
        return c
    return ''.join(rot13(c) for c in b64)

def invisible_unicode_inject(s: str) -> str:
    # Insert ZERO WIDTH SPACE (U+200B) between characters
    return '\u200b'.join(s) + '\u200b'

def generate_valid_payload():
    # For the valid payload, use plain target_url string as per PRD (no obfuscation)
    target_url = "http://target.local/vulnerable"
    # Modules must be valid strings like 'sigma', 'kappa', etc., use plain strings
    modules = ["sigma", "kappa"]
    payload = {
        "target_url": target_url,
        "modules": modules,
        "duration": 120,      # seconds
        "velocity": 5,        # attacks per second
        "concurrency": 3      # parallel threads
    }
    return payload

def generate_invalid_payloads():
    payloads = []

    # Missing target_url
    payloads.append({
        "modules": ["sigma", "kappa"],
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Empty modules list
    payloads.append({
        "target_url": "http://example.com",
        "modules": [],
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Invalid module string obfuscated but not valid agent name
    invalid_modules = [double_url_encode("invalidmodule@@@")] 
    payloads.append({
        "target_url": "http://example.com",
        "modules": invalid_modules,
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Modules with invisible unicode injected in invalid module names
    payloads.append({
        "target_url": "http://example.com",
        "modules": [invisible_unicode_inject("!!!invalid###")],
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Modules as wrong datatype (integer)
    payloads.append({
        "target_url": "http://example.com",
        "modules": [123, 456],
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Malformed JSON-like (e.g. string instead of list)
    payloads.append({
        "target_url": "http://example.com",
        "modules": "sigma,kappa",
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    # Missing modules field entirely
    payloads.append({
        "target_url": "http://example.com",
        "duration": 60,
        "velocity": 3,
        "concurrency": 1
    })

    return payloads

def test_post_api_attack_fire_with_valid_and_invalid_payloads():
    session = requests.Session()
    headers = {"Content-Type": "application/json"}
    post_url = BASE_URL + "/api/attack/fire"
    scans_url = BASE_URL + "/api/dashboard/scans"

    # 1. Test valid payload - expect 200 with status 'Swarm Online' and scan_id
    valid_payload = generate_valid_payload()
    scan_id = None
    try:
        response = session.post(post_url, json=valid_payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected 200, got {response.status_code} with body {response.text}"
        data = response.json()
        assert "status" in data and data["status"] == "Swarm Online", f"Unexpected status in response: {data}"
        assert "scan_id" in data and isinstance(data["scan_id"], str) and data["scan_id"], f"Missing or invalid scan_id: {data}"
        scan_id = data["scan_id"]

        # 2. Verify scan appears with status 'running' in GET /api/dashboard/scans
        scans_response = session.get(scans_url, timeout=TIMEOUT)
        assert scans_response.status_code == 200, f"GET /api/dashboard/scans failed with status {scans_response.status_code}"
        scans_list = scans_response.json()
        found_scan = next((s for s in scans_list if s.get("scan_id") == scan_id), None)
        assert found_scan is not None, f"Scan_id {scan_id} not found in dashboard scans"
        status = found_scan.get("status")
        assert status == "running", f"Expected scan status 'running', got '{status}'"

        # 3. Stress test concurrency/race conditions by launching multiple parallel scans
        def launch_parallel_scan(idx):
            p = generate_valid_payload()
            p["concurrency"] = (idx % 5) + 1
            p["velocity"] = (idx % 7) + 1
            try:
                r = session.post(post_url, json=p, headers=headers, timeout=TIMEOUT)
                if r.status_code != 200:
                    raise AssertionError(f"Parallel scan {idx} failed with {r.status_code}: {r.text}")
                jd = r.json()
                assert jd.get("status") == "Swarm Online"
            except Exception as e:
                raise e

        threads = []
        for i in range(10):
            t = threading.Thread(target=launch_parallel_scan, args=(i,))
            t.start()
            threads.append(t)
            time.sleep(0.05)

        for t in threads:
            t.join()

    finally:
        pass

    # 4. Test invalid payloads - expect 400 or 422 status, no scan created
    invalid_payloads = generate_invalid_payloads()
    before_invalid_response = session.get(scans_url, timeout=TIMEOUT)
    assert before_invalid_response.status_code == 200
    before_scans = before_invalid_response.json()
    before_scan_ids = {s.get("scan_id") for s in before_scans}

    for idx, invalid_payload in enumerate(invalid_payloads):
        try:
            resp = session.post(post_url, json=invalid_payload, headers=headers, timeout=TIMEOUT)
            assert resp.status_code in (400, 422), f"Invalid payload {idx} expected 400 or 422 but got {resp.status_code}: {resp.text}"
            j = resp.json()
            assert any(k in j for k in ["detail", "errors", "message"]), f"Expected validation error message for payload {idx}"

            scans_resp_after = session.get(scans_url, timeout=TIMEOUT)
            assert scans_resp_after.status_code == 200
            scans_after = scans_resp_after.json()
            after_scan_ids = {s.get("scan_id") for s in scans_after}
            new_ids = after_scan_ids - before_scan_ids
            assert len(new_ids) == 0, f"Invalid payload {idx} created scan(s) unexpectedly: {new_ids}"
        except requests.exceptions.Timeout:
            assert False, f"Request timed out for invalid payload index {idx}"
        except requests.exceptions.RequestException as e:
            assert False, f"Request failed for invalid payload index {idx} with exception {e}"

test_post_api_attack_fire_with_valid_and_invalid_payloads()
