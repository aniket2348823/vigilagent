import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_attack_replay_valid_vuln_id():
    # Step 1: Obtain a valid vuln_id by getting dashboard scans and extracting a vuln_id if available
    try:
        scans_resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        assert scans_resp.status_code == 200, f"Expected 200 from /api/dashboard/scans, got {scans_resp.status_code}"
        scans_data = scans_resp.json()
        # Attempt to find a vuln_id in scans data structure (assuming vulnerability info is inside scans)
        vuln_id = None
        # We need to heuristically look inside the scan list for vuln_id
        # Since no explicit structure is given, try common keys
        if isinstance(scans_data, dict):
            # The ScanList might contain items possibly with 'vulnerabilities' or similar
            for key in scans_data:
                value = scans_data[key]
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            # Look for vulnerabilities key or 'vuln_id' keys
                            if 'vuln_id' in item:
                                vuln_id = item['vuln_id']
                                break
                            if 'id' in item:
                                vuln_id = item['id']
                                break
                            # Check nested vulnerabilities list
                            if 'vulnerabilities' in item and isinstance(item['vulnerabilities'], list):
                                for v in item['vulnerabilities']:
                                    if isinstance(v, dict) and 'id' in v:
                                        vuln_id = v['id']
                                        break
                                if vuln_id:
                                    break
                    if vuln_id:
                        break
        
        # If no vuln_id found, the test cannot proceed
        assert vuln_id is not None, "No valid vuln_id found in dashboard scans to replay attack."

        # Step 2: POST to /api/attack/replay/{vuln_id}
        url = f"{BASE_URL}/api/attack/replay/{vuln_id}"
        response = requests.post(url, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected 200 but got {response.status_code}"

        body = response.json()
        assert isinstance(body, dict), "Response body should be a JSON object."
        assert 'replay_id' in body and isinstance(body['replay_id'], (str, int)), "Response missing 'replay_id'."
        assert 'status' in body and isinstance(body['status'], str), "Response missing 'status'."

    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_post_attack_replay_valid_vuln_id()