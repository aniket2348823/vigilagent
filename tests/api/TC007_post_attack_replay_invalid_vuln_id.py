import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_attack_replay_invalid_vuln_id():
    invalid_vuln_id = "00000000-0000-0000-0000-000000000000"
    url = f"{BASE_URL}/api/attack/replay/{invalid_vuln_id}"
    try:
        response = requests.post(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"
    
    assert response.status_code == 404, f"Expected 404 but got {response.status_code}"
    try:
        json_resp = response.json()
    except ValueError:
        assert False, "Response is not valid JSON"
    
    assert isinstance(json_resp, dict), "Response JSON is not a dictionary"
    # Check if error message is present in any common fields
    error_fields = ['error', 'message', 'detail']
    found_error_message = False
    for field in error_fields:
        if field in json_resp and isinstance(json_resp[field], str):
            if json_resp[field].lower() == "vulnerability not found":
                found_error_message = True
                break
    assert found_error_message, f"Expected error 'vulnerability not found' but not found in response JSON"

test_post_attack_replay_invalid_vuln_id()
