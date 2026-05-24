import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_attack_fire_disallowed_target():
    url = f"{BASE_URL}/api/attack/fire"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "target_url": "http://disallowed.example.com",
        "method": "GET",
        "concurrency": 1
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 403, f"Expected status code 403, got {response.status_code}"
        json_resp = response.json()
        # Check for 'detail' key in response for disallowed target error
        assert 'detail' in json_resp, f"Response JSON should contain 'detail' field, got: {json_resp}"
        assert "not in the allowed scope" in json_resp['detail'].lower() or "not permitted" in json_resp['detail'].lower(), \
            f"Expected error indicating 'not permitted' or 'not in the allowed scope', got: {json_resp['detail']}"
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

test_post_attack_fire_disallowed_target()
