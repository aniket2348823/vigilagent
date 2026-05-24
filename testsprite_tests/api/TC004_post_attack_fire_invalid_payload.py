import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_attack_fire_invalid_payload():
    url = f"{BASE_URL}/api/attack/fire"
    # Malformed payload examples: missing 'target_url' and wrong types
    invalid_payloads = [
        {},  # completely empty
        {"target_url": 12345, "method": "GET", "concurrency": 5},  # target_url wrong type
        {"method": "GET", "concurrency": 5},  # missing target_url
        {"target_url": "http://example.com", "method": 123, "concurrency": 5},  # method wrong type
        {"target_url": "http://example.com", "method": "GET", "concurrency": "high"},  # concurrency wrong type
        {"target_url": None, "method": "GET", "concurrency": 5},  # target_url None
        {"target_url": "http://example.com", "method": None, "concurrency": 5},  # method None
        {"target_url": "http://example.com", "method": "GET", "concurrency": None}  # concurrency None
    ]

    headers = {
        "Content-Type": "application/json"
    }

    for payload in invalid_payloads:
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        except requests.RequestException as e:
            assert False, f"Request failed with exception: {e}"

        assert response.status_code == 400, f"Expected 400 but got {response.status_code} for payload: {payload}"
        try:
            json_resp = response.json()
        except Exception:
            assert False, "Response is not JSON when validation error expected"

        # Expecting validation error details in response JSON
        response_str = str(json_resp).lower()
        assert ("validation" in response_str or "error" in response_str or "detail" in response_str), \
            f"Response does not contain validation error details: {json_resp}"

test_post_attack_fire_invalid_payload()
