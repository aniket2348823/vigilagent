import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_attack_fire_valid_payload():
    url = f"{BASE_URL}/api/attack/fire"
    payload = {
        "target_url": "http://example.com/api/test",
        "method": "GET",
        "concurrency": 5
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = None
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        data = response.json()
        assert isinstance(data, dict), "Response is not a JSON object"
        assert data.get("status") == "Swarm Online", f"Expected status 'Swarm Online', got {data.get('status')}"
        assert "scan_id" in data, "Missing 'scan_id' in response"
        assert isinstance(data["scan_id"], (str, int)), "'scan_id' should be string or int"
        assert "message" in data and isinstance(data["message"], str), "Missing or invalid 'message' in response"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_post_attack_fire_valid_payload()