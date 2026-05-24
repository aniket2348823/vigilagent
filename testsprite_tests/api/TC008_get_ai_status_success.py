import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {
    "Accept": "application/json"
}

def test_get_ai_status_success():
    url = f"{BASE_URL}/api/ai/status"
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request to {url} failed: {e}"

    assert response.status_code == 200, f"Expected status 200 but got {response.status_code}"

    try:
        data = response.json()
    except ValueError:
        assert False, "Response is not valid JSON"

    assert isinstance(data, dict), "Response JSON root should be a dictionary"

    # Validate circuit breaker state presence
    assert "circuit_breaker_tripped" in data, "Key 'circuit_breaker_tripped' not in response"
    assert isinstance(data["circuit_breaker_tripped"], bool), "'circuit_breaker_tripped' should be a boolean"

    # Validate agent capabilities presence
    assert "agent_capabilities" in data, "Key 'agent_capabilities' not in response"
    assert isinstance(data["agent_capabilities"], (dict, list)), "'agent_capabilities' should be dict or list"

test_get_ai_status_success()