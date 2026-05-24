import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_get_dashboard_stats_success():
    url = f"{BASE_URL}/api/dashboard/stats"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"
    
    assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}"
    
    try:
        data = response.json()
    except ValueError:
        assert False, "Response is not valid JSON"
    
    # Validate DashboardStats structure minimally
    assert isinstance(data, dict), "Response JSON is not an object"
    assert "metrics" in data, "Missing 'metrics' in response"
    assert "graph_data" in data, "Missing 'graph_data' in response"
    assert "recent_activity" in data, "Missing 'recent_activity' in response"
    
    # Optionally verify types of these fields if known (assuming dict or list)
    assert isinstance(data["metrics"], dict) or isinstance(data["metrics"], list), "'metrics' should be a dict or list"
    assert isinstance(data["graph_data"], dict) or isinstance(data["graph_data"], list), "'graph_data' should be a dict or list"
    assert isinstance(data["recent_activity"], list), "'recent_activity' should be a list"

test_get_dashboard_stats_success()