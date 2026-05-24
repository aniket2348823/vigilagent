import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_get_dashboard_scans_success():
    url = f"{BASE_URL}/api/dashboard/scans"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        json_data = response.json()
        # Assert that the response is either dict or list
        assert isinstance(json_data, (dict, list)), "Response is not a dict or list"
        # Check if list and has elements or dict with any list containing scans
        scans_found = False
        if isinstance(json_data, dict):
            for key in json_data:
                if isinstance(json_data[key], list) and len(json_data[key]) > 0:
                    scans_found = True
                    break
        elif isinstance(json_data, list):
            scans_found = len(json_data) > 0

        assert scans_found, "No active or historical scans found in ScanList"
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

test_get_dashboard_scans_success()