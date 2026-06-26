import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_get_data_list_success():
    url = f"{BASE_URL}/api/data"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        assert response.status_code == 200
        data_list = response.json()
        assert isinstance(data_list, list)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_get_data_list_success()