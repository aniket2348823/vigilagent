import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_post_data_create_object():
    url = f"{BASE_URL}/api/data"
    headers = {"Content-Type": "application/json"}
    payload = {
        "key": "test_key_tc010",
        "value": "test_value_tc010",
        "metadata": {"description": "Test object for TC010"}
    }
    response = None
    created_id = None

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code in (200, 201), f"Expected 200 or 201, got {response.status_code}"

        response_json = response.json()
        assert "id" in response_json, "Response JSON does not contain 'id'"

        assert "key" in response_json, "Response JSON does not contain 'key'"
        assert response_json["key"] == payload["key"], f"Response key '{response_json.get('key')}' does not match request '{payload['key']}'"

        assert "value" in response_json, "Response JSON does not contain 'value'"
        assert response_json["value"] == payload["value"], f"Response value '{response_json.get('value')}' does not match request '{payload['value']}'"

        assert "metadata" in response_json, "Response JSON does not contain 'metadata'"
        assert response_json["metadata"] == payload["metadata"], f"Response metadata '{response_json.get('metadata')}' does not match request '{payload['metadata']}'"

        created_id = response_json["id"]
        assert created_id, "Created object id is invalid"

    finally:
        if created_id:
            del_resp = requests.delete(url, json={"id": created_id}, headers=headers, timeout=TIMEOUT)
            assert del_resp.status_code in (200, 204), f"Cleanup delete expected 200 or 204, got {del_resp.status_code}"

test_post_data_create_object()
