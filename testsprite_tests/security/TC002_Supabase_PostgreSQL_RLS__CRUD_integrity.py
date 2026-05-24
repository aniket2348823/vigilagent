import requests
import time
import threading

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_supabase_postgresql_rls_and_crud_integrity():
    """
    Test Supabase DB interaction:
    - Verify RLS policies prevent unauthorized data access.
    - Verify upsert operations are idempotent and consistent.
    This simulates CRUD operations through the backend API,
    validate unauthorized requests are blocked, and confirm idempotency of upserts.
    """

    # Hypothetical secured Supabase CRUD API endpoints (assumed for test):
    # POST /api/data/items  -> create or upsert item {id?, data, owner}
    # GET  /api/data/items/{id} -> get item by id (authorized users only)
    # DELETE /api/data/items/{id} -> delete item by id (authorized users only)
    # Assume RLS is enforced by Supabase backend and unauthorized access returns 403 Forbidden.
    # No explicit auth token provided; test unauthorized vs authorized calls by switching owner.

    headers = {"Content-Type": "application/json"}

    # Helper function to create or upsert an item
    def upsert_item(item_payload):
        url = f"{BASE_URL}/api/data/items"
        try:
            resp = requests.post(url, json=item_payload, headers=headers, timeout=TIMEOUT)
            return resp
        except Exception as e:
            assert False, f"Upsert request failed: {e}"

    # Helper function to get item by id
    def get_item(item_id, owner_header=None):
        url = f"{BASE_URL}/api/data/items/{item_id}"
        req_headers = headers.copy()
        if owner_header:
            req_headers['X-User-Id'] = owner_header
        try:
            resp = requests.get(url, headers=req_headers, timeout=TIMEOUT)
            return resp
        except Exception as e:
            assert False, f"Get request failed: {e}"

    # Helper function to delete item by id
    def delete_item(item_id, owner_header=None):
        url = f"{BASE_URL}/api/data/items/{item_id}"
        req_headers = headers.copy()
        if owner_header:
            req_headers['X-User-Id'] = owner_header
        try:
            resp = requests.delete(url, headers=req_headers, timeout=TIMEOUT)
            return resp
        except Exception as e:
            assert False, f"Delete request failed: {e}"

    # 1. Create new item owned by user_1
    test_item = {
        "id": None,
        "data": {"key": "value1"},
        "owner": "user_1"
    }

    resp_create = upsert_item(test_item)
    assert resp_create.status_code == 200, f"Create/upsert failed with {resp_create.status_code}"
    created_data = resp_create.json()
    assert "id" in created_data and created_data["id"], "Created item id missing"
    item_id = created_data["id"]

    try:
        # 2. Retrieve item as owner user_1 - should succeed
        resp_get_owner = get_item(item_id, owner_header="user_1")
        assert resp_get_owner.status_code == 200, f"Owner access denied with {resp_get_owner.status_code}"
        data_owner = resp_get_owner.json()
        assert data_owner.get("owner") == "user_1", "Owner mismatch on retrieval"
        assert data_owner.get("data") == {"key": "value1"}, "Data mismatch on retrieval"

        # 3. Retrieve item as unauthorized user_2 - should be forbidden (RLS)
        resp_get_unauth = get_item(item_id, owner_header="user_2")
        assert resp_get_unauth.status_code == 403, f"Unauthorized access allowed with status {resp_get_unauth.status_code}"

        # 4. Upsert same item by owner user_1 with modified data to test idempotency
        idempotent_payload = {
            "id": item_id,
            "data": {"key": "value2"},
            "owner": "user_1"
        }
        resp_upsert1 = upsert_item(idempotent_payload)
        assert resp_upsert1.status_code == 200, f"Upsert update failed with {resp_upsert1.status_code}"

        # 5. Upsert same item again with same payload - no side effects expected
        resp_upsert2 = upsert_item(idempotent_payload)
        assert resp_upsert2.status_code == 200, f"Repeated upsert failed with {resp_upsert2.status_code}"
        assert resp_upsert1.json() == resp_upsert2.json(), "Upsert responses differ, violating idempotency"

        # 6. Retrieve item after upserts and verify updated data
        resp_get_after_upsert = get_item(item_id, owner_header="user_1")
        assert resp_get_after_upsert.status_code == 200, f"Owner retrieval after upsert failed with {resp_get_after_upsert.status_code}"
        retrieved_data = resp_get_after_upsert.json()
        assert retrieved_data.get("data") == {"key": "value2"}, "Data did not update correctly after upsert"

        # 7. Attempt injection attack in data field (simulate security check)
        injection_payload = {
            "id": None,
            "data": {"key": "' OR 1=1 --"},
            "owner": "user_1"
        }
        resp_injection = upsert_item(injection_payload)
        # The API should sanitize inputs and accept string as data without harm, respond 200
        assert resp_injection.status_code == 200, f"Injection payload rejected or caused error {resp_injection.status_code}"
        injected_item = resp_injection.json()
        injected_id = injected_item.get("id")
        assert injected_id is not None, "Injection payload item id missing"

        # 8. Retrieve injected item as user_1
        resp_get_injected = get_item(injected_id, owner_header="user_1")
        assert resp_get_injected.status_code == 200, f"Injected item access failed {resp_get_injected.status_code}"
        injected_data = resp_get_injected.json()
        assert injected_data.get("data") == {"key": "' OR 1=1 --"}, "Injected data corrupted on retrieval"

        # 9. Retrieve injected item as unauthorized user_2 -> 403
        resp_get_injected_unauth = get_item(injected_id, owner_header="user_2")
        assert resp_get_injected_unauth.status_code == 403, f"Unauthorized access to injected item allowed {resp_get_injected_unauth.status_code}"

    finally:
        # Cleanup created items
        delete_resp1 = delete_item(item_id, owner_header="user_1")
        assert delete_resp1.status_code in [200, 204, 404], f"Failed cleanup on item {item_id}"
        if 'injected_id' in locals():
            delete_resp2 = delete_item(injected_id, owner_header="user_1")
            assert delete_resp2.status_code in [200, 204, 404], f"Failed cleanup on item {injected_id}"

    # 10. Concurrency test: simulate race condition on upsert for same item id

    def concurrent_upsert(id_, owner_, data_, results, index):
        payload = {"id": id_, "owner": owner_, "data": data_}
        try:
            r = upsert_item(payload)
            results[index] = r
        except Exception as e:
            results[index] = e

    # Create initial item to upsert concurrently
    init_payload = {"id": None, "owner": "user_1", "data": {"key": "race0"}}
    resp_init = upsert_item(init_payload)
    assert resp_init.status_code == 200, "Initial item creation failed for concurrency test"
    concurrency_item_id = resp_init.json()["id"]

    upsert_results = [None, None, None, None]

    threads = []
    # Define different data for concurrent upserts
    data_variants = [{"key": "race1"}, {"key": "race2"}, {"key": "race3"}, {"key": "race4"}]

    for i in range(4):
        t = threading.Thread(target=concurrent_upsert, args=(concurrency_item_id, "user_1", data_variants[i], upsert_results, i))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    # Check that all upserts succeeded (200) and final data matches one of variants (one last write wins)
    for resp in upsert_results:
        assert hasattr(resp, "status_code") and resp.status_code == 200, f"Concurrent upsert failed or exception: {resp}"

    resp_final = get_item(concurrency_item_id, owner_header="user_1")
    assert resp_final.status_code == 200, "Failed to retrieve item after concurrent upserts"
    final_data = resp_final.json().get("data")
    allowed_data = [v for v in data_variants]
    assert any(final_data == v for v in allowed_data), "Data after concurrency upserts unexpected"

    # Cleanup concurrency test item
    del_resp = delete_item(concurrency_item_id, owner_header="user_1")
    assert del_resp.status_code in [200, 204, 404], "Cleanup failed for concurrency test item"

# test_supabase_postgresql_rls_and_crud_integrity()
