import requests
import threading
import time

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30
CONCURRENT_ATTEMPTS = 10

def test_distributed_race_condition_conflict_resolution():
    # Prepare a common payload for firing a scan swarm
    payload = {
        "target_url": "http://example.com/api/v1/resource",
        "method": "GET",
        "headers": {"User-Agent": "Vulagent-Scanner-Test"},
        "duration": 10
    }
    headers = {"Content-Type": "application/json"}

    # Use lock results to collect scan_ids and errors from concurrent requests
    results = {"scan_ids": [], "errors": []}
    results_lock = threading.Lock()

    def fire_swarm():
        try:
            resp = requests.post(
                f"{BASE_URL}/api/attack/fire",
                json=payload,
                headers=headers,
                timeout=TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                assert "scan_id" in data, "No scan_id in success response"
                assert data.get("status") == "Swarm Online"
                with results_lock:
                    results["scan_ids"].append(data["scan_id"])
            elif resp.status_code == 429:
                # Rate limit activated, acceptable under concurrency stress
                with results_lock:
                    results["errors"].append("429 Rate limit")
            else:
                # Record unexpected status codes or server errors
                with results_lock:
                    results["errors"].append(f"{resp.status_code} {resp.text}")
        except Exception as exc:
            with results_lock:
                results["errors"].append(f"Exception: {str(exc)}")

    threads = []
    for _ in range(CONCURRENT_ATTEMPTS):
        t = threading.Thread(target=fire_swarm)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Validate that at least one swarm launched successfully
    assert len(results["scan_ids"]) > 0, "No swarms launched successfully under concurrency"

    # Check errors to ensure no data/state corruption indication
    # Errors like 429 are expected under load but no 500 or malformed responses should appear
    for err in results["errors"]:
        assert not err.startswith("500"), f"Server error under concurrency: {err}"
        assert not err.startswith("422"), f"Unexpected validation error: {err}"

    # To verify atomic locking and conflict resolution, query dashboard scans and validate no duplicates or corrupted state
    try:
        resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        assert resp.status_code == 200, f"Failed to get dashboard scans: {resp.status_code}"
        scans_data = resp.json()
        # Extract scan_ids in dashboard
        dashboard_scan_ids = set()
        for scan in scans_data:
            scan_id = scan.get("scan_id")
            if scan_id:
                dashboard_scan_ids.add(scan_id)

        # Check that all successfully launched scan_ids appear in dashboard scans
        missing = [sid for sid in results["scan_ids"] if sid not in dashboard_scan_ids]
        assert not missing, f"The following scan_ids missing from dashboard scans: {missing}"

        # Check for duplicates or anomalies in scan records
        all_scan_ids = [scan.get("scan_id") for scan in scans_data if "scan_id" in scan]
        assert len(all_scan_ids) == len(set(all_scan_ids)), "Duplicate scan_id detected in dashboard scans"

    except Exception as exc:
        assert False, f"Exception during dashboard scans validation: {str(exc)}"

# test_distributed_race_condition_conflict_resolution()
