import requests
import time
import base64

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def launch_scan_with_valid_payload():
    target_url = "http://example.com/?q=test&x=1"
    modules = ["Sigma", "Alpha", "Kappa"]

    payload = {
        "target_url": target_url,
        "modules": modules,
        "duration": 3,
        "velocity": 5,
        "concurrency": 2
    }
    headers = {"Content-Type": "application/json"}

    r = requests.post(
        f"{BASE_URL}/api/attack/fire",
        json=payload,
        headers=headers,
        timeout=TIMEOUT
    )
    r.raise_for_status()
    json_data = r.json()
    assert r.status_code == 200, f"Expected 200 on scan start, got {r.status_code}"
    assert "scan_id" in json_data, "Missing scan_id in response"
    assert json_data.get("status") == "Swarm Online", f"Unexpected status: {json_data.get('status')}"
    return json_data["scan_id"]

def check_scan_completion(scan_id, max_wait_sec=90, poll_interval=5):
    for attempt in range(0, max_wait_sec, poll_interval):
        r = requests.get(
            f"{BASE_URL}/api/dashboard/scans",
            timeout=TIMEOUT
        )
        r.raise_for_status()
        scans = r.json()
        for scan in scans:
            if scan.get("scan_id") == scan_id:
                status = scan.get("status", "").lower()
                if status == "completed":
                    return True
                if status == "failed":
                    raise RuntimeError(f"Scan {scan_id} failed unexpectedly")
        time.sleep(poll_interval)
    return False

def get_report_pdf(scan_id):
    headers = {"Accept": "application/pdf"}
    r = requests.get(
        f"{BASE_URL}/api/reports/pdf/{scan_id}",
        headers=headers,
        timeout=TIMEOUT
    )
    return r

def get_report_pdf_nonexistent(scan_id):
    headers = {"Accept": "application/pdf"}
    r = requests.get(
        f"{BASE_URL}/api/reports/pdf/{scan_id}",
        headers=headers,
        timeout=TIMEOUT
    )
    return r

def delete_scan(scan_id):
    pass

def test_get_api_reports_pdf_with_existing_and_nonexistent_scan_id():
    scan_id = None
    try:
        scan_id = launch_scan_with_valid_payload()

        completed = check_scan_completion(scan_id)
        assert completed, f"Scan {scan_id} did not complete within timeout"

        r = get_report_pdf(scan_id)
        assert r.status_code == 200, f"Expected 200 for completed scan report, got {r.status_code}"
        content_type = r.headers.get("Content-Type", "")
        assert content_type == "application/pdf", f"Expected 'application/pdf', got '{content_type}'"
        content_disposition = r.headers.get("Content-Disposition", "")
        assert "filename=" in content_disposition.lower(), "Expected 'filename=' in Content-Disposition header"

        content = r.content
        assert content[:4] == b'%PDF', "Response content is not a valid PDF file"

        import uuid
        fake_scan_id = str(uuid.uuid4())
        if scan_id == fake_scan_id:
            fake_scan_id = str(uuid.uuid4())

        r2 = get_report_pdf_nonexistent(fake_scan_id)
        assert r2.status_code == 404, f"Expected 404 for nonexistent scan_id, got {r2.status_code}"
        json_err = r2.json()
        assert "error" in json_err or "message" in json_err, "Expected error message in 404 response"
        msg = json_err.get("error") or json_err.get("message") or ""
        assert ("not found" in msg.lower() or "not ready" in msg.lower()), f"Unexpected error message: {msg}"

        short_scan_id = launch_scan_with_valid_payload()
        r3 = get_report_pdf(short_scan_id)
        if r3.status_code != 404:
            content_type3 = r3.headers.get("Content-Type", "")
            assert content_type3 == "application/pdf", "Expected application/pdf if report ready early"
        else:
            json_err3 = r3.json()
            msg3 = json_err3.get("error") or json_err3.get("message") or ""
            assert ("not found" in msg3.lower() or "not ready" in msg3.lower()), f"Unexpected error message: {msg3}"

    finally:
        if scan_id:
            delete_scan(scan_id)

test_get_api_reports_pdf_with_existing_and_nonexistent_scan_id()
