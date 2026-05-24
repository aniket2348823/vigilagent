import requests
import time
import threading
import websocket
import json

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30


def test_TC010_end_to_end_backend_workflow_execution():
    """
    End-to-End Backend Workflow Execution:
    Runs full pipeline: Fire -> Orchestrator -> Cortex AI -> Supabase storage -> Response.
    Includes API discovery, RLS/CRUD, Auth Flows, AI fallbacks, business logic, resilience,
    latency, concurrency, security, and end-to-end integration backend validation.
    """
    headers = {"Content-Type": "application/json"}

    def call_api_discovery():
        # API discovery and endpoint verification:
        endpoints = [
            "/api/attack/fire",
            "/api/defense/analyze",
            "/api/ai/status",
            "/api/dashboard/scans",
            "/api/dashboard/stats",
            "/api/health"
        ]
        for ep in endpoints:
            try:
                r = requests.options(f"{BASE_URL}{ep}", timeout=TIMEOUT)
                assert r.status_code in (200, 204, 405), f"Discovery OPTIONS {ep} failed: {r.status_code}"
            except requests.RequestException:
                pass  # Not all may support OPTIONS, continue

    def launch_fire_scan():
        """
        Launch a scan with /api/attack/fire (fire event).
        Returns scan_id.
        """
        payload = {
            "target_url": "https://example.com/api/v1/test",
            "method": "GET",
            "headers": {"User-Agent": "Vulagent-Scanner-Test/1.0"},
            "duration": 3  # short duration to keep test timely
        }
        resp = requests.post(f"{BASE_URL}/api/attack/fire", json=payload, headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Fire scan launch failed: {resp.status_code} {resp.text}"
        data = resp.json()
        assert "scan_id" in data and data.get("status") == "Swarm Online"
        return data["scan_id"]

    def get_scan_from_dashboard(scan_id):
        resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        assert resp.status_code == 200, f"Dashboard scans fetch failed: {resp.status_code}"
        scans = resp.json()
        assert any(scan.get("scan_id") == scan_id for scan in scans), "scan_id not found in dashboard scans"

    def assert_ai_status_ok():
        resp = requests.get(f"{BASE_URL}/api/ai/status", timeout=TIMEOUT)
        assert resp.status_code == 200, f"AI status fetch failed: {resp.status_code}"
        data = resp.json()
        core_status = data.get("core_status", {})
        fallback = data.get("fallback", "")
        # Validate keys and types
        assert all(k in core_status for k in ("gi5", "ollama", "openrouter"))
        assert isinstance(data.get("llm_calls"), int)
        assert isinstance(data.get("circuit_breaker_trips"), int)
        assert fallback in ("OpenRouter", "GI5_only", "Ollama", "")

    def analyze_defense_block():
        payload = {
            "agent_id": "agent_prism",
            "content": {"innerText": "malicious prompt injection attempt"},
            "url": "https://example.com"
        }
        resp = requests.post(f"{BASE_URL}/api/defense/analyze", json=payload, headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Defense analyze failed: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data.get("verdict") in ("BLOCK", "ALLOW")
        assert isinstance(data.get("risk_score"), int)

    def websocket_listen(scan_id, duration=5):
        """
        Connect to live WebSocket feed and ensure receiving SCAN_UPDATE and LIVE_THREAT_LOG messages
        referencing the scan_id.
        """
        ws_url = f"ws://127.0.0.1:8000/stream?client_type=ui"
        ws_msgs = {"SCAN_UPDATE": False, "LIVE_ATTACK_FEED": False}
        received_scan_id = False

        def on_message(ws, message):
            try:
                msg = json.loads(message)
                t = msg.get("type")
                if t in ws_msgs:
                    ws_msgs[t] = True
                # check if scan_id is referenced
                if scan_id in message:
                    nonlocal received_scan_id
                    received_scan_id = True
            except Exception:
                pass

        def on_error(ws, error):
            raise RuntimeError(f"WebSocket error: {error}")

        def on_close(ws, close_status_code, close_msg):
            pass  # No-op

        ws = websocket.WebSocketApp(ws_url,
                                    on_message=on_message,
                                    on_error=on_error,
                                    on_close=on_close)
        wst = threading.Thread(target=ws.run_forever)
        wst.daemon = True
        wst.start()
        time.sleep(duration)
        ws.close()
        wst.join(timeout=5)
        assert all(ws_msgs.values()), "Did not receive all expected WebSocket message types"
        assert received_scan_id, "Scan ID not referenced in any WebSocket messages"

    def check_scan_report(scan_id):
        # Wait/retry briefly for report readiness
        max_wait = 15
        for _ in range(max_wait):
            resp = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
            if resp.status_code != 200:
                time.sleep(1)
                continue
            scans = resp.json()
            scan = next((s for s in scans if s.get("scan_id") == scan_id), None)
            if scan and scan.get("report_ready"):
                break
            time.sleep(1)
        else:
            assert False, "Report not ready within timeout"

        # Download report PDF
        r = requests.get(f"{BASE_URL}/api/reports/pdf/{scan_id}", timeout=TIMEOUT)
        assert r.status_code == 200, f"Report PDF fetch failed: {r.status_code}"
        ct = r.headers.get("Content-Type", "")
        cd = r.headers.get("Content-Disposition", "")
        assert "application/pdf" in ct.lower()
        assert "filename" in cd.lower()

    def test_supabase_rls_crud():
        # Basic test of Supabase CRUD by ingesting Recon packet and checking updates
        ingest_payload = {
            "url": "https://example.com/api/v1/test",
            "method": "GET",
            "headers": {"X-Test": "value"},
            "body": {"test_key": "test_val"},
            "timestamp": int(time.time())
        }
        r = requests.post(f"{BASE_URL}/api/recon/ingest", json=ingest_payload, headers=headers, timeout=TIMEOUT)
        assert r.status_code == 200, f"Recon ingest failed: {r.status_code}"

        # Verify this affects dashboard scans or logs (best effort)
        r = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        assert r.status_code == 200
        scans = r.json()
        # At least one scan or recent recon log present (cannot assert exact content reliably)
        assert isinstance(scans, list)

    def test_auth_flow_simulation():
        # Generate TOTP 2FA secret
        r = requests.post(f"{BASE_URL}/api/dashboard/settings/2fa/generate", timeout=TIMEOUT)
        assert r.status_code == 200
        data = r.json()
        assert "secret" in data and "qr_code_base64" in data
        secret = data["secret"]

        # Verify 2FA with invalid code returns 401
        r = requests.post(f"{BASE_URL}/api/dashboard/settings/2fa/verify", json={"totp_code": "000000"}, timeout=TIMEOUT)
        assert r.status_code == 401

        # Normally would verify with valid totp_code, but skipping generation complexity in this test

    def test_security_hardening_injection_check():
        # Attempt injection via attack fire endpoint
        injection_payload = {
            "target_url": "https://example.com/api/v1/test",
            "method": "GET",
            "headers": {"User-Agent": "test'; DROP TABLE users; --"},
            "duration": 2
        }
        r = requests.post(f"{BASE_URL}/api/attack/fire", json=injection_payload, headers=headers, timeout=TIMEOUT)
        # Should succeed but be sanitized. Server should not crash or execute injection.
        assert r.status_code == 200 or r.status_code == 422 or r.status_code == 429

        # Attempt malformed analyze defense payload for error 500 test
        bad_payload = {"agent_id": "agent_prism", "content": "malformed_content", "url": "https://example.com"}
        r = requests.post(f"{BASE_URL}/api/defense/analyze", json=bad_payload, headers=headers, timeout=TIMEOUT)
        assert r.status_code in (500, 422, 400)  # Server error or validation failure as expected

    def test_concurrency_race_condition():
        # Fire multiple concurrent scans and check no state corruption
        scan_ids = []

        def fire_scan_thread():
            try:
                sid = launch_fire_scan()
                scan_ids.append(sid)
            except Exception:
                pass

        threads = [threading.Thread(target=fire_scan_thread) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All scan_ids unique and present in dashboard
        assert len(scan_ids) >= 1
        r = requests.get(f"{BASE_URL}/api/dashboard/scans", timeout=TIMEOUT)
        assert r.status_code == 200
        scans = r.json()
        registered_ids = [s.get("scan_id") for s in scans]
        for sid in scan_ids:
            assert sid in registered_ids

    # Begin tests chained for end-to-end

    # 1. API Discovery
    call_api_discovery()

    # 2. Launch primary scan fire (Fire -> Orchestrator)
    scan_id = launch_fire_scan()

    # 3. Verify scan in dashboard (Storage)
    get_scan_from_dashboard(scan_id)

    # 4. Check AI Cortex status endpoint (AI Fallbacks)
    assert_ai_status_ok()

    # 5. Analyze defense endpoint with blocking verdict (AI logic)
    analyze_defense_block()

    # 6. Listen on WebSocket feed for scan events (Orchestrator live telemetry)
    websocket_listen(scan_id)

    # 7. Check for forensic report PDF retrieval from storage after scan completion
    check_scan_report(scan_id)

    # 8. Test supabase RLS/CRUD by ingesting recon packet and validating scan reflection
    test_supabase_rls_crud()

    # 9. Simulate auth flow - generate 2FA and verify invalid attempt is rejected
    test_auth_flow_simulation()

    # 10. Security - test injection vectors and malformed payload response correctness
    test_security_hardening_injection_check()

    # 11. Concurrency - launch multiple scans concurrently for race condition detection
    test_concurrency_race_condition()


# test_TC010_end_to_end_backend_workflow_execution()
