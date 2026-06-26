import requests
import pyotp
import time

BASE_URL = "http://localhost:8000/D:\\Antigravity 2\\API Endpoint Scanner"
HEADERS = {"Content-Type": "application/json"}
TIMEOUT = 30


def test_post_api_dashboard_settings_2fa_generate_verify_and_login():
    session = requests.Session()
    session.headers.update(HEADERS)

    try:
        # Step 1: Generate TOTP secret and QR code
        generate_url = f"{BASE_URL}/api/dashboard/settings/2fa/generate"
        resp = session.post(generate_url, timeout=TIMEOUT)
        assert resp.status_code == 200, f"2FA Generate failed: {resp.status_code} {resp.text}"
        data = resp.json()
        assert "totp_secret" in data, "Response missing totp_secret"
        assert "qr_code" in data, "Response missing qr_code"
        totp_secret = data["totp_secret"]

        # Prepare TOTP generator
        totp = pyotp.TOTP(totp_secret)

        # Step 2: Verify TOTP code to enable 2FA
        verify_url = f"{BASE_URL}/api/dashboard/settings/2fa/verify"
        valid_totp_code = totp.now()
        verify_payload = {"totp_code": valid_totp_code}
        resp = session.post(verify_url, json=verify_payload, timeout=TIMEOUT)
        assert resp.status_code == 200, f"2FA Verify failed: {resp.status_code} {resp.text}"
        verify_resp = resp.json()
        assert verify_resp.get("enabled") is True or "2fa_enabled" in verify_resp or "message" in verify_resp, "2FA verify did not confirm enabling"

        # Small delay to ensure TOTP current step is valid for login
        time.sleep(1)

        # Step 3: Login with valid TOTP
        login_url = f"{BASE_URL}/api/dashboard/auth/login"

        # We assume username and password must be provided to login.
        # Since no auth schema provided, we simulate a login with TOTP only as per PRD.
        # If username/password required, this test should be adjusted.

        # Payload with valid TOTP
        login_payload_valid = {
            "username": "testuser",
            "password": "password",  # Replace with valid test credentials or mock according to system
            "totp_code": totp.now()
        }
        resp = session.post(login_url, json=login_payload_valid, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Login with valid TOTP failed: {resp.status_code} {resp.text}"
        login_data = resp.json()
        assert "session_token" in login_data, "No session_token returned on successful login"
        assert "dashboard_access" in login_data or login_data.get("access") == "granted", "Dashboard access not granted on valid login"

        # Step 4: Login with invalid TOTP and expect 401 Unauthorized
        invalid_totp_code = "000000"  # An invalid fixed code
        login_payload_invalid = {
            "username": "testuser",
            "password": "password",
            "totp_code": invalid_totp_code
        }
        resp = session.post(login_url, json=login_payload_invalid, timeout=TIMEOUT)
        assert resp.status_code == 401, f"Login with invalid TOTP did not fail as expected: {resp.status_code} {resp.text}"
        err_data = resp.json()
        assert "invalid 2FA" in err_data.get("message", "").lower(), "Error message missing or wrong for invalid 2FA login"

    finally:
        # Cleanup would go here if 2FA setup created persistent changes or test user
        pass


test_post_api_dashboard_settings_2fa_generate_verify_and_login()