import requests
import time

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_auth_flow_and_privilege_escalation_simulation():
    """
    Validate session token persistence and unauthorized access attempt using invalid/expired credentials.
    Includes:
    - Login with valid credentials and obtain session token.
    - Access a protected endpoint with valid token.
    - Attempt access with invalid token.
    - Attempt access with expired token simulation.
    """

    # Sample valid credentials and 2FA flow emulation
    username = "testuser"
    correct_totp_code = "123456"  # Using static placeholder as test TOTP
    session_token = None

    headers = {"Content-Type": "application/json"}

    try:
        # 1. Generate TOTP secret (simulate 2FA generation)
        resp_2fa_generate = requests.post(
            f"{BASE_URL}/api/dashboard/settings/2fa/generate",
            headers=headers,
            timeout=TIMEOUT,
        )
        assert resp_2fa_generate.status_code == 200, f"2FA generate failed: {resp_2fa_generate.text}"
        data_2fa = resp_2fa_generate.json()
        assert "secret" in data_2fa and "qr_code_base64" in data_2fa

        # Skip 2FA verification step because the TOTP code "123456" is not guaranteed valid

        # 2. Login with correct username and correct totp_code
        resp_login = requests.post(
            f"{BASE_URL}/api/dashboard/auth/login",
            headers=headers,
            json={"username": username, "totp_code": correct_totp_code},
            timeout=TIMEOUT,
        )
        assert resp_login.status_code == 200, f"Login failed with valid creds: {resp_login.text}"
        login_data = resp_login.json()
        assert "session_token" in login_data
        session_token = login_data["session_token"]
        auth_headers = {"Authorization": f"Bearer {session_token}"}

        # 3. Use the session token to access a restricted endpoint: GET /api/dashboard/scans (assuming auth required)
        resp_scans = requests.get(
            f"{BASE_URL}/api/dashboard/scans",
            headers=auth_headers,
            timeout=TIMEOUT,
        )
        # We expect success or 200 valid access
        assert resp_scans.status_code == 200, f"Authorized access failed with valid token: {resp_scans.text}"

        # 4. Attempt access with invalid session token
        invalid_auth_headers = {"Authorization": "Bearer invalidtoken123"}
        resp_invalid_token = requests.get(
            f"{BASE_URL}/api/dashboard/scans",
            headers=invalid_auth_headers,
            timeout=TIMEOUT,
        )
        # Expect 401 Unauthorized or 403 Forbidden
        assert resp_invalid_token.status_code in (401, 403), \
            f"Unexpected status with invalid token: {resp_invalid_token.status_code} {resp_invalid_token.text}"

        # 5. Simulate expired token by using a fake expired token string:
        expired_auth_headers = {"Authorization": "Bearer expiredtoken123"}
        resp_expired_token = requests.get(
            f"{BASE_URL}/api/dashboard/scans",
            headers=expired_auth_headers,
            timeout=TIMEOUT,
        )
        assert resp_expired_token.status_code in (401, 403), \
            f"Unexpected status with expired token: {resp_expired_token.status_code} {resp_expired_token.text}"

        # 6. Attempt accessing an admin-protected endpoint (simulate privilege escalation)
        # Because no clear admin endpoint requires auth in PRD, we test /api/dashboard/settings/2fa/generate again with bad auth header to simulate unauthorized
        resp_unauthorized_admin = requests.post(
            f"{BASE_URL}/api/dashboard/settings/2fa/generate",
            headers={"Authorization": "Bearer invalidtoken123", "Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
        # Expect 401/403 as unauthorized access
        assert resp_unauthorized_admin.status_code in (401, 403), \
            f"Unauthorized privileged endpoint access allowed unexpectedly: {resp_unauthorized_admin.status_code}"

    except requests.RequestException as e:
        assert False, f"Request failed with exception: {e}"
    finally:
        # No resource to clean up explicitly in this test (tokens etc managed server side)
        pass

# test_auth_flow_and_privilege_escalation_simulation()
