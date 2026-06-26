import requests
import base64
import urllib.parse
import threading
import time

BASE_URL = "http://localhost:8000"
API_PATH = "/api/defense/analyze"
FULL_URL = f"{BASE_URL}{API_PATH}"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}

VALID_AGENT_IDS = ["Sigma", "Kappa", "Alpha"]
SAMPLE_URL = "https://example.com/test"
SAMPLE_SESSION_ID = "session-1234"

# Helper to double URL encode a string
def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

# Helper to Base64 + ROT13 encode a string
def base64_rot13_encode(s: str) -> str:
    b64_encoded = base64.b64encode(s.encode()).decode()
    rot13_trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )
    return b64_encoded.translate(rot13_trans)

# Invisible Unicode zero-width space injection for obfuscation
def invisible_unicode_injection(s: str) -> str:
    zwsp = "\u200b"
    result = ""
    for c in s:
        result += c + zwsp
    return result

def post_analyze(payload: dict):
    return requests.post(FULL_URL, json=payload, headers=HEADERS, timeout=TIMEOUT)

def test_post_api_defense_analyze_with_valid_and_invalid_payloads():
    # === Valid payloads with heavy obfuscation ===
    valid_contents = [
        "<script>alert('XSS')</script>",
        "Normal benign content with no threat",
        "const msg = 'DROP TABLE users;';",
        "eval(window.atob('c29ldGY='));"  # some JS code snippet
    ]

    # Obfuscate these payloads with multiple layers
    obfuscated_contents = []
    for content in valid_contents:
        # Combination of double URL encode, base64+ROT13, and invisible unicode
        encoded = double_url_encode(content)
        encoded = base64_rot13_encode(encoded)
        encoded = invisible_unicode_injection(encoded)
        obfuscated_contents.append(encoded)

    for agent_id in VALID_AGENT_IDS:
        for obf_content in obfuscated_contents:
            payload = {
                "agent_id": agent_id,
                "content": obf_content,
                "url": SAMPLE_URL,
                "session_id": SAMPLE_SESSION_ID,
            }
            try:
                resp = post_analyze(payload)
            except Exception as e:
                assert False, f"Request failed unexpectedly for valid input: {e}"
            assert resp.status_code == 200, f"Expected 200 for valid payload, got {resp.status_code}"
            json_resp = resp.json()
            assert "verdict" in json_resp, "Response missing verdict"
            assert json_resp["verdict"] in ["BLOCK", "ALLOW"], f"Unexpected verdict: {json_resp['verdict']}"
            assert "reason" in json_resp and isinstance(json_resp["reason"], str) and len(json_resp["reason"]) > 0
            assert "risk_score" in json_resp and isinstance(json_resp["risk_score"], (int, float))
            # Simulate frontend/extension blocking behavior trigger validation for BLOCK verdict
            if json_resp["verdict"] == "BLOCK":
                # Suppose blocking behavior triggers a specific field or flag (simulate)
                assert "block_triggered" not in json_resp or json_resp.get("block_triggered", True) in [True, False]

    # === Invalid payloads: malformed content ===
    malformed_contents = [
        None,
        "",
        12345,  # invalid type
        {"unexpected": "dict"},
        [1, 2, 3],
        "<script><script>alert()</script>",  # broken script tag
        "\ud800",  # Lone surrogate invalid unicode
        base64.b64encode(b"\x00\xff\xfe").decode(),
        double_url_encode("%%%")  # invalid triple percent encoding pattern
    ]

    for malformed_content in malformed_contents:
        payload = {
            "agent_id": VALID_AGENT_IDS[0],
            "content": malformed_content,
            "url": SAMPLE_URL,
            "session_id": SAMPLE_SESSION_ID,
        }
        try:
            resp = post_analyze(payload)
        except Exception as e:
            # This request should not raise exceptions, only return 4xx
            assert False, f"Request failed unexpectedly for malformed content: {e}"
        assert resp.status_code in [400, 422], f"Expected 400 or 422 for malformed content, got {resp.status_code}"
        # Response should not contain verdict
        try:
            json_resp = resp.json()
            assert "verdict" not in json_resp
        except Exception:
            # Non-JSON error response is acceptable
            pass

    # === Invalid payloads: unsupported agent_id ===
    unsupported_agents = ["UnknownAgent", "", None, 123, "\u03c3igma", "\u03a3igma"]

    valid_content_plain = "Normal benign content"

    for agent_id in unsupported_agents:
        payload = {
            "agent_id": agent_id,
            "content": valid_content_plain,
            "url": SAMPLE_URL,
            "session_id": SAMPLE_SESSION_ID,
        }
        try:
            resp = post_analyze(payload)
        except Exception as e:
            assert False, f"Request failed unexpectedly for unsupported agent_id: {e}"
        assert resp.status_code in [400, 422], f"Expected 400 or 422 for unsupported agent_id, got {resp.status_code}"
        try:
            json_resp = resp.json()
            assert "verdict" not in json_resp
        except Exception:
            pass

    # === Stress test: parallel requests with heavy obfuscation and concurrent potential race conditions ===
    thread_results = []
    def worker_thread(agent_idx, content_idx):
        agent = VALID_AGENT_IDS[agent_idx % len(VALID_AGENT_IDS)]
        content = obfuscated_contents[content_idx % len(obfuscated_contents)]
        pld = {
            "agent_id": agent,
            "content": content,
            "url": SAMPLE_URL,
            "session_id": SAMPLE_SESSION_ID,
        }
        try:
            r = post_analyze(pld)
            if r.status_code != 200:
                thread_results.append((False, f"Status {r.status_code}"))
                return
            j = r.json()
            if j.get("verdict") not in ["BLOCK", "ALLOW"]:
                thread_results.append((False, f"Invalid verdict {j.get('verdict')}"))
                return
            # no exception: success
            thread_results.append((True, None))
        except Exception as e:
            thread_results.append((False, str(e)))

    thread_list = []
    concurrency = 50  # stress concurrency with 50 parallel threads
    for i in range(concurrency):
        t = threading.Thread(target=worker_thread, args=(i % len(VALID_AGENT_IDS), i % len(obfuscated_contents)))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join(timeout=TIMEOUT)
    # All threads must succeed
    failures = [res for success, res in thread_results if not success]
    assert len(failures) == 0, f"Parallel stress test failed with errors: {failures}"

test_post_api_defense_analyze_with_valid_and_invalid_payloads()
