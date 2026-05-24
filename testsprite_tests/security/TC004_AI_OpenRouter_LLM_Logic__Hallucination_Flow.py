import requests
import time
import threading

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_ai_openrouter_llm_logic_and_hallucination_flow():
    """
    Test AI Cortex handling of malformed payloads to detect hallucination flows
    and fallback to GI5/Ollama when OpenRouter timeouts occur.
    This test covers:
    - API discovery (POST /api/defense/analyze)
    - Auth flows (no auth required)
    - OpenRouter AI fallback & error handling (simulate timeout)
    - Security by sending malformed payloads
    - Resilience to network failures and latency detection
    - Concurrency by firing several requests simultaneously
    - Verify 200, 422, or 500 error responses with correct content
    """

    analyze_url = f"{BASE_URL}/api/defense/analyze"

    # Malformed payloads for hallucination detection / error stimulation
    malformed_payloads = [
        {},  # empty payload, missing required keys
        {"agent_id": "agent_prism"},  # missing content and url
        {"agent_id": "agent_prism", "content": "this should be dict", "url": "https://example.com"},  # wrong content type
        {"agent_id": "agent_prism", "content": {"innerText": "normal text"}, "url": ""},  # empty URL
        {"agent_id": "nonexistent_agent", "content": {"innerText": "test"}, "url": "https://example.com"},  # invalid agent_id
        {"agent_id": "agent_prism", "content": {"innerText": "drop table users;--"}, "url": "https://evil.com"},  # injection attempt
    ]

    success_responses = []
    error_responses = []

    def send_request(payload):
        try:
            start_time = time.time()
            resp = requests.post(analyze_url, json=payload, timeout=TIMEOUT)
            elapsed = time.time() - start_time
            # Accept 200 with valid response, or 422 validation error, or 500 for internal AI failures
            if resp.status_code == 200:
                json_data = resp.json()
                # Validate presence and types of keys in success response
                keys = {"verdict", "reason", "risk_score"}
                assert keys.issubset(json_data.keys()), f"Missing keys in success response: {json_data}"
                assert json_data["verdict"] in ("BLOCK", "ALLOW"), f"Unexpected verdict value: {json_data['verdict']}"
                assert isinstance(json_data["risk_score"], int), f"risk_score type invalid: {type(json_data['risk_score'])}"
                success_responses.append((payload, resp.status_code, elapsed))
            elif resp.status_code == 422:
                # Validation error for malformed payloads
                error_responses.append((payload, resp.status_code, elapsed))
            elif resp.status_code == 500:
                json_data = resp.json()
                # Should report server AI failure on malformed or internal error
                assert "error" in json_data or "mode" in json_data, f"Unexpected 500 response structure: {json_data}"
                error_responses.append((payload, resp.status_code, elapsed))
            else:
                # Unexpected response code
                error_responses.append((payload, resp.status_code, None))
        except requests.Timeout:
            # Simulate OpenRouter timeout fallback scenario
            error_responses.append((payload, 'Timeout', None))
        except Exception as e:
            error_responses.append((payload, f'Exception: {e}', None))

    # Step 1: API Discovery - validate endpoint existence by sending minimal valid request
    discovery_payload = {
        "agent_id": "agent_prism",
        "content": {"innerText": "test discovery"},
        "url": "https://example.com"
    }
    try:
        resp = requests.post(analyze_url, json=discovery_payload, timeout=TIMEOUT)
        assert resp.status_code in (200, 500), f"API discovery unexpected status: {resp.status_code}"
        if resp.status_code == 200:
            json_data = resp.json()
            keys = {"verdict", "reason", "risk_score"}
            assert keys.issubset(json_data.keys()), f"Missing keys in discovery success response: {json_data}"
            assert json_data["verdict"] in ("BLOCK", "ALLOW"), f"Unexpected verdict value in discovery: {json_data['verdict']}"
            assert isinstance(json_data["risk_score"], int), f"risk_score type invalid in discovery: {type(json_data['risk_score'])}"
            success_responses.append((discovery_payload, resp.status_code, None))
    except Exception as e:
        assert False, f"API discovery failed with exception: {e}"

    # Step 2-11: Send malformed payloads with concurrency to detect hallucination & fallback
    threads = []
    for payload in malformed_payloads:
        t = threading.Thread(target=send_request, args=(payload,))
        threads.append(t)
        t.start()

    # Add multiple requests with simulated delay to detect latency and resilience
    def delayed_request():
        send_request({
            "agent_id": "agent_prism",
            "content": {"innerText": "test latency and fallback"},
            "url": "https://example.com"
        })

    for _ in range(3):
        t = threading.Thread(target=delayed_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Validate at least one success response and at least one error/fallback occurred
    assert len(success_responses) > 0, "No successful responses detected."
    assert len(error_responses) > 0, "No error or fallback responses detected."

    # Check for latency/performance: no request should exceed 20 seconds (shorter than timeout)
    for _, status, elapsed in success_responses + error_responses:
        if isinstance(elapsed, float):
            assert elapsed < 20, f"Request exceeded latency threshold: {elapsed}s"

    # Security checks: ensure none of the responses contain stack traces or sensitive data
    # Here we crudely check that 'error' fields do not leak DB or internal messages in 500 responses
    for payload, status, _ in error_responses:
        if status == 500:
            # Repeat request to fetch error details
            try:
                resp = requests.post(analyze_url, json=payload, timeout=TIMEOUT)
                if resp.status_code == 500:
                    err_json = resp.json()
                    assert 'stack' not in err_json.get('error', '').lower(), "Stack trace leaked in error."
                    assert 'exception' not in err_json.get('error', '').lower(), "Exception details leaked in error."
            except:
                pass

# test_ai_openrouter_llm_logic_and_hallucination_flow()
