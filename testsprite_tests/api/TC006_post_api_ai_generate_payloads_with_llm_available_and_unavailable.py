import requests
import base64
import urllib.parse
import string
import random
import time

BASE_URL = "http://localhost:8000"
API_PATH = "/api/ai/generate_payloads"
TIMEOUT = 30

def double_url_encode(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

def base64_rot13_encode(s):
    b64 = base64.b64encode(s.encode()).decode()
    rot13 = b64.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    return rot13

def insert_invisible_unicode(s):
    # Insert ZERO WIDTH SPACE (U+200B) randomly into the string
    zwsp = '\u200b'
    positions = random.sample(range(len(s)+1), k=max(1, len(s)//10))
    s_list = list(s)
    for pos in sorted(positions, reverse=True):
        s_list.insert(pos, zwsp)
    return ''.join(s_list)

def generate_obfuscated_context():
    vuln_type = "SQL Injection"
    response_sample = (
        "SELECT * FROM users WHERE username = 'admin' -- "
        "DROP TABLE sessions; -- "
        "UNION SELECT password FROM secrets; "
    )
    # Apply heavy obfuscations:
    # 1. Double URL Encoding
    vuln_type_enc = double_url_encode(vuln_type)
    response_sample_enc = double_url_encode(response_sample)
    # 2. Base64+ROT13 encoding (for extra deep obfuscation on a part)
    extra_obf = base64_rot13_encode("DROP TABLE users;")
    # 3. Insert invisible Unicode in another string part for stress
    response_sample_invis = insert_invisible_unicode(response_sample)
    # Compose final mixed context string by concatenation
    combined_response_sample = response_sample_enc + "|" + extra_obf + "|" + response_sample_invis
    return {
        "vuln_type": vuln_type_enc,
        "response_sample": combined_response_sample
    }

def test_post_api_ai_generate_payloads_with_llm_available_and_unavailable():
    url = BASE_URL + API_PATH
    headers = {
        "Content-Type": "application/json"
    }

    # 1. Test with LLM available simulation (normal call)
    context1 = generate_obfuscated_context()
    payload1 = {
        "context": {
            "vuln_type": context1["vuln_type"],
            "response_sample": context1["response_sample"]
        },
        "simulate_llm_unavailable": False  # Assume this flag simulates availability
    }

    resp1 = None
    try:
        resp1 = requests.post(url, json=payload1, headers=headers, timeout=TIMEOUT)
        assert resp1.status_code == 200, f"Expected 200, got {resp1.status_code}"
        json_resp = resp1.json()
        # Validate structure: generated payloads array from GI5+Cortex fusion
        assert "generated_payloads" in json_resp, "Missing 'generated_payloads' in response"
        assert isinstance(json_resp["generated_payloads"], list), "'generated_payloads' should be a list"
        assert len(json_resp["generated_payloads"]) > 0, "generated_payloads should not be empty"
        # Validate fusion indication without circuit_breaker
        assert json_resp.get("circuit_breaker") is None or json_resp.get("circuit_breaker") is False, "circuit_breaker should not be true when LLM is available"
        # Additional deep assertions on payload contents (obfuscated payloads supported)
        for p in json_resp["generated_payloads"]:
            assert isinstance(p, str), "Each payload must be string"
            # Payloads should be decoded properly - no empty strings allowed
            assert len(p.strip()) > 0, "Payload cannot be empty or blank"
    except Exception as e:
        if resp1 is not None:
            raise AssertionError(f"LLM available test failed with status {resp1.status_code}: {resp1.text}") from e
        else:
            raise AssertionError("LLM available test failed, no response received") from e

    # 2. Test with LLM unavailable simulation (simulate remote LLM down fallback)
    context2 = generate_obfuscated_context()
    payload2 = {
        "context": {
            "vuln_type": context2["vuln_type"],
            "response_sample": context2["response_sample"]
        },
        "simulate_llm_unavailable": True  # This flag tells backend to simulate LLM failure fallback
    }

    resp2 = None
    try:
        resp2 = requests.post(url, json=payload2, headers=headers, timeout=TIMEOUT)
        assert resp2.status_code == 200, f"Expected 200, got {resp2.status_code}"
        json_resp = resp2.json()
        # Validate deterministic payloads from GI5 only (likely reduced set)
        assert "generated_payloads" in json_resp, "Missing 'generated_payloads' in response"
        payloads = json_resp["generated_payloads"]
        assert isinstance(payloads, list), "'generated_payloads' should be a list"
        assert len(payloads) > 0, "generated_payloads should not be empty"
        # Validate presence of circuit_breaker status indicating fallback
        assert json_resp.get("circuit_breaker") is True, "circuit_breaker should be true when LLM is unavailable"
        # Ensure output is deterministic and reduced (heuristic: length of array less or equal than first test)
        assert len(payloads) <= len(resp1.json().get("generated_payloads", [])), "Fallback payload count should be less or equal to fusion payload count"
        # Payload format checks
        for p in payloads:
            assert isinstance(p, str), "Each payload must be string"
            assert len(p.strip()) > 0, "Payload cannot be empty or blank"
    except Exception as e:
        if resp2 is not None:
            raise AssertionError(f"LLM unavailable fallback test failed with status {resp2.status_code}: {resp2.text}") from e
        else:
            raise AssertionError("LLM unavailable fallback test failed, no response received") from e

test_post_api_ai_generate_payloads_with_llm_available_and_unavailable()
