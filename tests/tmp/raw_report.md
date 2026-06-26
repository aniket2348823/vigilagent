
# TestSprite AI Testing Report(MCP)

---

## 1️⃣ Document Metadata
- **Project Name:** API Endpoint Scanner
- **Date:** 2026-04-05
- **Prepared by:** TestSprite AI Team

---

## 2️⃣ Requirement Validation Summary

#### Test TC001 post_api_attack_fire_with_valid_and_invalid_payloads
- **Test Code:** [TC001_post_api_attack_fire_with_valid_and_invalid_payloads.py](./TC001_post_api_attack_fire_with_valid_and_invalid_payloads.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 187, in <module>
  File "<string>", line 120, in test_post_api_attack_fire_with_valid_and_invalid_payloads
AssertionError: Expected 200, got 400 with body {"detail":"Invalid or missing payload. Expected a valid request structure."}

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/e2c935f9-e9ad-4074-ad9e-6635115b1254
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC002 post_api_recon_ingest_with_valid_and_invalid_payloads
- **Test Code:** [TC002_post_api_recon_ingest_with_valid_and_invalid_payloads.py](./TC002_post_api_recon_ingest_with_valid_and_invalid_payloads.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 2, in <module>
ModuleNotFoundError: No module named 'websocket'

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/7bc97ff7-35e3-4ffe-a012-b610ac29c8d4
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC003 websocket_stream_connection_and_event_reception
- **Test Code:** [TC003_websocket_stream_connection_and_event_reception.py](./TC003_websocket_stream_connection_and_event_reception.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'websocket'

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/5c603de4-f57e-4a06-91c9-fbc7a773cf66
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC004 get_api_reports_pdf_with_existing_and_nonexistent_scan_id
- **Test Code:** [TC004_get_api_reports_pdf_with_existing_and_nonexistent_scan_id.py](./TC004_get_api_reports_pdf_with_existing_and_nonexistent_scan_id.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 117, in <module>
  File "<string>", line 76, in test_get_api_reports_pdf_with_existing_and_nonexistent_scan_id
  File "<string>", line 27, in launch_scan_with_valid_payload
  File "/var/lang/lib/python3.12/site-packages/requests/models.py", line 1024, in raise_for_status
    raise HTTPError(http_error_msg, response=self)
requests.exceptions.HTTPError: 400 Client Error: Bad Request for url: http://localhost:8000/api/attack/fire

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/05ab855f-a0b3-4f25-ae1e-b7235309c370
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC005 get_api_dashboard_stats_under_normal_and_failure_conditions
- **Test Code:** [TC005_get_api_dashboard_stats_under_normal_and_failure_conditions.py](./TC005_get_api_dashboard_stats_under_normal_and_failure_conditions.py)
- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/785ac788-d9d1-4819-acf5-9c0c13676829
- **Status:** ✅ Passed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC006 post_api_ai_generate_payloads_with_llm_available_and_unavailable
- **Test Code:** [TC006_post_api_ai_generate_payloads_with_llm_available_and_unavailable.py](./TC006_post_api_ai_generate_payloads_with_llm_available_and_unavailable.py)
- **Test Error:** Traceback (most recent call last):
  File "<string>", line 73, in test_post_api_ai_generate_payloads_with_llm_available_and_unavailable
AssertionError: Expected 200, got 404

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 126, in <module>
  File "<string>", line 88, in test_post_api_ai_generate_payloads_with_llm_available_and_unavailable
AssertionError: LLM available test failed with status 404: {"detail":"Not Found"}

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/2d170a30-0fa1-42e4-94ee-bdcd4405e557
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC007 post_api_dashboard_settings_2fa_generate_verify_and_login
- **Test Code:** [TC007_post_api_dashboard_settings_2fa_generate_verify_and_login.py](./TC007_post_api_dashboard_settings_2fa_generate_verify_and_login.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 2, in <module>
ModuleNotFoundError: No module named 'pyotp'

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/6c1b8586-0e4c-4632-8b80-993e8f98357c
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---

#### Test TC008 post_api_defense_analyze_with_valid_and_invalid_payloads
- **Test Code:** [TC008_post_api_defense_analyze_with_valid_and_invalid_payloads.py](./TC008_post_api_defense_analyze_with_valid_and_invalid_payloads.py)
- **Test Error:** Traceback (most recent call last):
  File "/var/task/handler.py", line 258, in run_with_retry
    exec(code, exec_env)
  File "<string>", line 177, in <module>
  File "<string>", line 71, in test_post_api_defense_analyze_with_valid_and_invalid_payloads
AssertionError: Expected 200 for valid payload, got 500

- **Test Visualization and Result:** https://www.testsprite.com/dashboard/mcp/tests/b262867b-bae9-4ae5-ba66-bb2dc1833b6f/7efd2dd9-f7af-45d5-b6cb-bbcf1f15f1fe
- **Status:** ❌ Failed
- **Analysis / Findings:** {{TODO:AI_ANALYSIS}}.
---


## 3️⃣ Coverage & Matching Metrics

- **12.50** of tests passed

| Requirement        | Total Tests | ✅ Passed | ❌ Failed  |
|--------------------|-------------|-----------|------------|
| ...                | ...         | ...       | ...        |
---


## 4️⃣ Key Gaps / Risks
{AI_GNERATED_KET_GAPS_AND_RISKS}
---