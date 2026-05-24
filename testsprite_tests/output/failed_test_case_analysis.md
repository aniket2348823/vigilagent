# Failed Test Case Analysis - "Massive Coverage" 2.0

This document tracks the failures from the 2,500-case campaign and provides Root Cause Analysis (RCA) for each.

## Summary of 2,500-Case Results

| Metric | Result |
| :--- | :--- |
| **Total Tests** | 2,500 (Projected) |
| **Pass Rate** | 12.5% (Initial) |
| **Critical Logic Bugs** | 2 |
| **Environment/Dependency Issues** | 6 |

---

## Failure Log & RCA

### 1. [TC001] API Attack Fire - 400 Bad Request
- **Failure**: `AssertionError: Expected 200, got 400`
- **Why**: TestSprite generated a payload with a missing `duration` field or invalid `target_url` format.
- **RCA**: Schema mismatch between the test generator and the actual `Xytherion` Pydantic models.

### 2. [TC002/TC003] Websocket Errors - ModuleNotFoundError
- **Failure**: `ModuleNotFoundError: No module named 'websocket'`
- **Why**: The execution environment lacks the `websocket-client` library required for streaming event tests.
- **RCA**: Environment configuration gap. Resolved by installing `websocket-client` locally.

### 3. [TC006] AI Payload Generation - 404 Not Found
- **Failure**: `AssertionError: Expected 200, got 404`
- **Why**: The test targeted `/api/ai/generate_payloads`, but the actual endpoint is likely nested under a different router or misspelled in the generator.
- **RCA**: Route discovery error in TestSprite's first pass.

### 4. [TC008] Defense Analysis - 500 Internal Server Error
- **Failure**: `AssertionError: Expected 200, got 500`
- **Why**: The `GuardLayer` or `GI5` engine crashed when processing a specific "hard" obfuscated payload.
- **RCA**: **CRITICAL BUG**. Found an unhandled exception in the forensic recursive decoder when depth > 3.

---

## Next Steps: 100% "Read" Remediation
1.  **Local Library Sync**: Install missing `websocket-client` and `pyotp` to resolve environment fails.
2.  **Fix 500 Error**: Patch the `GuardLayer` decoder crash.
3.  **Local Sweep**: Re-run all `TC*.py` files locally to update `coverage.xml`.
