# Antigravity V5 Test Suite

Comprehensive test suite for the Antigravity V5 autonomous penetration testing system.

## 📁 Directory Structure

```
testsprite_tests/
├── api/                    # API endpoint tests
├── integration/            # Integration and end-to-end tests
├── security/               # Security and authentication tests
├── performance/            # Performance and stress tests
├── output/                 # Test output files and reports
├── codebase/              # Codebase analysis tests
├── tmp/                   # Temporary test files
└── README.md              # This file
```

---

## 🧪 Test Categories

### API Tests (`api/`)

Tests for REST API endpoints, WebSocket connections, and API functionality.

**Test Files:**
- `TC001_API_Layer_Discovery__Discovery_Verification.py` - API discovery and verification
- `TC001_get_dashboard_stats_success.py` - Dashboard statistics endpoint
- `TC002_get_dashboard_scans_success.py` - Scan listing endpoint
- `TC003_post_attack_fire_valid_payload.py` - Attack execution with valid payload
- `TC004_post_attack_fire_invalid_payload.py` - Attack execution with invalid payload
- `TC005_post_attack_fire_disallowed_target.py` - Attack on disallowed target
- `TC006_post_attack_replay_valid_vuln_id.py` - Vulnerability replay
- `TC007_post_attack_replay_invalid_vuln_id.py` - Invalid vulnerability replay
- `TC002_post_api_recon_ingest_with_valid_and_invalid_payloads.py` - Recon data ingestion
- `TC004_get_api_reports_pdf_with_existing_and_nonexistent_scan_id.py` - PDF report generation
- `TC005_get_api_dashboard_stats_under_normal_and_failure_conditions.py` - Dashboard stats resilience
- `TC006_post_api_ai_generate_payloads_with_llm_available_and_unavailable.py` - AI payload generation
- `TC007_post_api_dashboard_settings_2fa_generate_verify_and_login.py` - 2FA authentication
- `TC008_post_api_defense_analyze_with_valid_and_invalid_payloads.py` - Defense analysis
- `TC008_get_ai_status_success.py` - AI status endpoint
- `TC009_get_data_list_success.py` - Data listing endpoint
- `TC010_post_data_create_object.py` - Data object creation
- `TC003_websocket_stream_connection_and_event_reception.py` - WebSocket streaming

**Run API Tests:**
```bash
pytest testsprite_tests/api/ -v
```

---

### Integration Tests (`integration/`)

End-to-end workflow tests and business logic validation.

**Test Files:**
- `TC010_End_to_End_Backend_Workflow_Execution.py` - Complete backend workflow
- `TC005_Business_Logic_Orchestration__Data_Transformations.py` - Business logic validation
- `TC011_Functional__Branch_Coverage_Mapping.py` - Code coverage analysis
- `test_backend_comprehensive_audit.py` - Comprehensive backend audit
- `test_deep_audit_generated.py` - Deep audit tests

**Run Integration Tests:**
```bash
pytest testsprite_tests/integration/ -v
```

---

### Security Tests (`security/`)

Authentication, authorization, and security vulnerability tests.

**Test Files:**
- `TC003_Auth_Flow__Privilege_Escalation_Simulation.py` - Privilege escalation testing
- `TC004_AI_OpenRouter_LLM_Logic__Hallucination_Flow.py` - AI hallucination and injection
- `TC002_Supabase_PostgreSQL_RLS__CRUD_integrity.py` - Database security (RLS)

**Run Security Tests:**
```bash
pytest testsprite_tests/security/ -v
```

---

### Performance Tests (`performance/`)

Load testing, stress testing, and performance benchmarks.

**Test Files:**
- `TC007_API_Latency__Core_Bottleneck_Identification.py` - API latency analysis
- `TC008_Distributed_Race_Condition__Conflict_Resolution.py` - Race condition testing
- `TC006_Graceful_Degradation__Network_Resilience.py` - Network resilience
- `massive_test_suite.py` - Large-scale test suite
- `massive_local_test_suite.py` - Local stress testing
- `massive_2500_campaign.py` - 2500-request campaign

**Run Performance Tests:**
```bash
pytest testsprite_tests/performance/ -v --tb=short
```

**Run Massive Test Suite:**
```bash
python testsprite_tests/performance/massive_test_suite.py
```

---

### Output Files (`output/`)

Test execution logs, failure reports, and analysis documents.

**File Types:**
- `pytest_*.txt` - Pytest execution logs
- `extracted_failures.*` - Extracted failure information
- `*_analysis.md` - Test analysis reports
- `*_report.md` - Test execution reports

---

## 🚀 Running Tests

### Run All Tests
```bash
pytest testsprite_tests/ -v
```

### Run Specific Category
```bash
# API tests only
pytest testsprite_tests/api/ -v

# Integration tests only
pytest testsprite_tests/integration/ -v

# Security tests only
pytest testsprite_tests/security/ -v

# Performance tests only
pytest testsprite_tests/performance/ -v
```

### Run with Coverage
```bash
pytest testsprite_tests/ --cov=backend --cov-report=html
```

### Run Specific Test
```bash
pytest testsprite_tests/api/TC001_get_dashboard_stats_success.py -v
```

### Run with Markers
```bash
# Run only smoke tests
pytest testsprite_tests/ -m smoke

# Run only slow tests
pytest testsprite_tests/ -m slow

# Skip slow tests
pytest testsprite_tests/ -m "not slow"
```

---

## 📊 Test Configuration

### pytest.ini

The project uses `pytest.ini` for test configuration:

```ini
[pytest]
testpaths = testsprite_tests tests
python_files = test_*.py TC*.py
python_classes = Test*
python_functions = test_*
markers =
    smoke: Quick smoke tests
    slow: Slow-running tests
    integration: Integration tests
    security: Security tests
    performance: Performance tests
```

### conftest.py

Shared fixtures and test configuration are defined in `conftest.py` files:
- Root `conftest.py` - Global fixtures
- Category-specific `conftest.py` - Category fixtures

---

## 🔧 Test Development Guidelines

### Naming Conventions

**Test Files:**
- API tests: `TC###_<description>.py`
- Unit tests: `test_<module_name>.py`
- Integration tests: `test_<workflow_name>.py`

**Test Functions:**
- Use descriptive names: `test_<what>_<condition>_<expected>`
- Example: `test_attack_fire_valid_payload_returns_200()`

### Test Structure

```python
def test_feature_name():
    """
    Test description explaining what is being tested.
    """
    # Arrange - Set up test data
    payload = {"target": "https://example.com"}
    
    # Act - Execute the test
    response = client.post("/api/attack/fire", json=payload)
    
    # Assert - Verify results
    assert response.status_code == 200
    assert "scan_id" in response.json()
```

### Fixtures

Use fixtures for common setup:

```python
@pytest.fixture
def mock_target():
    return {"url": "https://example.com", "method": "GET"}

def test_with_fixture(mock_target):
    assert mock_target["url"] == "https://example.com"
```

### Markers

Use markers to categorize tests:

```python
@pytest.mark.smoke
def test_critical_path():
    pass

@pytest.mark.slow
def test_long_running():
    pass
```

---

## 📈 Test Metrics

### Coverage Goals
- **Overall Coverage:** 80%+
- **Core Modules:** 90%+
- **API Endpoints:** 95%+
- **Critical Paths:** 100%

### Test Execution Time
- **Smoke Tests:** < 30 seconds
- **Unit Tests:** < 2 minutes
- **Integration Tests:** < 10 minutes
- **Full Suite:** < 30 minutes

---

## 🐛 Debugging Tests

### Run with Verbose Output
```bash
pytest testsprite_tests/ -vv
```

### Show Print Statements
```bash
pytest testsprite_tests/ -s
```

### Stop on First Failure
```bash
pytest testsprite_tests/ -x
```

### Run Last Failed Tests
```bash
pytest testsprite_tests/ --lf
```

### Debug with PDB
```bash
pytest testsprite_tests/ --pdb
```

---

## 📝 Test Data

### Test Configuration Files
- `standard_prd.json` - Standard product requirements
- `testsprite_backend_test_plan.json` - Backend test plan

### Mock Data
Mock data and fixtures are defined in:
- `conftest.py` files
- Individual test files
- `tests/` directory fixtures

---

## 🔗 Related Documentation

- **Architecture:** `../docs/ARCHITECTURE.md`
- **API Documentation:** `../README.md`
- **Development Guide:** `../docs/DEVELOPMENT.md` (if exists)
- **Contributing:** `../CONTRIBUTING.md` (if exists)

---

## 📞 Support

For test-related issues:
1. Check test output in `output/` directory
2. Review test logs for detailed error messages
3. Run tests with `-vv` for verbose output
4. Create GitHub issue with `testing` label

---

## 🎯 Test Checklist

Before committing code, ensure:
- [ ] All tests pass locally
- [ ] New features have corresponding tests
- [ ] Test coverage meets minimum requirements
- [ ] No skipped tests without justification
- [ ] Test names are descriptive
- [ ] Test documentation is updated

---

**Last Updated:** May 24, 2026  
**Total Test Files:** 30+  
**Test Categories:** 4 (API, Integration, Security, Performance)  
**Maintained By:** Antigravity V5 Development Team
