"""Tests for backend.reporting.cvss_engine — CVSS31 scoring, severity bands."""
import pytest
from backend.reporting.cvss_engine import cvss31_base, severity_band, score_for_vuln_class, CVSSCalculator, _roundup


class TestRoundup:
    def test_exact(self):
        assert _roundup(4.0) == 4.0

    def test_rounds_up(self):
        assert _roundup(4.11) == 4.2


class TestSeverityBand:
    def test_critical(self):
        assert severity_band(9.5) == "CRITICAL"

    def test_high(self):
        assert severity_band(7.5) == "HIGH"

    def test_medium(self):
        assert severity_band(5.0) == "MEDIUM"

    def test_low(self):
        assert severity_band(3.0) == "LOW"

    def test_info(self):
        # CVSS 4.0 spec: a 0.0 base score is rated NONE (the engine's own
        # docstring — bands: 9.0-10.0 CRITICAL, 7.0-8.9 HIGH, 4.0-6.9 MEDIUM,
        # 0.1-3.9 LOW, 0.0 NONE). INFO is a display-only concept, not a band.
        assert severity_band(0.0) == "NONE"


class TestCVSS31Base:
    def test_default(self):
        score, vector = cvss31_base()
        assert score >= 0
        assert "CVSS" in vector

    def test_network_attack(self):
        score, vector = cvss31_base(av="N")
        assert score >= 0

    def test_local_attack(self):
        score, vector = cvss31_base(av="L")
        assert score >= 0


class TestScoreForVulnClass:
    def test_sqli(self):
        score, vector = score_for_vuln_class("SQL_INJECTION")
        assert score > 0

    def test_xss(self):
        score, vector = score_for_vuln_class("XSS")
        assert score > 0

    def test_unknown(self):
        score, vector = score_for_vuln_class("UNKNOWN_VULN")
        assert score >= 0


class TestCVSSCalculator:
    def test_creation(self):
        calc = CVSSCalculator()
        assert calc is not None
