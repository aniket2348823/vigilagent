"""Tests for backend.core.endpoint_tracker — EndpointTracker."""
import pytest
from backend.core.endpoint_tracker import EndpointTracker


class TestEndpointTracker:
    def test_creation(self):
        et = EndpointTracker(scan_id="test-scan")
        assert et.scan_id == "test-scan"
        assert isinstance(et.discovered, set)
        assert isinstance(et.tested, set)
        assert isinstance(et.vulnerable, set)

    def test_normalize_url(self):
        et = EndpointTracker(scan_id="test")
        normalized = et.normalize_url("http://example.com:80/path?query=1#frag")
        assert isinstance(normalized, str)
        assert "#" not in normalized  # fragments removed

    def test_discover(self):
        et = EndpointTracker(scan_id="test")
        et.add_discovered("http://example.com/api")
        assert "http://example.com/api" in et.discovered or len(et.discovered) >= 1

    def test_mark_tested(self):
        et = EndpointTracker(scan_id="test")
        et.add_discovered("http://example.com/api")
        et.mark_tested("http://example.com/api")
        assert len(et.tested) >= 1

    def test_mark_vulnerable(self):
        et = EndpointTracker(scan_id="test")
        et.add_discovered("http://example.com/api")
        et.mark_vulnerable("http://example.com/api", "SQL Injection")
        assert len(et.vulnerable) >= 1
