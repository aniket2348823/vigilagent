# ═══════════════════════════════════════════════════════════════════════════════
# Vigilagent :: ENDPOINT TRACKER — COVERAGE MONITORING
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Tracks discovered vs tested endpoints to ensure complete coverage
#          Prevents incomplete scans and missed vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════════

import logging
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger("EndpointTracker")


class EndpointTracker:
    """
    Tracks endpoint discovery and testing to ensure comprehensive coverage.
    Provides real-time metrics on scan completeness.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.discovered: set[str] = set()  # All endpoints found by recon
        self.tested: set[str] = set()  # Endpoints that were attacked
        self.vulnerable: set[str] = set()  # Endpoints with confirmed vulns
        self.discovery_times: dict[str, datetime] = {}
        self.test_times: dict[str, datetime] = {}

        logger.info(f"[{scan_id}] EndpointTracker initialized")

    def normalize_url(self, url: str) -> str:
        """Normalize URL for consistent tracking"""
        try:
            parsed = urlparse(url)
            # Remove fragments and normalize
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return normalized.lower().rstrip("/")
        except Exception as exc:
            logger.debug("EndpointTracker: URL parse failed for %s: %s", url, exc)
            return url.lower().rstrip("/")

    def add_discovered(self, url: str, source: str = "unknown") -> bool:
        """
        Register a newly discovered endpoint.
        Returns True if this is a new discovery, False if already known.
        """
        normalized = self.normalize_url(url)

        if normalized in self.discovered:
            return False

        self.discovered.add(normalized)
        self.discovery_times[normalized] = datetime.now()

        logger.debug(f"[{self.scan_id}] Endpoint discovered by {source}: {normalized} (Total: {len(self.discovered)})")
        return True

    def mark_tested(self, url: str, agent: str = "unknown") -> bool:
        """
        Mark an endpoint as tested.
        Returns True if this is the first test, False if already tested.
        """
        normalized = self.normalize_url(url)

        # Auto-add to discovered if not already there
        if normalized not in self.discovered:
            self.add_discovered(normalized, source=agent)

        if normalized in self.tested:
            return False

        self.tested.add(normalized)
        self.test_times[normalized] = datetime.now()

        logger.debug(
            f"[{self.scan_id}] Endpoint tested by {agent}: {normalized} (Coverage: {self.get_coverage():.1f}%)"
        )
        return True

    def mark_vulnerable(self, url: str, vuln_type: str = "unknown"):
        """Mark an endpoint as having a confirmed vulnerability"""
        normalized = self.normalize_url(url)

        # Auto-add to discovered and tested if not already there
        if normalized not in self.discovered:
            self.add_discovered(normalized, source="vuln_detection")
        if normalized not in self.tested:
            self.mark_tested(normalized, agent="vuln_detection")

        self.vulnerable.add(normalized)

        logger.info(f"[{self.scan_id}] Vulnerability confirmed: {normalized} ({vuln_type})")

    def get_coverage(self) -> float:
        """
        Calculate test coverage percentage.
        Returns 0.0 if no endpoints discovered, otherwise percentage tested.
        """
        if not self.discovered:
            return 0.0
        return (len(self.tested) / len(self.discovered)) * 100

    def get_untested(self) -> set[str]:
        """Get set of discovered but untested endpoints"""
        return self.discovered - self.tested

    def get_vulnerability_rate(self) -> float:
        """
        Calculate vulnerability rate (vulnerable / tested).
        Returns 0.0 if no endpoints tested.
        """
        if not self.tested:
            return 0.0
        return (len(self.vulnerable) / len(self.tested)) * 100

    def is_complete(self, threshold: float = 95.0) -> bool:
        """
        Check if scan coverage meets the completeness threshold.
        Default threshold is 95% (allows for some unreachable endpoints).
        """
        return self.get_coverage() >= threshold

    def get_metrics(self) -> dict:
        """Get comprehensive tracking metrics"""
        coverage = self.get_coverage()
        vuln_rate = self.get_vulnerability_rate()

        return {
            "scan_id": self.scan_id,
            "endpoints_discovered": len(self.discovered),
            "endpoints_tested": len(self.tested),
            "endpoints_vulnerable": len(self.vulnerable),
            "coverage_percent": round(coverage, 2),
            "vulnerability_rate_percent": round(vuln_rate, 2),
            "untested_count": len(self.get_untested()),
            "is_complete": self.is_complete(),
        }

    def get_telemetry(self) -> dict:
        """Get detailed telemetry for reporting"""
        metrics = self.get_metrics()

        # Add timing information
        if self.discovery_times and self.test_times:
            first_discovery = min(self.discovery_times.values())
            last_test = max(self.test_times.values()) if self.test_times else first_discovery
            scan_duration = (last_test - first_discovery).total_seconds()

            metrics["scan_duration_seconds"] = round(scan_duration, 2)
            metrics["endpoints_per_minute"] = round((len(self.tested) / max(scan_duration / 60, 0.1)), 2)

        return metrics

    def get_untested_sample(self, limit: int = 10) -> list:
        """Get a sample of untested endpoints for logging/reporting"""
        untested = list(self.get_untested())
        return untested[:limit]
