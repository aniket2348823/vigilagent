"""
URL Validation Utility for SSRF Protection
Validates URLs against allowlists and blocks dangerous patterns.
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class URLValidator:
    """
    Validates URLs to prevent SSRF (Server-Side Request Forgery) attacks.
    Implements allowlist-based validation with pattern blocking.
    """

    def __init__(self):
        # Allowed hosts for scanning - only localhost and explicit test domains
        # SECURITY: 0.0.0.0 and host.docker.internal removed from default allowlist
        # to prevent SSRF bypass. Add explicitly via add_allowed_host() if needed.
        # CRITICAL FIX (#40): For a pentest scanner, the allowlist must include
        # common test/lab targets. Real-world target validation is handled by
        # the scan's scope policy (not this SSRF guard). SSRF protection is
        # enforced by: (1) blocked cloud metadata IPs, (2) blocked dangerous
        # schemes, (3) injection character checks.
        self.allowed_hosts: set[str] = {
            "localhost",
            "127.0.0.1",
            "test-env.local",
            "example.com",
            "www.example.com",
            # Common pentest lab / CTF / dev targets
            "juice-shop.herokuapp.com",
            "demo.testfire.net",
            "testphp.vulnweb.com",
            "testasp.vulnweb.com",
            "testaspnet.vulnweb.com",
            "hackazon.org",
            "owasp.org",
        }

        # Allowed private IP ranges (for internal testing)
        self.allowed_private_ranges = [
            re.compile(r"^10\."),  # 10.x.x.x
            re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),  # 172.16-31.x.x
            re.compile(r"^192\.168\."),  # 192.168.x.x
        ]

        # Blocked patterns (cloud metadata, file protocols, etc.)
        self.blocked_patterns = [
            re.compile(r"169\.254\.169\.254"),  # AWS metadata
            re.compile(r"metadata\.google\.internal"),  # GCP metadata
            re.compile(r"metadata\.azure\.com"),  # Azure metadata
            re.compile(r"^file://", re.I),  # File protocol
            re.compile(r"^ftp://", re.I),  # FTP protocol
            re.compile(r"^gopher://", re.I),  # Gopher protocol
            re.compile(r"^dict://", re.I),  # Dict protocol
            re.compile(r"^ldap://", re.I),  # LDAP protocol
            re.compile(r"^tftp://", re.I),  # TFTP protocol
            re.compile(r"localhost:631"),  # CUPS printing service
            re.compile(r"127\.0\.0\.1:631"),  # CUPS printing service
        ]

        # Allowed schemes
        self.allowed_schemes = {"http", "https"}

    def add_allowed_host(self, host: str):
        """Add a host to the allowlist."""
        self.allowed_hosts.add(host.lower())
        logger.info(f"Added allowed host: {host}")

    def remove_allowed_host(self, host: str):
        """Remove a host from the allowlist."""
        self.allowed_hosts.discard(host.lower())
        logger.info(f"Removed allowed host: {host}")

    def validate(self, url: str, allow_private: bool = True) -> tuple[bool, str]:
        """
        Validate a URL against security rules.

        Args:
            url: The URL to validate
            allow_private: Whether to allow private IP ranges

        Returns:
            Tuple of (is_valid, reason)
        """
        # Basic URL parsing
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Malformed URL: {str(e)}"

        # Check for injection characters
        if any(ch in url for ch in ["<", ">", '"', "'", "`", "\n", "\r"]):
            return False, "URL contains potential injection characters"

        # Validate scheme
        if parsed.scheme not in self.allowed_schemes:
            return False, f"Invalid scheme '{parsed.scheme}'. Only HTTP/HTTPS allowed"

        hostname = parsed.hostname or ""

        # Check blocked patterns first (highest priority)
        for pattern in self.blocked_patterns:
            if pattern.search(url):
                logger.warning(f"Blocked URL matching pattern {pattern.pattern}: {url}")
                return False, f"URL matches blocked pattern: {pattern.pattern}"

        # Check if hostname is in allowlist
        if hostname in self.allowed_hosts:
            return True, "OK"

        # Allow .test domains (RFC 2606)
        if hostname.endswith(".test"):
            return True, "OK"

        # Allow private IP ranges if enabled
        if allow_private:
            for pattern in self.allowed_private_ranges:
                if pattern.match(hostname):
                    return True, "OK"

        # FIX-010: Removed non-standard port bypass that allowed SSRF.
        # Any hostname with a non-standard port must still be in the allowlist.
        # The previous code returned True for any hostname with a non-standard port,
        # which completely bypassed the allowlist and enabled SSRF attacks.

        # Reject everything else (public domains not in allowlist)
        logger.warning(f"Rejected URL not in allowlist: {url}")
        return False, (f"Target '{hostname}' is not in the allowed scope. Add it to ALLOWED_HOSTS or use a private IP.")

    def validate_or_raise(self, url: str, allow_private: bool = True):
        """
        Validate URL and raise exception if invalid.

        Raises:
            ValueError: If URL is invalid
        """
        is_valid, reason = self.validate(url, allow_private)
        if not is_valid:
            raise ValueError(f"Invalid URL: {reason}")
        return True


# Global validator instance
url_validator = URLValidator()


def validate_url(url: str, allow_private: bool = True) -> tuple[bool, str]:
    """
    Convenience function to validate a URL.

    Args:
        url: The URL to validate
        allow_private: Whether to allow private IP ranges

    Returns:
        Tuple of (is_valid, reason)
    """
    return url_validator.validate(url, allow_private)


def validate_url_or_raise(url: str, allow_private: bool = True):
    """
    Convenience function to validate URL and raise exception if invalid.

    Args:
        url: The URL to validate
        allow_private: Whether to allow private IP ranges

    Raises:
        ValueError: If URL is invalid
    """
    return url_validator.validate_or_raise(url, allow_private)
