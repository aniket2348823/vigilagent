"""
Alpha V6 Nuclei Template Manager.

Manages custom and community templates for targeted validation.
Extracts template paths from the local nuclei repo at D:\\projects\\nuclei.
"""

from __future__ import annotations

import logging
from pathlib import Path

from backend.core.config import settings

logger = logging.getLogger("alpha.nuclei")


class NucleiTemplateManager:
    """Manages Nuclei template selection for targeted scanning."""

    def __init__(self, tool_root: Path | None = None):
        self.tool_root = tool_root or Path(getattr(settings, "ALPHA_TOOL_ROOT", r"D:\projects"))
        self.templates_dir = self.tool_root / "nuclei-templates"
        # Fallback to nuclei repo's integration test templates
        if not self.templates_dir.exists():
            self.templates_dir = self.tool_root / "nuclei" / "examples"

    def get_templates_for_tech(self, technologies: list[str]) -> list[str]:
        """Return template paths relevant to detected technologies."""
        tech_template_map: dict[str, list[str]] = {
            "wordpress": ["http/technologies/wordpress/"],
            "joomla": ["http/technologies/joomla/"],
            "drupal": ["http/technologies/drupal/"],
            "apache": ["http/misconfiguration/apache/", "http/cves/apache/"],
            "nginx": ["http/misconfiguration/nginx/"],
            "iis": ["http/misconfiguration/iis/"],
            "tomcat": ["http/cves/tomcat/", "http/default-logins/tomcat/"],
            "spring": ["http/cves/spring/", "http/misconfiguration/springboot/"],
            "laravel": ["http/technologies/laravel/"],
            "django": ["http/technologies/django/"],
            "express": ["http/technologies/express/"],
            "graphql": [
                "http/exposed-panels/graphql-playground.yaml",
                "http/misconfiguration/graphql-introspection.yaml",
            ],
            "jenkins": ["http/cves/jenkins/", "http/default-logins/jenkins/"],
            "gitlab": ["http/cves/gitlab/"],
            "jira": ["http/cves/jira/"],
            "confluence": ["http/cves/confluence/"],
        }
        paths = []
        for tech in technologies:
            tech_lower = tech.lower()
            for key, templates in tech_template_map.items():
                if key in tech_lower:
                    for t in templates:
                        full_path = self.templates_dir / t
                        if full_path.exists():
                            paths.append(str(full_path))
                        else:
                            paths.append(t)  # Nuclei will resolve from its own templates
        return paths

    def get_severity_templates(self, severity: str = "critical,high") -> list[str]:
        """Return template args for severity-based scanning."""
        return ["-severity", severity]

    def get_misconfiguration_templates(self) -> list[str]:
        """Return paths to misconfiguration-focused templates."""
        misc_dirs = [
            "http/misconfiguration/",
            "http/exposed-panels/",
            "http/default-logins/",
            "http/exposures/",
        ]
        found = []
        for d in misc_dirs:
            full = self.templates_dir / d
            if full.exists():
                found.append(str(full))
        return found

    def get_cve_templates(self, year: str | None = None) -> list[str]:
        """Return CVE template paths, optionally filtered by year."""
        cve_dir = self.templates_dir / "http" / "cves"
        if not cve_dir.exists():
            return ["-tags", "cve"]
        if year:
            year_dir = cve_dir / year
            return [str(year_dir)] if year_dir.exists() else ["-tags", f"cve{year}"]
        return [str(cve_dir)]

    def build_nuclei_args(
        self,
        *,
        technologies: list[str] | None = None,
        severity: str = "critical,high,medium",
        tags: list[str] | None = None,
    ) -> list[str]:
        """Build nuclei CLI args for targeted scanning."""
        args = ["-severity", severity]
        if tags:
            args.extend(["-tags", ",".join(tags)])
        if technologies:
            template_paths = self.get_templates_for_tech(technologies)
            if template_paths:
                args.extend(["-t", ",".join(template_paths)])
        return args


class PayloadManager:
    """Manages payload lists from PayloadsAllTheThings."""

    def __init__(self, tool_root: Path | None = None):
        self.root = tool_root or Path(getattr(settings, "ALPHA_TOOL_ROOT", r"D:\projects"))
        self.payloads_dir = self.root / "PayloadsAllTheThings"

    def get_sqli_payloads(self, max_count: int = 100) -> list[str]:
        """Get SQL injection test payloads."""
        return self._load_payloads("SQL Injection", max_count)

    def get_xss_payloads(self, max_count: int = 100) -> list[str]:
        """Get XSS test payloads."""
        return self._load_payloads("XSS Injection", max_count)

    def get_ssrf_payloads(self, max_count: int = 50) -> list[str]:
        """Get SSRF test payloads."""
        return self._load_payloads("Server Side Request Forgery", max_count)

    def get_lfi_payloads(self, max_count: int = 50) -> list[str]:
        """Get LFI/path traversal test payloads."""
        return self._load_payloads("File Inclusion", max_count)

    def _load_payloads(self, category: str, max_count: int) -> list[str]:
        """Load payloads from a category directory."""
        cat_dir = self.payloads_dir / category
        if not cat_dir.exists():
            return []
        payloads: list[str] = []
        for f in sorted(cat_dir.rglob("*.txt")):
            if len(payloads) >= max_count:
                break
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
                        if len(payloads) >= max_count:
                            break
            except Exception as exc:
                logger.debug(f"[PayloadManager] Failed to read {f}: {exc}")
                continue
        return payloads


class SecListsManager:
    """Manages wordlists from SecLists."""

    def __init__(self, tool_root: Path | None = None):
        self.root = tool_root or Path(getattr(settings, "ALPHA_TOOL_ROOT", r"D:\projects"))
        self.seclists_dir = self.root / "SecLists"

    def get_wordlist(self, category: str, name: str) -> Path | None:
        """Get a specific wordlist by category and name."""
        path = self.seclists_dir / "Discovery" / category / name
        return path if path.exists() else None

    def get_api_wordlists(self) -> list[Path]:
        """Get API-focused wordlists."""
        api_dir = self.seclists_dir / "Discovery" / "Web-Content" / "api"
        if not api_dir.exists():
            return []
        return sorted(api_dir.glob("*.txt"))

    def get_dns_wordlists(self) -> list[Path]:
        """Get DNS subdomain brute-force wordlists."""
        dns_dir = self.seclists_dir / "Discovery" / "DNS"
        if not dns_dir.exists():
            return []
        return [f for f in sorted(dns_dir.glob("*.txt")) if "subdomains" in f.name.lower()]

    def get_directory_wordlist(self, size: str = "medium") -> Path | None:
        """Get a directory brute-force wordlist by size."""
        size_map = {
            "small": "DirBuster-2007_directory-list-2.3-small.txt",
            "medium": "DirBuster-2007_directory-list-2.3-medium.txt",
            "big": "DirBuster-2007_directory-list-2.3-big.txt",
            "common": "common.txt",
            "raft": "raft-medium-directories.txt",
        }
        name = size_map.get(size, size_map["medium"])
        return self.get_wordlist("Web-Content", name)

    def get_password_wordlists(self) -> list[Path]:
        """Get common password wordlists."""
        pw_dir = self.seclists_dir / "Passwords"
        if not pw_dir.exists():
            return []
        return sorted(pw_dir.glob("*.txt"))[:10]
