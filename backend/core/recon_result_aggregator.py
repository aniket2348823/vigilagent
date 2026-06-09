"""Compresses raw recon tool output into structured summaries.

WHY: Raw nuclei/ffuf output can be 100MB+. Agents have ~128K token
context windows. Without compression, agents drown in data.

This is the bridge between the Data Plane (Event Bus) and the
Control Plane (Master Agent). It converts raw tool stdout into
compact JSON that fits in the agent context window.
"""

import json
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ReconSummary:
    """Compressed recon results — ~2KB from ~100MB raw output."""
    open_ports: List[int] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    endpoints_with_params: List[str] = field(default_factory=list)
    total_raw_size_mb: float = 0.0

    def to_agent_context(self, max_hosts: int = 20, max_dirs: int = 50) -> str:
        """Format for agent context window (~500 tokens)."""
        hosts_display = self.live_hosts[:max_hosts]
        dirs_display = self.directories[:max_dirs]
        host_extra = len(self.live_hosts) - max_hosts
        dir_extra = len(self.directories) - max_dirs

        lines = [f"RECON SUMMARY ({self.total_raw_size_mb:.1f}MB raw to compressed):"]
        lines.append(f"Open Ports: {self.open_ports}")
        hosts_str = ", ".join(hosts_display)
        if host_extra > 0:
            hosts_str += f" ...+{host_extra}"
        lines.append(f"Live Hosts: {len(self.live_hosts)} ({hosts_str})")
        lines.append(f"Tech Stack: {', '.join(self.tech_stack)}")
        dirs_str = ", ".join(dirs_display)
        if dir_extra > 0:
            dirs_str += f" ...+{dir_extra}"
        lines.append(f"Directories: {len(self.directories)} ({dirs_str})")
        crit_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'critical')
        lines.append(f"Vulnerabilities: {len(self.vulnerabilities)} ({crit_count} critical)")
        lines.append(f"Attack Candidates: {len(self.endpoints_with_params)} endpoints with params")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON transport."""
        return {
            "open_ports": self.open_ports,
            "live_hosts": self.live_hosts,
            "directories": self.directories,
            "vulnerabilities": self.vulnerabilities,
            "tech_stack": self.tech_stack,
            "endpoints_with_params": self.endpoints_with_params,
            "total_raw_size_mb": self.total_raw_size_mb,
        }


class ReconResultAggregator:
    """Parses raw tool output into compressed ReconSummary.

    Each tool has a different output format:
    - nmap: XML (parse with xml.etree)
    - httpx: JSONL (one JSON per line)
    - ffuf: JSON (single object with results array)
    - nuclei: JSONL (one JSON per line)
    - subfinder/amass: plain text (one per line)
    - masscan: JSON (port scan results)
    """

    def aggregate(self, tool_results: Dict[str, Any]) -> ReconSummary:
        """Convert raw tool output to compressed summary."""
        def _size_mb(val: Any) -> float:
            if isinstance(val, str):
                return len(val.encode('utf-8')) / 1_000_000
            elif isinstance(val, (dict, list)):
                return len(json.dumps(val).encode('utf-8')) / 1_000_000
            return 0.0

        return ReconSummary(
            open_ports=self._parse_nmap_ports(tool_results.get("nmap", "")),
            live_hosts=self._parse_httpx_hosts(tool_results.get("httpx", "")),
            directories=self._parse_ffuf_paths(tool_results.get("ffuf", "")),
            vulnerabilities=self._parse_nuclei_vulns(tool_results.get("nuclei", "")),
            tech_stack=self._parse_httpx_tech(tool_results.get("httpx", "")),
            endpoints_with_params=self._find_param_endpoints(tool_results),
            total_raw_size_mb=sum(_size_mb(v) for v in tool_results.values()),
        )

    def _parse_nmap_ports(self, raw: Any) -> List[int]:
        """Extract open ports from nmap output."""
        if not raw:
            return []
        if isinstance(raw, dict):
            ports = []
            for host in raw.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        ports.append(int(port.get("port", 0)))
            return sorted(set(ports))
        # Parse from string
        ports = []
        for match in re.finditer(r'(\d+)/(?:tcp|udp)\s+open', str(raw)):
            ports.append(int(match.group(1)))
        return sorted(set(ports))

    def _parse_httpx_hosts(self, raw: Any) -> List[str]:
        """Extract live hosts from httpx JSONL output."""
        if not raw:
            return []
        hosts = set()
        if isinstance(raw, str):
            for line in raw.strip().split('\n'):
                try:
                    obj = json.loads(line)
                    if obj.get("url"):
                        hosts.add(obj["url"])
                except (json.JSONDecodeError, TypeError):
                    pass
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and item.get("url"):
                    hosts.add(item["url"])
        return sorted(hosts)

    def _parse_ffuf_paths(self, raw: Any) -> List[str]:
        """Extract directories from ffuf JSON output."""
        if not raw:
            return []
        paths = set()
        if isinstance(raw, dict):
            for result in raw.get("results", []):
                if result.get("input"):
                    paths.add(result["input"].get("FUZZ", ""))
        elif isinstance(raw, str):
            try:
                obj = json.loads(raw)
                for result in obj.get("results", []):
                    if result.get("input"):
                        paths.add(result["input"].get("FUZZ", ""))
            except (json.JSONDecodeError, TypeError):
                pass
        return sorted(p for p in paths if p)

    def _parse_nuclei_vulns(self, raw: Any) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from nuclei JSONL output."""
        if not raw:
            return []
        vulns = []
        if isinstance(raw, str):
            for line in raw.strip().split('\n'):
                try:
                    obj = json.loads(line)
                    vulns.append({
                        "template_id": obj.get("template-id", ""),
                        "severity": obj.get("info", {}).get("severity", "unknown"),
                        "matched_at": obj.get("matched-at", ""),
                        "name": obj.get("info", {}).get("name", ""),
                    })
                except (json.JSONDecodeError, TypeError):
                    pass
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    vulns.append({
                        "template_id": item.get("template-id", ""),
                        "severity": item.get("info", {}).get("severity", "unknown"),
                        "matched_at": item.get("matched-at", ""),
                        "name": item.get("info", {}).get("name", ""),
                    })
        return vulns

    def _parse_httpx_tech(self, raw: Any) -> List[str]:
        """Extract tech stack from httpx output."""
        if not raw:
            return []
        tech = set()
        if isinstance(raw, str):
            for line in raw.strip().split('\n'):
                try:
                    obj = json.loads(line)
                    for t in obj.get("tech", []):
                        tech.add(t)
                except (json.JSONDecodeError, TypeError):
                    pass
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    for t in item.get("tech", []):
                        tech.add(t)
        return sorted(tech)

    def _find_param_endpoints(self, tool_results: Dict[str, Any]) -> List[str]:
        """Find endpoints with query parameters (attack candidates)."""
        endpoints = set()
        # From httpx
        httpx_raw = tool_results.get("httpx", "")
        if isinstance(httpx_raw, str):
            for line in httpx_raw.strip().split('\n'):
                try:
                    obj = json.loads(line)
                    url = obj.get("url", "")
                    if '?' in url:
                        endpoints.add(url)
                except (json.JSONDecodeError, TypeError):
                    pass
        # From gau/waybackurls
        for key in ["gau", "waybackurls"]:
            raw = tool_results.get(key, "")
            if isinstance(raw, str):
                for line in raw.strip().split('\n'):
                    if '?' in line:
                        endpoints.add(line.strip())
        return sorted(endpoints)
