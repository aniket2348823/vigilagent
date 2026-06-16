"""Parser for nmap XML output."""
from __future__ import annotations
import logging
from pathlib import Path
from backend.parsers.recon.base import ParsedEntity

# FIX: Use defusedxml to prevent XXE attacks when parsing untrusted nmap XML output.
# Falls back to stdlib xml.etree if defusedxml is not installed.
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import warnings
    warnings.warn(
        "defusedxml not installed; nmap XML parser is vulnerable to XXE. "
        "Install with: pip install defusedxml",
        stacklevel=2,
    )
    import xml.etree.ElementTree as ET

logger = logging.getLogger("parsers.nmap")


def parse_nmap_xml(path: Path | str) -> list[ParsedEntity]:
    p = Path(path)
    if not p.exists():
        logger.warning("Nmap XML file not found: %s", p)
        return []
    try:
        tree = ET.parse(str(p))
    except ET.ParseError as e:
        logger.warning("Failed to parse nmap XML %s: %s", p, e)
        return []
    root = tree.getroot()
    entities: list[ParsedEntity] = []

    for host_el in root.findall(".//host"):
        addrs = host_el.findall("address")
        ip = ""
        mac = ""
        for addr in addrs:
            if addr.get("addrtype") == "ipv4": ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac": mac = addr.get("addr", "")
        hostnames = [hn.get("name", "") for hn in host_el.findall(".//hostname") if hn.get("name")]
        status = host_el.find("status")
        host_state = status.get("state", "unknown") if status is not None else "unknown"

        if ip:
            entities.append(ParsedEntity(kind="ip", label=ip, confidence=0.95,
                properties={"hostnames": hostnames, "state": host_state, "mac": mac},
                source_tool="nmap", phase="dns_infrastructure"))

        for port_el in host_el.findall(".//port"):
            portid = port_el.get("portid", "0")
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if port_state != "open": continue
            service_el = port_el.find("service")
            svc_name = service_el.get("name", "") if service_el is not None else ""
            svc_product = service_el.get("product", "") if service_el is not None else ""
            svc_version = service_el.get("version", "") if service_el is not None else ""
            svc_extra = service_el.get("extrainfo", "") if service_el is not None else ""
            cpe_els = port_el.findall(".//cpe")
            cpes = [c.text for c in cpe_els if c.text]

            label = f"{ip or hostnames[0] if hostnames else 'unknown'}:{portid}"
            entities.append(ParsedEntity(kind="service", label=label, confidence=0.95,
                properties={"host": ip, "port": int(portid), "protocol": protocol,
                             "service_name": svc_name, "product": svc_product,
                             "version": svc_version, "extra_info": svc_extra, "cpes": cpes,
                             "hostnames": hostnames},
                source_tool="nmap", phase="dns_infrastructure"))

        for script_el in host_el.findall(".//script"):
            script_id = script_el.get("id", "")
            output = script_el.get("output", "")
            if script_id and output:
                entities.append(ParsedEntity(kind="nmap_script", label=f"{ip}:{script_id}",
                    confidence=0.8, properties={"script_id": script_id, "output": output[:2000], "host": ip},
                    source_tool="nmap", phase="dns_infrastructure"))
    return entities

class NmapParser:
    """Parser wrapper for backward compatibility."""
    @staticmethod
    def parse_nmap_xml(*args, **kwargs):
        return parse_nmap_xml(*args, **kwargs)

