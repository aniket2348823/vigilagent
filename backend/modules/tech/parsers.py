import json
import logging
from typing import Any

logger = logging.getLogger("parsers")

# HIGH-50: Use defusedxml to prevent XXE attacks
try:
    import defusedxml.ElementTree as ET
except ImportError:
    ET = None  # Disable XML parsing entirely if defusedxml not installed
    logger.warning("defusedxml not installed — XML parsing DISABLED to prevent XXE. pip install defusedxml")

# MED-43: Maximum input size to prevent OOM on malicious payloads
_MAX_XML_LEN = 5 * 1024 * 1024  # 5 MB
_MAX_JSONL_LEN = 5 * 1024 * 1024  # 5 MB


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    if ET is None:
        logger.error("defusedxml not installed — cannot parse XML")
        return []
    if len(xml_text) > _MAX_XML_LEN:
        logger.warning("XML input exceeds %d byte limit, truncating", _MAX_XML_LEN)
        xml_text = xml_text[:_MAX_XML_LEN]
    root = ET.fromstring(xml_text)
    nodes = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr", "") if addr_el is not None else ""
        nodes.append({"type": "Host", "id": host_addr, "properties": {"address": host_addr}})
        for port in host.findall(".//port"):
            service = port.find("service")
            port_id = f"{host_addr}:{port.get('portid')}/{port.get('protocol')}"
            nodes.append({
                "type": "Service",
                "id": port_id,
                "properties": {
                    "host": host_addr,
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "name": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                },
            })
    return nodes


def parse_nuclei_jsonl(jsonl_text: str) -> list[dict[str, Any]]:
    if len(jsonl_text) > _MAX_JSONL_LEN:
        logger.warning("JSONL input exceeds %d byte limit, truncating", _MAX_JSONL_LEN)
        jsonl_text = jsonl_text[:_MAX_JSONL_LEN]
    findings = []
    for line in jsonl_text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        findings.append({
            "type": "Vulnerability",
            "id": item.get("template-id") or item.get("templateID") or item.get("matched-at"),
            "properties": {
                "url": item.get("matched-at") or item.get("host"),
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "tags": info.get("tags", []),
            },
        })
    return findings


def parse_httpx_jsonl(jsonl_text: str) -> list[dict[str, Any]]:
    if len(jsonl_text) > _MAX_JSONL_LEN:
        logger.warning("JSONL input exceeds %d byte limit, truncating", _MAX_JSONL_LEN)
        jsonl_text = jsonl_text[:_MAX_JSONL_LEN]
    endpoints = []
    for line in jsonl_text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = item.get("url") or item.get("input")
        endpoints.append({
            "type": "URL",
            "id": url,
            "properties": {
                "status_code": item.get("status_code"),
                "title": item.get("title", ""),
                "tech": item.get("tech", []),
                "webserver": item.get("webserver", ""),
            },
        })
    return endpoints

