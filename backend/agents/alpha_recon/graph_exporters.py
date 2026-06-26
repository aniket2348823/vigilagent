"""
Alpha V6 Graph Exporters — Neo4j + STIX/OpenCTI compatible.

Exports the entity graph to:
- Neo4j Cypher import scripts
- STIX 2.1 bundles (compatible with OpenCTI)
- Maltego CSV
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from backend.agents.alpha_recon.models import ReconRunResult, stable_id

if TYPE_CHECKING:
    from pathlib import Path

    from backend.parsers.recon.base import ParsedEntity

logger = logging.getLogger("alpha.graph_export")


class Neo4jExporter:
    """Export entity graph as Neo4j Cypher import script."""

    def export(self, entities: list[ParsedEntity], relationships: list[dict], output_path: Path) -> Path:
        lines = [
            "// Alpha V6 Deep Recon — Neo4j Import Script",
            "// Generated automatically. Run with: cypher-shell < this_file.cypher",
            "",
            "// Create constraints",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE;",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;",
            "",
        ]

        # Node creation
        kind_to_label = {
            "subdomain": "Domain",
            "ip": "IP",
            "http_service": "Service",
            "open_port": "Port",
            "certificate": "Certificate",
            "crawled_endpoint": "Endpoint",
            "historical_url": "URL",
            "discovered_path": "Path",
            "api_route": "APIRoute",
            "js_endpoint": "JSEndpoint",
            "js_file": "JSFile",
            "secret": "Secret",
            "vulnerability_candidate": "Vulnerability",
            "dns_record": "DNSRecord",
            "cloud_asset": "CloudAsset",
            "oob_interaction": "OOBInteraction",
            "visual_artifact": "Visual",
            "favicon": "Favicon",
            "service": "Service",
            "email": "Email",
        }

        for e in entities:
            label = kind_to_label.get(e.kind, "Entity")
            props = {
                "id": e.id or stable_id(e.scan_id, e.kind, e.label),
                "kind": e.kind,
                "label": e.label,
                "confidence": e.confidence,
                "source_tool": e.source_tool,
                "phase": e.phase,
                "scan_id": e.scan_id,
            }
            # Merge top-level properties
            for k, v in (e.properties or {}).items():
                if isinstance(v, (str, int, float, bool)):
                    props[k] = v
            props_str = ", ".join(f"{k}: {json.dumps(v)}" for k, v in props.items() if v is not None)
            lines.append(f"MERGE (n:{label} {{{props_str}}});")

        lines.append("")

        # Relationship creation
        # SECURITY FIX (C-14): Sanitize rel_type to prevent Cypher injection.
        # Only allow alphanumeric characters and underscores in relationship names.
        import re as _re

        for rel in relationships:
            src_id = rel.get("src_entity_id", "")
            dst_id = rel.get("dst_entity_id", "")
            raw_rel = rel.get("relationship", "RELATED_TO")
            rel_type = _re.sub(r"[^A-Za-z0-9_]", "_", raw_rel.upper())
            if not rel_type:
                rel_type = "RELATED_TO"
            conf = rel.get("confidence", 0.5)
            lines.append(
                f"MATCH (a {{id: {json.dumps(src_id)}}}), (b {{id: {json.dumps(dst_id)}}}) "
                f"MERGE (a)-[:{rel_type} {{confidence: {conf}}}]->(b);"
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(f"Neo4j export: {len(entities)} nodes, {len(relationships)} edges → {output_path}")
        return output_path


class STIXExporter:
    """Export findings as STIX 2.1 bundle (OpenCTI-compatible)."""

    STIX_SPEC_VERSION = "2.1"

    def export(self, entities: list[ParsedEntity], result: ReconRunResult, output_path: Path) -> Path:
        objects = []

        # Identity for the tool
        tool_identity = {
            "type": "identity",
            "spec_version": self.STIX_SPEC_VERSION,
            "id": f"identity--{stable_id('alpha-v6', 'tool', 'identity')}",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": "AlphaV6-Recon",
            "identity_class": "system",
            "description": "Automated reconnaissance engine",
        }
        objects.append(tool_identity)

        # Convert entities to STIX
        for e in entities:
            stix_obj = self._entity_to_stix(e, tool_identity["id"])
            if stix_obj:
                objects.append(stix_obj)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{stable_id(result.scan_id, 'stix', 'bundle')}",
            "objects": objects,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        logger.info(f"STIX export: {len(objects)} objects → {output_path}")
        return output_path

    def _entity_to_stix(self, e: ParsedEntity, identity_ref: str) -> dict | None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entity_id = e.id or stable_id(e.scan_id, e.kind, e.label)

        if e.kind == "subdomain":
            return {
                "type": "domain-name",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"domain-name--{entity_id}",
                "value": e.label,
                "object_marking_refs": [],
            }
        elif e.kind == "ip":
            return {
                "type": "ipv4-addr",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"ipv4-addr--{entity_id}",
                "value": e.label,
            }
        elif e.kind == "vulnerability_candidate":
            return {
                "type": "vulnerability",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"vulnerability--{entity_id}",
                "created": now,
                "modified": now,
                "name": e.properties.get("name", e.label),
                "description": e.properties.get("description", ""),
                "created_by_ref": identity_ref,
                "confidence": int(e.confidence * 100),
                "external_references": [
                    {
                        "source_name": e.source_tool,
                        "description": e.properties.get("template_id", ""),
                    }
                ],
            }
        elif e.kind == "http_service":
            return {
                "type": "url",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"url--{entity_id}",
                "value": e.label,
            }
        elif e.kind == "email":
            return {
                "type": "email-addr",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"email-addr--{entity_id}",
                "value": e.label,
            }
        elif e.kind == "certificate":
            return {
                "type": "x509-certificate",
                "spec_version": self.STIX_SPEC_VERSION,
                "id": f"x509-certificate--{entity_id}",
                "subject": e.label,
                "serial_number": e.properties.get("serial", ""),
            }
        return None


class MaltegoExporter:
    """Export entities as Maltego-compatible CSV."""

    def export(self, entities: list[ParsedEntity], output_path: Path) -> Path:
        lines = ["EntityType,EntityValue,Properties"]

        type_map = {
            "subdomain": "maltego.Domain",
            "ip": "maltego.IPv4Address",
            "http_service": "maltego.Website",
            "email": "maltego.EmailAddress",
            "open_port": "maltego.Port",
            "certificate": "maltego.X509Certificate",
            "vulnerability_candidate": "maltego.Vulnerability",
        }

        for e in entities:
            maltego_type = type_map.get(e.kind)
            if not maltego_type:
                continue
            props = json.dumps(e.properties or {}).replace('"', "'")
            lines.append(f"{maltego_type},{e.label},{props}")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path
