"""
Alpha V6 Entity Relationship & Confidence Engine.

Manages relationships between recon entities, deduplication with
confidence merging, and graph construction for attack surface mapping.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from backend.agents.alpha_recon.models import ReconEntity, SourceRef, stable_id
from backend.core.database import db_manager

# Ensure the Alpha V6 recon DB extensions (create_recon_relationship, tool
# outputs, OOB interactions, phase updates) are patched onto EliteDBManager.
# The patch only takes effect if this module is imported — without it the
# entity engine crashes on every ingest with "no attribute
# 'create_recon_relationship'" and recon findings never reach the DB/graph.
from backend.agents.alpha_recon import db_extensions  # noqa: F401  (side-effect: patches EliteDBManager)
from backend.core.unified_knowledge_graph import (
    EdgeKind,
    KGNode,
    NodeKind,
    knowledge_graph,
)

if TYPE_CHECKING:
    from backend.parsers.recon.base import ParsedEntity

logger = logging.getLogger("alpha.entity_engine")

# Map parser entity kinds to knowledge graph node kinds
_KIND_MAP: dict[str, NodeKind] = {
    "subdomain": NodeKind.DOMAIN,
    "ip": NodeKind.HOST,
    "dns_record": NodeKind.DOMAIN,
    "open_port": NodeKind.SERVICE,
    "service": NodeKind.SERVICE,
    "http_service": NodeKind.SERVICE,
    "certificate": NodeKind.HOST,
    "endpoint": NodeKind.ENDPOINT,
    "crawled_endpoint": NodeKind.ENDPOINT,
    "discovered_path": NodeKind.ENDPOINT,
    "browser_endpoint": NodeKind.ENDPOINT,
    "api_route": NodeKind.ENDPOINT,
    "js_endpoint": NodeKind.ENDPOINT,
    "js_file": NodeKind.URL,
    "form_action": NodeKind.ENDPOINT,
    "historical_url": NodeKind.URL,
    "parameter": NodeKind.PARAMETER,
    "secret": NodeKind.SECRET,
    "vulnerability_candidate": NodeKind.VULNERABILITY,
    "oob_interaction": NodeKind.EVIDENCE,
    "visual_artifact": NodeKind.EVIDENCE,
    "favicon": NodeKind.EVIDENCE,
    "cloud_asset": NodeKind.HOST,
    "browser_error": NodeKind.EVIDENCE,
}

# Relationship inference rules
_EDGE_RULES: list[tuple[str, str, EdgeKind]] = [
    ("subdomain", "ip", EdgeKind.RESOLVES_TO),
    ("dns_record", "ip", EdgeKind.RESOLVES_TO),
    ("ip", "open_port", EdgeKind.EXPOSES),
    ("ip", "service", EdgeKind.EXPOSES),
    ("subdomain", "http_service", EdgeKind.EXPOSES),
    ("http_service", "crawled_endpoint", EdgeKind.CONTAINS_ENDPOINT),
    ("http_service", "discovered_path", EdgeKind.CONTAINS_ENDPOINT),
    ("http_service", "browser_endpoint", EdgeKind.CONTAINS_ENDPOINT),
    ("endpoint", "parameter", EdgeKind.ACCEPTS_PARAMETER),
    ("endpoint", "secret", EdgeKind.LEAKS_SECRET),
    ("endpoint", "vulnerability_candidate", EdgeKind.HAS_VULN),
    ("http_service", "certificate", EdgeKind.SUPPORTS),
]


class EntityEngine:
    """Manages entity persistence, deduplication, and relationship building."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._entities: dict[str, ParsedEntity] = {}  # dedup_key -> entity
        self._relationships: list[tuple[str, str, str, float]] = []  # src, dst, rel, conf

    async def ingest_entities(self, entities: list[ParsedEntity]) -> list[ReconEntity]:
        """Ingest parsed entities with deduplication and confidence merging."""
        persisted: list[ReconEntity] = []

        for entity in entities:
            key = entity.dedup_key
            existing = self._entities.get(key)

            if existing:
                # Merge: bump confidence, add source
                existing.confidence = min(1.0, existing.confidence + entity.confidence * 0.2)
                if entity.source_tool not in str(existing.properties.get("sources", "")):
                    existing.properties.setdefault("merged_sources", []).append(entity.source_tool)
                continue

            self._entities[key] = entity

            # Persist to Supabase
            recon_entity = ReconEntity(
                kind=entity.kind,
                label=entity.label,
                scan_id=self.scan_id,
                confidence=entity.confidence,
                sources=[SourceRef(tool=entity.source_tool, phase=entity.phase, confidence=entity.confidence)],
                properties=entity.properties,
            ).ensure_id()

            await db_manager.upsert_recon_entity(
                id=recon_entity.id,
                scan_id=self.scan_id,
                kind=recon_entity.kind,
                label=recon_entity.label,
                normalized=recon_entity.properties,
                sources=[s.model_dump(mode="json") for s in recon_entity.sources],
                confidence=recon_entity.confidence,
            )

            # Update knowledge graph
            node_kind = _KIND_MAP.get(entity.kind, NodeKind.EVIDENCE)
            node = KGNode(
                node_kind,
                entity.label,
                {
                    "scan_id": self.scan_id,
                    "confidence": entity.confidence,
                    "source": entity.source_tool,
                    **_safe_props(entity.properties),
                },
            )
            knowledge_graph.upsert_node(node)

            persisted.append(recon_entity)

        # Build relationships
        await self._build_relationships()

        return persisted

    async def _build_relationships(self) -> None:
        """Infer relationships between entities based on their properties."""
        entity_list = list(self._entities.values())

        # Group by kind for efficient matching
        by_kind: dict[str, list[ParsedEntity]] = {}
        for e in entity_list:
            by_kind.setdefault(e.kind, []).append(e)

        # DNS resolution: subdomain -> IP
        for sub in by_kind.get("subdomain", []) + by_kind.get("dns_record", []):
            ips = sub.properties.get("a", []) + sub.properties.get("aaaa", [])
            resolved_ip = sub.properties.get("resolved_ip", "")
            if resolved_ip:
                ips.append(resolved_ip)
            for ip_str in ips:
                ip_entity = self._entities.get(f"ip:{ip_str}")
                if ip_entity:
                    await self._persist_relationship(sub, ip_entity, "resolves_to", 0.95)

        # Host -> Port/Service
        for port_entity in by_kind.get("open_port", []) + by_kind.get("service", []):
            host = port_entity.properties.get("host", "")
            if host:
                host_entity = self._entities.get(f"ip:{host}") or self._entities.get(f"subdomain:{host}")
                if host_entity:
                    await self._persist_relationship(host_entity, port_entity, "exposes", 0.9)

        # HTTP Service -> Endpoints
        for ep in (
            by_kind.get("crawled_endpoint", [])
            + by_kind.get("discovered_path", [])
            + by_kind.get("browser_endpoint", [])
            + by_kind.get("api_route", [])
        ):
            host = ep.properties.get("host", "")
            if host:
                svc = self._entities.get(f"http_service:{host}") or self._entities.get(f"subdomain:{host}")
                if svc:
                    await self._persist_relationship(svc, ep, "contains_endpoint", 0.8)

        # Endpoint -> Vulnerability Candidate
        for vuln in by_kind.get("vulnerability_candidate", []):
            host = vuln.properties.get("host", "")
            matched = vuln.properties.get("matched_at", "")
            target = host or matched
            if target:
                for ep in entity_list:
                    if ep.kind in ("endpoint", "http_service", "subdomain") and target in ep.label:
                        await self._persist_relationship(ep, vuln, "has_vuln", 0.7)
                        break

    async def _persist_relationship(
        self, src: ParsedEntity, dst: ParsedEntity, relationship: str, confidence: float
    ) -> None:
        """Persist a relationship to the database and knowledge graph."""
        rel_id = stable_id(self.scan_id, src.dedup_key, dst.dedup_key, relationship)

        # Knowledge graph
        src_kind = _KIND_MAP.get(src.kind, NodeKind.EVIDENCE)
        dst_kind = _KIND_MAP.get(dst.kind, NodeKind.EVIDENCE)
        src_node = KGNode(src_kind, src.label, {"scan_id": self.scan_id})
        dst_node = KGNode(dst_kind, dst.label, {"scan_id": self.scan_id})

        edge_kind_map = {
            "resolves_to": EdgeKind.RESOLVES_TO,
            "exposes": EdgeKind.EXPOSES,
            "contains_endpoint": EdgeKind.CONTAINS_ENDPOINT,
            "has_vuln": EdgeKind.HAS_VULN,
            "leaks_secret": EdgeKind.LEAKS_SECRET,
            "accepts_parameter": EdgeKind.ACCEPTS_PARAMETER,
            "authenticated_by": EdgeKind.AUTHENTICATED_BY,
        }
        edge_kind = edge_kind_map.get(relationship, EdgeKind.REACHES)
        knowledge_graph.link(src_node, dst_node, edge_kind, weight=confidence)

        # Persist to DB
        await db_manager.create_recon_relationship(
            id=rel_id,
            scan_id=self.scan_id,
            src_entity_id=stable_id(self.scan_id, src.kind, src.label),
            dst_entity_id=stable_id(self.scan_id, dst.kind, dst.label),
            relationship=relationship,
            confidence=confidence,
            evidence={"src_kind": src.kind, "dst_kind": dst.kind},
        )

    def get_attack_surface_stats(self) -> dict[str, int]:
        """Return entity counts by kind."""
        counts: dict[str, int] = {}
        for e in self._entities.values():
            counts[e.kind] = counts.get(e.kind, 0) + 1
        return counts


def _safe_props(props: dict[str, Any], max_keys: int = 10) -> dict[str, Any]:
    """Limit props to safe, small values for KG node storage."""
    result = {}
    for key, value in list(props.items())[:max_keys]:
        if isinstance(value, (str, int, float, bool)):
            if isinstance(value, str) and len(value) > 200:
                value = value[:200]
            result[key] = value
        elif isinstance(value, list) and len(value) <= 5:
            result[key] = [str(v)[:100] for v in value]
    return result
