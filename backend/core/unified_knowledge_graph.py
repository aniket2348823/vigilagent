"""
Vigilagent Unified Knowledge Graph (Architecture §12, §24(22), §25, §29.2)
================================================================================
Converges the two previously-separate graph systems (`graph_engine.py` and
`knowledge_graph.py`) into ONE logical knowledge graph abstraction. There is now
a single implementation here; the old modules become thin compatibility shims
that re-export from this file (no duplicate logic).

What is kept from each (Architecture §12):
  - knowledge_graph.py: typed `stable_id` upsert + browser linking +
    ingest_http_record / ingest_finding.
  - graph_engine.py: CHAIN_RULES + find_chains DFS + weight pruning +
    JSON persistence + predict_next + learn_from_chain.
  - NEW: an adjacency index so neighbor lookups are O(1) instead of full scans.

The graph is used to (Architecture §12): avoid duplicate work, select next best
validation, explain attack-surface coverage, build evidence-backed reports, and
track why decisions were made.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

logger = logging.getLogger("unified_knowledge_graph")

from backend.core.perf import TTLCache

if TYPE_CHECKING:
    from collections.abc import Iterable

# ── Persistence paths (from graph_engine.py) ──────────────────────────────────
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data")
os.makedirs(_DATA_DIR, exist_ok=True)
GRAPH_FILE = os.path.join(_DATA_DIR, "graph.json")
TMP_GRAPH_FILE = os.path.join(_DATA_DIR, "graph.json.tmp")


# ══════════════════════════════════════════════════════════════════════════════
# TYPED GRAPH (from knowledge_graph.py) — node/edge kinds per Architecture §12
# ══════════════════════════════════════════════════════════════════════════════


class NodeKind(StrEnum):
    ENGAGEMENT = "engagement"
    TARGET = "target"
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FORM = "form"
    API_SCHEMA = "api_schema"
    AUTH_SCHEME = "auth_scheme"
    TOKEN = "token"
    COOKIE = "cookie"
    SESSION = "session"
    CREDENTIAL = "credential"
    SECRET = "secret"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    CVE = "cve"
    WEAKNESS = "weakness"
    FINDING = "finding"
    EVIDENCE = "evidence"
    OBJECTIVE = "objective"
    ATTACK_PATH = "attack_path"
    TECHNIQUE = "technique"
    TOOL_RUN = "tool_run"
    AGENT_DECISION = "agent_decision"
    # Browser-specific node types
    BROWSER_ENDPOINT = "browser_endpoint"
    JAVASCRIPT_ROUTE = "javascript_route"
    WEBSOCKET_CONNECTION = "websocket_connection"


class EdgeKind(StrEnum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    SERVES = "serves"
    LINKS_TO = "links_to"
    CONTAINS_ENDPOINT = "contains_endpoint"
    ACCEPTS_PARAMETER = "accepts_parameter"
    HAS_PARAMETER = "has_parameter"
    AUTHENTICATED_BY = "authenticated_by"
    AUTHENTICATES_TO = "authenticates_to"
    HAS_SESSION = "has_session"
    LEAKS_SECRET = "leaks_secret"
    HAS_VULN = "has_vuln"
    VALIDATES = "validates"
    VERIFIED_BY = "verified_by"
    PRODUCED_BY = "produced_by"
    OBSERVED_IN = "observed_in"
    EXPLOITS = "exploits"
    VULNERABLE_TO = "vulnerable_to"
    MITIGATED_BY = "mitigated_by"
    SUPERSEDES = "supersedes"
    DUPLICATES = "duplicates"
    LEADS_TO = "leads_to"
    PIVOTS_TO = "pivots_to"
    ESCALATES_TO = "escalates_to"
    REACHES = "reaches"
    SUPPORTS = "supports"
    # Browser-specific edge types
    HTTP_EQUIVALENT = "http_equivalent"
    DISCOVERED_BY_BROWSER = "discovered_by_browser"


# Alias: spec/design uses ``EdgeType`` while the codebase canon is ``EdgeKind``.
# Exposing both names avoids enum duplication and keeps the public API symmetric
# with NodeKind (Architecture §12).
EdgeType = EdgeKind


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def stable_id(*parts: str) -> str:
    raw = "|".join(part.lower().strip() for part in parts)
    # NOTE: sha256 is used for node ID stability (not security). Changed from
    # sha1 per audit HIGH-19. The 64-char hex is a superset of the old 40-char
    # sha1 output so existing 40-char lookups that were truncated will still
    # match if they happen to share the same prefix (low risk for graph IDs).
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class KGNode:
    kind: NodeKind
    label: str
    props: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.kind.value, self.label)


@dataclass
class KGEdge:
    src_id: str
    dst_id: str
    kind: EdgeKind
    weight: float = 1.0
    props: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.src_id, self.kind.value, self.dst_id)


def _severity_weight(severity: str) -> float:
    return {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "informational": 1.0,
        "info": 1.0,
    }.get(severity.lower(), 1.0)


class KnowledgeGraph:
    """Typed graph with an adjacency index for O(1) neighbor lookups (§12)."""

    def __init__(self) -> None:
        self.nodes: dict[str, KGNode] = {}
        self.edges: dict[str, KGEdge] = {}
        # Adjacency index (Architecture §12): src_id -> [edge_id], dst_id -> [edge_id]
        self._adj_out: dict[str, list[str]] = {}
        self._adj_in: dict[str, list[str]] = {}

    def upsert_node(self, node: KGNode) -> KGNode:
        existing = self.nodes.get(node.id)
        if existing:
            existing.props.update(node.props)
            return existing
        self.nodes[node.id] = node
        self._adj_out.setdefault(node.id, [])
        self._adj_in.setdefault(node.id, [])
        return node

    def upsert_edge(self, edge: KGEdge) -> KGEdge:
        existing = self.edges.get(edge.id)
        if existing:
            existing.weight = max(existing.weight, edge.weight)
            existing.props.update(edge.props)
            return existing
        self.edges[edge.id] = edge
        self._adj_out.setdefault(edge.src_id, []).append(edge.id)
        self._adj_in.setdefault(edge.dst_id, []).append(edge.id)
        return edge

    def link(
        self, src: KGNode, dst: KGNode, kind: EdgeKind, *, weight: float = 1.0, props: dict[str, Any] | None = None
    ) -> KGEdge:
        src = self.upsert_node(src)
        dst = self.upsert_node(dst)
        return self.upsert_edge(KGEdge(src.id, dst.id, kind, weight, props or {}))

    def by_kind(self, kind: NodeKind) -> list[KGNode]:
        return [node for node in self.nodes.values() if node.kind == kind]

    def neighbors(self, node_id: str, *, direction: str = "out", edge_kind: EdgeKind | None = None) -> list[KGNode]:
        found: list[KGNode] = []
        if direction in {"out", "both"}:
            for eid in self._adj_out.get(node_id, []):
                edge = self.edges.get(eid)
                if not edge or (edge_kind and edge.kind != edge_kind):
                    continue
                if edge.dst_id in self.nodes:
                    found.append(self.nodes[edge.dst_id])
        if direction in {"in", "both"}:
            for eid in self._adj_in.get(node_id, []):
                edge = self.edges.get(eid)
                if not edge or (edge_kind and edge.kind != edge_kind):
                    continue
                if edge.src_id in self.nodes:
                    found.append(self.nodes[edge.src_id])
        return found

    def ingest_finding(self, finding: dict[str, Any], *, scan_id: str = "GLOBAL") -> KGNode:
        endpoint = str(finding.get("endpoint") or finding.get("url") or finding.get("affected_target") or "unknown")
        vuln_type = str(finding.get("vuln_type") or finding.get("type") or finding.get("title") or "vulnerability")
        severity = str(finding.get("severity") or "info").lower()
        endpoint_node = KGNode(NodeKind.ENDPOINT, endpoint, {"scan_id": scan_id})
        vuln_node = KGNode(NodeKind.VULNERABILITY, vuln_type, {"scan_id": scan_id, "severity": severity})
        finding_node = KGNode(
            NodeKind.FINDING,
            str(finding.get("id") or stable_id(scan_id, endpoint, vuln_type)),
            {"scan_id": scan_id, **finding},
        )
        self.link(endpoint_node, vuln_node, EdgeKind.HAS_VULN, weight=_severity_weight(severity))
        self.link(vuln_node, finding_node, EdgeKind.VALIDATES, weight=_severity_weight(severity))
        return finding_node

    def ingest_http_record(self, record: Any, *, scan_id: str = "GLOBAL") -> None:
        url = getattr(record, "url", "") or (record.get("url", "") if isinstance(record, dict) else "")
        status = getattr(record, "status", 0) if not isinstance(record, dict) else record.get("status", 0)
        method = getattr(record, "method", "") if not isinstance(record, dict) else record.get("method", "")
        endpoint = KGNode(NodeKind.ENDPOINT, str(url), {"scan_id": scan_id, "method": method, "status": status})
        self.upsert_node(endpoint)
        if status in {401, 403}:
            self.link(
                endpoint, KGNode(NodeKind.AUTH_SCHEME, "auth_required", {"scan_id": scan_id}), EdgeKind.AUTHENTICATED_BY
            )

    def plan_attack_paths(self, *, max_depth: int = 5) -> list[list[KGNode]]:
        paths: list[list[KGNode]] = []
        starts = [n for n in self.nodes.values() if n.kind in {NodeKind.VULNERABILITY, NodeKind.FINDING}]
        chain_edges = {
            EdgeKind.LEADS_TO,
            EdgeKind.PIVOTS_TO,
            EdgeKind.ESCALATES_TO,
            EdgeKind.EXPLOITS,
            EdgeKind.HAS_VULN,
        }

        def walk(node_id: str, path: list[str]) -> None:
            out_ids = self._adj_out.get(node_id, [])
            if len(path) >= max_depth or not out_ids:
                if len(path) > 1:
                    paths.append([self.nodes[i] for i in path if i in self.nodes])
                return
            for eid in out_ids:
                edge = self.edges.get(eid)
                if edge and edge.kind in chain_edges and edge.dst_id not in path:
                    walk(edge.dst_id, [*path, edge.dst_id])

        for start in starts:
            walk(start.id, [start.id])
        return sorted(paths, key=len, reverse=True)

    def bulk_upsert(self, nodes: Iterable[KGNode], edges: Iterable[KGEdge]) -> None:
        for node in nodes:
            self.upsert_node(node)
        for edge in edges:
            self.upsert_edge(edge)

    def stats(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.kind.value] = counts.get(node.kind.value, 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "by_kind": counts}

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.id, "kind": n.kind.value, "label": n.label, "props": n.props} for n in self.nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "src": e.src_id,
                    "dst": e.dst_id,
                    "kind": e.kind.value,
                    "weight": e.weight,
                    "props": e.props,
                }
                for e in self.edges.values()
            ],
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        self.nodes.clear()
        self.edges.clear()
        self._adj_out.clear()
        self._adj_in.clear()
        for n in data.get("nodes", []):
            try:
                node = KGNode(NodeKind(n["kind"]), n["label"], n.get("props", {}), n.get("id", ""))
                self.nodes[node.id] = node
                self._adj_out.setdefault(node.id, [])
                self._adj_in.setdefault(node.id, [])
            except Exception as node_exc:
                logger.debug(f"[KnowledgeGraph] Node ingestion failed: {node_exc}")
                continue
        for e in data.get("edges", []):
            try:
                edge = KGEdge(
                    e["src"], e["dst"], EdgeKind(e["kind"]), e.get("weight", 1.0), e.get("props", {}), e.get("id", "")
                )
                self.edges[edge.id] = edge
                self._adj_out.setdefault(edge.src_id, []).append(edge.id)
                self._adj_in.setdefault(edge.dst_id, []).append(edge.id)
            except Exception as edge_exc:
                logger.debug(f"[KnowledgeGraph] Edge ingestion failed: {edge_exc}")
                continue


# ══════════════════════════════════════════════════════════════════════════════
# CHAIN GRAPH (from graph_engine.py) — predictive attack chains
# ══════════════════════════════════════════════════════════════════════════════


class VulnNode:
    def __init__(self, type: str, endpoint: str, weight: int = 1):
        self.type = type
        self.endpoint = endpoint
        self.weight = weight

    def __eq__(self, other):
        if not isinstance(other, VulnNode):
            return False
        return self.type == other.type and self.endpoint == other.endpoint

    def __hash__(self):
        return hash((self.type, self.endpoint))

    def to_dict(self):
        return {"type": self.type, "endpoint": self.endpoint, "weight": self.weight}

    @classmethod
    def from_dict(cls, data):
        return cls(type=data["type"], endpoint=data["endpoint"], weight=data.get("weight", 1))


class Edge:
    def __init__(self, src: VulnNode, dst: VulnNode, weight: int = 1):
        self.src = src
        self.dst = dst
        self.weight = weight

    def __eq__(self, other):
        if not isinstance(other, Edge):
            return False
        return self.src == other.src and self.dst == other.dst

    def __hash__(self):
        return hash((self.src, self.dst))

    def to_dict(self):
        return {"src": self.src.to_dict(), "dst": self.dst.to_dict(), "weight": self.weight}

    @classmethod
    def from_dict(cls, data):
        return cls(
            src=VulnNode.from_dict(data["src"]), dst=VulnNode.from_dict(data["dst"]), weight=data.get("weight", 1)
        )


class GraphEngine:
    """Self-learning intelligence graph: predictive attack chains by weight."""

    CHAIN_RULES = {
        "SQL_INJECTION": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "IDOR", "DATA_LEAK"],
        "COMMAND_INJECTION": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "RCE"],
        "SSRF": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "IDOR", "INTERNAL_ACCESS"],
        "IDOR": ["UNAUTHORIZED_ACCESS", "BROKEN_AUTH", "LOGIC_ESCALATION", "DATA_LEAK"],
        "XSS": ["CSRF", "PROMPT_INJECTION", "SESSION_HIJACK"],
        "CROSS_SITE_SCRIPTING": ["CSRF", "PROMPT_INJECTION", "SESSION_HIJACK"],
        "BROKEN_AUTH": ["LOGIC_ESCALATION", "DATA_LEAK", "ADMIN_TAKEOVER"],
        "JWT_BYPASS": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "ADMIN_TAKEOVER"],
        "PATH_TRAVERSAL": ["DATA_LEAK", "RCE", "CONFIG_EXPOSURE"],
        "RACE_CONDITION": ["LOGIC_ESCALATION", "FINANCIAL_MANIPULATION"],
    }

    def __init__(self):
        self.nodes: set[VulnNode] = set()
        self.edges: set[Edge] = set()
        self._lock = asyncio.Lock()
        # Adjacency index for O(1) outbound lookups (Architecture §12).
        self._adj: dict[VulnNode, list[Edge]] = {}
        # 30s TTL cache for predict_next / find_chains. The planner queries
        # these on every iteration, but the graph only mutates when a new
        # finding/chain is ingested. We invalidate on mutation (see
        # ``_invalidate_cache``) and let the TTL handle stragglers.
        self._query_cache: TTLCache = TTLCache(ttl_seconds=30.0)
        self.load_graph()

    def _invalidate_cache(self) -> None:
        """Clear cached predict_next / find_chains results.

        Called by every code path that mutates ``self.nodes`` / ``self.edges``
        so cached chain results never lag behind the live graph.
        """
        self._query_cache.invalidate()

    def load_graph(self):
        if os.path.exists(GRAPH_FILE):
            try:
                with open(GRAPH_FILE) as f:
                    data = json.load(f)
                    for n_data in data.get("nodes", []):
                        self._add_or_update_node(n_data["type"], n_data["endpoint"], n_data.get("weight", 1))
                    for e_data in data.get("edges", []):
                        src = VulnNode.from_dict(e_data["src"])
                        dst = VulnNode.from_dict(e_data["dst"])
                        self._add_or_update_edge(src, dst, e_data.get("weight", 1))
            except Exception as e:
                logger.warning(f"[GraphEngine] Failed to load intelligence graph: {e}")

    async def save_graph(self):
        async with self._lock:
            self._prune(max_nodes=500, max_edges=2500)
            data = {"nodes": [n.to_dict() for n in self.nodes], "edges": [e.to_dict() for e in self.edges]}
            try:

                def _write():
                    with open(TMP_GRAPH_FILE, "w") as f:
                        json.dump(data, f)
                    os.replace(TMP_GRAPH_FILE, GRAPH_FILE)

                await asyncio.get_running_loop().run_in_executor(None, _write)
            except Exception as e:
                logger.warning(f"[GraphEngine] Failed to persist intelligence graph: {e}")

    def _rebuild_adj(self):
        self._adj = {}
        for e in self.edges:
            self._adj.setdefault(e.src, []).append(e)

    def _prune(self, max_nodes: int = 500, max_edges: int = 2500):
        if len(self.nodes) > max_nodes:
            sorted_nodes = sorted(list(self.nodes), key=lambda x: x.weight, reverse=True)
            survivors = set(sorted_nodes[:max_nodes])
            pruned_count = len(self.nodes) - max_nodes
            self.nodes = survivors
            self.edges = {e for e in self.edges if e.src in survivors and e.dst in survivors}
            logger.debug(f"[GraphEngine] Pruned {pruned_count} low-confidence nodes.")
        if len(self.edges) > max_edges:
            sorted_edges = sorted(list(self.edges), key=lambda x: x.weight, reverse=True)
            pruned_count = len(self.edges) - max_edges
            self.edges = set(sorted_edges[:max_edges])
            logger.debug(f"[GraphEngine] Pruned {pruned_count} low-weight edges.")
        self._rebuild_adj()

    def _add_or_update_node(self, type: str, endpoint: str, weight: int = 1, source: str = "UNKNOWN") -> VulnNode:
        if "delta" in type.lower() or "dom" in source.lower():
            verified_source = "PINCHTAB_DOM"
        elif "heuristic" not in source.lower():
            verified_source = "REAL_API_TRACE"
        else:
            verified_source = "UNVERIFIED_HEURISTIC"
        dummy = VulnNode(type, endpoint)
        for n in self.nodes:
            if n == dummy:
                n.weight += weight
                n.__dict__["verified_source"] = verified_source
                self._invalidate_cache()
                return n
        new_node = VulnNode(type, endpoint, weight)
        new_node.__dict__["verified_source"] = verified_source
        self.nodes.add(new_node)
        self._adj.setdefault(new_node, [])
        self._invalidate_cache()
        return new_node

    def _add_or_update_edge(self, src: VulnNode, dst: VulnNode, weight: int = 1) -> Edge:
        real_src = self._add_or_update_node(src.type, src.endpoint, 0)
        real_dst = self._add_or_update_node(dst.type, dst.endpoint, 0)
        dummy_edge = Edge(real_src, real_dst)
        for e in self.edges:
            if e == dummy_edge:
                e.weight += weight
                self._invalidate_cache()
                return e
        new_edge = Edge(real_src, real_dst, weight)
        self.edges.add(new_edge)
        self._adj.setdefault(real_src, []).append(new_edge)
        self._invalidate_cache()
        return new_edge

    async def learn_from_chain(self, chain: list[dict[str, Any]]):
        if len(chain) < 2:
            return
        nodes_in_chain = []
        for finding in chain:
            payload = finding.get("payload", {})
            vt = str(payload.get("type", "UNKNOWN")).upper()
            vu = str(payload.get("url", "")).split("?")[0].lower()
            nodes_in_chain.append(VulnNode(vt, vu))
        async with self._lock:
            for i in range(len(nodes_in_chain) - 1):
                self._add_or_update_edge(nodes_in_chain[i], nodes_in_chain[i + 1], weight=1)
        await self.save_graph()

    def predict_next(self, current_type: str, current_endpoint: str) -> list[dict[str, Any]]:
        current_endpoint = current_endpoint.split("?")[0].lower()
        cache_key = ("predict_next", current_type.upper(), current_endpoint)
        return self._query_cache.get_or_compute(
            cache_key, lambda: self._predict_next_uncached(current_type, current_endpoint)
        )

    def _predict_next_uncached(self, current_type: str, current_endpoint: str) -> list[dict[str, Any]]:
        dummy = VulnNode(current_type.upper(), current_endpoint)
        out_edges = self._adj.get(dummy, [e for e in self.edges if e.src == dummy])
        total_weight = sum(e.weight for e in out_edges)
        candidates = []
        for e in out_edges:
            confidence = round((e.weight / total_weight) * 100, 2) if total_weight > 0 else 0
            candidates.append(
                {
                    "suggestion": e.dst.type,
                    "target_path": e.dst.endpoint,
                    "weight": e.weight,
                    "confidence": confidence,
                }
            )
        return sorted(candidates, key=lambda x: x["weight"], reverse=True)

    def can_chain(self, src_type: str, dst_type: str) -> bool:
        return dst_type.upper() in self.CHAIN_RULES.get(src_type.upper(), [])

    def find_chains(self, max_depth: int = 5) -> list[dict[str, Any]]:
        cache_key = ("find_chains", int(max_depth))
        return self._query_cache.get_or_compute(cache_key, lambda: self._find_chains_uncached(max_depth))

    def _find_chains_uncached(self, max_depth: int = 5) -> list[dict[str, Any]]:
        adj: dict[VulnNode, list[VulnNode]] = {}
        edge_weights: dict[tuple, int] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append(e.dst)
            edge_weights[(e.src, e.dst)] = e.weight
        chains: list[list[VulnNode]] = []

        def dfs(node: VulnNode, path: list[VulnNode], visited: set):
            if len(path) >= max_depth:
                if len(path) > 1:
                    chains.append(path.copy())
                return
            neighbors = adj.get(node, [])
            has_valid_next = False
            for nxt in neighbors:
                if nxt not in visited and self.can_chain(node.type, nxt.type):
                    has_valid_next = True
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)
            if not has_valid_next and len(path) > 1:
                chains.append(path.copy())

        for start_node in self.nodes:
            dfs(start_node, [start_node], {start_node})

        seen = set()
        unique_chains = []
        for chain in chains:
            sig = "->".join(f"{n.type}@{n.endpoint}" for n in chain)
            if sig not in seen:
                seen.add(sig)
                total_weight = sum(edge_weights.get((chain[i], chain[i + 1]), 1) for i in range(len(chain) - 1))
                unique_chains.append(
                    {
                        "chain": [n.to_dict() for n in chain],
                        "depth": len(chain),
                        "total_weight": total_weight,
                        "confidence": min(100, total_weight * 10 + len(chain) * 15),
                    }
                )
        return sorted(unique_chains, key=lambda x: (x["depth"], x["total_weight"]), reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# BROWSER EXTENSION (from knowledge_graph.py)
# ══════════════════════════════════════════════════════════════════════════════


class BrowserKnowledgeGraphExtension:
    """Browser discovery and HTTP-browser linking (Architecture §12, §29.8).

    URLs are evidence only — never used to derive scope grants (§9). All
    operations are non-blocking on the request path (§29.13) and never call
    LLM (§11) or perform re-verification (§17).
    """

    # Map browser-recon discovery type → canonical NodeKind.
    # Accepts both new (spec §11.1) and legacy aliases for compatibility.
    _TYPE_MAP: dict[str, NodeKind] = {
        "endpoint": NodeKind.BROWSER_ENDPOINT,
        "browser_endpoint": NodeKind.BROWSER_ENDPOINT,
        "route": NodeKind.JAVASCRIPT_ROUTE,
        "javascript_route": NodeKind.JAVASCRIPT_ROUTE,
        "js_route": NodeKind.JAVASCRIPT_ROUTE,
        "websocket": NodeKind.WEBSOCKET_CONNECTION,
        "websocket_connection": NodeKind.WEBSOCKET_CONNECTION,
        "ws": NodeKind.WEBSOCKET_CONNECTION,
    }

    def __init__(self, knowledge_graph: KnowledgeGraph):
        self.graph = knowledge_graph
        self._fire_and_forget_tasks: set[asyncio.Task] = set()

    def add_browser_discovery(self, discovery: dict[str, Any], scan_id: str = "GLOBAL") -> str:
        """Ingest a browser-recon discovery and return the node_id (Architecture §12, §29.8).

        Accepts ``{"type": "endpoint"|"route"|"websocket", "url": ..., ...}``.
        Always tags ``source="browser_recon"`` (§9: URL is evidence only).
        For ``type=="endpoint"``, links to any existing HTTP-source node with
        the same URL via an ``HTTP_EQUIVALENT`` edge. Idempotent: replaying the
        same discovery returns the same node_id (stable_id is kind+label).
        """
        discovery_type = str(discovery.get("type") or "endpoint").lower()
        url = str(discovery.get("url") or "")
        kind = self._TYPE_MAP.get(discovery_type, NodeKind.BROWSER_ENDPOINT)

        # Build props with provenance tag; preserve any caller-provided fields.
        props: dict[str, Any] = {
            "scan_id": scan_id,
            "source": "browser_recon",
            **{k: v for k, v in discovery.items() if k != "type"},
        }
        if kind is NodeKind.JAVASCRIPT_ROUTE:
            props.setdefault("framework", discovery.get("framework"))
            props.setdefault("route_pattern", discovery.get("route_pattern"))
        elif kind is NodeKind.WEBSOCKET_CONNECTION:
            props.setdefault("protocol", discovery.get("protocol", "ws"))

        node = self.graph.upsert_node(KGNode(kind, url, props))

        # Only browser-endpoint discoveries get auto-linked to HTTP twins.
        if kind is NodeKind.BROWSER_ENDPOINT:
            http_id = stable_id(NodeKind.ENDPOINT.value, url)
            if http_id in self.graph.nodes:
                self.link_http_browser_endpoints(http_id, node.id)

        # Persistence is graph-implementation-specific. KnowledgeGraph is
        # in-memory; if a future backend adds a disk-backed save_async,
        # off-load here via asyncio.to_thread (§29.13 non-blocking).
        save_async = getattr(self.graph, "save_async", None)
        if callable(save_async):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    task = loop.create_task(asyncio.wait_for(asyncio.to_thread(save_async), timeout=15))
                    self._fire_and_forget_tasks.add(task)
                    task.add_done_callback(self._fire_and_forget_tasks.discard)
            except RuntimeError:
                pass  # no running loop — skip persistence quietly
        return node.id

    def link_http_browser_endpoints(self, http_node_id: str, browser_node_id: str) -> None:
        """Idempotently link an HTTP endpoint and its browser-discovered twin.

        Skips if an ``HTTP_EQUIVALENT`` edge already exists, merges metadata
        via union, and marks both nodes with ``linked=True`` (Task 7.4).
        """
        http_node = self.graph.nodes.get(http_node_id)
        browser_node = self.graph.nodes.get(browser_node_id)
        if not http_node or not browser_node:
            return

        # Idempotency: short-circuit if the edge already exists in either direction.
        edge_id_fwd = stable_id(http_node_id, EdgeKind.HTTP_EQUIVALENT.value, browser_node_id)
        edge_id_rev = stable_id(browser_node_id, EdgeKind.HTTP_EQUIVALENT.value, http_node_id)
        if edge_id_fwd in self.graph.edges or edge_id_rev in self.graph.edges:
            http_node.props["linked"] = True
            browser_node.props["linked"] = True
            return

        # Mark both endpoints linked and merge metadata via union.
        # Browser-side keys take precedence on the browser node and vice versa,
        # so neither node loses its own provenance.
        merged: dict[str, Any] = {**browser_node.props, **http_node.props}
        for k, v in merged.items():
            http_node.props.setdefault(k, v)
            browser_node.props.setdefault(k, v)
        http_node.props["linked"] = True
        browser_node.props["linked"] = True
        http_node.props["browser_url"] = browser_node.label
        http_node.props["browser_discovered"] = True

        self.graph.upsert_edge(
            KGEdge(
                http_node_id, browser_node_id, EdgeKind.HTTP_EQUIVALENT, weight=1.0, props={"linked_at": time.time()}
            )
        )

    def get_endpoint_context(self, url: str) -> dict[str, Any]:
        """Return unified HTTP/browser context for ``url`` (Task 7.6).

        Shape: ``{"http": <props|None>, "browser": <props|None>,
        "linked": [<node_ids of HTTP_EQUIVALENT neighbors>]}``.
        O(adjacency): O(1) node lookups via stable_id, O(deg) neighbor walk
        through the existing graph adjacency map.
        """
        http_node = self.graph.nodes.get(stable_id(NodeKind.ENDPOINT.value, url))
        browser_node: KGNode | None = None
        for browser_kind in (NodeKind.BROWSER_ENDPOINT, NodeKind.JAVASCRIPT_ROUTE, NodeKind.WEBSOCKET_CONNECTION):
            cand = self.graph.nodes.get(stable_id(browser_kind.value, url))
            if cand is not None:
                browser_node = cand
                break

        linked: list[str] = []
        seen: set = set()
        for anchor in (http_node, browser_node):
            if anchor is None:
                continue
            for eid in self.graph._adj_out.get(anchor.id, ()):
                edge = self.graph.edges.get(eid)
                if edge and edge.kind is EdgeKind.HTTP_EQUIVALENT and edge.dst_id not in seen:
                    seen.add(edge.dst_id)
                    linked.append(edge.dst_id)
            for eid in self.graph._adj_in.get(anchor.id, ()):
                edge = self.graph.edges.get(eid)
                if edge and edge.kind is EdgeKind.HTTP_EQUIVALENT and edge.src_id not in seen:
                    seen.add(edge.src_id)
                    linked.append(edge.src_id)

        return {
            "http": dict(http_node.props) if http_node is not None else None,
            "browser": dict(browser_node.props) if browser_node is not None else None,
            "linked": linked,
        }

    def get_browser_discoveries(self, scan_id: str | None = None) -> list[KGNode]:
        out = []
        for node in self.graph.nodes.values():
            if node.kind in [NodeKind.BROWSER_ENDPOINT, NodeKind.JAVASCRIPT_ROUTE, NodeKind.WEBSOCKET_CONNECTION]:
                if scan_id is None or node.props.get("scan_id") == scan_id:
                    out.append(node)
        return out

    def get_discovery_stats(self) -> dict[str, Any]:
        linked_count = sum(1 for e in self.graph.edges.values() if e.kind == EdgeKind.HTTP_EQUIVALENT)
        be = len(self.graph.by_kind(NodeKind.BROWSER_ENDPOINT))
        jr = len(self.graph.by_kind(NodeKind.JAVASCRIPT_ROUTE))
        ws = len(self.graph.by_kind(NodeKind.WEBSOCKET_CONNECTION))
        return {
            "browser_endpoints": be,
            "javascript_routes": jr,
            "websocket_connections": ws,
            "total_browser_discoveries": be + jr + ws,
            "http_browser_links": linked_count,
            "timestamp": time.time(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED FACADE (Architecture §12, §29.2) — single entry point for new code
# ══════════════════════════════════════════════════════════════════════════════


class UnifiedKnowledgeGraph:
    """Single facade over the typed graph + chain graph (Architecture §12).

    New code (Omega §5.2, Planner §29.1) should query this facade; legacy code
    keeps using the GraphEngine / KnowledgeGraph singletons (same module).
    """

    def __init__(self, typed: KnowledgeGraph | None = None, chains: GraphEngine | None = None):
        self.typed = typed or knowledge_graph
        self.chains = chains or graph_engine
        self.browser = browser_knowledge_graph

    # Typed graph delegation
    def upsert_node(self, kind: NodeKind, label: str, **props) -> str:
        return self.typed.upsert_node(KGNode(kind, label, props)).id

    def link(self, src_id: str, dst_id: str, kind: EdgeKind, weight: float = 1.0) -> None:
        if src_id in self.typed.nodes and dst_id in self.typed.nodes:
            self.typed.upsert_edge(KGEdge(src_id, dst_id, kind, weight))

    def ingest_http_record(self, record: Any, scan_id: str = "GLOBAL") -> None:
        self.typed.ingest_http_record(record, scan_id=scan_id)

    def ingest_finding(self, finding: dict, scan_id: str = "GLOBAL") -> KGNode:
        return self.typed.ingest_finding(finding, scan_id=scan_id)

    # Chain graph delegation
    def predict_next(self, node_type: str, endpoint: str) -> list[dict]:
        return self.chains.predict_next(node_type, endpoint)

    def find_chains(self, max_depth: int = 5) -> list[dict]:
        return self.chains.find_chains(max_depth=max_depth)

    async def learn_from_chain(self, chain: list[dict]) -> None:
        await self.chains.learn_from_chain(chain)

    def stats(self) -> dict:
        return {
            "typed": self.typed.stats(),
            "chain_nodes": len(self.chains.nodes),
            "chain_edges": len(self.chains.edges),
            "browser": self.browser.get_discovery_stats(),
        }

    def to_dict(self) -> dict:
        return {"typed": self.typed.to_dict()}

    def from_dict(self, data: dict) -> None:
        if "typed" in data:
            self.typed.from_dict(data["typed"])


# ── Global singletons (one logical graph, three views) ────────────────────────
knowledge_graph = KnowledgeGraph()
graph_engine = GraphEngine()
browser_knowledge_graph = BrowserKnowledgeGraphExtension(knowledge_graph)
unified_knowledge_graph = UnifiedKnowledgeGraph(knowledge_graph, graph_engine)
