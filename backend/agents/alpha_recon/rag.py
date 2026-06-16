from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from backend.agents.alpha_recon.models import EndpointFinding, ReconEntity, stable_id
from backend.core.database import db_manager
from backend.core.memory import memory_store

logger = logging.getLogger("alpha.rag")


class ReconRAGPipeline:
    """
    Lightweight RAG pipeline for Alpha recon.

    It stores normalized observations as small retrievable chunks in both the
    local dual-store memory and Supabase semantic_memory. Embeddings can be
    added later without changing callers; for now retrieval is lexical.
    """

    def __init__(self, scan_id: str, artifact_root: str):
        self.scan_id = scan_id
        self.path = Path(artifact_root) / "normalized" / "rag_chunks.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def ingest_entity(self, entity: ReconEntity) -> str:
        text = f"{entity.kind}: {entity.label} confidence={entity.confidence} props={json.dumps(entity.properties, default=str)[:1000]}"
        return await self._store("recon_entity", text, entity.model_dump(mode="json"))

    async def ingest_endpoint(self, endpoint: EndpointFinding) -> str:
        params = ", ".join(param.name for param in endpoint.parameters)
        text = (
            f"endpoint {endpoint.method} {endpoint.url} status={endpoint.status_code} "
            f"type={endpoint.endpoint_type} risk={endpoint.risk_class} score={endpoint.priority_score} "
            f"auth_required={endpoint.auth_required} params={params} tech={','.join(endpoint.technologies)}"
        )
        return await self._store("recon_endpoint", text, endpoint.model_dump(mode="json"), endpoint_pattern=endpoint.normalized_path)

    async def ingest_tool_summary(self, tool_name: str, summary: dict[str, Any]) -> str:
        text = f"tool {tool_name}: {json.dumps(summary, default=str)[:2000]}"
        return await self._store("tool_summary", text, {"tool_name": tool_name, **summary})

    async def _store(
        self,
        memory_type: str,
        content: str,
        metadata: dict[str, Any],
        *,
        endpoint_pattern: str = "",
        confidence: float = 0.0,
    ) -> str:
        chunk_id = stable_id(self.scan_id, memory_type, content[:512])
        record = {
            "id": chunk_id,
            "timestamp": time.time(),
            "scan_id": self.scan_id,
            "memory_type": memory_type,
            "content": content,
            "metadata": metadata,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
        await memory_store.remember_semantic({**record, "vector": []})
        await db_manager.store_semantic_memory(
            memory_type=memory_type,
            endpoint_pattern=endpoint_pattern,
            content=content,
            metadata=metadata,
            embedding=None,
            confidence=confidence,
        )
        return chunk_id

    def recall_lexical(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        terms = {term.lower() for term in re.findall(r"[A-Za-z0-9_./:-]+", query)}
        scored: list[tuple[int, dict[str, Any]]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except Exception as exc:
                logger.debug(f"[ReconRAG] JSON parse failed: {exc}")
                continue
            haystack = f"{row.get('content', '')} {json.dumps(row.get('metadata', {}), default=str)}".lower()
            score = sum(1 for term in terms if term and term in haystack)
            if score:
                scored.append((score, row))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [{**row, "lexical_score": score} for score, row in scored[:limit]]
