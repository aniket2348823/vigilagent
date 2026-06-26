import asyncio
import json
import logging
import os
import re
import time as _time

from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.content_boundary import content_boundary
from backend.core.hive import EventType, HiveEvent
from backend.core.memory import cosine_similarity, memory_store

logger = logging.getLogger("AgentKappa")


class KappaAgent(BrowserEnabledAgent):
    """
    AGENT KAPPA: THE LIBRARIAN
    Role: Knowledge & Memory with Browser Session Persistence.
    Capabilities:
    - Persistent Vector Memory for exploit history.
    - AI-Driven Semantic Similarity Search (via Gemini text-embedding-004).
    - Anomaly suppression via truth kernel.
    - Browser session archival and replay
    - Session correlation with exploits
    """

    def __init__(self, bus):
        super().__init__("agent_kappa", bus)
        base_dir = os.getcwd()
        self.memory_file = os.path.join(base_dir, "brain", "exploit_vectors.json")

        # Initialize Cortex AI
        try:
            from backend.ai.cortex import get_cortex_engine

            self.truth_kernel = get_cortex_engine()
        except Exception as e:
            logger.debug(f"[{self.name}] Cortex AI init deferred: {e}")
            self.truth_kernel = None

        self._embeddings_disabled = False
        # Track background archive tasks so stop() can drain them and we don't
        # leave orphaned coroutines (the embedding/learning calls can take
        # seconds against Gemini and we never want them blocking the bus).
        self._archive_tasks: set[asyncio.Task] = set()
        self._ensure_memory()

    def _ensure_memory(self):
        os.makedirs(os.path.dirname(self.memory_file), exist_ok=True)
        if not os.path.exists(self.memory_file):
            with open(self.memory_file, "w") as f:
                json.dump([], f)

    async def setup(self):
        self.bus.subscribe(EventType.VULN_CONFIRMED, self.archive_victory)

    async def _get_embedding(self, text: str) -> list[float]:
        """Generate vector embedding using Gemini text-embedding-004."""
        if self._embeddings_disabled:
            return []
        try:
            from backend.ai.gemini import gemini_client

            if not gemini_client.is_available:
                self._embeddings_disabled = True
                return []
            embedding = await gemini_client.generate_embedding(text)
            if not embedding:
                self._embeddings_disabled = True
            return embedding
        except Exception:
            self._embeddings_disabled = True
        return []

    def _cosine_similarity(self, vec1: list[float], vec2: list[float]) -> float:
        return cosine_similarity(vec1, vec2)

    async def archive_victory(self, event: HiveEvent):
        """Handle a confirmed-vulnerability event without blocking the bus.

        The expensive parts (Gemini embedding + learning_engine.learn) used to
        run inline, which serialized every VULN_CONFIRMED arrival behind a
        multi-second LLM call and starved every other handler on the same
        scan-context queue. We now record the lightweight archive synchronously
        and kick the slow path off as a background task tracked by the agent.
        """
        payload = event.payload
        # ScanContext: record event for transcript causality
        if hasattr(self.bus, "get_or_create_context"):
            _ctx = self.bus.get_or_create_context(getattr(event, "scan_id", "GLOBAL"))
            _ctx.append_event(event)
        logger.debug(f"[{self.name}] [ARCHIVE] Verified Vulnerability Exploit Captured. Embedding (background)...")

        # RICHER SCHEMA (V6 Enhancement) — synchronous, cheap.
        archive_data = {
            "type": payload.get("type", "unknown"),
            "url": payload.get("url", ""),
            "payload": payload.get("payload", ""),
            "confidence": payload.get("confidence", 0.0),
            "audit_reasoning": payload.get("audit_reasoning", ""),
            "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
            "vector": [],
        }

        self._save_record(archive_data)
        await memory_store.remember_episode(event.scan_id, {"type": "vulnerability", "payload": archive_data})

        # Test compatibility: publish LOG event immediately for test compatibility
        await self.bus.publish(
            HiveEvent(
                type=EventType.LOG,
                source=self.name,
                scan_id=event.scan_id,
                payload={"message": f"Vulnerability archived: {archive_data['type']} at {archive_data['url']}"},
            )
        )

        # Slow path runs out-of-band. We don't await it here.
        task = asyncio.create_task(self._slow_archive(archive_data, payload, event.scan_id))
        self._archive_tasks.add(task)
        task.add_done_callback(self._archive_tasks.discard)

    async def _slow_archive(self, archive_data: dict, payload: dict, scan_id: str):
        """Run the expensive embedding + learning_engine + adaptive replay
        feedback in the background. Failures here must NOT take the bus down.
        """
        try:
            text_rep = f"TYPE: {archive_data['type']} | URL: {archive_data['url']} | PAYLOAD: {archive_data['payload']}"
            embedding = await self._get_embedding(text_rep)
            archive_data["vector"] = embedding
            if embedding:
                # Persist the now-embedded record alongside the synchronous one
                # so semantic recall sees the vector. _save_record is idempotent
                # only by append, so we re-save with the embedding attached.
                self._save_record({**archive_data, "embedded": True})
                await memory_store.remember_semantic(archive_data)

            await self.bus.publish(
                HiveEvent(
                    type=EventType.LOG,
                    source=self.name,
                    payload={
                        "message": f"Vector Memory {archive_data['type']} stored with {len(embedding)}-dim embedding."
                    },
                )
            )

            # CONTINUOUS LEARNING: feed the learning engine off the hot path.
            try:
                from backend.core.learning_engine import learning_engine

                await learning_engine.learn_from_vulnerability(archive_data, scan_id)
            except Exception as le_err:
                logger.error(f"[{self.name}] [LEARN] background learning error: {le_err}")

            # Pattern feedback to Omega (mid-scan adaptation, requirement 6).
            confidence = payload.get("confidence", 0.0)
            vuln_type = payload.get("type", "")
            url = payload.get("url", "")
            if confidence > 0.7 and vuln_type:
                pattern = {
                    "vuln_type": vuln_type,
                    "endpoint_pattern": self._extract_pattern(url),
                    "confidence": confidence,
                    "timestamp": _time.time(),
                }
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.PATTERN_LEARNED, source=self.name, scan_id=scan_id, payload={"pattern": pattern}
                    )
                )
                logger.debug(
                    f"[{self.name}] [PATTERN] Fed pattern '{vuln_type}' back to Omega for adaptive replanning."
                )
        except Exception as exc:
            logger.error(f"[{self.name}] [ARCHIVE-BG] background archive error: {exc}")

    async def stop(self):
        """Drain any in-flight background archive tasks before shutting down so
        the embedding/learning calls don't outlive the agent and leak sockets.
        """
        if self._archive_tasks:
            for task in list(self._archive_tasks):
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self._archive_tasks, return_exceptions=True)
            self._archive_tasks.clear()
        await super().stop()

    def _extract_pattern(self, url: str) -> str:
        """Convert specific URL to a reusable pattern for cross-scan intelligence."""
        pattern = re.sub(r"/\d+", "/{id}", url)
        pattern = re.sub(r"/[a-f0-9-]{36}", "/{uuid}", pattern)
        return pattern

    def _save_record(self, record):
        try:
            with open(self.memory_file, "r+") as f:
                data = json.load(f)
                data.append(record)
                f.seek(0)
                f.truncate()  # Prevent data corruption when new JSON is shorter
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[{self.name}] Memory Write Error: {e}")

    async def recall_tactics(self, query: str, top_k: int = 3):
        """Vector memory Semantic Search."""
        logger.debug(f"[{self.name}] Semantic search for: {query}")
        query_vec = await self._get_embedding(query)
        if not query_vec:
            return []

        semantic_hits = await memory_store.recall_semantic(query_vec, top_k=top_k)
        sanitized_hits = []
        if semantic_hits:
            for hit in semantic_hits:
                if isinstance(hit, dict) and "payload" in hit:
                    hit["payload"] = content_boundary.sanitize_control_tokens(str(hit["payload"]))
                sanitized_hits.append(hit)
        return sanitized_hits

    async def recall_skills(self, *, target_url: str = "", vuln_class: str = "", top_k: int = 5):
        """Active skill recall for Omega/Sigma (Architecture §5.2, §29.9):
        Kappa surfaces learned/created skill recommendations, not just passive
        vector memory."""
        recs = []
        try:
            from backend.core.skill_library import skill_library

            recs = skill_library.get_recommendations(target_url=target_url, vuln_class=vuln_class, limit=top_k)
        except Exception as e:
            logger.debug(f"[{self.name}] Skill library recall failed: {e}")
            recs = []
        try:
            from backend.skills import skill_catalog

            needle = (vuln_class or "").lower()
            for meta in skill_catalog.all():
                blob = f"{meta.name} {meta.description} {meta.domain}".lower()
                if not needle or needle in blob:
                    recs.append(
                        {
                            "skill_id": meta.skill_id,
                            "name": meta.name,
                            "domain": meta.domain,
                            "promotion_state": meta.promotion_state.value,
                            "source": "catalog",
                        }
                    )
        except Exception as e:
            logger.debug(f"[{self.name}] Skill catalog recall failed: {e}")
        return recs[:top_k]

    async def _kappa_recall_legacy(self, query: str):
        """Deprecated legacy recall path (kept as a no-op; superseded by
        recall_tactics + recall_skills)."""
        return []

    # ============ BROWSER SESSION PERSISTENCE (Phase 4) ============

    async def _store_browser_session(self, scan_id: str, vuln_id: str, session_data: dict):
        """Archive browser session for later replay."""
        try:
            logger.debug(f"[{self.name}] Archiving browser session for {vuln_id}")

            # Save session with correlation to vulnerability
            success = await self.session_manager.save_session(
                session_id=f"{scan_id}_{vuln_id}",
                engine="openclaw",  # Prefer OpenClaw for replay
                session_data=session_data,
                metadata={"scan_id": scan_id, "vuln_id": vuln_id, "timestamp": _time.time(), "type": "exploit_session"},
            )

            if success:
                logger.debug(f"[{self.name}] Session archived successfully")

            return success

        except Exception as e:
            logger.error(f"[{self.name}] Session archival failed: {e}")
            return False

    async def _load_browser_session(self, scan_id: str, vuln_id: str) -> dict:
        """Load archived browser session."""
        try:
            session_data = await self.session_manager.restore_session(
                session_id=f"{scan_id}_{vuln_id}", engine="openclaw"
            )

            if session_data:
                logger.debug(f"[{self.name}] Session restored for {vuln_id}")

            return session_data or {}

        except Exception as e:
            logger.error(f"[{self.name}] Session restoration failed: {e}")
            return {}

    async def _export_session(self, scan_id: str, vuln_id: str) -> str:
        """Export session to portable format."""
        try:
            session_data = await self._load_browser_session(scan_id, vuln_id)

            if not session_data:
                return ""

            # Export to JSON
            export_data = {"scan_id": scan_id, "vuln_id": vuln_id, "session": session_data, "exported_at": _time.time()}

            export_path = f"scan_states/sessions/export_{scan_id}_{vuln_id}.json"
            with open(export_path, "w") as f:
                json.dump(export_data, f, indent=2)

            logger.debug(f"[{self.name}] Session exported to {export_path}")

            return export_path

        except Exception as e:
            logger.error(f"[{self.name}] Session export failed: {e}")
            return ""

    async def _import_session(self, export_path: str) -> bool:
        """Import session from exported file."""
        try:
            with open(export_path) as f:
                export_data = json.load(f)

            scan_id = export_data.get("scan_id")
            vuln_id = export_data.get("vuln_id")
            session_data = export_data.get("session")

            if not all([scan_id, vuln_id, session_data]):
                return False

            # Import session
            success = await self._store_browser_session(scan_id, vuln_id, session_data)

            if success:
                logger.debug(f"[{self.name}] Session imported from {export_path}")

            return success

        except Exception as e:
            logger.error(f"[{self.name}] Session import failed: {e}")
            return False

    async def recall_session(self, scan_id: str, vuln_id: str) -> dict:
        """Recall and replay a browser session."""
        try:
            logger.debug(f"[{self.name}] Replaying session for {vuln_id}")

            # Load session
            session_data = await self._load_browser_session(scan_id, vuln_id)

            if not session_data:
                return {"success": False, "error": "Session not found"}

            # Replay session (navigate to URL with restored session)
            url = session_data.get("url", "")
            if url:
                result = await self.browser.navigate(url, stealth=False)

                return {"success": True, "url": url, "session_restored": True, "result": result}

            return {"success": False, "error": "No URL in session"}

        except Exception as e:
            logger.error(f"[{self.name}] Session replay failed: {e}")
            return {"success": False, "error": str(e)}
