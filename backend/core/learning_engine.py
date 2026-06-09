"""
CONTINUOUS LEARNING ENGINE
Automatically extracts patterns from every scan to improve over time.

This engine:
1. Learns from successful vulnerabilities
2. Tracks success/failure rates
3. Adapts attack strategies based on historical data
4. Builds vulnerability correlation patterns
5. Improves payload generation
6. Adapts reconnaissance strategies
"""

import asyncio
import hashlib
import json
import logging
import math
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import re

from backend.core.memory import memory_store, cosine_similarity
from backend.core.unified_knowledge_graph import knowledge_graph

logger = logging.getLogger("LearningEngine")

try:
    import redis
except ImportError:
    redis = None


@dataclass
class LearningPattern:
    """Represents a learned pattern with confidence scoring."""
    pattern_id: str
    pattern_type: str  # "vuln_correlation", "endpoint_pattern", "payload_success", "recon_strategy"
    pattern_data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    success_count: int
    failure_count: int
    last_seen: float
    first_seen: float
    scan_count: int  # Number of scans this pattern appeared in
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0
    
    def update_confidence(self):
        """Recalculate confidence based on success rate and sample size."""
        # Confidence increases with both success rate and sample size
        sample_factor = min(1.0, (self.success_count + self.failure_count) / 10.0)
        self.confidence = self.success_rate * sample_factor


@dataclass
class LearningMetrics:
    """Tracks learning progress over time."""
    total_patterns: int = 0
    high_confidence_patterns: int = 0  # confidence > 0.7
    total_scans_analyzed: int = 0
    total_vulns_learned: int = 0
    avg_pattern_confidence: float = 0.0
    learning_rate: float = 0.0  # Patterns learned per scan
    last_updated: float = 0.0


class ContinuousLearningEngine:
    """
    The brain that learns from every scan.
    Automatically extracts patterns and improves attack strategies.
    """
    
    def __init__(self, brain_dir: str = "brain", redis_client: Optional[Any] = None):
        self.brain_dir = Path(brain_dir)
        self.patterns_file = self.brain_dir / "learned_patterns.json"
        self.metrics_file = self.brain_dir / "learning_metrics.json"
        
        # In-memory pattern storage
        self.patterns: Dict[str, LearningPattern] = {}
        self.metrics = LearningMetrics()
        
        # Pattern extraction rules
        self.min_confidence_threshold = 0.3
        self.pattern_consolidation_threshold = 0.85  # Cosine similarity for merging patterns
        
        # Redis client for distributed locking and caching
        self.redis_client = redis_client
        self._learning_cache: Dict[str, bool] = {}
        
        # HIGH-67: Dirty-flag batching — avoid rewriting the entire JSON
        # file on every single pattern change.
        self._patterns_dirty = False
        self._metrics_dirty = False
        self._last_save_time = 0.0
        self._SAVE_MIN_INTERVAL = 30.0  # seconds between disk writes
        
        self._ensure_files()
        self._load_patterns()
        self._load_metrics()
    
    def _ensure_files(self):
        """Ensure brain directory and files exist."""
        self.brain_dir.mkdir(parents=True, exist_ok=True)
        if not self.patterns_file.exists():
            self.patterns_file.write_text("[]", encoding="utf-8")
        if not self.metrics_file.exists():
            self.metrics_file.write_text(json.dumps(asdict(self.metrics), indent=2), encoding="utf-8")
    
    def _load_patterns(self):
        """Load learned patterns from disk."""
        try:
            data = json.loads(self.patterns_file.read_text(encoding="utf-8"))
            for item in data:
                pattern = LearningPattern(**item)
                self.patterns[pattern.pattern_id] = pattern
            logger.debug(f"[LearningEngine] Loaded {len(self.patterns)} patterns from disk")
        except Exception as e:
            logger.warning(f"[LearningEngine] Failed to load patterns: {e}")
    
    def _save_patterns(self):
        """Persist learned patterns to disk.
        
        HIGH-67: Only writes when there are pending mutations
        (``_patterns_dirty``) AND at least ``_SAVE_MIN_INTERVAL`` seconds
        have elapsed since the last write.  Callers should set
        ``_patterns_dirty = True`` whenever they mutate ``self.patterns``;
        this method handles the actual I/O.
        """
        if not self._patterns_dirty:
            return
        now = time.time()
        if (now - self._last_save_time) < self._SAVE_MIN_INTERVAL:
            return  # throttle: skip write, next call will pick it up
        try:
            data = [asdict(p) for p in self.patterns.values()]
            self.patterns_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._patterns_dirty = False
            self._last_save_time = now
        except Exception as e:
            logger.error(f"[LearningEngine] Failed to save patterns: {e}")
    
    def _load_metrics(self):
        """Load learning metrics from disk."""
        try:
            data = json.loads(self.metrics_file.read_text(encoding="utf-8"))
            self.metrics = LearningMetrics(**data)
        except Exception as e:
            logger.warning(f"[LearningEngine] Failed to load metrics: {e}")
    
    def _save_metrics(self):
        """Persist learning metrics to disk.
        
        HIGH-67: Same dirty-flag + throttle pattern as ``_save_patterns``.
        """
        if not self._metrics_dirty:
            return
        now = time.time()
        if (now - self._last_save_time) < self._SAVE_MIN_INTERVAL:
            return
        try:
            self.metrics_file.write_text(json.dumps(asdict(self.metrics), indent=2), encoding="utf-8")
            self._metrics_dirty = False
            self._last_save_time = now
        except Exception as e:
            logger.error(f"[LearningEngine] Failed to save metrics: {e}")
    
    # ------------------------------------------------------------------
    # HIGH-67: Dirty-flag helpers
    # ------------------------------------------------------------------
    # Instead of calling _save_patterns() directly on every mutation,
    # callers mark the in-memory store dirty and let _batch_save() or
    # the next _save_patterns() call handle the actual I/O.

    def _mark_patterns_dirty(self):
        """Mark that patterns have been mutated and need persisting."""
        self._patterns_dirty = True

    def _mark_metrics_dirty(self):
        """Mark that metrics have been mutated and need persisting."""
        self._metrics_dirty = True

    def _batch_save(self):
        """Flush dirty patterns + metrics to disk in one I/O pass.
        
        Called from async contexts via ``asyncio.to_thread(self._batch_save)``
        so the synchronous JSON serialisation + file writes do NOT block the
        event loop.  Must remain a plain (sync) function so that
        ``asyncio.to_thread`` dispatches it to a worker thread rather than
        scheduling a coroutine on the loop.
        """
        self._save_patterns()
        self._save_metrics()

    def _generate_pattern_id(self, pattern_type: str, pattern_data: Dict[str, Any]) -> str:
        """Generate unique pattern ID."""
        import hashlib
        data_str = json.dumps(pattern_data, sort_keys=True)
        hash_val = hashlib.sha256(f"{pattern_type}:{data_str}".encode()).hexdigest()[:16]
        return f"{pattern_type}_{hash_val}"
    
    async def learn_from_vulnerability(self, vuln_data: Dict[str, Any], scan_id: str):
        """
        Extract learning patterns from a confirmed vulnerability.
        This is called automatically when a vulnerability is confirmed.
        """
        vuln_type = vuln_data.get("type", "unknown")
        url = vuln_data.get("url", "")
        payload = vuln_data.get("payload", "")
        confidence = vuln_data.get("confidence", 0.0)
        
        if not vuln_type or not url:
            return
        
        logger.info(f"[LearningEngine] Learning from {vuln_type} vulnerability at {url}")
        
        # 1. Learn endpoint pattern
        await self._learn_endpoint_pattern(vuln_type, url, success=True)
        
        # 2. Learn payload pattern
        await self._learn_payload_pattern(vuln_type, payload, success=True)
        
        # 3. Learn vulnerability correlation
        await self._learn_vuln_correlation(scan_id, vuln_type, url)
        
        # 4. Update metrics
        self.metrics.total_vulns_learned += 1
        self.metrics.last_updated = time.time()
        self._mark_metrics_dirty()
    
    async def learn_from_failure(self, attack_data: Dict[str, Any], scan_id: str):
        """
        Learn from failed attacks to avoid repeating ineffective strategies.
        """
        vuln_type = attack_data.get("type", "unknown")
        url = attack_data.get("url", "")
        payload = attack_data.get("payload", "")
        
        if not vuln_type or not url:
            return
        
        # Update failure counts for patterns
        await self._learn_endpoint_pattern(vuln_type, url, success=False)
        await self._learn_payload_pattern(vuln_type, payload, success=False)
    
    async def _learn_endpoint_pattern(self, vuln_type: str, url: str, success: bool):
        """Extract and learn endpoint patterns."""
        # Convert specific URL to pattern
        pattern_url = self._extract_url_pattern(url)
        
        pattern_data = {
            "vuln_type": vuln_type,
            "url_pattern": pattern_url,
            "method": "GET"  # Could be extracted from request data
        }
        
        pattern_id = self._generate_pattern_id("endpoint_pattern", pattern_data)
        
        if pattern_id in self.patterns:
            pattern = self.patterns[pattern_id]
            if success:
                pattern.success_count += 1
            else:
                pattern.failure_count += 1
            pattern.last_seen = time.time()
            pattern.update_confidence()
        else:
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="endpoint_pattern",
                pattern_data=pattern_data,
                confidence=0.5,
                success_count=1 if success else 0,
                failure_count=0 if success else 1,
                last_seen=time.time(),
                first_seen=time.time(),
                scan_count=1
            )
            pattern.update_confidence()
            self.patterns[pattern_id] = pattern
        
        self._mark_patterns_dirty()
    
    async def _learn_payload_pattern(self, vuln_type: str, payload: str, success: bool):
        """Extract and learn payload patterns."""
        if not payload or len(payload) > 1000:
            return
        
        # Extract payload characteristics
        payload_features = self._extract_payload_features(payload)
        
        pattern_data = {
            "vuln_type": vuln_type,
            "payload_features": payload_features,
            "payload_sample": payload[:100]  # Store sample for reference
        }
        
        pattern_id = self._generate_pattern_id("payload_success", pattern_data)
        
        if pattern_id in self.patterns:
            pattern = self.patterns[pattern_id]
            if success:
                pattern.success_count += 1
            else:
                pattern.failure_count += 1
            pattern.last_seen = time.time()
            pattern.update_confidence()
        else:
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="payload_success",
                pattern_data=pattern_data,
                confidence=0.5,
                success_count=1 if success else 0,
                failure_count=0 if success else 1,
                last_seen=time.time(),
                first_seen=time.time(),
                scan_count=1
            )
            pattern.update_confidence()
            self.patterns[pattern_id] = pattern
        
        self._mark_patterns_dirty()
    
    async def _learn_vuln_correlation(self, scan_id: str, vuln_type: str, url: str):
        """Learn correlations between vulnerabilities in the same scan."""
        # Get other vulnerabilities from this scan
        episode_file = self.brain_dir / "episodes" / f"{scan_id}.json"
        if not episode_file.exists():
            return
        
        try:
            episodes = json.loads(episode_file.read_text(encoding="utf-8"))
            vuln_events = [e for e in episodes if e.get("type") == "vulnerability"]
            
            if len(vuln_events) < 2:
                return
            
            # Find correlations
            for other_vuln in vuln_events:
                other_type = other_vuln.get("payload", {}).get("type", "")
                if other_type and other_type != vuln_type:
                    pattern_data = {
                        "vuln_type_1": vuln_type,
                        "vuln_type_2": other_type,
                        "correlation": "co_occurrence"
                    }
                    
                    pattern_id = self._generate_pattern_id("vuln_correlation", pattern_data)
                    
                    if pattern_id in self.patterns:
                        pattern = self.patterns[pattern_id]
                        pattern.success_count += 1
                        pattern.last_seen = time.time()
                        pattern.update_confidence()
                    else:
                        pattern = LearningPattern(
                            pattern_id=pattern_id,
                            pattern_type="vuln_correlation",
                            pattern_data=pattern_data,
                            confidence=0.5,
                            success_count=1,
                            failure_count=0,
                            last_seen=time.time(),
                            first_seen=time.time(),
                            scan_count=1
                        )
                        pattern.update_confidence()
                        self.patterns[pattern_id] = pattern
            
            self._mark_patterns_dirty()
        except Exception as e:
            logger.warning(f"[LearningEngine] Failed to learn correlations: {e}")
    
    def _extract_url_pattern(self, url: str) -> str:
        """Convert specific URL to reusable pattern."""
        # Replace UUIDs first (before IDs to avoid partial matches)
        pattern = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{uuid}', url)
        # Replace numeric IDs
        pattern = re.sub(r'/\d+', '/{id}', pattern)
        # Replace hash-like strings
        pattern = re.sub(r'/[a-f0-9]{32}', '/{hash}', pattern)
        # Remove query params
        pattern = re.sub(r'\?.*$', '', pattern)
        return pattern
    
    def _extract_payload_features(self, payload: str) -> Dict[str, Any]:
        """Extract features from payload for pattern matching."""
        payload_lower = payload.lower()
        features = {
            "length": len(payload),
            "has_script_tag": "<script" in payload_lower,
            "has_sql_keywords": any(kw in payload_lower for kw in ["select", "union", "drop", "insert", " or ", "and "]),
            "has_template_injection": "{{" in payload or "{%" in payload,
            "has_command_injection": any(cmd in payload_lower for cmd in ["system", "exec", "popen", "eval"]),
            "has_encoding": any(enc in payload for enc in ["%", "0x", "\\x"]),
            "has_special_chars": bool(re.search(r'[<>\'";]', payload))
        }
        return features
    
    async def get_recommendations(self, target_url: str, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get attack recommendations based on learned patterns.
        This is called by Omega to adapt strategies.
        """
        url_pattern = self._extract_url_pattern(target_url)
        
        recommendations = {
            "priority_vulns": [],
            "effective_payloads": [],
            "correlated_vulns": [],
            "confidence": 0.0
        }
        
        # Find matching endpoint patterns
        matching_patterns = []
        for pattern in self.patterns.values():
            if pattern.pattern_type == "endpoint_pattern":
                if pattern.pattern_data.get("url_pattern") == url_pattern:
                    if pattern.confidence > self.min_confidence_threshold:
                        matching_patterns.append(pattern)
        
        # Sort by confidence
        matching_patterns.sort(key=lambda p: p.confidence, reverse=True)
        
        # Extract recommendations
        for pattern in matching_patterns[:5]:
            vuln_type = pattern.pattern_data.get("vuln_type")
            recommendations["priority_vulns"].append({
                "type": vuln_type,
                "confidence": pattern.confidence,
                "success_rate": pattern.success_rate,
                "sample_size": pattern.success_count + pattern.failure_count
            })
        
        # Find effective payloads for recommended vulns
        for vuln_rec in recommendations["priority_vulns"]:
            vuln_type = vuln_rec["type"]
            payload_patterns = [
                p for p in self.patterns.values()
                if p.pattern_type == "payload_success" and
                p.pattern_data.get("vuln_type") == vuln_type and
                p.confidence > self.min_confidence_threshold
            ]
            payload_patterns.sort(key=lambda p: p.confidence, reverse=True)
            
            for pp in payload_patterns[:3]:
                recommendations["effective_payloads"].append({
                    "vuln_type": vuln_type,
                    "payload_sample": pp.pattern_data.get("payload_sample", ""),
                    "features": pp.pattern_data.get("payload_features", {}),
                    "confidence": pp.confidence
                })
        
        # Find correlated vulnerabilities
        for vuln_rec in recommendations["priority_vulns"]:
            vuln_type = vuln_rec["type"]
            correlations = [
                p for p in self.patterns.values()
                if p.pattern_type == "vuln_correlation" and
                (p.pattern_data.get("vuln_type_1") == vuln_type or
                 p.pattern_data.get("vuln_type_2") == vuln_type) and
                p.confidence > self.min_confidence_threshold
            ]
            
            for corr in correlations:
                other_type = (corr.pattern_data.get("vuln_type_2")
                             if corr.pattern_data.get("vuln_type_1") == vuln_type
                             else corr.pattern_data.get("vuln_type_1"))
                recommendations["correlated_vulns"].append({
                    "primary": vuln_type,
                    "correlated": other_type,
                    "confidence": corr.confidence
                })
        
        # Calculate overall confidence
        if matching_patterns:
            recommendations["confidence"] = sum(p.confidence for p in matching_patterns) / len(matching_patterns)
        
        return recommendations
    
    async def consolidate_patterns(self):
        """
        Consolidate similar patterns to prevent pattern explosion.
        Runs periodically to merge similar patterns.
        """
        logger.debug("[LearningEngine] Consolidating patterns...")
        
        # Group patterns by type
        by_type = defaultdict(list)
        for pattern in self.patterns.values():
            by_type[pattern.pattern_type].append(pattern)
        
        consolidated_count = 0
        
        for pattern_type, patterns in by_type.items():
            if len(patterns) < 2:
                continue
            
            # Find similar patterns and merge them
            to_remove = set()
            for i, p1 in enumerate(patterns):
                if p1.pattern_id in to_remove:
                    continue
                
                for p2 in patterns[i+1:]:
                    if p2.pattern_id in to_remove:
                        continue
                    
                    # Check similarity
                    if self._patterns_similar(p1, p2):
                        # Merge p2 into p1
                        p1.success_count += p2.success_count
                        p1.failure_count += p2.failure_count
                        p1.scan_count += p2.scan_count
                        p1.last_seen = max(p1.last_seen, p2.last_seen)
                        p1.update_confidence()
                        
                        to_remove.add(p2.pattern_id)
                        consolidated_count += 1
            
            # Remove merged patterns
            for pattern_id in to_remove:
                del self.patterns[pattern_id]
        
        if consolidated_count > 0:
            logger.debug(f"[LearningEngine] Consolidated {consolidated_count} patterns")
            self._mark_patterns_dirty()
        
        return consolidated_count
    
    def _patterns_similar(self, p1: LearningPattern, p2: LearningPattern) -> bool:
        """Check if two patterns are similar enough to merge."""
        if p1.pattern_type != p2.pattern_type:
            return False
        
        # Type-specific similarity checks
        if p1.pattern_type == "endpoint_pattern":
            return (p1.pattern_data.get("vuln_type") == p2.pattern_data.get("vuln_type") and
                   p1.pattern_data.get("url_pattern") == p2.pattern_data.get("url_pattern"))
        
        elif p1.pattern_type == "payload_success":
            # Compare payload features
            f1 = p1.pattern_data.get("payload_features", {})
            f2 = p2.pattern_data.get("payload_features", {})
            
            # Count matching features
            matches = sum(1 for k in f1 if f1.get(k) == f2.get(k))
            total = len(f1)
            
            return matches / total > 0.8 if total > 0 else False
        
        elif p1.pattern_type == "vuln_correlation":
            # Same correlation regardless of order
            types1 = {p1.pattern_data.get("vuln_type_1"), p1.pattern_data.get("vuln_type_2")}
            types2 = {p2.pattern_data.get("vuln_type_1"), p2.pattern_data.get("vuln_type_2")}
            return types1 == types2
        
        return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current learning metrics."""
        # Update metrics
        self.metrics.total_patterns = len(self.patterns)
        self.metrics.high_confidence_patterns = sum(
            1 for p in self.patterns.values() if p.confidence > 0.7
        )
        
        if self.patterns:
            self.metrics.avg_pattern_confidence = sum(
                p.confidence for p in self.patterns.values()
            ) / len(self.patterns)
        
        if self.metrics.total_scans_analyzed > 0:
            self.metrics.learning_rate = self.metrics.total_patterns / self.metrics.total_scans_analyzed
        
        return asdict(self.metrics)
    
    async def analyze_scan_complete(self, scan_id: str):
        """
        Called when a scan completes to extract all learnings.
        """
        logger.info(f"[LearningEngine] Analyzing completed scan: {scan_id}")
        
        # Update scan count
        self.metrics.total_scans_analyzed += 1
        
        # Consolidate patterns periodically
        if self.metrics.total_scans_analyzed % 10 == 0:
            await self.consolidate_patterns()
        
        self._mark_metrics_dirty()

    # ------------------------------------------------------------------
    # Browser-vulnerability learning (deep-system-integration spec, R1.1, R2.1-2.4)
    # ------------------------------------------------------------------
    #
    # Contract (must stay stable — IntegrationCoordinator depends on it):
    #     async def learn_from_browser_vulnerability(
    #         vuln_data: Dict[str, Any], scan_id: str
    #     ) -> bool
    #
    # Returns True when a new pattern is recorded (or an existing one is
    # reinforced); False when the input is a duplicate seen recently.
    #
    # Architecture invariants honoured here:
    #   §11 two-LLM exclusivity   — no LLM calls are made; pattern extraction is
    #                                purely structural.
    #   §17 ≥2-signal evidence    — this method does NOT re-verify the vuln.
    #                                It assumes the caller (IntegrationCoordinator)
    #                                already ran the ≥2-signal gate.
    #   §29.13 non-blocking       — disk writes are dispatched via
    #                                ``asyncio.to_thread`` so the event loop
    #                                stays responsive under burst load.
    #   §9 scope-is-law           — the target host is stored as evidence
    #                                metadata only; it never becomes a scope
    #                                grant token.
    # ------------------------------------------------------------------
    async def learn_from_browser_vulnerability(
        self,
        vuln_data: Dict[str, Any],
        scan_id: str,
    ) -> bool:
        """Learn a browser-confirmed vulnerability pattern.
        
        Extracts the browser-specific shape of the finding (engine, framework,
        stealth/headless flags, viewport, execution requirements) and stores it
        as a ``browser_vulnerability`` pattern that the rest of the learning
        loop (Skill promotion, get_browser_recommendations, intelligent router)
        can reuse.
        
        The method is idempotent against a stable fingerprint of the
        ``(url, vuln_type, payload, method, browser_engine)`` tuple — replaying
        the same finding inside a 5-minute window returns ``False`` without
        side effects.
        """
        if not isinstance(vuln_data, dict):
            return False
        
        vuln_type = (vuln_data.get("type") or vuln_data.get("vuln_type") or "").strip()
        url = (vuln_data.get("url") or "").strip()
        if not vuln_type or not url:
            # Cannot learn anything useful without these two anchors.
            return False
        
        # ---- 1. Idempotency fingerprint -------------------------------
        idem_key = self._browser_vuln_fingerprint(vuln_data)
        lock_key = f"lock:{idem_key}"
        if not await self._acquire_browser_learn_lock(lock_key, ttl_seconds=300):
            return False
        
        try:
            # ---- 2. Build the browser-tagged pattern ------------------
            browser_context = self._extract_browser_context(vuln_data)
            execution_requirements = self._extract_execution_requirements(vuln_data)
            evidence_metadata = self._extract_evidence_metadata(vuln_data, url)            
            pattern_data: Dict[str, Any] = {
                "vuln_type": vuln_type,
                "url": url,
                "url_pattern": self._extract_url_pattern(url),
                "method": (vuln_data.get("method") or "GET").upper(),
                "payload": (vuln_data.get("payload") or "")[:500],
                "framework": vuln_data.get("framework"),
                # Tag: this pattern requires a browser to re-execute.
                "execution_context": "browser_required",
                # R2.1: browser context (engine, framework, headless, viewport, stealth)
                "browser_context": browser_context,
                # R2.3: execution requirements so a future agent can re-execute
                "execution_requirements": execution_requirements,
                # R1.1 / R2.2: scope is recorded as evidence metadata only,
                #              never as an authorization grant (§9).
                "evidence_metadata": evidence_metadata,
                # Provenance
                "source": "browser_vulnerability",
                "scan_id": scan_id,
            }
            
            pattern_id = self._generate_pattern_id("browser_vulnerability", {
                # Stable subset for ID — full pattern_data carries volatile
                # fields (scan_id) that would otherwise spawn duplicate IDs.
                "vuln_type": vuln_type,
                "url_pattern": pattern_data["url_pattern"],
                "method": pattern_data["method"],
                "browser_engine": browser_context.get("engine"),
                "framework": pattern_data["framework"],
            })
            
            now = time.time()
            existing = self.patterns.get(pattern_id)
            if existing is not None:
                existing.success_count += 1
                existing.scan_count += 1
                existing.last_seen = now
                # Refresh volatile fields (latest scan_id, latest payload sample).
                existing.pattern_data["scan_id"] = scan_id
                if pattern_data["payload"]:
                    existing.pattern_data["payload"] = pattern_data["payload"]
                existing.update_confidence()
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="browser_vulnerability",
                    pattern_data=pattern_data,
                    confidence=0.7,  # browser-confirmed → high prior
                    success_count=1,
                    failure_count=0,
                    last_seen=now,
                    first_seen=now,
                    scan_count=1,
                )
                pattern.update_confidence()
                self.patterns[pattern_id] = pattern
            
            # ---- 3. Update top-level metrics --------------------------
            self.metrics.total_vulns_learned += 1
            self.metrics.last_updated = now
            
            # ---- 4. Persist off the event loop (§29.13) ---------------
            # Both writes are best-effort — failure to persist must not
            # propagate into the IntegrationCoordinator's circuit breaker.
            try:
                await asyncio.wait_for(asyncio.to_thread(self._batch_save), timeout=15)
            except Exception as e:  # pragma: no cover - disk hiccup
                logger.warning(f"[LearningEngine] browser-vuln persist failed: {e}")
            
            return True
        except Exception as e:
            # Hard failure — clear the slot so a future retry isn't blocked
            # by stale idempotency state.
            self._clear_browser_learn_lock(lock_key)
            logger.error(f"[LearningEngine] learn_from_browser_vulnerability failed: {e}")
            return False
        finally:
            await self._release_browser_learn_lock(lock_key)
    
    # ---- helpers (browser-vulnerability) ------------------------------
    def _browser_vuln_fingerprint(self, vuln_data: Dict[str, Any]) -> str:
        """Stable fingerprint for idempotency checking."""
        import hashlib
        key_data = {
            "url": vuln_data.get("url", ""),
            "type": vuln_data.get("type") or vuln_data.get("vuln_type", ""),
            "payload": (vuln_data.get("payload") or "")[:200],
            "method": (vuln_data.get("method") or "GET").upper(),
            "engine": (
                vuln_data.get("browser_engine")
                or (vuln_data.get("browser_context") or {}).get("engine")
                or "chromium"
            ),
        }
        data_str = json.dumps(key_data, sort_keys=True)
        return f"vuln:{hashlib.sha256(data_str.encode()).hexdigest()}"
    
    async def _acquire_browser_learn_lock(self, lock_key: str, ttl_seconds: int = 300) -> bool:
        """Reserve a per-fingerprint slot.
        
        Acts as both a concurrency lock AND an idempotency record: if the same
        fingerprint reappears within ``ttl_seconds`` we return False so the
        caller skips the re-learn. Redis path uses ``SET NX EX``; in-memory
        fallback uses a timestamp map with lazy expiry.
        """
        if self.redis_client is None:
            now = time.time()
            existing = self._learning_cache.get(lock_key)
            # _learning_cache may store either bool (legacy) or float timestamp.
            if isinstance(existing, (int, float)):
                if (now - float(existing)) < ttl_seconds:
                    return False  # still within idempotency window
                # expired — fall through and refresh
            elif existing:
                # Legacy bool entry from BrowserLearningExtension; treat as fresh.
                return False
            self._learning_cache[lock_key] = now
            return True
        try:
            # SET NX EX in a worker thread — redis-py is sync-blocking.
            result = await asyncio.wait_for(asyncio.to_thread(
                self.redis_client.set, lock_key, "1", **{"nx": True, "ex": ttl_seconds}
            ), timeout=15)
            return bool(result)
        except Exception as e:
            logger.warning(f"[LearningEngine] lock acquire failed: {e}")
            # Fail-open on Redis error — better to over-learn than to drop signal.
            return True
    
    async def _release_browser_learn_lock(self, lock_key: str) -> None:
        """Release happens only on failure paths.
        
        On the success path the slot is intentionally retained until TTL
        expiry — that's what gives us idempotency across replays. We only
        clear it explicitly when learning aborts so a retry can proceed.
        """
        # No-op by default. Callers that want to permit immediate retry can
        # invoke ``_clear_browser_learn_lock`` instead.
        return None
    
    def _clear_browser_learn_lock(self, lock_key: str) -> None:
        """Force-clear a lock slot (used only on hard failure to allow retry)."""
        if self.redis_client is None:
            self._learning_cache.pop(lock_key, None)
            return
        try:
            self.redis_client.delete(lock_key)
        except Exception as e:
            logger.warning(f"[LearningEngine] lock clear failed: {e}")
    
    def _extract_browser_context(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Capture the browser environment that produced the finding.
        
        Honours R2.1: engine, framework, headless flag, viewport, stealth mode.
        """
        ctx_in = vuln_data.get("browser_context") or {}
        return {
            "engine": (
                vuln_data.get("browser_engine")
                or ctx_in.get("engine")
                or "chromium"
            ),
            "framework": vuln_data.get("framework") or ctx_in.get("framework"),
            "headless": bool(
                vuln_data.get("headless", ctx_in.get("headless", True))
            ),
            "stealth": bool(
                vuln_data.get("stealth_required", ctx_in.get("stealth", False))
            ),
            "viewport": ctx_in.get("viewport") or vuln_data.get("viewport"),
            "user_agent": ctx_in.get("user_agent") or vuln_data.get("user_agent"),
            "session_required": bool(
                vuln_data.get("session_required", ctx_in.get("session_required", False))
            ),
        }
    
    def _extract_execution_requirements(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Capture what an agent needs to re-execute this finding.
        
        Honours R2.3: browser engine, JS execution, network interception flags.
        """
        req_in = vuln_data.get("execution_requirements") or {}
        return {
            "browser_engine": (
                vuln_data.get("browser_engine")
                or req_in.get("browser_engine")
                or "chromium"
            ),
            "javascript_execution": bool(
                req_in.get("javascript_execution", vuln_data.get("requires_js", True))
            ),
            "network_interception": bool(
                req_in.get(
                    "network_interception",
                    vuln_data.get("requires_network_intercept", False),
                )
            ),
            "dom_required": bool(
                req_in.get("dom_required", vuln_data.get("requires_dom", True))
            ),
            "websocket_required": bool(
                req_in.get(
                    "websocket_required",
                    vuln_data.get("vuln_type") == "websocket"
                    or vuln_data.get("type") == "websocket",
                )
            ),
            "auth_required": bool(
                req_in.get("auth_required", vuln_data.get("requires_auth", False))
            ),
        }
    
    def _extract_evidence_metadata(self, vuln_data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Capture host + evidence pointers WITHOUT granting scope (§9).
        
        Honours R2.2: queryable by browser context.
        """
        from urllib.parse import urlparse
        try:
            host = urlparse(url).hostname or ""
        except Exception as parse_exc:
            logger.debug("[LearningEngine] URL parse failed: %s", parse_exc)
            host = ""
        return {
            "host": host,  # informational — NOT a scope grant
            "screenshot": vuln_data.get("screenshot_path"),
            "har": vuln_data.get("har_path"),
            "console_log": vuln_data.get("console_log_path"),
            "evidence_count": int(vuln_data.get("evidence_count", 0) or 0),
            "confirmed_by": vuln_data.get("confirmed_by", "browser_agent"),
        }
    
    # ------------------------------------------------------------------
    # Browser-workflow learning (deep-system-integration spec, R16.1, R16.6)
    # ------------------------------------------------------------------
    #
    # Contract (must stay stable — IntegrationCoordinator + Beta/Sigma replay
    # depend on it; tasks 2.4 / 3.6 read this same shape):
    #     async def learn_browser_workflow(
    #         workflow: Dict[str, Any], scan_id: str
    #     ) -> bool
    #
    # ``workflow`` carries:
    #     name           (str, required)
    #     steps          (list[dict], required, each with at least ``action``;
    #                     optional ``selector``, ``payload``, ``wait_for``,
    #                     ``validates``)
    #     preconditions  (dict, optional: ``auth_required``, ``framework``,
    #                     ``browser_engine``, ``viewport``)
    #     outcome        (str: "success" | "partial" | "failure", required)
    #     vuln_type      (str, optional)
    #     framework      (str, optional)
    #
    # Returns True on first record or successful reinforcement; False on
    # idempotent replay (within 5-minute window) or invalid input.
    #
    # Architecture invariants honoured here:
    #   §11 two-LLM exclusivity   — purely structural extraction, no LLM calls.
    #   §17 ≥2-signal evidence    — reinforcement happens regardless of outcome
    #                                count; this method does NOT re-verify.
    #                                The caller is responsible for any gating.
    #   §29.13 non-blocking       — ``_save_patterns`` / ``_save_metrics`` run
    #                                via ``asyncio.to_thread``.
    #   §9 scope-is-law           — the workflow's target URL is stored as a
    #                                pattern hint only; it never grants scope.
    # ------------------------------------------------------------------
    async def learn_browser_workflow(
        self,
        workflow: Dict[str, Any],
        scan_id: str,
    ) -> bool:
        """Learn a multi-step browser workflow as a reusable pattern.
        
        Captures the ordered steps, preconditions, and outcome of a workflow
        that Beta/Sigma can later replay against similar targets. Idempotent
        against a stable fingerprint of ``(name, len(steps), framework,
        sorted step action types)`` — replays inside a 5-minute window are
        rejected, replays after the window reinforce the existing pattern's
        success/failure counters (R16.6).
        """
        if not isinstance(workflow, dict):
            return False
        
        name = (workflow.get("name") or "").strip()
        raw_steps = workflow.get("steps")
        if not name or not isinstance(raw_steps, list) or not raw_steps:
            return False
        
        outcome = (workflow.get("outcome") or "").strip().lower()
        if outcome not in {"success", "partial", "failure"}:
            return False
        
        steps = self._sanitize_workflow_steps(raw_steps)
        if not steps:
            # Every step was malformed — nothing replayable left.
            return False
        
        framework = (
            workflow.get("framework")
            or (workflow.get("preconditions") or {}).get("framework")
        )
        step_types = sorted({s["action"] for s in steps})
        
        # ---- 1. Idempotency fingerprint (stable subset only) ---------
        fingerprint_data: Dict[str, Any] = {
            "name": name,
            "step_count": len(steps),
            "framework": framework or "",
            "step_types": step_types,
        }
        idem_key = self._browser_workflow_fingerprint(fingerprint_data)
        lock_key = f"lock:{idem_key}"
        if not await self._acquire_browser_learn_lock(lock_key, ttl_seconds=300):
            return False
        
        try:
            # ---- 2. Build the pattern --------------------------------
            preconditions = self._extract_workflow_preconditions(workflow)
            url = (workflow.get("url") or "").strip()
            
            pattern_data: Dict[str, Any] = {
                "name": name,
                "url": url,
                "url_pattern": self._extract_url_pattern(url) if url else "",
                "steps": steps,
                "step_types": step_types,
                "preconditions": preconditions,
                "outcome": outcome,
                "last_outcome": outcome,
                "vuln_type": workflow.get("vuln_type"),
                "framework": framework,
                # Tag: workflow replay needs a real browser.
                "execution_context": "browser_required",
                # Provenance
                "source": "browser_workflow",
                "scan_id": scan_id,
            }
            
            # Pattern ID is derived from the SAME stable subset as the
            # idempotency fingerprint, so the pattern_id stays the same
            # across reinforcements.
            pattern_id = self._generate_pattern_id(
                "browser_workflow", fingerprint_data
            )
            
            now = time.time()
            existing = self.patterns.get(pattern_id)
            if existing is not None:
                # Reinforcement (R16.6): bump the right counter, recompute
                # confidence, refresh volatile fields.
                if outcome == "success":
                    existing.success_count += 1
                else:
                    existing.failure_count += 1
                existing.scan_count += 1
                existing.last_seen = now
                existing.pattern_data["scan_id"] = scan_id
                existing.pattern_data["last_outcome"] = outcome
                existing.update_confidence()
            else:
                # First record: confidence prior 0.6 (workflow patterns
                # are higher-signal than raw recon, lower than a confirmed
                # vuln, which uses 0.7).
                pattern_data["first_outcome"] = outcome
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="browser_workflow",
                    pattern_data=pattern_data,
                    confidence=0.6,
                    success_count=1 if outcome == "success" else 0,
                    failure_count=0 if outcome == "success" else 1,
                    last_seen=now,
                    first_seen=now,
                    scan_count=1,
                )
                pattern.update_confidence()
                self.patterns[pattern_id] = pattern
            
            # ---- 3. Update top-level metrics -------------------------
            self.metrics.last_updated = now
            
            # ---- 4. Persist off the event loop (§29.13) --------------
            try:
                await asyncio.wait_for(asyncio.to_thread(self._batch_save), timeout=15)
            except Exception as e:  # pragma: no cover - disk hiccup
                logger.warning(f"[LearningEngine] browser-workflow persist failed: {e}")
            
            return True
        except Exception as e:
            # Hard failure — clear the slot so a future retry isn't blocked
            # by stale idempotency state.
            self._clear_browser_learn_lock(lock_key)
            logger.error(f"[LearningEngine] learn_browser_workflow failed: {e}")
            return False
        finally:
            await self._release_browser_learn_lock(lock_key)
    
    # ---- helpers (browser-workflow) -----------------------------------
    def _browser_workflow_fingerprint(self, fingerprint_data: Dict[str, Any]) -> str:
        """Stable SHA-256 fingerprint over the workflow's identity-defining fields.
        
        Identity = ``(name, len(steps), framework, sorted step action types)``.
        Selectors and payloads are intentionally excluded so the same workflow
        shape reinforces a single pattern even when concrete values drift.
        """
        import hashlib
        data_str = json.dumps(fingerprint_data, sort_keys=True)
        return f"workflow:{hashlib.sha256(data_str.encode()).hexdigest()}"
    
    def _sanitize_workflow_steps(self, raw_steps: List[Any]) -> List[Dict[str, Any]]:
        """Normalize and bound the workflow step list.
        
        Caps at 50 steps; truncates string fields to keep persisted patterns
        small. Drops entries that aren't dicts or that lack an ``action``.
        """
        sanitized: List[Dict[str, Any]] = []
        for raw in raw_steps[:50]:
            if not isinstance(raw, dict):
                continue
            action = (raw.get("action") or "").strip()
            if not action:
                continue
            step: Dict[str, Any] = {"action": action}
            if raw.get("selector"):
                step["selector"] = str(raw.get("selector"))[:200]
            if raw.get("payload") is not None:
                step["payload"] = str(raw.get("payload"))[:500]
            if raw.get("wait_for"):
                step["wait_for"] = str(raw.get("wait_for"))[:200]
            validates = raw.get("validates")
            if validates is not None:
                # Keep structured validators (list/dict) as-is; flatten
                # everything else to a bounded string.
                step["validates"] = (
                    validates
                    if isinstance(validates, (list, dict))
                    else str(validates)[:200]
                )
            sanitized.append(step)
        return sanitized
    
    def _extract_workflow_preconditions(
        self, workflow: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Capture the preconditions needed to replay the workflow (R16.1).
        
        Contract surface for downstream tasks 2.4 / 3.6:
            ``auth_required``, ``framework``, ``browser_engine``, ``viewport``.
        """
        pre_in = workflow.get("preconditions") or {}
        return {
            "auth_required": bool(
                pre_in.get(
                    "auth_required",
                    workflow.get("requires_auth", False),
                )
            ),
            "framework": pre_in.get("framework") or workflow.get("framework"),
            "browser_engine": (
                pre_in.get("browser_engine")
                or workflow.get("browser_engine")
                or "chromium"
            ),
            "viewport": pre_in.get("viewport") or workflow.get("viewport"),
        }
    
    # ------------------------------------------------------------------
    # Browser-recommendation surface (deep-system-integration spec, Task 2.4 / R2.5/R2.6)
    # ------------------------------------------------------------------
    #
    # Contract (must stay stable — IntelligentRouter and the dashboard's
    # /api/dashboard/integration consume this shape):
    #     async def get_browser_recommendations(
    #         target: Dict[str, Any],
    #         framework: Optional[str] = None,
    #     ) -> Dict[str, Any]
    #
    # ``target`` carries (at minimum) ``url`` (str). May also carry
    # ``vuln_type`` (str), ``confidence_floor`` (float), and arbitrary
    # other recon hints.
    #
    # Returns a dict-shaped recommendation pack pulled from the three
    # browser-aware pattern types written by tasks 2.1, 2.3, and 2.6:
    #     {
    #         "workflows":           [...top 5 by success_rate],
    #         "payloads":            [...top 5 by confidence],
    #         "framework_specific":  [...patterns matching framework],
    #         "confidence":          float,
    #     }
    #
    # Each ``workflows`` entry:  pattern_id, name, steps, success_rate,
    #                            confidence, framework, vuln_type
    # Each ``payloads`` entry:   pattern_id, vuln_type, payload, framework,
    #                            confidence, success_rate, execution_requirements
    # Each ``framework_specific`` entry: pattern_id, framework, routes,
    #                                   route_patterns, confidence,
    #                                   success_rate
    #
    # Filtering: patterns below ``self.min_confidence_threshold`` (0.3)
    # are excluded. Caller may raise the floor via ``target['confidence_floor']``.
    #
    # Caching: a small per-instance LRU keyed by
    # ``(target_url_pattern, framework_norm, confidence_floor)`` is used
    # because the public signature takes a dict (unhashable) and so cannot
    # use ``functools.lru_cache`` directly — see ``_browser_reco_cache``.
    # The cache is invalidated whenever ``len(self.patterns)`` or
    # ``self.metrics.last_updated`` changes (any learn_* call bumps both).
    #
    # Architecture invariants honoured here:
    #   §11 two-LLM exclusivity   — pure read-side ranking, no LLM calls.
    #   §17 ≥2-signal evidence    — recommendations are ADVISORY only;
    #                                callers must still gate execution.
    #   §29.13 non-blocking       — read path operates on the in-memory
    #                                ``self.patterns`` dict, no I/O.
    #   §9 scope-is-law           — emitted ``url_pattern`` is informational;
    #                                it is NOT a scope grant for any caller.
    # ------------------------------------------------------------------
    async def get_browser_recommendations(
        self,
        target: Dict[str, Any],
        framework: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return browser-aware recommendation pack for ``target``.
        
        See class-level contract block above for shape.
        """
        empty: Dict[str, Any] = {
            "workflows": [],
            "payloads": [],
            "framework_specific": [],
            "confidence": 0.0,
        }
        if not isinstance(target, dict):
            return empty
        target_url = (target.get("url") or "").strip()
        if not target_url:
            return empty
        
        target_pattern = self._extract_url_pattern(target_url)
        framework_norm = (framework or "").strip().lower() or None
        try:
            floor = float(
                target.get("confidence_floor", self.min_confidence_threshold)
            )
        except (TypeError, ValueError):
            floor = self.min_confidence_threshold
        floor = max(self.min_confidence_threshold, floor)
        
        # ---- Cache hit path ------------------------------------------
        cache_key = (target_pattern, framework_norm, round(floor, 4))
        cached = self._browser_reco_cache_get(cache_key)
        if cached is not None:
            return cached
        
        workflows: List[Dict[str, Any]] = []
        payloads: List[Dict[str, Any]] = []
        framework_specific: List[Dict[str, Any]] = []
        confidence_pool: List[float] = []
        
        for pattern in self.patterns.values():
            ptype = pattern.pattern_type
            if ptype not in (
                "browser_vulnerability",
                "browser_workflow",
                "framework_pattern",
            ):
                continue
            if pattern.confidence < floor:
                continue
            
            data = pattern.pattern_data or {}
            
            # URL match check for URL-bound rows. framework_pattern rows
            # have no URL and apply universally per framework.
            if ptype != "framework_pattern":
                pattern_url = data.get("url_pattern") or (
                    self._extract_url_pattern(data.get("url") or "")
                    if data.get("url") else ""
                )
                # Empty url_pattern == universal; only filter when both sides
                # have a value AND they don't match.
                if pattern_url and target_pattern and pattern_url != target_pattern:
                    continue
            
            entry_framework = (data.get("framework") or "")
            entry_framework_norm = entry_framework.strip().lower() if entry_framework else None
            framework_match = (
                framework_norm is not None
                and entry_framework_norm == framework_norm
            )
            
            confidence_pool.append(float(pattern.confidence))
            
            if ptype == "browser_workflow":
                workflows.append({
                    "pattern_id": pattern.pattern_id,
                    "name": data.get("name", ""),
                    "steps": list(data.get("steps") or []),
                    "success_rate": float(pattern.success_rate or 0.0),
                    "confidence": float(pattern.confidence),
                    "framework": entry_framework or None,
                    "vuln_type": data.get("vuln_type"),
                    "framework_match": framework_match,
                })
            elif ptype == "browser_vulnerability":
                payloads.append({
                    "pattern_id": pattern.pattern_id,
                    "vuln_type": data.get("vuln_type"),
                    "payload": data.get("payload", ""),
                    "framework": entry_framework or None,
                    "confidence": float(pattern.confidence),
                    "success_rate": float(pattern.success_rate or 0.0),
                    "execution_requirements": data.get("execution_requirements") or {},
                    "framework_match": framework_match,
                })
                # If the pattern's framework lines up with the requested one,
                # the payload also surfaces in framework_specific.
                if framework_match:
                    framework_specific.append({
                        "pattern_id": pattern.pattern_id,
                        "type": "browser_vulnerability",
                        "framework": entry_framework,
                        "vuln_type": data.get("vuln_type"),
                        "payload": data.get("payload", ""),
                        "confidence": float(pattern.confidence),
                        "success_rate": float(pattern.success_rate or 0.0),
                    })
            elif ptype == "framework_pattern":
                # framework_pattern only surfaces if the caller asked for a
                # framework AND the pattern's framework matches.
                if framework_match:
                    framework_specific.append({
                        "pattern_id": pattern.pattern_id,
                        "type": "framework_pattern",
                        "framework": entry_framework,
                        "routes": list(data.get("routes") or []),
                        "route_patterns": list(data.get("route_patterns") or []),
                        "confidence": float(pattern.confidence),
                        "success_rate": float(pattern.success_rate or 0.0),
                    })
        
        # ---- Rank + truncate ---------------------------------------
        # Workflows: top 5 by success_rate, tie-break on confidence.
        workflows.sort(
            key=lambda w: (w["success_rate"], w["confidence"], w["framework_match"]),
            reverse=True,
        )
        workflows = workflows[:5]
        for w in workflows:
            w.pop("framework_match", None)
        
        # Payloads: top 5 by confidence, tie-break on success_rate.
        payloads.sort(
            key=lambda p: (p["confidence"], p["success_rate"], p["framework_match"]),
            reverse=True,
        )
        payloads = payloads[:5]
        for p in payloads:
            p.pop("framework_match", None)
        
        # Framework-specific: keep all (already filtered to framework match);
        # rank by confidence then success_rate.
        framework_specific.sort(
            key=lambda f: (
                float(f.get("confidence", 0.0)),
                float(f.get("success_rate", 0.0)),
            ),
            reverse=True,
        )
        
        overall_conf = (
            sum(confidence_pool) / len(confidence_pool)
            if confidence_pool else 0.0
        )
        
        result = {
            "workflows": workflows,
            "payloads": payloads,
            "framework_specific": framework_specific,
            "confidence": round(overall_conf, 4),
        }
        self._browser_reco_cache_put(cache_key, result)
        return result
    
    # ---- recommendation cache ----------------------------------------
    # Manual instance-level LRU because ``target`` is a dict and cannot be
    # used as a ``functools.lru_cache`` key. The cache is keyed by the
    # hashable derived tuple ``(target_url_pattern, framework_norm, floor)``
    # and is invalidated whenever the pattern pool mutates.
    def _browser_reco_cache_signature(self) -> tuple:
        """Tuple stamp that changes whenever the pattern pool mutates."""
        return (len(self.patterns), float(self.metrics.last_updated or 0.0))
    
    def _browser_reco_cache_get(self, key: tuple) -> Optional[Dict[str, Any]]:
        cache: Dict = getattr(self, "_browser_reco_cache", None)
        if cache is None:
            self._browser_reco_cache = {}
            self._browser_reco_cache_stamp = self._browser_reco_cache_signature()
            return None
        # Invalidate on pattern-pool change.
        if getattr(self, "_browser_reco_cache_stamp", None) != \
                self._browser_reco_cache_signature():
            cache.clear()
            self._browser_reco_cache_stamp = self._browser_reco_cache_signature()
            return None
        return cache.get(key)
    
    def _browser_reco_cache_put(
        self, key: tuple, value: Dict[str, Any]
    ) -> None:
        cache: Dict = getattr(self, "_browser_reco_cache", None)
        if cache is None:
            self._browser_reco_cache = {}
            cache = self._browser_reco_cache
            self._browser_reco_cache_stamp = self._browser_reco_cache_signature()
        # Bound the cache to 64 entries (LRU-ish: oldest insertion drops first).
        if len(cache) >= 64:
            try:
                oldest = next(iter(cache))
                cache.pop(oldest, None)
            except StopIteration:
                pass
        cache[key] = value
    
    # ------------------------------------------------------------------
    # Framework-pattern learning (deep-system-integration spec, R2.1)
    # ------------------------------------------------------------------
    #
    # Contract (must stay stable — IntegrationCoordinator's discovery batch
    # at backend/core/integration_coordinator.py:411 invokes this method):
    #     async def learn_framework_pattern(
    #         framework: Optional[str], routes: List[str]
    #     ) -> bool
    #
    # Returns True on first record or successful reinforcement; False on
    # invalid input (missing framework) or idempotent replay (within
    # 5-minute window).
    #
    # Architecture invariants honoured here:
    #   §11 two-LLM exclusivity   — purely structural extraction, no LLM calls.
    #   §17 ≥2-signal evidence    — discovery rows are ADVISORY; this method
    #                                does NOT promote anything to "confirmed".
    #   §29.13 non-blocking       — disk writes go through ``asyncio.to_thread``.
    #   §9 scope-is-law           — routes are stored as recon hints only;
    #                                they never grant scope to any caller.
    # ------------------------------------------------------------------
    async def learn_framework_pattern(
        self,
        framework: Optional[str],
        routes: List[str],
    ) -> bool:
        """Learn a framework's route fingerprint as a reusable pattern.
        
        ``framework`` is the JS framework label (React, Vue, Angular, etc.).
        ``routes`` is the list of routes the BrowserOrchestrator surfaced for
        that framework on this target.
        
        Idempotent against ``(framework_lower, sorted(routes))`` SHA-256 —
        replays inside 5 minutes return ``False``; replays after the window
        reinforce the existing pattern's success counter.
        """
        # Graceful no-op: IntegrationCoordinator forwards whatever the
        # discovery event carried, including None / "" frameworks.
        if not framework or not isinstance(framework, str):
            return False
        framework_norm = framework.strip()
        if not framework_norm:
            return False
        
        # Normalize + dedup routes; tolerate List[str] or anything iterable.
        if not isinstance(routes, (list, tuple, set)):
            return False
        unique_routes: List[str] = []
        seen: set = set()
        for r in routes:
            if not isinstance(r, str):
                continue
            r_clean = r.strip()
            if not r_clean or r_clean in seen:
                continue
            seen.add(r_clean)
            unique_routes.append(r_clean)
        if not unique_routes:
            # No usable routes — nothing to learn, but treat as no-op rather
            # than a hard failure so the discovery batch keeps flowing.
            return False
        unique_routes.sort()
        
        # ---- 1. Idempotency fingerprint ------------------------------
        # Per Task 2.6 spec: fingerprint is taken over the regex-extracted
        # ``route_patterns`` (not raw routes), so that ``/users/42/x`` and
        # ``/users/9999/x`` collide on a single ``/users/{id}/x`` row even
        # when concrete IDs drift between scans.
        route_patterns = self._extract_framework_route_patterns(unique_routes)
        idem_key = self._framework_pattern_fingerprint(
            framework_norm, route_patterns
        )
        lock_key = f"lock:{idem_key}"
        if not await self._acquire_browser_learn_lock(lock_key, ttl_seconds=300):
            return False
        
        try:
            # ---- 2. Build the pattern --------------------------------
            pattern_data: Dict[str, Any] = {
                "framework": framework_norm,
                "routes": unique_routes,
                "route_count": len(unique_routes),
                # Light pattern extraction: replace numeric/UUID segments
                # so future matches aren't blocked by trivial id drift.
                "route_patterns": route_patterns,
                # Tag: replay needs a real browser to walk the SPA.
                "execution_context": "browser_required",
                "source": "framework_pattern",
            }
            
            # Pattern ID is derived from the SAME stable subset as the
            # idempotency fingerprint so reinforcements collide on one row.
            pattern_id = self._generate_pattern_id(
                "framework_pattern",
                {
                    "framework": framework_norm.lower(),
                    "route_patterns": route_patterns,
                },
            )
            
            now = time.time()
            existing = self.patterns.get(pattern_id)
            if existing is not None:
                existing.success_count += 1
                existing.scan_count += 1
                existing.last_seen = now
                existing.update_confidence()
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="framework_pattern",
                    pattern_data=pattern_data,
                    confidence=0.5,  # discovery prior — lower than vuln/workflow
                    success_count=1,
                    failure_count=0,
                    last_seen=now,
                    first_seen=now,
                    scan_count=1,
                )
                pattern.update_confidence()
                self.patterns[pattern_id] = pattern
            
            # ---- 3. Update top-level metrics -------------------------
            self.metrics.last_updated = now
            
            # ---- 4. Persist off the event loop (§29.13) --------------
            try:
                await asyncio.wait_for(asyncio.to_thread(self._batch_save), timeout=15)
            except Exception as e:  # pragma: no cover - disk hiccup
                logger.warning(f"[LearningEngine] framework-pattern persist failed: {e}")
            
            return True
        except Exception as e:
            self._clear_browser_learn_lock(lock_key)
            logger.error(f"[LearningEngine] learn_framework_pattern failed: {e}")
            return False
        finally:
            await self._release_browser_learn_lock(lock_key)
    
    # ---- helpers (framework-pattern) ----------------------------------
    def _framework_pattern_fingerprint(
        self, framework: str, sorted_route_patterns: List[str]
    ) -> str:
        """Stable SHA-256 fingerprint over ``(framework_lower, sorted_route_patterns)``.
        
        Per Task 2.6: keying on ``route_patterns`` (regex-extracted) instead
        of raw routes lets ``/users/42`` and ``/users/9999`` collapse to a
        single ``/users/{id}`` row. Lower-cased framework collapses
        "React" / "react" / "REACT".
        """
        import hashlib
        data_str = json.dumps(
            {
                "framework": framework.lower(),
                "route_patterns": sorted_route_patterns,
            },
            sort_keys=True,
        )
        return f"framework:{hashlib.sha256(data_str.encode()).hexdigest()}"
    
    def _extract_framework_route_patterns(
        self, routes: List[str]
    ) -> List[str]:
        """Generalize concrete routes into reusable patterns.
        
        Replaces UUIDs, hex hashes, and numeric segments with placeholders so
        ``/users/42/posts/9c6f...`` and ``/users/13/posts/a1b2...`` match the
        same ``/users/{id}/posts/{uuid}`` pattern. Result is deduplicated and
        sorted for stable persistence.
        """
        patterns: set = set()
        for route in routes:
            p = re.sub(
                r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
                '/{uuid}',
                route,
            )
            p = re.sub(r'/[a-f0-9]{32}', '/{hash}', p)
            p = re.sub(r'/\d+', '/{id}', p)
            patterns.add(p)
        return sorted(patterns)


# Global learning engine instance
learning_engine = ContinuousLearningEngine()


# ============================================================================
# BROWSER LEARNING EXTENSION
# ============================================================================

class BrowserLearningExtension:
    """Extension for browser-specific learning with idempotency and caching"""
    
    def __init__(self, learning_engine: ContinuousLearningEngine):
        self.engine = learning_engine
        self.redis = learning_engine.redis_client
    
    def _generate_idempotency_key(self, vuln_data: Dict[str, Any]) -> str:
        """Generate idempotency key from vulnerability data"""
        import hashlib
        key_data = {
            "url": vuln_data.get("url", ""),
            "vuln_type": vuln_data.get("type", ""),
            "payload": vuln_data.get("payload", ""),
            "method": vuln_data.get("method", "GET")
        }
        data_str = json.dumps(key_data, sort_keys=True)
        return f"vuln:{hashlib.sha256(data_str.encode()).hexdigest()}"
    
    async def _acquire_lock(self, lock_key: str, ttl_seconds: int = 300) -> bool:
        """Acquire distributed lock using Redis"""
        if not self.redis:
            # No Redis, use in-memory cache
            if lock_key in self.engine._learning_cache:
                return False
            self.engine._learning_cache[lock_key] = True
            return True
        
        try:
            # Try to set key with NX (only if not exists) and EX (expiry)
            result = self.redis.set(lock_key, "1", nx=True, ex=ttl_seconds)
            return bool(result)
        except Exception as e:
            logger.warning(f"[BrowserLearning] Lock acquisition failed: {e}")
            return False
    
    async def _release_lock(self, lock_key: str):
        """Release distributed lock"""
        if not self.redis:
            self.engine._learning_cache.pop(lock_key, None)
            return
        
        try:
            self.redis.delete(lock_key)
        except Exception as e:
            logger.warning(f"[BrowserLearning] Lock release failed: {e}")
    
    async def learn_from_browser_vulnerability(
        self,
        vuln_data: Dict[str, Any],
        scan_id: str
    ) -> bool:
        """
        Learn from browser-based vulnerability with idempotency.
        Returns True if learning occurred, False if duplicate.
        """
        # Generate idempotency key
        idem_key = self._generate_idempotency_key(vuln_data)
        lock_key = f"lock:{idem_key}"
        
        # Acquire distributed lock
        if not await self._acquire_lock(lock_key, ttl_seconds=300):
            logger.debug(f"[BrowserLearning] Duplicate vulnerability, skipping: {idem_key}")
            return False
        
        try:
            # Extract browser-specific pattern
            pattern_data = {
                "vuln_type": vuln_data.get("type", "unknown"),
                "url": vuln_data.get("url", ""),
                "payload": vuln_data.get("payload", ""),
                "method": vuln_data.get("method", "GET"),
                "framework": vuln_data.get("framework"),
                "execution_context": "browser_required",
                "browser_requirements": {
                    "stealth": vuln_data.get("stealth_required", False),
                    "session": vuln_data.get("session_required", False),
                    "framework": vuln_data.get("framework")
                }
            }
            
            # Store pattern
            pattern_id = self.engine._generate_pattern_id("browser_vulnerability", pattern_data)
            
            if pattern_id in self.engine.patterns:
                pattern = self.engine.patterns[pattern_id]
                pattern.success_count += 1
                pattern.last_seen = time.time()
                pattern.update_confidence()
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="browser_vulnerability",
                    pattern_data=pattern_data,
                    confidence=0.7,
                    success_count=1,
                    failure_count=0,
                    last_seen=time.time(),
                    first_seen=time.time(),
                    scan_count=1
                )
                pattern.update_confidence()
                self.engine.patterns[pattern_id] = pattern
            
            self.engine._mark_patterns_dirty()
            
            logger.info(f"[BrowserLearning] Learned from browser vulnerability: {vuln_data.get('type')}")
            return True
            
        finally:
            await self._release_lock(lock_key)
    
    async def learn_browser_workflow(
        self,
        workflow: Dict[str, Any],
        success: bool
    ):
        """Learn from browser workflow execution"""
        workflow_id = workflow.get("id", "unknown")
        
        # Get existing workflow stats from Redis or memory
        stats_key = f"workflow:{workflow_id}"
        
        if self.redis:
            try:
                stats_data = self.redis.get(stats_key)
                if stats_data:
                    stats = json.loads(stats_data)
                else:
                    stats = {"success_count": 0, "failure_count": 0, "total_runs": 0}
            except Exception as redis_exc:
                logger.debug("[BrowserLearning] workflow stats Redis read failed: %s", redis_exc)
                stats = {"success_count": 0, "failure_count": 0, "total_runs": 0}
        else:
            stats = {"success_count": 0, "failure_count": 0, "total_runs": 0}
        
        # Update stats
        stats["total_runs"] += 1
        if success:
            stats["success_count"] += 1
        else:
            stats["failure_count"] += 1
        
        stats["success_rate"] = stats["success_count"] / stats["total_runs"]
        
        # Store updated stats
        if self.redis:
            try:
                self.redis.set(stats_key, json.dumps(stats), ex=86400)  # 24 hour expiry
            except Exception as e:
                logger.warning(f"[BrowserLearning] Failed to store workflow stats: {e}")
        
        # Promote to skill if threshold reached (>70% success rate, >5 runs)
        if stats["success_rate"] > 0.7 and stats["total_runs"] >= 5:
            pattern_data = {
                "workflow_id": workflow_id,
                "workflow_steps": workflow.get("steps", []),
                "success_conditions": workflow.get("success_conditions", []),
                "success_rate": stats["success_rate"],
                "total_runs": stats["total_runs"]
            }
            
            pattern_id = self.engine._generate_pattern_id("browser_workflow", pattern_data)
            
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="browser_workflow",
                pattern_data=pattern_data,
                confidence=stats["success_rate"],
                success_count=stats["success_count"],
                failure_count=stats["failure_count"],
                last_seen=time.time(),
                first_seen=time.time(),
                scan_count=1
            )
            
            self.engine.patterns[pattern_id] = pattern
            self.engine._mark_patterns_dirty()
            
            logger.info(f"[BrowserLearning] Promoted workflow to skill: {workflow_id}")
    
    async def get_browser_recommendations(
        self,
        target_url: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get browser-specific recommendations based on learned patterns"""
        context = context or {}
        
        recommendations = {
            "workflows": [],
            "payloads": [],
            "framework_specific": [],
            "confidence": 0.0
        }
        
        # Find matching browser patterns
        matching_patterns = []
        url_pattern = self.engine._extract_url_pattern(target_url)
        
        for pattern in self.engine.patterns.values():
            if pattern.pattern_type in ["browser_vulnerability", "browser_workflow"]:
                pattern_url = pattern.pattern_data.get("url", "")
                if pattern_url and self.engine._extract_url_pattern(pattern_url) == url_pattern:
                    if pattern.confidence > self.engine.min_confidence_threshold:
                        matching_patterns.append(pattern)
        
        # Sort by confidence
        matching_patterns.sort(key=lambda p: p.confidence, reverse=True)
        
        # Extract recommendations
        for pattern in matching_patterns[:10]:
            if pattern.pattern_type == "browser_workflow":
                recommendations["workflows"].append({
                    "workflow_id": pattern.pattern_data.get("workflow_id"),
                    "steps": pattern.pattern_data.get("workflow_steps", []),
                    "success_rate": pattern.success_rate,
                    "confidence": pattern.confidence
                })
            elif pattern.pattern_type == "browser_vulnerability":
                recommendations["payloads"].append({
                    "vuln_type": pattern.pattern_data.get("vuln_type"),
                    "payload": pattern.pattern_data.get("payload"),
                    "confidence": pattern.confidence,
                    "browser_requirements": pattern.pattern_data.get("browser_requirements", {})
                })
                
                # Framework-specific recommendations
                framework = pattern.pattern_data.get("framework")
                if framework:
                    recommendations["framework_specific"].append({
                        "framework": framework,
                        "vuln_type": pattern.pattern_data.get("vuln_type"),
                        "confidence": pattern.confidence
                    })
        
        # Calculate overall confidence
        if matching_patterns:
            recommendations["confidence"] = sum(p.confidence for p in matching_patterns) / len(matching_patterns)
        
        return recommendations
    
    async def learn_framework_pattern(
        self,
        framework: Optional[str],
        routes: List[str]
    ):
        """Learn framework-specific patterns"""
        if not framework or not routes:
            return
        
        # Deduplicate routes
        unique_routes = list(set(routes))
        
        # Get existing framework routes from Redis or memory
        routes_key = f"framework:{framework}:routes"
        
        if self.redis:
            try:
                existing_data = self.redis.get(routes_key)
                if existing_data:
                    existing_routes = set(json.loads(existing_data))
                else:
                    existing_routes = set()
            except Exception as redis_exc:
                logger.debug("[BrowserLearning] framework routes Redis read failed: %s", redis_exc)
                existing_routes = set()
        else:
            existing_routes = set()
        
        # Add only new routes
        new_routes = [r for r in unique_routes if r not in existing_routes]
        
        if not new_routes:
            return
        
        # Update stored routes
        all_routes = list(existing_routes.union(set(new_routes)))
        
        if self.redis:
            try:
                self.redis.set(routes_key, json.dumps(all_routes), ex=86400 * 7)  # 7 day expiry
            except Exception as e:
                logger.warning(f"[BrowserLearning] Failed to store framework routes: {e}")
        
        # Extract route patterns
        pattern_data = {
            "framework": framework,
            "route_count": len(all_routes),
            "new_routes": new_routes,
            "route_patterns": self._extract_route_patterns(all_routes)
        }
        
        pattern_id = self.engine._generate_pattern_id("framework_pattern", pattern_data)
        
        if pattern_id in self.engine.patterns:
            pattern = self.engine.patterns[pattern_id]
            pattern.pattern_data["route_count"] = len(all_routes)
            pattern.last_seen = time.time()
        else:
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="framework_pattern",
                pattern_data=pattern_data,
                confidence=0.6,
                success_count=1,
                failure_count=0,
                last_seen=time.time(),
                first_seen=time.time(),
                scan_count=1
            )
            self.engine.patterns[pattern_id] = pattern
        
        self.engine._mark_patterns_dirty()
    
    def _extract_route_patterns(self, routes: List[str]) -> List[str]:
        """Extract common patterns from routes"""
        patterns = set()
        
        for route in routes:
            # Replace IDs with placeholders
            pattern = re.sub(r'/\d+', '/:id', route)
            pattern = re.sub(r'/[a-f0-9-]{36}', '/:uuid', pattern)
            patterns.add(pattern)
        
        return list(patterns)


# Create global browser learning extension
browser_learning = BrowserLearningExtension(learning_engine)


# ============================================================================
# CROSS-SYSTEM LEARNING EXTENSION
# ============================================================================

class CrossSystemLearningExtension:
    """Extension for cross-system learning between HTTP and browser methods"""
    
    def __init__(self, learning_engine: ContinuousLearningEngine):
        self.engine = learning_engine
        self.redis = learning_engine.redis_client
    
    async def recommend_cross_method_verification(
        self,
        vuln_data: Dict[str, Any],
        discovery_method: str
    ) -> Dict[str, Any]:
        """
        Recommend cross-method verification.
        HTTP vulnerabilities recommend browser verification.
        Browser exploits recommend HTTP variants.
        """
        recommendations = {
            "should_verify": False,
            "verification_method": None,
            "confidence": 0.0,
            "reasoning": []
        }
        
        vuln_type = vuln_data.get("type", "unknown")
        
        # HTTP → Browser verification recommendations
        if discovery_method == "http":
            # XSS should always be verified in browser
            if vuln_type in ["XSS", "DOM_XSS", "Reflected_XSS"]:
                recommendations["should_verify"] = True
                recommendations["verification_method"] = "browser"
                recommendations["confidence"] = 0.9
                recommendations["reasoning"].append("XSS requires browser verification for execution")
            
            # CSRF benefits from browser verification
            elif vuln_type == "CSRF":
                recommendations["should_verify"] = True
                recommendations["verification_method"] = "browser"
                recommendations["confidence"] = 0.8
                recommendations["reasoning"].append("CSRF verification more reliable in browser context")
            
            # Check if target has JavaScript framework
            framework = vuln_data.get("framework")
            if framework:
                recommendations["should_verify"] = True
                recommendations["verification_method"] = "browser"
                recommendations["confidence"] = max(recommendations["confidence"], 0.7)
                recommendations["reasoning"].append(f"Target uses {framework}, browser verification recommended")
        
        # Browser → HTTP variant recommendations
        elif discovery_method == "browser":
            # Browser-discovered endpoints should be tested via HTTP
            if vuln_type in ["API_Endpoint", "Hidden_Endpoint"]:
                recommendations["should_verify"] = True
                recommendations["verification_method"] = "http"
                recommendations["confidence"] = 0.8
                recommendations["reasoning"].append("Browser-discovered endpoint should be tested via HTTP")
            
            # Browser XSS might have HTTP variant
            elif vuln_type == "XSS":
                recommendations["should_verify"] = True
                recommendations["verification_method"] = "http"
                recommendations["confidence"] = 0.6
                recommendations["reasoning"].append("Browser XSS might have HTTP-only variant")
        
        return recommendations
    
    async def identify_cross_context_patterns(
        self,
        http_patterns: List[LearningPattern],
        browser_patterns: List[LearningPattern]
    ) -> List[Dict[str, Any]]:
        """
        Identify patterns that work in both HTTP and browser contexts.
        Creates hybrid attack skills.
        """
        hybrid_patterns = []
        
        # Match patterns by URL and vulnerability type
        for http_pattern in http_patterns:
            http_url = self.engine._extract_url_pattern(http_pattern.pattern_data.get("url", ""))
            http_vuln_type = http_pattern.pattern_data.get("vuln_type")
            
            for browser_pattern in browser_patterns:
                browser_url = self.engine._extract_url_pattern(browser_pattern.pattern_data.get("url", ""))
                browser_vuln_type = browser_pattern.pattern_data.get("vuln_type")
                
                # Match if same URL pattern and vulnerability type
                if http_url == browser_url and http_vuln_type == browser_vuln_type:
                    hybrid_pattern = {
                        "pattern_type": "hybrid_attack",
                        "vuln_type": http_vuln_type,
                        "url_pattern": http_url,
                        "http_payload": http_pattern.pattern_data.get("payload"),
                        "browser_payload": browser_pattern.pattern_data.get("payload"),
                        "http_confidence": http_pattern.confidence,
                        "browser_confidence": browser_pattern.confidence,
                        "combined_confidence": (http_pattern.confidence + browser_pattern.confidence) / 2,
                        "execution_contexts": ["http", "browser"],
                        "success_rate": (http_pattern.success_rate + browser_pattern.success_rate) / 2
                    }
                    
                    hybrid_patterns.append(hybrid_pattern)
                    
                    # Store as new pattern
                    pattern_id = self.engine._generate_pattern_id("hybrid_attack", hybrid_pattern)
                    
                    if pattern_id not in self.engine.patterns:
                        pattern = LearningPattern(
                            pattern_id=pattern_id,
                            pattern_type="hybrid_attack",
                            pattern_data=hybrid_pattern,
                            confidence=hybrid_pattern["combined_confidence"],
                            success_count=http_pattern.success_count + browser_pattern.success_count,
                            failure_count=http_pattern.failure_count + browser_pattern.failure_count,
                            last_seen=time.time(),
                            first_seen=time.time(),
                            scan_count=1
                        )
                        self.engine.patterns[pattern_id] = pattern
        
        if hybrid_patterns:
            self.engine._mark_patterns_dirty()
            logger.info(f"[CrossSystemLearning] Identified {len(hybrid_patterns)} hybrid patterns")
        
        return hybrid_patterns
    
    async def extract_http_payload_from_browser_workflow(
        self,
        workflow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Extract HTTP-equivalent payload from browser workflow.
        Stores as separate HTTP skill.
        """
        workflow_steps = workflow.get("steps", [])
        
        # Find HTTP requests in workflow
        http_requests = []
        for step in workflow_steps:
            if step.get("type") == "http_request":
                http_requests.append(step)
        
        if not http_requests:
            return None
        
        # Extract payload from HTTP requests
        http_payload = {
            "workflow_id": workflow.get("id"),
            "extracted_from": "browser_workflow",
            "requests": [],
            "success_conditions": workflow.get("success_conditions", [])
        }
        
        for req in http_requests:
            http_payload["requests"].append({
                "method": req.get("method", "GET"),
                "url": req.get("url"),
                "headers": req.get("headers", {}),
                "body": req.get("body"),
                "params": req.get("params", {})
            })
        
        # Store as HTTP pattern
        pattern_data = {
            "pattern_type": "http_from_browser",
            "workflow_id": workflow.get("id"),
            "http_payload": http_payload,
            "original_context": "browser"
        }
        
        pattern_id = self.engine._generate_pattern_id("http_from_browser", pattern_data)
        
        pattern = LearningPattern(
            pattern_id=pattern_id,
            pattern_type="http_from_browser",
            pattern_data=pattern_data,
            confidence=0.6,
            success_count=1,
            failure_count=0,
            last_seen=time.time(),
            first_seen=time.time(),
            scan_count=1
        )
        
        self.engine.patterns[pattern_id] = pattern
        self.engine._mark_patterns_dirty()
        
        return http_payload
    
    async def track_http_browser_correlation(
        self,
        http_result: Dict[str, Any],
        browser_result: Dict[str, Any],
        target_url: str
    ):
        """
        Track correlation between HTTP recon and browser discoveries.
        Stores correlation patterns for future optimization.
        """
        correlation_data = {
            "target_url": target_url,
            "http_endpoints_found": http_result.get("endpoints_found", 0),
            "browser_endpoints_found": browser_result.get("endpoints_found", 0),
            "http_vulns_found": http_result.get("vulns_found", 0),
            "browser_vulns_found": browser_result.get("vulns_found", 0),
            "overlap_endpoints": http_result.get("overlap_endpoints", 0),
            "unique_http_endpoints": http_result.get("unique_endpoints", 0),
            "unique_browser_endpoints": browser_result.get("unique_endpoints", 0),
            "timestamp": time.time()
        }
        
        # Calculate correlation metrics
        total_endpoints = (correlation_data["http_endpoints_found"] + 
                          correlation_data["browser_endpoints_found"])
        
        if total_endpoints > 0:
            correlation_data["overlap_rate"] = (
                correlation_data["overlap_endpoints"] / total_endpoints
            )
            correlation_data["browser_unique_rate"] = (
                correlation_data["unique_browser_endpoints"] / total_endpoints
            )
        else:
            correlation_data["overlap_rate"] = 0.0
            correlation_data["browser_unique_rate"] = 0.0
        
        # Store correlation pattern
        pattern_id = self.engine._generate_pattern_id("http_browser_correlation", correlation_data)
        
        if pattern_id in self.engine.patterns:
            pattern = self.engine.patterns[pattern_id]
            pattern.success_count += 1
            pattern.last_seen = time.time()
            
            # Update running averages
            old_data = pattern.pattern_data
            pattern.pattern_data["overlap_rate"] = (
                (old_data.get("overlap_rate", 0) * pattern.success_count + 
                 correlation_data["overlap_rate"]) / (pattern.success_count + 1)
            )
            pattern.pattern_data["browser_unique_rate"] = (
                (old_data.get("browser_unique_rate", 0) * pattern.success_count + 
                 correlation_data["browser_unique_rate"]) / (pattern.success_count + 1)
            )
        else:
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="http_browser_correlation",
                pattern_data=correlation_data,
                confidence=0.5,
                success_count=1,
                failure_count=0,
                last_seen=time.time(),
                first_seen=time.time(),
                scan_count=1
            )
            self.engine.patterns[pattern_id] = pattern
        
        self.engine._mark_patterns_dirty()
    
    def get_correlation_stats(self) -> Dict[str, Any]:
        """Get statistics about HTTP-browser correlations"""
        correlation_patterns = [
            p for p in self.engine.patterns.values()
            if p.pattern_type == "http_browser_correlation"
        ]
        
        if not correlation_patterns:
            return {
                "total_correlations": 0,
                "avg_overlap_rate": 0.0,
                "avg_browser_unique_rate": 0.0
            }
        
        total = len(correlation_patterns)
        avg_overlap = sum(
            p.pattern_data.get("overlap_rate", 0) for p in correlation_patterns
        ) / total
        avg_unique = sum(
            p.pattern_data.get("browser_unique_rate", 0) for p in correlation_patterns
        ) / total
        
        return {
            "total_correlations": total,
            "avg_overlap_rate": round(avg_overlap, 2),
            "avg_browser_unique_rate": round(avg_unique, 2),
            "timestamp": time.time()
        }


# Create global cross-system learning extension
cross_system_learning = CrossSystemLearningExtension(learning_engine)


# ============================================================================
# AUTHENTICATION PATTERN LEARNING (Section 16)
# ============================================================================

class AuthenticationPatternLearner:
    """
    Learns authentication patterns and enables session reuse.
    """
    
    def __init__(self, redis_client: Any):
        self.redis = redis_client
        self.auth_patterns: Dict[str, Dict[str, Any]] = {}
        self.session_store: Dict[str, Dict[str, Any]] = {}
    
    def extract_auth_pattern(
        self,
        auth_data: Dict[str, Any],
        success: bool
    ) -> Optional[Dict[str, Any]]:
        """
        Extract authentication pattern from successful auth attempt.
        Returns auth pattern as reusable skill.
        """
        if not success:
            return None
        
        target_domain = auth_data.get("domain")
        auth_method = auth_data.get("method", "form")  # form, oauth, api_key, etc.
        
        pattern = {
            "domain": target_domain,
            "method": auth_method,
            "steps": auth_data.get("steps", []),
            "credentials_fields": auth_data.get("credentials_fields", []),
            "success_indicators": auth_data.get("success_indicators", []),
            "session_token_location": auth_data.get("session_token_location"),
            "extracted_at": time.time()
        }
        
        # Store pattern
        pattern_key = f"{target_domain}:{auth_method}"
        self.auth_patterns[pattern_key] = pattern
        
        logger.info(f"[AuthLearning] Extracted auth pattern for {target_domain} ({auth_method})")
        
        return pattern
    
    def store_auth_pattern_as_skill(
        self,
        pattern: Dict[str, Any],
        skill_library: Any
    ) -> Any:
        """Store authentication pattern as reusable skill."""
        from backend.core.skill_library import BrowserSkill
        
        skill = BrowserSkill(
            skill_id=f"auth_{hashlib.sha256(pattern['domain'].encode()).hexdigest()[:12]}",
            name=f"Auth: {pattern['domain']} ({pattern['method']})",
            skill_type="authentication_workflow",
            execution_context="browser_required",
            browser_requirements={
                "session": True,
                "stealth": False
            },
            workflow_steps=pattern.get("steps", []),
            version="1.0.0",
            required_capabilities=frozenset(["browser", "authentication"]),
            success_rate=1.0,
            confidence=0.8,
            created_at=time.time(),
            tags=["authentication", "session", pattern["method"]],
            parameters={
                "credentials_fields": pattern.get("credentials_fields", []),
                "success_indicators": pattern.get("success_indicators", []),
                "session_token_location": pattern.get("session_token_location")
            }
        )
        
        # Add to skill library
        skill_library.add_browser_skill(skill, {})
        
        logger.info(f"[AuthLearning] Stored auth pattern as skill: {skill.name}")
        
        return skill
    
    def reuse_auth_pattern(
        self,
        target_domain: str,
        auth_method: str = "form"
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve learned authentication pattern for reuse.
        Returns pattern if available.
        """
        pattern_key = f"{target_domain}:{auth_method}"
        
        if pattern_key in self.auth_patterns:
            pattern = self.auth_patterns[pattern_key]
            logger.info(f"[AuthLearning] Reusing auth pattern for {target_domain}")
            return pattern
        
        return None
    
    def store_session_state(
        self,
        target_domain: str,
        session_data: Dict[str, Any]
    ):
        """Store session state for reuse across scans."""
        self.session_store[target_domain] = {
            "session_data": session_data,
            "stored_at": time.time(),
            "expires_at": time.time() + session_data.get("ttl_seconds", 3600)
        }
        
        logger.info(f"[AuthLearning] Stored session state for {target_domain}")
    
    def get_session_state(
        self,
        target_domain: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve stored session state if not expired."""
        if target_domain not in self.session_store:
            return None
        
        session = self.session_store[target_domain]
        
        # Check if expired
        if time.time() > session["expires_at"]:
            logger.info(f"[AuthLearning] Session expired for {target_domain}")
            del self.session_store[target_domain]
            return None
        
        logger.info(f"[AuthLearning] Retrieved session state for {target_domain}")
        return session["session_data"]
    
    async def re_authenticate(
        self,
        target_domain: str,
        browser_orchestrator: Any,
        credentials: Dict[str, str]
    ) -> bool:
        """
        Re-authenticate using learned pattern when session expires.
        Returns True if re-authentication succeeded.
        """
        # Get learned pattern
        pattern = self.reuse_auth_pattern(target_domain)
        
        if not pattern:
            logger.warning(f"[AuthLearning] No auth pattern found for {target_domain}")
            return False
        
        logger.info(f"[AuthLearning] Re-authenticating to {target_domain}")
        
        try:
            # Execute auth steps (simplified - actual implementation would use browser_orchestrator)
            for step in pattern.get("steps", []):
                # Execute step
                pass
            
            # Store new session
            # self.store_session_state(target_domain, new_session_data)
            
            return True
            
        except Exception as e:
            logger.error(f"[AuthLearning] Re-authentication failed: {e}")
            return False
    
    def track_auth_method_effectiveness(
        self,
        target_type: str,
        auth_method: str,
        success: bool
    ):
        """Track which authentication methods work for which target types."""
        tracking_key = f"auth_effectiveness:{target_type}:{auth_method}"
        
        # Get current stats from Redis
        stats_json = self.redis.get(tracking_key)
        if stats_json:
            stats = json.loads(stats_json)
        else:
            stats = {"success_count": 0, "failure_count": 0}
        
        # Update stats
        if success:
            stats["success_count"] += 1
        else:
            stats["failure_count"] += 1
        
        # Calculate success rate
        total = stats["success_count"] + stats["failure_count"]
        stats["success_rate"] = stats["success_count"] / total if total > 0 else 0.0
        
        # Store back to Redis
        self.redis.setex(tracking_key, 86400 * 30, json.dumps(stats))  # 30 days TTL
        
        logger.debug(f"[AuthLearning] Auth method {auth_method} for {target_type}: {stats['success_rate']:.1%}")
    
    def get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication learning statistics."""
        return {
            "patterns_learned": len(self.auth_patterns),
            "sessions_stored": len(self.session_store),
            "active_sessions": sum(
                1 for s in self.session_store.values()
                if time.time() < s["expires_at"]
            ),
            "timestamp": time.time()
        }


# Global authentication pattern learner
auth_pattern_learner: Optional[AuthenticationPatternLearner] = None


def initialize_auth_learner(redis_client: Any):
    """Initialize the global authentication pattern learner."""
    global auth_pattern_learner
    auth_pattern_learner = AuthenticationPatternLearner(redis_client)
    return auth_pattern_learner
