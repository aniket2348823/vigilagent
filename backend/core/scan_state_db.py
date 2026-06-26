"""
Vigilagent Scan State Database (Architecture §5.6, §20, §29.13)
================================================================================
Durable SQLite-backed execution state, adapting the Hermes `hermes_state.py`
pattern for scans:

  - WAL mode where supported, fallback journal mode where WAL fails.
  - Schema version table for migrations.
  - FTS5 search over messages, tool-output summaries, findings, and evidence.
  - Parent scan/session chains (after compression or resume).
  - Jittered write retry to avoid lock convoys.
  - Periodic checkpoint and maintenance.
  - Durable task leases so workers can resume/reassign after crash.

This replaces fragile JSON-only scan memory for anything that affects execution
(Architecture §25). The legacy JSON StateManager remains for UI stats.

Tables (Architecture §5.6):
  scans, scan_sessions, tasks, task_attempts, agent_runs, tool_runs, messages,
  events, approvals, findings, evidence, skills, skill_runs, learning_updates,
  graph_nodes, graph_edges, checkpoints
"""

from __future__ import annotations

import json
import logging
import random
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from backend.core.perf import dumps_fast

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger("vigilagent.scan_state_db")

_SCHEMA_VERSION = 2
_DEFAULT_DB_PATH = Path("scan_states") / "scan_state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    parent_scan_id TEXT,
    target TEXT,
    mode TEXT,
    phase TEXT,
    status TEXT,
    authorized INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id TEXT PRIMARY KEY,
    scan_id TEXT,
    parent_session_id TEXT,
    created_at TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    scan_id TEXT,
    parent_task_id TEXT,
    agent TEXT,
    objective TEXT,
    phase TEXT,
    status TEXT,
    lease_owner TEXT,
    lease_expires_at REAL,
    created_at TEXT,
    updated_at TEXT,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS task_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    attempt_no INTEGER,
    status TEXT,
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY,
    scan_id TEXT,
    agent TEXT,
    phase TEXT,
    status TEXT,
    budget_used INTEGER,
    started_at TEXT,
    finished_at TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS tool_runs (
    tool_run_id TEXT PRIMARY KEY,
    scan_id TEXT,
    tool TEXT,
    agent TEXT,
    backend TEXT,
    exit_code INTEGER,
    status TEXT,
    duration_ms INTEGER,
    output_sha256 TEXT,
    output_summary TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    role TEXT,
    agent TEXT,
    content TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    type TEXT,
    source TEXT,
    payload TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    scan_id TEXT,
    action TEXT,
    status TEXT,
    requested_at TEXT,
    decided_at TEXT,
    decided_by TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    title TEXT,
    severity TEXT,
    state TEXT,
    confidence REAL,
    asset TEXT,
    description TEXT,
    evidence_ids TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_id TEXT,
    kind TEXT,
    path TEXT,
    sha256 TEXT,
    description TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS skills (
    skill_id TEXT PRIMARY KEY,
    name TEXT,
    domain TEXT,
    risk_class TEXT,
    promotion_state TEXT,
    success_rate REAL,
    failure_rate REAL,
    meta TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS skill_runs (
    skill_run_id TEXT PRIMARY KEY,
    scan_id TEXT,
    skill_id TEXT,
    agent TEXT,
    risk_class TEXT,
    scope_decision TEXT,
    confidence REAL,
    result TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS learning_updates (
    update_id TEXT PRIMARY KEY,
    scan_id TEXT,
    kind TEXT,
    subsystem TEXT,
    detail TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT PRIMARY KEY,
    scan_id TEXT,
    kind TEXT,
    label TEXT,
    props TEXT
);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    scan_id TEXT,
    src_id TEXT,
    dst_id TEXT,
    kind TEXT,
    weight REAL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    scan_id TEXT,
    phase TEXT,
    completed_endpoints TEXT,
    pending_endpoints TEXT,
    findings TEXT,
    graph_snapshot TEXT,
    budgets TEXT,
    boundary TEXT,
    safe INTEGER DEFAULT 1,
    agent_health TEXT,
    remaining_tasks TEXT,
    created_at TEXT
);
"""

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
    scan_id, kind, ref_id, text
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _loads(value: Any) -> dict:
    """Best-effort JSON decode for persisted task payloads (already-dict safe)."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        out = json.loads(value)
        return out if isinstance(out, dict) else {}
    except Exception as e:
        logger.debug("[ScanStateDB] _loads decode failed: %s", e)
        return {}


class ScanStateDB:
    """Durable SQLite state for scan execution (Architecture §5.6)."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._fts_enabled = False
        self._conn = self._connect()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.DatabaseError:
            # Fallback journal mode where WAL fails (Architecture §5.6).
            conn.execute("PRAGMA journal_mode=DELETE;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            try:
                self._conn.executescript(_FTS_SCHEMA)
                self._fts_enabled = True
            except sqlite3.OperationalError:
                logger.warning("FTS5 unavailable; full-text search disabled.")
                self._fts_enabled = False

            cur = self._conn.execute("SELECT version FROM schema_version LIMIT 1;")
            row = cur.fetchone()
            if row is None:
                self._conn.execute("INSERT INTO schema_version (version) VALUES (?);", (_SCHEMA_VERSION,))
            else:
                self._migrate(int(row["version"]))
            self._conn.commit()

    def _migrate(self, from_version: int) -> None:
        """Additive, idempotent schema migrations (Architecture §5.6)."""
        if from_version >= _SCHEMA_VERSION:
            return
        # v1 -> v2: enrich checkpoints with safe-boundary/resume columns (§20).
        existing = {r["name"] for r in self._conn.execute("PRAGMA table_info(checkpoints);").fetchall()}
        for col, ddl in (
            ("boundary", "ALTER TABLE checkpoints ADD COLUMN boundary TEXT;"),
            ("safe", "ALTER TABLE checkpoints ADD COLUMN safe INTEGER DEFAULT 1;"),
            ("agent_health", "ALTER TABLE checkpoints ADD COLUMN agent_health TEXT;"),
            ("remaining_tasks", "ALTER TABLE checkpoints ADD COLUMN remaining_tasks TEXT;"),
        ):
            if col not in existing:
                with suppress(sqlite3.OperationalError):
                    self._conn.execute(ddl)
        self._conn.execute("UPDATE schema_version SET version=?;", (_SCHEMA_VERSION,))

    # ── Jittered write retry (Architecture §5.6) ──────────────────────────────

    @contextmanager
    def _write(self, retries: int = 5):
        attempt = 0
        while True:
            try:
                with self._lock:
                    yield self._conn
                    self._conn.commit()
                return
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < retries:
                    attempt += 1
                    time.sleep(random.uniform(0.02, 0.15) * attempt)
                    continue
                raise

    def _index(self, scan_id: str, kind: str, ref_id: str, text: str) -> None:
        if not self._fts_enabled or not text:
            return
        with suppress(sqlite3.OperationalError):
            self._conn.execute(
                "INSERT INTO search_index (scan_id, kind, ref_id, text) VALUES (?,?,?,?);",
                (scan_id, kind, ref_id, text[:8000]),
            )

    # ── Scans ──────────────────────────────────────────────────────────────────

    def upsert_scan(
        self,
        scan_id: str,
        *,
        target: str = "",
        mode: str = "",
        phase: str = "",
        status: str = "running",
        authorized: bool = False,
        parent_scan_id: str | None = None,
        meta: dict | None = None,
    ) -> None:
        with self._write() as c:
            existing = c.execute("SELECT scan_id FROM scans WHERE scan_id=?;", (scan_id,)).fetchone()
            if existing:
                c.execute(
                    "UPDATE scans SET target=?, mode=?, phase=?, status=?, authorized=?, "
                    "updated_at=?, meta=? WHERE scan_id=?;",
                    (target, mode, phase, status, int(authorized), _now(), json.dumps(meta or {}), scan_id),
                )
            else:
                c.execute(
                    "INSERT INTO scans (scan_id, parent_scan_id, target, mode, phase, status, "
                    "authorized, created_at, updated_at, meta) VALUES (?,?,?,?,?,?,?,?,?,?);",
                    (
                        scan_id,
                        parent_scan_id,
                        target,
                        mode,
                        phase,
                        status,
                        int(authorized),
                        _now(),
                        _now(),
                        json.dumps(meta or {}),
                    ),
                )

    def set_phase(self, scan_id: str, phase: str) -> None:
        with self._write() as c:
            c.execute("UPDATE scans SET phase=?, updated_at=? WHERE scan_id=?;", (phase, _now(), scan_id))

    def get_scan(self, scan_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE scan_id=?;", (scan_id,)).fetchone()
        return dict(row) if row else None

    # ── Tasks + durable leases (Architecture §5.6) ────────────────────────────

    def upsert_task(
        self,
        task_id: str,
        scan_id: str,
        *,
        agent: str = "",
        objective: str = "",
        phase: str = "",
        status: str = "pending",
        parent_task_id: str | None = None,
        payload: dict | None = None,
    ) -> None:
        with self._write() as c:
            exists = c.execute("SELECT task_id FROM tasks WHERE task_id=?;", (task_id,)).fetchone()
            if exists:
                c.execute(
                    "UPDATE tasks SET status=?, updated_at=?, payload=? WHERE task_id=?;",
                    (status, _now(), json.dumps(payload or {}), task_id),
                )
            else:
                c.execute(
                    "INSERT INTO tasks (task_id, scan_id, parent_task_id, agent, objective, phase, "
                    "status, created_at, updated_at, payload) VALUES (?,?,?,?,?,?,?,?,?,?);",
                    (
                        task_id,
                        scan_id,
                        parent_task_id,
                        agent,
                        objective,
                        phase,
                        status,
                        _now(),
                        _now(),
                        json.dumps(payload or {}),
                    ),
                )

    def acquire_lease(self, task_id: str, owner: str, ttl_seconds: int = 300) -> bool:
        """Acquire a durable task lease; returns False if held by another live owner."""
        now = time.time()
        with self._write() as c:
            row = c.execute("SELECT lease_owner, lease_expires_at FROM tasks WHERE task_id=?;", (task_id,)).fetchone()
            if (
                row
                and row["lease_owner"]
                and row["lease_expires_at"]
                and row["lease_expires_at"] > now
                and row["lease_owner"] != owner
            ):
                return False
            c.execute(
                "UPDATE tasks SET lease_owner=?, lease_expires_at=?, status='running', updated_at=? WHERE task_id=?;",
                (owner, now + ttl_seconds, _now(), task_id),
            )
            return True

    def release_lease(self, task_id: str, *, status: str = "completed") -> None:
        with self._write() as c:
            c.execute(
                "UPDATE tasks SET lease_owner=NULL, lease_expires_at=NULL, status=?, updated_at=? WHERE task_id=?;",
                (status, _now(), task_id),
            )

    def pending_tasks(self, scan_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tasks WHERE scan_id=? AND status IN ('pending','running');", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Tool runs (Architecture §8 audit) ─────────────────────────────────────

    def record_tool_run(
        self,
        tool_run_id: str,
        scan_id: str,
        *,
        tool: str,
        agent: str,
        backend: str,
        exit_code: int | None,
        status: str,
        duration_ms: int,
        output_sha256: str = "",
        output_summary: str = "",
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO tool_runs (tool_run_id, scan_id, tool, agent, backend, "
                "exit_code, status, duration_ms, output_sha256, output_summary, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                (
                    tool_run_id,
                    scan_id,
                    tool,
                    agent,
                    backend,
                    exit_code,
                    status,
                    duration_ms,
                    output_sha256,
                    output_summary,
                    _now(),
                ),
            )
            self._index(scan_id, "tool_run", tool_run_id, f"{tool} {output_summary}")

    # ── Messages / events (FTS-indexed) ───────────────────────────────────────

    def add_message(self, scan_id: str, role: str, content: str, agent: str = "") -> None:
        with self._write() as c:
            cur = c.execute(
                "INSERT INTO messages (scan_id, role, agent, content, created_at) VALUES (?,?,?,?,?);",
                (scan_id, role, agent, content, _now()),
            )
            self._index(scan_id, "message", str(cur.lastrowid), content)

    def add_event(self, scan_id: str, etype: str, source: str, payload: dict | None = None) -> None:
        with self._write() as c:
            c.execute(
                "INSERT INTO events (scan_id, type, source, payload, created_at) VALUES (?,?,?,?,?);",
                (scan_id, etype, source, json.dumps(payload or {}), _now()),
            )

    def add_events_bulk(self, events: Iterable[dict]) -> int:
        """Insert many events in one transaction (Architecture §5.6 throughput).

        Each event dict: ``{"scan_id", "type", "source", "payload"}``. Avoids
        the one-transaction-per-insert overhead that dominated when an agent
        emits dozens of events in a tight loop. Returns rows inserted.
        """
        rows = [
            (e.get("scan_id", ""), e.get("type", ""), e.get("source", ""), dumps_fast(e.get("payload") or {}), _now())
            for e in events
        ]
        if not rows:
            return 0
        with self._write() as c:
            c.executemany(
                "INSERT INTO events (scan_id, type, source, payload, created_at) VALUES (?,?,?,?,?);",
                rows,
            )
        return len(rows)

    def add_messages_bulk(self, messages: Iterable[dict]) -> int:
        """Insert many messages in one transaction. FTS indexing is best-effort."""
        ts = _now()
        rows = [
            (m.get("scan_id", ""), m.get("role", ""), m.get("agent", ""), m.get("content", ""), ts) for m in messages
        ]
        if not rows:
            return 0
        with self._write() as c:
            c.executemany(
                "INSERT INTO messages (scan_id, role, agent, content, created_at) VALUES (?,?,?,?,?);",
                rows,
            )
            # Best-effort FTS index: rebuild incrementally only if available.
            if self._fts_enabled:
                last = c.execute("SELECT last_insert_rowid();").fetchone()
                last_id = int(last[0]) if last else 0
                start_id = last_id - len(rows) + 1
                if start_id > 0:
                    fts_rows = [
                        (rows[i][0], "message", str(start_id + i), (rows[i][3] or "")[:8000]) for i in range(len(rows))
                    ]
                    with suppress(sqlite3.OperationalError):
                        c.executemany(
                            "INSERT INTO search_index (scan_id, kind, ref_id, text) VALUES (?,?,?,?);",
                            fts_rows,
                        )
        return len(rows)

    # ── Findings / evidence (Architecture §17, §18) ───────────────────────────

    def upsert_finding(
        self,
        finding_id: str,
        scan_id: str,
        *,
        title: str,
        severity: str,
        state: str = "candidate",
        confidence: float = 0.0,
        asset: str = "",
        description: str = "",
        evidence_ids: Iterable[str] = (),
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO findings (finding_id, scan_id, title, severity, state, "
                "confidence, asset, description, evidence_ids, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                (
                    finding_id,
                    scan_id,
                    title,
                    severity,
                    state,
                    confidence,
                    asset,
                    description,
                    json.dumps(list(evidence_ids)),
                    _now(),
                ),
            )
            self._index(scan_id, "finding", finding_id, f"{title} {description}")

    def add_evidence(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        finding_id: str = "",
        kind: str = "",
        path: str = "",
        sha256: str = "",
        description: str = "",
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO evidence (evidence_id, scan_id, finding_id, kind, path, "
                "sha256, description, created_at) VALUES (?,?,?,?,?,?,?,?);",
                (evidence_id, scan_id, finding_id, kind, path, sha256, description, _now()),
            )
            self._index(scan_id, "evidence", evidence_id, description)

    # ── Checkpoints (Architecture §20) ────────────────────────────────────────

    def save_checkpoint(
        self,
        checkpoint_id: str,
        scan_id: str,
        *,
        phase: str,
        completed_endpoints: list[str],
        pending_endpoints: list[str],
        findings: list[dict],
        graph_snapshot: dict,
        budgets: dict,
        boundary: str = "phase",
        safe: bool = True,
        agent_health: dict | None = None,
        remaining_tasks: list[dict] | None = None,
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO checkpoints (checkpoint_id, scan_id, phase, "
                "completed_endpoints, pending_endpoints, findings, graph_snapshot, budgets, "
                "boundary, safe, agent_health, remaining_tasks, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (
                    checkpoint_id,
                    scan_id,
                    phase,
                    dumps_fast(completed_endpoints),
                    dumps_fast(pending_endpoints),
                    dumps_fast(findings),
                    dumps_fast(graph_snapshot),
                    dumps_fast(budgets),
                    boundary,
                    int(safe),
                    dumps_fast(agent_health or {}),
                    dumps_fast(remaining_tasks or []),
                    _now(),
                ),
            )

    # ── Phase-boundary checkpoint/resume (Architecture §20) ───────────────────
    #
    # Hermes drives durability from explicit safe boundaries: a snapshot is
    # taken AFTER each completed phase and BEFORE any risky/destructive step,
    # and resume restores from the last *safe* boundary. The helpers below adopt
    # that pattern for scans, capturing graph snapshot + remaining task queue +
    # budget counters + agent health so a crashed scan resumes cleanly.

    def _capture_graph_snapshot(self, scan_id: str) -> dict:
        """Snapshot the durable target graph for a scan (nodes + edges)."""
        with self._lock:
            nodes = [
                dict(r)
                for r in self._conn.execute(
                    "SELECT node_id, kind, label, props FROM graph_nodes WHERE scan_id=?;", (scan_id,)
                ).fetchall()
            ]
            edges = [
                dict(r)
                for r in self._conn.execute(
                    "SELECT edge_id, src_id, dst_id, kind, weight FROM graph_edges WHERE scan_id=?;", (scan_id,)
                ).fetchall()
            ]
        return {"nodes": nodes, "edges": edges}

    def _capture_findings(self, scan_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM findings WHERE scan_id=?;", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def checkpoint_phase(
        self,
        scan_id: str,
        phase: str,
        *,
        completed_endpoints: list[str] | None = None,
        pending_endpoints: list[str] | None = None,
        budgets: dict | None = None,
        agent_health: dict | None = None,
        boundary: str = "phase_complete",
        safe: bool = True,
        checkpoint_id: str | None = None,
    ) -> str:
        """Checkpoint AFTER a phase completes (Architecture §20 safe boundary).

        Auto-captures the graph snapshot, current findings, and the remaining
        task queue (pending/running tasks) so resume() can restore execution
        from this boundary. Returns the checkpoint_id.
        """
        cp_id = checkpoint_id or f"cp-{scan_id}-{uuid.uuid4().hex[:12]}"
        remaining = self.pending_tasks(scan_id)
        self.save_checkpoint(
            cp_id,
            scan_id,
            phase=phase,
            completed_endpoints=completed_endpoints or [],
            pending_endpoints=pending_endpoints or [],
            findings=self._capture_findings(scan_id),
            graph_snapshot=self._capture_graph_snapshot(scan_id),
            budgets=budgets or {},
            boundary=boundary,
            safe=safe,
            agent_health=agent_health or {},
            remaining_tasks=remaining,
        )
        self.add_event(
            scan_id,
            "checkpoint",
            "scan_state_db",
            {"checkpoint_id": cp_id, "phase": phase, "boundary": boundary, "safe": safe},
        )
        return cp_id

    def checkpoint_before_validation(
        self,
        scan_id: str,
        phase: str,
        *,
        completed_endpoints: list[str] | None = None,
        pending_endpoints: list[str] | None = None,
        budgets: dict | None = None,
        agent_health: dict | None = None,
        checkpoint_id: str | None = None,
    ) -> str:
        """Checkpoint BEFORE a risky validation/exploit step (Architecture §20).

        Recorded as a safe boundary so a crash mid-validation resumes from the
        pre-validation state rather than a partially-applied one.
        """
        return self.checkpoint_phase(
            scan_id,
            phase,
            completed_endpoints=completed_endpoints,
            pending_endpoints=pending_endpoints,
            budgets=budgets,
            agent_health=agent_health,
            boundary="pre_validation",
            safe=True,
            checkpoint_id=checkpoint_id,
        )

    def latest_checkpoint(self, scan_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE scan_id=? ORDER BY created_at DESC LIMIT 1;", (scan_id,)
            ).fetchone()
        return self._hydrate_checkpoint(row)

    def latest_safe_checkpoint(self, scan_id: str) -> dict | None:
        """Latest checkpoint at a safe boundary (Architecture §20 resume target)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE scan_id=? AND safe=1 ORDER BY created_at DESC LIMIT 1;", (scan_id,)
            ).fetchone()
        return self._hydrate_checkpoint(row)

    @staticmethod
    def _hydrate_checkpoint(row: sqlite3.Row | None) -> dict | None:
        if not row:
            return None
        data = dict(row)
        for k in (
            "completed_endpoints",
            "pending_endpoints",
            "findings",
            "graph_snapshot",
            "budgets",
            "agent_health",
            "remaining_tasks",
        ):
            if k in data:
                try:
                    data[k] = json.loads(data[k]) if data[k] else None
                except Exception as e:
                    logger.debug("[ScanStateDB] _hydrate JSON decode for %s failed: %s", k, e)
        if "safe" in data and data["safe"] is not None:
            data["safe"] = bool(data["safe"])
        return data

    def resume(self, scan_id: str) -> dict | None:
        """Resume a scan from its last completed safe boundary (Architecture §20).

        Restores from the latest *safe* checkpoint (falling back to the latest
        checkpoint if none is flagged safe), re-points the scan to that phase,
        re-enqueues the persisted remaining task queue, and returns a resume
        context: ``{checkpoint, phase, pending_tasks, budgets, agent_health,
        graph_snapshot}``. Returns None when there is nothing to resume.
        """
        cp = self.latest_safe_checkpoint(scan_id) or self.latest_checkpoint(scan_id)
        if not cp:
            return None

        phase = cp.get("phase") or ""
        if phase:
            self.set_phase(scan_id, phase)

        # Re-enqueue any tasks captured in the checkpoint that are not already
        # pending/running, so workers can pick them back up after a crash.
        remaining = cp.get("remaining_tasks") or []
        live_ids = {t["task_id"] for t in self.pending_tasks(scan_id)}
        requeued: list[str] = []
        for task in remaining:
            tid = task.get("task_id")
            if not tid or tid in live_ids:
                continue
            self.upsert_task(
                tid,
                scan_id,
                agent=task.get("agent", ""),
                objective=task.get("objective", ""),
                phase=task.get("phase", phase),
                status="pending",
                parent_task_id=task.get("parent_task_id"),
                payload=_loads(task.get("payload")),
            )
            requeued.append(tid)

        with self._write() as c:
            c.execute("UPDATE scans SET status='running', updated_at=? WHERE scan_id=?;", (_now(), scan_id))
        self.add_event(
            scan_id,
            "resume",
            "scan_state_db",
            {"checkpoint_id": cp.get("checkpoint_id"), "phase": phase, "requeued": requeued},
        )
        return {
            "checkpoint": cp,
            "phase": phase,
            "pending_tasks": self.pending_tasks(scan_id),
            "budgets": cp.get("budgets") or {},
            "agent_health": cp.get("agent_health") or {},
            "graph_snapshot": cp.get("graph_snapshot") or {},
        }

    # ── Skills + learning (Architecture §5.3, §13.2, §13.3) ───────────────────

    def upsert_skill(
        self,
        skill_id: str,
        *,
        name: str,
        domain: str,
        risk_class: str,
        promotion_state: str = "candidate",
        success_rate: float = 0.0,
        failure_rate: float = 0.0,
        meta: dict | None = None,
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO skills (skill_id, name, domain, risk_class, promotion_state, "
                "success_rate, failure_rate, meta, updated_at) VALUES (?,?,?,?,?,?,?,?,?);",
                (
                    skill_id,
                    name,
                    domain,
                    risk_class,
                    promotion_state,
                    success_rate,
                    failure_rate,
                    json.dumps(meta or {}),
                    _now(),
                ),
            )

    def record_learning_update(
        self, update_id: str, scan_id: str, *, kind: str, subsystem: str, detail: dict | None = None
    ) -> None:
        with self._write() as c:
            c.execute(
                "INSERT OR REPLACE INTO learning_updates (update_id, scan_id, kind, subsystem, detail, created_at) "
                "VALUES (?,?,?,?,?,?);",
                (update_id, scan_id, kind, subsystem, json.dumps(detail or {}), _now()),
            )

    # ── Search (Architecture §5.6 FTS) ────────────────────────────────────────

    def search(self, query: str, *, scan_id: str | None = None, limit: int = 25) -> list[dict]:
        if not self._fts_enabled or not query:
            return []
        sql = "SELECT scan_id, kind, ref_id, text FROM search_index WHERE search_index MATCH ?"
        params: list[Any] = [query]
        if scan_id:
            sql += " AND scan_id=?"
            params.append(scan_id)
        sql += " LIMIT ?;"
        params.append(limit)
        with self._lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:
                return []
        return [dict(r) for r in rows]

    # ── Maintenance ────────────────────────────────────────────────────────────

    def checkpoint_wal(self) -> None:
        with self._lock, suppress(sqlite3.OperationalError):
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception as e:
                logger.debug("[ScanStateDB] close error: %s", e)


# Global durable scan-state store.
scan_state_db = ScanStateDB()
