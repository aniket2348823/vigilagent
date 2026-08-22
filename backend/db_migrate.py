"""
Database Migration Runner — applies the Vigilagent schema to Supabase.

Usage:
    python -m backend.db_migrate

Two paths:

1. **Auto-apply (preferred):** set ``SUPABASE_DATABASE_URL`` in ``.env`` to your
   Supabase connection string (Project Settings → Database → Connection string
   → Pooler, the ``postgresql://...`` URL — use the "Transaction" pooler for
   migrations so it survives long-running statements). Requires ``asyncpg``
   (``pip install asyncpg``). This connects directly to Postgres and executes
   ``supabase/migrations/001_initial_schema.sql`` (everything is
   ``CREATE ... IF NOT EXISTS``, so re-running is safe), then prints a
   per-table present/missing report.

2. **Manual:** without a connection string, prints the exact SQL file to paste
   into the Supabase SQL Editor and verifies nothing.

The PostgREST API (used by the app's anon/service key) cannot run DDL, which
is why the migration needs either a direct DB connection (path 1) or the SQL
Editor (path 2).
"""

import asyncio
import os
import sys
from pathlib import Path

# Tables the backend queries/writes via the Supabase client. The probe reports
# which of these exist after the migration so missing ones are obvious.
REQUIRED_TABLES = [
    "distributed_tasks",
    "recon_runs",
    "agent_proficiency",
    "toolcalls",
    "semantic_memory",
    "agent_decisions",
    "vulnerabilities",
    "task_assignments",
    "scan_episodes",
    "recon_tool_outputs",
    "recon_relationships",
    "recon_oob_interactions",
    "recon_entities",
    "recon_endpoint_scores",
    "recon_artifacts",
    "http_responses",
    "http_requests",
    "exploit_results",
    "approvals",
]

_MIGRATION_FILE = Path(__file__).resolve().parent.parent / "supabase" / "migrations" / "001_initial_schema.sql"


def _split_statements(sql: str) -> list[str]:
    """Split SQL on TOP-LEVEL semicolons only.

    asyncpg's execute() accepts one statement per call, so the migration file
    must be split. A naive ``str.split(";")`` breaks inside ``DO $$ ... $$``
    blocks and single-quoted strings, so scan char-by-char and only treat ``;``
    as a terminator outside dollar-quoted bodies (``$$`` / ``$tag$``) and
    single-quoted strings (with ``''`` escapes).
    """
    import re

    statements: list[str] = []
    current: list[str] = []
    i, n = 0, len(sql)
    in_dollar: str | None = None

    def _flush() -> None:
        stmt = "".join(current).strip()
        if stmt:
            # Drop pure-comment header lines but keep the SQL in mixed
            # fragments (a comment above a CREATE TABLE must not discard it).
            kept = [ln for ln in stmt.splitlines() if ln.strip() and not ln.strip().startswith("--")]
            clean = "\n".join(kept).strip()
            if clean:
                statements.append(clean)
        current.clear()

    while i < n:
        c = sql[i]
        if in_dollar:
            if sql.startswith(in_dollar, i):
                current.append(in_dollar)
                i += len(in_dollar)
                in_dollar = None
                continue
            current.append(c)
            i += 1
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_0-9]*\$", sql[i:])
            if m:
                in_dollar = m.group(0)
                current.append(in_dollar)
                i += len(in_dollar)
                continue
            current.append(c)
            i += 1
            continue
        if c == "'":
            current.append(c)
            i += 1
            while i < n:
                if sql[i] == "'":
                    current.append("'")
                    i += 1
                    if i < n and sql[i] == "'":  # '' escape inside string
                        current.append("'")
                        i += 1
                        continue
                    break
                current.append(sql[i])
                i += 1
            continue
        if c == ";":
            _flush()
            i += 1
            continue
        current.append(c)
        i += 1
    _flush()
    return statements


async def _apply_with_asyncpg(conn_string: str) -> None:
    import asyncpg  # local import: dependency is optional

    sql = _MIGRATION_FILE.read_text(encoding="utf-8")
    print(f"Applying {_MIGRATION_FILE.name} ({len(sql)} bytes) ...")
    # statement_cache_size=0: the Supabase Transaction pooler (supavisor/
    # pgbouncer transaction mode) rejects asyncpg prepared statements, which
    # otherwise breaks multi-statement migrations and verification queries.
    conn = await asyncpg.connect(conn_string, timeout=30, statement_cache_size=0)
    try:
        statements = _split_statements(sql)
        applied = 0
        for stmt in statements:
            await conn.execute(stmt)
            applied += 1
        print(f"Migration executed successfully ✓ ({applied} statements)")
    finally:
        await conn.close()


async def _verify(conn_string: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(conn_string, timeout=30, statement_cache_size=0)
    try:
        rows = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1::text[]);",
            REQUIRED_TABLES,
        )
    finally:
        await conn.close()

    present = {r["tablename"] for r in rows}
    missing = [t for t in REQUIRED_TABLES if t not in present]
    print(f"Tables present: {len(present)}/{len(REQUIRED_TABLES)}")
    if missing:
        print("Still missing:")
        for t in missing:
            print(f"  ✗ {t}")
        print("Re-run the migration or paste the SQL into the Supabase SQL Editor.")
    else:
        print("All required tables present ✓ — Supabase persistence is ready.")


def _manual_instructions() -> None:
    if not _MIGRATION_FILE.exists():
        print(f"ERROR: migration file not found: {_MIGRATION_FILE}")
        sys.exit(1)
    print(f"\n--- Manual path ---")
    print(f"1. Open {_MIGRATION_FILE.name} and copy its contents.")
    print(f"2. Supabase Dashboard → SQL Editor → paste → Run (safe to re-run).")
    print(f"3. Restart the backend.")
    print(f"\nOr, for automated application:")
    print(f"   - Add SUPABASE_DATABASE_URL to .env (Project Settings → Database →")
    print(f"     Connection string → Pooler → Transaction, postgresql://...).")
    print(f"   - pip install asyncpg")
    print(f"   - Run this command again: python -m backend.db_migrate")


def _env_values() -> dict[str, str]:
    """Values from the project .env file, NOT the process environment.

    Reading the file directly (instead of load_dotenv + os.getenv) makes the
    migration tool immune to stale DATABASE_URL values left in a long-running
    shell session (a dead IPv6-only hostname was observed overriding the fixed
    .env value). CI deployments that inject env vars still work: anything the
    file does not define falls back to os.getenv below.
    """
    from dotenv import dotenv_values

    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        return {k: v for k, v in dotenv_values(env_file).items() if v is not None}
    return {}


def main() -> None:
    file_env = _env_values()

    # .env file wins (single source of truth the user edits); OS env is only a
    # fallback for CI-style deployments that inject values.
    url = file_env.get("SUPABASE_URL") or os.getenv("SUPABASE_URL")
    key = file_env.get("SUPABASE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        print("ERROR: SUPABASE_URL and SUPABASE_KEY must be set in .env")
        sys.exit(1)

    conn_string = file_env.get("SUPABASE_DATABASE_URL") or file_env.get("DATABASE_URL")
    if not conn_string:
        conn_string = os.getenv("SUPABASE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not conn_string:
        print("SUPABASE_DATABASE_URL not set — using manual path.")
        _manual_instructions()
        sys.exit(0)

    try:
        asyncio.run(_apply_with_asyncpg(conn_string))
        asyncio.run(_verify(conn_string))
    except ModuleNotFoundError:
        print("ERROR: asyncpg is not installed. Run `pip install asyncpg`, then retry.")
        print("Until then, use the manual path:")
        _manual_instructions()
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - CLI tool: report and exit
        print(f"ERROR: migration failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
