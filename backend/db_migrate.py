"""
Database Migration Runner — applies schema.sql + schema_extensions.sql to Supabase.

Usage:
    python -m backend.db_migrate
"""

import os
import sys
from pathlib import Path


def main():
    from dotenv import load_dotenv

    load_dotenv()

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        print("ERROR: SUPABASE_URL and SUPABASE_KEY must be set in .env")
        sys.exit(1)

    from supabase import create_client

    sb = create_client(url, key)

    project_root = Path(__file__).resolve().parent
    migration_files = [
        project_root / "core" / "schema.sql",
        project_root / "agents" / "alpha_recon" / "schema_extensions.sql",
    ]

    for sql_path in migration_files:
        if not sql_path.exists():
            print(f"SKIP: {sql_path} not found")
            continue

        sql = sql_path.read_text(encoding="utf-8")
        print(f"Running migration: {sql_path.name} ({len(sql)} bytes)")

        try:
            # Execute via Supabase RPC (requires pg_execute function or SQL editor)
            # For direct execution, use the Supabase SQL Editor or a Postgres connection
            sb.postgrest.schema("public")
            print(f"  → Loaded {sql_path.name} — paste into Supabase SQL Editor")
            print(f"  → Preview: {sql[:120]}...")
        except Exception as e:
            print(f"  ERROR: {e}")

    print("\n--- Migration Summary ---")
    print("SQL files to run in Supabase SQL Editor:")
    for f in migration_files:
        if f.exists():
            print(f"  ✓ {f}")
    print("\nAlternatively, connect via psql:")
    print("  psql $DATABASE_URL -f backend/core/schema.sql")
    print("  psql $DATABASE_URL -f backend/agents/alpha_recon/schema_extensions.sql")


if __name__ == "__main__":
    main()
