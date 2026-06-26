#!/usr/bin/env python3
"""
Self-Awareness Migration Runner

This script runs database migrations for the self-aware agents feature.
It provides safe migration execution with rollback capability.

Usage:
    python run_migration.py migrate    # Apply migration
    python run_migration.py rollback   # Rollback migration
    python run_migration.py status     # Check migration status
"""

import asyncio
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# CRIT-20: Gate migration execution behind env var
MIGRATION_ALLOWED_ENV = os.environ.get("MIGRATION_ALLOWED", "").lower()
MIGRATION_GATED = MIGRATION_ALLOWED_ENV not in ("true", "1", "yes")


# CLI output helper — print() is correct here since this is a CLI tool,
# not a library.  Logger output may be invisible depending on log config.
def _out(msg: str) -> None:
    print(msg, flush=True)


# CRIT-13: Whitelist of valid table names for status checks
_VALID_TABLES = frozenset(
    {
        "agent_proficiency",
        "agent_performance",
        "agent_decisions",
        "agent_adaptations",
    }
)

from backend.core.database import db_manager


class MigrationRunner:
    """Handles database migration execution"""

    def __init__(self):
        self.migrations_dir = Path(__file__).parent
        self.migrate_script = self.migrations_dir / "add_self_awareness_tables.sql"
        self.rollback_script = self.migrations_dir / "rollback_self_awareness_tables.sql"

    async def check_status(self) -> dict:
        """Check if self-awareness tables exist"""
        query = """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name IN ('agent_proficiency', 'agent_performance', 'agent_decisions', 'agent_adaptations')
        ORDER BY table_name;
        """

        try:
            await db_manager.initialize()
            results = await db_manager.fetch_all(query)

            tables_found = [row["table_name"] for row in results]
            expected_tables = ["agent_adaptations", "agent_decisions", "agent_performance", "agent_proficiency"]

            status = {
                "migrated": len(tables_found) == 4,
                "tables_found": tables_found,
                "tables_missing": [t for t in expected_tables if t not in tables_found],
                "partial_migration": 0 < len(tables_found) < 4,
            }

            return status

        except Exception as e:
            return {"error": str(e), "migrated": False}

    async def run_migration(self) -> bool:
        """Execute migration script"""
        if MIGRATION_GATED:
            _out("MIGRATION_ALLOWED=true must be set to run migrations.")
            return False
        _out("=" * 80)
        _out("SELF-AWARE AGENTS MIGRATION")
        _out("=" * 80)

        # Check current status
        _out("\n[1/4] Checking current migration status...")
        status = await self.check_status()

        if status.get("error"):
            _out(f"❌ Error checking status: {status['error']}")
            return False

        if status["migrated"]:
            _out("✅ Migration already applied. All tables exist.")
            return True

        if status["partial_migration"]:
            _out("⚠️  Partial migration detected!")
            _out(f"   Found: {status['tables_found']}")
            _out(f"   Missing: {status['tables_missing']}")
            _out("\n   Please rollback first, then re-run migration.")
            return False

        _out("✅ No existing tables found. Ready to migrate.")

        # Read migration script
        _out("\n[2/4] Reading migration script...")
        if not self.migrate_script.exists():
            _out(f"❌ Migration script not found: {self.migrate_script}")
            return False

        migration_sql = self.migrate_script.read_text(encoding="utf-8")
        _out(f"✅ Loaded migration script ({len(migration_sql)} bytes)")

        # Execute migration
        _out("\n[3/4] Executing migration...")
        try:
            await db_manager.initialize()
            await db_manager.execute(migration_sql)
            _out("✅ Migration executed successfully")
        except Exception as e:
            _out(f"❌ Migration failed: {e}")
            return False

        # Verify migration
        _out("\n[4/4] Verifying migration...")
        status = await self.check_status()

        if status["migrated"]:
            _out("✅ Migration verified successfully!")
            _out("\nCreated tables:")
            for table in status["tables_found"]:
                _out(f"  - {table}")
            return True
        else:
            _out("❌ Migration verification failed")
            _out(f"   Expected 4 tables, found {len(status['tables_found'])}")
            return False

    async def run_rollback(self) -> bool:
        """Execute rollback script"""
        if MIGRATION_GATED:
            _out("MIGRATION_ALLOWED=true must be set to rollback migrations.")
            return False
        _out("=" * 80)
        _out("SELF-AWARE AGENTS ROLLBACK")
        _out("=" * 80)

        # Check current status
        _out("\n[1/4] Checking current migration status...")
        status = await self.check_status()

        if status.get("error"):
            _out(f"❌ Error checking status: {status['error']}")
            return False

        if not status["migrated"] and not status["partial_migration"]:
            _out("✅ No tables to rollback. Database is clean.")
            return True

        _out(f"⚠️  Found {len(status['tables_found'])} tables to remove:")
        for table in status["tables_found"]:
            _out(f"   - {table}")

        # Confirm rollback
        _out("\n⚠️  WARNING: This will permanently delete all self-awareness data!")
        response = input("   Type 'yes' to confirm rollback: ")

        if response.lower() != "yes":
            _out("❌ Rollback cancelled")
            return False

        # Read rollback script
        _out("\n[2/4] Reading rollback script...")
        if not self.rollback_script.exists():
            _out(f"❌ Rollback script not found: {self.rollback_script}")
            return False

        rollback_sql = self.rollback_script.read_text(encoding="utf-8")
        _out(f"✅ Loaded rollback script ({len(rollback_sql)} bytes)")

        # Execute rollback
        _out("\n[3/4] Executing rollback...")
        try:
            await db_manager.initialize()
            await db_manager.execute(rollback_sql)
            _out("✅ Rollback executed successfully")
        except Exception as e:
            _out(f"❌ Rollback failed: {e}")
            return False

        # Verify rollback
        _out("\n[4/4] Verifying rollback...")
        status = await self.check_status()

        if not status["migrated"] and not status["partial_migration"]:
            _out("✅ Rollback verified successfully!")
            _out("   All self-awareness tables removed.")
            return True
        else:
            _out("❌ Rollback verification failed")
            _out(f"   Found {len(status['tables_found'])} remaining tables")
            return False

    async def print_status(self):
        """Print current migration status"""
        _out("=" * 80)
        _out("SELF-AWARE AGENTS MIGRATION STATUS")
        _out("=" * 80)

        status = await self.check_status()

        if status.get("error"):
            _out(f"\n❌ Error: {status['error']}")
            return

        _out(f"\nMigration Status: {'✅ MIGRATED' if status['migrated'] else '❌ NOT MIGRATED'}")

        if status["tables_found"]:
            _out(f"\nTables Found ({len(status['tables_found'])}/4):")
            for table in status["tables_found"]:
                _out(f"  ✅ {table}")

        if status["tables_missing"]:
            _out(f"\nTables Missing ({len(status['tables_missing'])}/4):")
            for table in status["tables_missing"]:
                _out(f"  ❌ {table}")

        if status["partial_migration"]:
            _out("\n⚠️  WARNING: Partial migration detected!")
            _out("   Run rollback, then re-run migration.")

        _out()


async def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        _out("Usage: python run_migration.py [migrate|rollback|status]")
        sys.exit(1)

    command = sys.argv[1].lower()
    runner = MigrationRunner()

    try:
        if command == "migrate":
            success = await runner.run_migration()
            sys.exit(0 if success else 1)

        elif command == "rollback":
            success = await runner.run_rollback()
            sys.exit(0 if success else 1)

        elif command == "status":
            await runner.print_status()
            sys.exit(0)

        else:
            _out(f"Unknown command: {command}")
            _out("Usage: python run_migration.py [migrate|rollback|status]")
            sys.exit(1)

    except KeyboardInterrupt:
        _out("\n\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        _out(f"\n❌ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
