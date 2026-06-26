"""
v2 BROWSER-AWARE SKILL MIGRATION (deep-system-integration spec, Task 5.10)
==========================================================================

Migrates skills written under the legacy v1 schema to the v2 browser-aware
schema. v2 adds three required fields to every persisted skill:

    * ``version``               — semver string; defaults to ``"1.0.0"``
    * ``execution_context``     — ``"browser_required"`` or ``"http_only"``;
                                  v1 skills default to ``"http_only"``
    * ``required_capabilities`` — list[str]; v1 skills default to ``[]``

The migration is idempotent:
  * skills that already carry ``version`` AND ``execution_context`` AND
    ``required_capabilities`` are recognized as v2 and skipped
  * a sentinel file (``brain/skills/.v2_migration_complete``) is written on
    a fully successful run; subsequent runs short-circuit unless ``--force``
    is passed

Architecture invariants honored here:
  §11  two-LLM exclusivity   — pure file-rewrite, no LLM calls
  §17  ≥2-signal evidence    — migration does not promote/verify anything
  §29.13 non-blocking        — sync CLI, run from a worker not the API loop
  §9   scope-is-law          — host info on a skill is informational only;
                                this migration NEVER reads a skill's host
                                field as a scope grant

CLI:
    python -m backend.skills.migrations.v2_browser --apply          # run
    python -m backend.skills.migrations.v2_browser --apply --force  # ignore sentinel
    python -m backend.skills.migrations.v2_browser --dry-run        # report only
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("v2_browser_migration")

# --- Migration constants -------------------------------------------------
V2_VERSION_DEFAULT = "1.0.0"
V2_EXECUTION_CONTEXT_DEFAULT = "http_only"
V2_REQUIRED_CAPABILITIES_DEFAULT: list[str] = []
V2_SENTINEL = ".v2_migration_complete"
V2_REQUIRED_FIELDS = ("version", "execution_context", "required_capabilities")


# --- Internal helpers ----------------------------------------------------
def _is_v2(record: dict[str, Any]) -> bool:
    """Return True if a skill record already carries every v2 field."""
    return all(k in record for k in V2_REQUIRED_FIELDS)


def _upgrade_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``record`` with any missing v2 field filled in."""
    upgraded = dict(record)
    if "version" not in upgraded:
        upgraded["version"] = V2_VERSION_DEFAULT
    if "execution_context" not in upgraded:
        # v1 skills are HTTP unless they already carry browser-y fields.
        # We err on the side of "http_only" because misclassifying a
        # browser skill as http_only is a no-op (it just won't surface in
        # browser-only searches), whereas the inverse would route a real
        # http skill to a browser pool unnecessarily.
        upgraded["execution_context"] = V2_EXECUTION_CONTEXT_DEFAULT
    if "required_capabilities" not in upgraded:
        upgraded["required_capabilities"] = list(V2_REQUIRED_CAPABILITIES_DEFAULT)
    return upgraded


def _iter_skill_files(skills_dir: Path):
    """Yield every per-skill JSON file under ``skills_dir`` (recursive)."""
    if not skills_dir.exists():
        return
    for path in skills_dir.rglob("*.json"):
        # metadata.json lives at the top of skills_dir and is handled
        # separately at the end of the migration.
        if path.name == "metadata.json":
            continue
        yield path


# --- Public migration API ------------------------------------------------
def migrate(
    *,
    brain_dir: str = "brain",
    apply: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Run the v1 -> v2 browser-aware skill migration.

    Args:
        brain_dir: Brain directory root (mirrors SkillLibrary's default).
        apply:     When False, returns a report without writing any files.
        force:     When True, ignore the v2 sentinel and re-run the
                   migration even if it was previously completed.

    Returns:
        A report dict with: ``files_seen``, ``files_upgraded``,
        ``files_already_v2``, ``files_failed``, ``re_imported``,
        ``sentinel_written``, ``elapsed_seconds``, and ``failed_paths``.
    """
    started = time.time()
    skills_dir = Path(brain_dir) / "skills"
    sentinel_path = skills_dir / V2_SENTINEL

    report: dict[str, Any] = {
        "files_seen": 0,
        "files_upgraded": 0,
        "files_already_v2": 0,
        "files_failed": 0,
        "re_imported": 0,
        "sentinel_written": False,
        "elapsed_seconds": 0.0,
        "failed_paths": [],
        "skipped_due_to_sentinel": False,
    }

    # Idempotency short-circuit: sentinel present and not --force.
    if not force and sentinel_path.exists():
        report["skipped_due_to_sentinel"] = True
        report["elapsed_seconds"] = round(time.time() - started, 4)
        logger.info(
            "[v2_browser] sentinel present at %s; skipping (use --force to override)",
            sentinel_path,
        )
        return report

    # ---- 1. Walk every skill JSON and upgrade in place --------------
    upgraded_records: list[tuple[Path, dict[str, Any]]] = []
    for skill_path in _iter_skill_files(skills_dir):
        report["files_seen"] += 1
        try:
            record = json.loads(skill_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("[v2_browser] cannot read %s: %s", skill_path, e)
            report["files_failed"] += 1
            report["failed_paths"].append(str(skill_path))
            continue
        if not isinstance(record, dict):
            logger.warning("[v2_browser] %s is not a JSON object; skipping", skill_path)
            continue
        if _is_v2(record):
            report["files_already_v2"] += 1
            upgraded_records.append((skill_path, record))
            continue
        new_record = _upgrade_record(record)
        report["files_upgraded"] += 1
        upgraded_records.append((skill_path, new_record))
        if apply:
            try:
                skill_path.write_text(
                    json.dumps(new_record, indent=2),
                    encoding="utf-8",
                )
            except Exception as e:
                logger.error("[v2_browser] cannot write %s: %s", skill_path, e)
                report["files_failed"] += 1
                report["failed_paths"].append(str(skill_path))

    # ---- 2. Re-import every upgraded record through SkillLibrary ----
    # so the capability/context/framework indexes get populated. This is
    # done LAST so a partial failure on any single record doesn't corrupt
    # the on-disk JSON we just wrote.
    if apply:
        try:
            # Local imports keep this module importable even when running
            # from a fresh checkout where the skill_library global doesn't
            # initialise cleanly (e.g. during tests).
            from backend.core.skill_library import (
                BrowserSkill,
            )
            from backend.core.skill_library import (
                skill_library as _skill_library,
            )
        except Exception as e:
            logger.error("[v2_browser] cannot import SkillLibrary; re-import phase skipped: %s", e)
        else:
            for skill_path, record in upgraded_records:
                # Only browser-shape skills go through add_browser_skill;
                # http_only skills are already in the library — they only
                # needed the JSON field upgrade and the capability/context
                # indexes are tagged via metadata refresh below.
                if record.get("execution_context") != "browser_required":
                    continue
                try:
                    skill = BrowserSkill.from_dict(record)
                except Exception as e:
                    logger.error("[v2_browser] cannot rehydrate browser skill from %s: %s", skill_path, e)
                    continue
                try:
                    # add_browser_skill returns False on duplicate skill_id;
                    # that's fine — it means the skill is already indexed.
                    if _skill_library.add_browser_skill(skill, {}):
                        report["re_imported"] += 1
                except Exception as e:
                    logger.error(
                        "[v2_browser] add_browser_skill failed for %s: %s",
                        skill_path,
                        e,
                    )

            # Refresh indexes once at the end so http_only skills also pick
            # up their (empty) required_capabilities entry where applicable.
            try:
                from backend.core.skill_library import browser_skill_library

                browser_skill_library._rebuild_indexes()
            except Exception as e:
                logger.warning("[v2_browser] index rebuild failed (non-fatal): %s", e)

    # ---- 3. Drop the sentinel so re-runs short-circuit --------------
    if apply and report["files_failed"] == 0:
        try:
            skills_dir.mkdir(parents=True, exist_ok=True)
            sentinel_path.write_text(
                json.dumps(
                    {
                        "completed_at": time.time(),
                        "files_seen": report["files_seen"],
                        "files_upgraded": report["files_upgraded"],
                        "schema_version": "v2_browser",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            report["sentinel_written"] = True
        except Exception as e:
            logger.warning("[v2_browser] sentinel write failed: %s", e)

    report["elapsed_seconds"] = round(time.time() - started, 4)
    return report


# --- CLI -----------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.skills.migrations.v2_browser",
        description=(
            "Migrate persisted skills to v2 browser-aware schema. "
            "Adds version='1.0.0', execution_context='http_only', "
            "required_capabilities=[] when missing. Idempotent."
        ),
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--apply",
        action="store_true",
        help="Write upgraded records to disk and re-import through SkillLibrary.",
    )
    g.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be migrated without writing anything.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Ignore the v2 sentinel and re-run even if previously completed.",
    )
    parser.add_argument(
        "--brain-dir",
        default="brain",
        help="Brain directory (default: 'brain').",
    )
    return parser


def main(argv: list[str] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-7s %(name)s :: %(message)s",
    )
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    report = migrate(
        brain_dir=args.brain_dir,
        apply=bool(args.apply),
        force=bool(args.force),
    )

    print(json.dumps(report, indent=2, default=str))
    # Non-zero exit if any record failed to migrate.
    return 1 if report["files_failed"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
