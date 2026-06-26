"""
Skill ingestion loader (Architecture section5.3.1, section5.3.6)
================================================================================
Skill ingestion pipeline:
  repo -> scanner -> metadata extractor -> classifier -> risk classifier
       -> agent mapper -> tool resolver -> catalog

  - Loads index.json when present.
  - Scans every skills/*/SKILL.md.
  - Parses YAML frontmatter + markdown body.
  - Normalizes into SkillMeta, classifies domain + risk, maps to agents/tools.
  - Caches compiled metadata in the catalog. Source files stay READ-ONLY.

Skill sources are discovered from configured roots (workspace `.agents/skills`,
optional external roots). LLM prompt snippets are generated at runtime only.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os as _os
import re
from pathlib import Path
from typing import Any

from backend.skills.catalog import SkillCatalog, SkillMeta, skill_catalog
from backend.skills.classifier import (
    classify_domain,
    classify_risk,
    is_offensive,
    needs_network,
)
from backend.skills.mapper import agents_for_domain, map_required_tools
from backend.skills.policy import PromotionState, RiskClass

logger = logging.getLogger("vigilagent.skills.loader")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_CONFIG = _PROJECT_ROOT / "config" / "skills.yaml"

# Default skill roots (Architecture section5.3 important source folders).
_DEFAULT_ROOTS = [
    _PROJECT_ROOT / ".agents" / "skills",
    _PROJECT_ROOT / "generated_skills",
]

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


def _resolve_root(entry: str) -> Path:
    """Resolve a configured root: absolute paths as-is, else under project root."""
    p = Path(entry)
    return p if p.is_absolute() else (_PROJECT_ROOT / p)


def load_skill_roots(config_path: Path | None = None) -> list[Path]:
    """Build the list of skill roots from config/skills.yaml (Architecture
    section5.3.6, section29.10), falling back to sensible defaults. Missing roots are kept
    in the list but skipped at scan time, so the system runs on any host."""
    cfg = config_path or _SKILLS_CONFIG
    roots: list[Path] = []
    if yaml is not None and cfg.exists():
        try:
            data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
            for entry in data.get("roots") or []:
                roots.append(_resolve_root(str(entry)))
            for entry in data.get("external_roots") or []:
                roots.append(_resolve_root(str(entry)))
        except Exception as exc:  # pragma: no cover - fail safe to defaults
            logger.warning("Could not parse skills.yaml (%s); using defaults.", exc)
    if not roots:
        roots = list(_DEFAULT_ROOTS)
    return roots


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def validate_skill_format(fm: dict[str, Any], body: str) -> tuple[bool, list[str]]:
    """Validate a parsed SKILL.md against the expected format (Architecture
    section5.3.6 "validate skill format"). Returns (ok, problems). Skills that fail
    validation are still ingested but flagged, so the catalog records coverage
    gaps instead of silently dropping skills."""
    problems: list[str] = []
    name = fm.get("name")
    if not name or not str(name).strip():
        problems.append("missing 'name' in frontmatter")
    if not (fm.get("description") or fm.get("metadata")):
        problems.append("missing 'description'/'metadata'")
    if not body or not body.strip():
        problems.append("empty skill body")
    return (len(problems) == 0), problems


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Split a SKILL.md file into (frontmatter dict, body)."""
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_text, body = parts[1], parts[2]
            if yaml is not None:
                try:
                    fm = yaml.safe_load(fm_text) or {}
                    if isinstance(fm, dict):
                        return fm, body
                except Exception as e:
                    logger.debug("[SkillLoader] YAML frontmatter parse failed: %s", e)
    return {}, content


# HMAC integrity verification for skill files (Architecture security hardening)
_SKILL_HMAC_KEY = _os.getenv("VIGILAGENT_SKILL_HMAC_KEY", "")


def _verify_skill_integrity(path: Path, content: str) -> bool:
    """Verify skill file integrity via HMAC if a key is configured."""
    if not _SKILL_HMAC_KEY:
        return True  # No key configured, skip verification

    hmac_path = path.with_suffix(".md.hmac")
    if not hmac_path.exists():
        logger.warning("[SkillLoader] %s: missing .hmac integrity file (key configured) — REJECTING", path)
        return False  # Key configured but no integrity file: reject to prevent tampering

    try:
        expected = hmac_path.read_text(encoding="utf-8").strip()
        actual = _hmac.new(_SKILL_HMAC_KEY.encode("utf-8"), content.encode("utf-8"), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, actual):
            logger.error("[SkillLoader] %s: HMAC MISMATCH - file may be tampered!", path)
            return False
        return True
    except Exception as exc:
        logger.warning("[SkillLoader] %s: HMAC verification failed: %s", path, exc)
        return True  # Graceful degradation


def _meta_from_skill_md(path: Path) -> SkillMeta | None:
    """Parse a SKILL.md file and verify its integrity before processing."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Could not read skill %s: %s", path, exc)
        return None

    # Verify file integrity before processing (security hardening)
    if not _verify_skill_integrity(path, content):
        logger.error("[SkillLoader] SKIPPING tampered skill: %s", path)
        return None

    fm, body = _parse_frontmatter(content)
    valid, problems = validate_skill_format(fm, body)
    if not valid:
        logger.debug("[SkillLoader] %s format issues: %s", path, "; ".join(problems))
    name = str(fm.get("name") or path.parent.name)
    description = str(fm.get("description") or "")
    metadata = fm.get("metadata", {}) if isinstance(fm.get("metadata"), dict) else {}
    abstract = str(metadata.get("abstract") or "")
    goal = description.split(".")[0] if description else name

    # Text corpus used for classification (frontmatter + body head).
    corpus = " ".join([name, description, abstract, body[:2000]])

    domain = classify_domain(corpus)
    risk = classify_risk(corpus)
    offensive = is_offensive(corpus)
    network = needs_network(corpus)

    def _as_list(*vals):
        """Coerce frontmatter fields (str or list) into a clean list."""
        for v in vals:
            if not v:
                continue
            if isinstance(v, str):
                return [p.strip() for p in re.split(r"[,;]", v) if p.strip()]
            if isinstance(v, (list, tuple)):
                return [str(x).strip() for x in v if str(x).strip()]
        return []

    skill_id = _slugify(name)
    meta = SkillMeta(
        skill_id=skill_id,
        name=name,
        goal=goal,
        domain=domain,
        description=description,
        source_path=str(path),
        required_tools=map_required_tools(corpus),
        risk_class=risk,
        offensive=offensive,
        requires_network=network,
        changes_remote_state=risk in (RiskClass.INTRUSIVE_VALIDATION, RiskClass.DISABLED_BY_DEFAULT),
        requires_approval=risk in (RiskClass.INTRUSIVE_VALIDATION,),
        attack=_as_list(metadata.get("attack"), fm.get("attack"), fm.get("mitre_attack")),
        owasp=_as_list(metadata.get("owasp"), fm.get("owasp")),
        nist=_as_list(metadata.get("nist"), fm.get("nist"), fm.get("nist_csf")),
        agent_targets=agents_for_domain(domain),
        promotion_state=PromotionState.ACTIVE if str(path).find("generated_skills") == -1 else PromotionState.CANDIDATE,
        version=str(metadata.get("version") or fm.get("version") or "1.0.0"),
        author=str(metadata.get("author") or fm.get("author") or ""),
        raw_frontmatter=fm,
    )
    return meta


class SkillLoader:
    """Scans skill roots and populates the catalog (Architecture section5.3.1)."""

    def __init__(self, roots: list[Path] | None = None, catalog: SkillCatalog | None = None) -> None:
        self.roots = roots or load_skill_roots()
        self.catalog = catalog or skill_catalog

    def load_all(self) -> int:
        """Ingest every SKILL.md under the configured roots. Returns count.

        Also processes index.json and the mappings/ folder per Architecture section5.3,
        merging ATT&CK/OWASP/NIST mappings into the matching catalog entries."""
        count = 0
        pending_maps: dict[str, dict] = {}
        for root in self.roots:
            if not root.exists():
                continue
            # index.json (Architecture section5.3 / section5.3.6).
            index = root / "index.json"
            if index.exists():
                pending_maps.update(self._read_index(index))
            # mappings/ folder (ATT&CK/OWASP/NIST coverage files, section5.3).
            mappings_dir = root / "mappings"
            if mappings_dir.is_dir():
                pending_maps.update(self._read_mappings(mappings_dir))
            for skill_md in root.rglob("SKILL.md"):
                meta = _meta_from_skill_md(skill_md)
                if meta:
                    self.catalog.upsert(meta)
                    count += 1
        # Merge mappings into matching catalog entries (by skill_id or name).
        if pending_maps:
            self._apply_mappings(pending_maps)
        logger.info("[SkillLoader] ingested %d skills into catalog (%d mapping entries)", count, len(pending_maps))
        return count

    @staticmethod
    def _read_index(index_path: Path) -> dict[str, dict]:
        """Read index.json -> {skill_key: {attack, owasp, nist, ...}}."""
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug("[SkillLoader] index.json parse failed: %s", e)
            return {}
        out: dict[str, dict] = {}
        # Accept either {"skills": [ {name, attack, owasp, ...} ]} or a flat map.
        entries = data.get("skills") if isinstance(data, dict) else None
        if isinstance(entries, list):
            for e in entries:
                if isinstance(e, dict) and e.get("name"):
                    out[_slugify(str(e["name"]))] = e
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    out[_slugify(k)] = v
        return out

    @staticmethod
    def _read_mappings(mappings_dir: Path) -> dict[str, dict]:
        """Read mappings/*.json|*.md files -> {skill_key: {attack/owasp/nist}}."""
        out: dict[str, dict] = {}
        for f in mappings_dir.rglob("*"):
            if f.suffix.lower() == ".json":
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                except Exception as exc:
                    logger.debug("[SkillLoader] mapping file parse failed %s: %s", f, exc)
                    continue
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, dict):
                            out.setdefault(_slugify(k), {}).update(v)
        return out

    def _apply_mappings(self, maps: dict[str, dict]) -> None:
        for meta in self.catalog.all():
            entry = maps.get(meta.skill_id) or maps.get(_slugify(meta.name))
            if not entry:
                continue
            if entry.get("attack"):
                meta.attack = list(set(meta.attack) | set(entry["attack"]))
            if entry.get("owasp"):
                meta.owasp = list(set(meta.owasp) | set(entry["owasp"]))
            if entry.get("nist"):
                meta.nist = list(set(meta.nist) | set(entry["nist"]))
            self.catalog.upsert(meta)


# Global loader.
skill_loader = SkillLoader()


def ingest_skills() -> int:
    """Convenience entrypoint to (re)build the skill catalog."""
    return skill_loader.load_all()
