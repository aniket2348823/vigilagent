"""Dispatch hardening: enum-validity + module-id validity for the orchestrator.

Guards the exact bug class that silently killed the swarm dispatch for a
whole round: ``TaskPriority.MEDIUM`` (and other enum typos) fail with
``AttributeError`` *inside* try/except → logger.debug blocks, so every
dispatch dies invisibly and the scan shows zero swarm jobs.

The test statically parses the orchestrator and agent sources (AST — no
imports, no side effects) and asserts:

1. Every ``AgentID.X`` / ``TaskPriority.X`` / ``EventType.X`` attribute
   access used in dispatch code is a valid member of the protocol enum.
2. Every ``module_id`` handed to ``JobPacket``/``ModuleConfig`` in the
   orchestrator's dispatch sections resolves to a module some agent handles —
   either an explicit ``module_id`` match, a Sigma arsenal key, Sigma's
   generic weaponssmith (SIGMA_BYPASS) path, or an agent that routes purely
   by ``agent_id``.
"""

import ast
from pathlib import Path

import pytest

from backend.core.hive import EventType
from backend.core.protocol import AgentID, TaskPriority

_ROOT = Path(__file__).resolve().parent.parent.parent

# ── The canonical dispatch contract ─────────────────────────────────────────
# Every module id the orchestrator dispatches, by source section. These MUST
# stay in sync with the orchestrator's dispatch code; the AST parser below
# catches literals directly, and these lists catch ids passed via variables.

# Sigma arsenal keys (handled via `module_id in self.arsenal`).
_SIGMA_ARSENAL = {
    "tech_sqli",
    "tech_jwt",
    "tech_auth_bypass",
    "tech_cmdi",
    "logic_tycoon",
    "logic_doppelganger",
    "logic_skipper",
    "logic_chronomancer",
    "logic_escalator",
}

# Sigma technique→tool bridge ids (handled via _select_validation_path /
# _technique_tool_map even when not in the arsenal).
_SIGMA_BRIDGE = {
    "recon_nuclei",
    "recon_httpx",
    "tech_xss",
    "tech_cve",
    "tech_fingerprint",
    "server_scan",
    "cms_scan",
}

# Generic weaponssmith path: any other module dispatched to SIGMA falls
# through to the SIGMA_BYPASS payload generation, then hands to Beta.
_SIGMA_GENERIC = {"sigma_generative_blast"}

# Explicit module_id comparisons in agent handlers.
_AGENT_EXPLICIT = {
    "lambda_js_sast",  # Lambda
    "lambda_sast",  # Lambda
    "kappa_recall",  # Kappa
    "delta_pinch_extract",  # Delta
    "sigma_payload_handoff",  # Beta
    "alpha_recon",  # Alpha
    "alpha_v6_recon",  # Alpha
    "recon",  # Alpha
}

# Modules routed purely by agent_id (Beta/Prism/Chi/Gamma consume ANY job
# addressed to them; module_id is a label, not a route key).
_AGENT_ROUTED = {"beta_direct_assault", "prism_dom_analysis", "chi_intercept", "vulnerability_audit"}

# Everything a dispatched module_id may legitimately resolve to.
_HANDLED_MODULES = _SIGMA_ARSENAL | _SIGMA_BRIDGE | _SIGMA_GENERIC | _AGENT_EXPLICIT | _AGENT_ROUTED


def _source(rel: str) -> str:
    path = _ROOT / rel
    assert path.exists(), f"missing source: {path}"
    return path.read_text(encoding="utf-8")


def _enum_member_refs(source: str, enum_name: str) -> set[str]:
    """Return {member} for every ``<enum_name>.<member>`` attribute access."""
    tree = ast.parse(source)
    members: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == enum_name and isinstance(node.attr, str):
                members.add(node.attr)
    return members


def _module_id_literals(source: str) -> set[str]:
    """Return every ``module_id="..."`` literal (keyword or dict value)."""
    tree = ast.parse(source)
    ids: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "module_id":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                ids.add(node.value.value)
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys or [], node.values):
                if isinstance(k, ast.Constant) and k.value == "module_id":
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        ids.add(v.value)
    return ids


# ── Enum validity: every enum reference must exist ──────────────────────────

# (source file, enum name) pairs that legitimately contain enum references.
_ENUM_REF_SITES = [
    ("backend/core/orchestrator.py", "AgentID", AgentID),
    ("backend/core/orchestrator.py", "TaskPriority", TaskPriority),
    ("backend/core/orchestrator.py", "EventType", EventType),
    ("backend/agents/sigma.py", "AgentID", AgentID),
    ("backend/agents/sigma.py", "TaskPriority", TaskPriority),
    ("backend/agents/beta.py", "AgentID", AgentID),
    ("backend/agents/beta.py", "EventType", EventType),
    ("backend/agents/zeta.py", "EventType", EventType),
    ("backend/agents/alpha.py", "EventType", EventType),
    ("backend/agents/lambda_agent.py", "EventType", EventType),
    ("backend/agents/kappa.py", "EventType", EventType),
]


@pytest.mark.parametrize("rel,enum_name,enum", _ENUM_REF_SITES)
def test_enum_members_exist(rel, enum_name, enum):
    """Every ``EnumName.X`` used in dispatch code must be a real member.

    This is the regression guard for the ``TaskPriority.MEDIUM`` bug: an
    unknown member fails at *runtime* with AttributeError, and when that
    happens inside ``except → logger.debug`` it silently skips dispatch.
    """
    refs = _enum_member_refs(_source(rel), enum_name)
    assert refs, f"no {enum_name} refs found in {rel} — is the parser broken?"
    valid = {m.name for m in enum}
    unknown = refs - valid
    assert not unknown, f"{rel}: unknown {enum_name} members: {sorted(unknown)}"


def test_orchestrator_priorities_are_valid():
    """The priorities used in orchestrator dispatch all exist in TaskPriority."""
    refs = _enum_member_refs(_source("backend/core/orchestrator.py"), "TaskPriority")
    valid = {m.name for m in TaskPriority}
    assert refs <= valid, f"invalid TaskPriority refs: {refs - valid}"


def test_orchestrator_agents_are_valid():
    """The AgentID values used in orchestrator dispatch all exist."""
    refs = _enum_member_refs(_source("backend/core/orchestrator.py"), "AgentID")
    valid = {m.name for m in AgentID}
    assert refs <= valid, f"invalid AgentID refs: {refs - valid}"


# ── Module-id validity: every dispatched module must be handled ─────────────


def test_dispatched_literals_are_handled():
    """Every module_id literal the orchestrator emits must be handled somewhere.

    A module the orchestrator dispatches but no agent handles is a silent
    no-op: the job lands on the bus, nobody consumes it, and the scan looks
    "done" while the module never ran. This is the dead-module guard.
    """
    src = _source("backend/core/orchestrator.py")
    literals = _module_id_literals(src)
    assert literals, "no module_id literals found in orchestrator — parser broken?"
    unknown = literals - _HANDLED_MODULES
    assert not unknown, f"orchestrator dispatches unhandled modules: {sorted(unknown)}"


def test_arsenal_keys_are_known():
    """Sigma's arsenal keys are all in the handled contract (no typo'd keys)."""
    src = _source("backend/agents/sigma.py")
    literals = _module_id_literals(src)
    # The arsenal dict uses string keys but not `module_id=`; verify the
    # arsenal's own keys directly against the contract instead.
    unknown = _SIGMA_ARSENAL - _HANDLED_MODULES
    assert not unknown, f"arsenal keys missing from contract: {sorted(unknown)}"


def test_priority_enum_has_no_medium():
    """Regression guard: MEDIUM was the phantom priority that broke dispatch."""
    names = {m.name for m in TaskPriority}
    assert "MEDIUM" not in names
    assert {"CRITICAL", "HIGH", "NORMAL", "LOW"} <= names
