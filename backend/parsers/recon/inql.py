"""Parser for inql GraphQL introspection output.

inql writes per-target JSON (introspection schema) and/or query files. We
extract the GraphQL types/queries/mutations as endpoint+schema entities. The
parser is tolerant of both the raw introspection JSON and inql's summary JSON.
"""

from __future__ import annotations

from pathlib import Path

from backend.parsers.recon.base import ParsedEntity, safe_json_file


def _collect_types(schema: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (queries, mutations, types) names from an introspection schema."""
    queries: list[str] = []
    mutations: list[str] = []
    types: list[str] = []
    data = schema.get("data", schema)
    s = data.get("__schema", {}) if isinstance(data, dict) else {}
    qroot = (s.get("queryType") or {}).get("name", "")
    mroot = (s.get("mutationType") or {}).get("name", "")
    for t in s.get("types", []) or []:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", ""))
        if not name or name.startswith("__"):
            continue
        types.append(name)
        if name == qroot:
            queries = [str(f.get("name", "")) for f in t.get("fields", []) or [] if isinstance(f, dict)]
        elif name == mroot:
            mutations = [str(f.get("name", "")) for f in t.get("fields", []) or [] if isinstance(f, dict)]
    return queries, mutations, types


def parse_inql_output(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    p = Path(path)
    # inql may emit a stdout text file; try to locate a sibling JSON schema.
    data = safe_json_file(path)
    if not data and p.exists():
        for sibling in p.parent.glob("*.json"):
            data = safe_json_file(sibling)
            if data:
                break
    if not isinstance(data, dict):
        return entities

    queries, mutations, types = _collect_types(data)
    if not (queries or mutations or types):
        return entities

    entities.append(
        ParsedEntity(
            kind="graphql_schema",
            label="graphql_introspection",
            confidence=0.85,
            properties={
                "query_count": len(queries),
                "mutation_count": len(mutations),
                "type_count": len(types),
                "queries": queries[:50],
                "mutations": mutations[:50],
            },
            source_tool="inql",
            phase="api_reconnaissance",
        )
    )
    for m in mutations:
        if m:
            entities.append(
                ParsedEntity(
                    kind="graphql_mutation",
                    label=m,
                    confidence=0.8,
                    properties={"operation": "mutation", "risk": "HIGH"},
                    source_tool="inql",
                    phase="api_reconnaissance",
                )
            )
    return entities
