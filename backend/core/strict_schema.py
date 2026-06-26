from __future__ import annotations

from copy import deepcopy
from typing import Any


def ensure_strict_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a tool/function JSON schema into the stricter provider-safe shape:
    explicit required keys, no extra object properties, and strict nested objects.
    """
    root = deepcopy(schema or {})
    return _ensure_strict(root, root)


def _ensure_strict(node: Any, root: dict[str, Any]) -> Any:
    if isinstance(node, list):
        return [_ensure_strict(item, root) for item in node]
    if not isinstance(node, dict):
        return node

    if "$ref" in node and len(node) == 1:
        return node

    schema_type = node.get("type")
    if schema_type == "object" or "properties" in node:
        props = node.get("properties") or {}
        node["properties"] = {key: _ensure_strict(value, root) for key, value in props.items()}
        node["required"] = sorted(props.keys())
        node["additionalProperties"] = False

    if "items" in node:
        node["items"] = _ensure_strict(node["items"], root)

    for combiner in ("anyOf", "allOf", "oneOf"):
        if combiner in node:
            node[combiner] = [_ensure_strict(item, root) for item in node[combiner]]

    if "$defs" in node:
        node["$defs"] = {key: _ensure_strict(value, root) for key, value in node["$defs"].items()}

    if "definitions" in node:
        node["definitions"] = {key: _ensure_strict(value, root) for key, value in node["definitions"].items()}

    return node


def resolve_ref(*, root: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"Only local JSON schema refs are supported: {ref}")
    current: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"Unresolved schema ref: {ref}")
        current = current[part]
    return current
