from __future__ import annotations

from backend.core.approval import approval_store
from backend.core.tool_registry import ToolDefinition, tool_registry
from backend.core.tool_types import ToolType
from backend.modules.tech.jwt import crack_hs256_secret, forge_alg_none, forge_hs256, parse_jwt


async def http_request_tool(
    method: str,
    url: str,
    headers: dict | None = None,
    json_body: dict | None = None,
    data: str | None = None,
    approved_state_change: bool = False,
    scan_id: str = "GLOBAL",
):
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and not approved_state_change:
        approval_store.require(
            scan_id=scan_id,
            tool_name="http_request",
            reason=f"{method.upper()} {url} changes remote state and requires approval.",
            payload={"method": method.upper(), "url": url},
        )
    from backend.modules.tech.http_client import http_client  # deferred: aiohttp chain

    record = await http_client.request(
        method,
        url,
        headers=headers or {},
        json=json_body,
        data=data,
        approved_state_change=approved_state_change,
        scan_id=scan_id,
    )
    return record.__dict__


async def sandbox_run_tool(command: str, timeout: int = 120, scan_id: str = "GLOBAL"):
    from backend.core.sandbox import DockerSandbox  # deferred: docker SDK chain

    sandbox = DockerSandbox()
    result = await sandbox.run(command, engagement_id=scan_id, timeout=timeout)
    return result.__dict__


def jwt_parse_tool(token: str):
    return parse_jwt(token)


def jwt_forge_none_tool(token: str, claim_overrides: dict | None = None):
    return {"token": forge_alg_none(token, claim_overrides or {})}


def jwt_forge_hs256_tool(token: str, secret: str, claim_overrides: dict | None = None):
    return {"token": forge_hs256(token, secret, claim_overrides or {})}


def jwt_crack_hs256_tool(token: str, candidates: list[str]):
    return {"secret": crack_hs256_secret(token, candidates)}


def recon_tool_inventory_tool():
    from backend.tools.recon import RECON_TOOLS, check_tool_availability  # deferred: recon chain

    return [
        {
            "name": spec.name,
            "phase": spec.phase,
            "passive": spec.passive,
            "modes": [mode.value for mode in spec.modes],
            "availability": check_tool_availability(spec).model_dump(mode="json"),
        }
        for spec in RECON_TOOLS
    ]


def register_default_tools() -> None:
    if tool_registry.exists("http_request"):
        return

    tool_registry.register(
        ToolDefinition(
            name="http_request",
            description="Send a scoped HTTP request, record request/response evidence, and return the captured record.",
            tool_type=ToolType.SEARCH_NETWORK,
            handler=http_request_tool,
            mutates_state=False,
            requires_approval=False,
            store_result=True,
            parameters={
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "json_body": {"type": "object"},
                    "data": {"type": "string"},
                    "approved_state_change": {"type": "boolean"},
                },
            },
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="sandbox_run",
            description="Run a command inside the scan Docker sandbox.",
            tool_type=ToolType.ENVIRONMENT,
            handler=sandbox_run_tool,
            requires_approval=True,
            summarize_result=True,
            store_result=True,
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
            },
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="jwt_parse",
            description="Parse JWT header, payload, signature, and algorithm.",
            tool_type=ToolType.ANALYSIS,
            handler=jwt_parse_tool,
            parameters={"type": "object", "properties": {"token": {"type": "string"}}},
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="jwt_forge_none",
            description="Forge a JWT with alg=none for controlled verification.",
            tool_type=ToolType.ANALYSIS,
            handler=jwt_forge_none_tool,
            requires_approval=True,
            parameters={
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                    "claim_overrides": {"type": "object"},
                },
            },
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="jwt_forge_hs256",
            description="Forge a JWT signed with an explicit HS256 secret for controlled verification.",
            tool_type=ToolType.ANALYSIS,
            handler=jwt_forge_hs256_tool,
            requires_approval=True,
            parameters={
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                    "secret": {"type": "string"},
                    "claim_overrides": {"type": "object"},
                },
            },
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="jwt_crack_hs256",
            description="Try candidate secrets against an HS256 JWT signature.",
            tool_type=ToolType.ANALYSIS,
            handler=jwt_crack_hs256_tool,
            parameters={
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                    "candidates": {"type": "array", "items": {"type": "string"}},
                },
            },
        )
    )
    tool_registry.register(
        ToolDefinition(
            name="recon_tool_inventory",
            description="List Alpha V6 recon tool capabilities, phases, modes, and local availability.",
            tool_type=ToolType.ANALYSIS,
            handler=recon_tool_inventory_tool,
            summarize_result=True,
            store_result=True,
            parameters={"type": "object", "properties": {}},
        )
    )


