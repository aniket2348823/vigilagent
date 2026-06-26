from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from backend.core.strict_schema import ensure_strict_json_schema
from backend.core.tool_types import ToolType, get_tool_type

ToolHandler = Callable[..., Awaitable[Any] | Any]


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    handler: ToolHandler | None = None
    tool_type: ToolType = ToolType.NONE
    requires_approval: bool = False
    mutates_state: bool = False
    summarize_result: bool = True
    store_result: bool = False
    strict_parameters: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        self.tool_type = self.tool_type if self.tool_type != ToolType.NONE else get_tool_type(self.name)
        self.strict_parameters = ensure_strict_json_schema(self.parameters)

    def llm_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.strict_parameters,
            },
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> ToolDefinition:
        self._tools[definition.name] = definition
        return definition

    def decorator(self, **kwargs: Any):
        def _wrap(handler: ToolHandler) -> ToolHandler:
            self.register(ToolDefinition(handler=handler, **kwargs))
            return handler

        return _wrap

    def get(self, name: str) -> ToolDefinition:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def exists(self, name: str) -> bool:
        return name in self._tools

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.llm_schema() for tool in self._tools.values()]

    def by_type(self, tool_type: ToolType) -> list[ToolDefinition]:
        return [tool for tool in self._tools.values() if tool.tool_type == tool_type]


tool_registry = ToolRegistry()
