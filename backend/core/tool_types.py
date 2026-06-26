from enum import StrEnum


class ToolType(StrEnum):
    NONE = "none"
    ENVIRONMENT = "environment"
    SEARCH_NETWORK = "search_network"
    SEARCH_VECTOR_DB = "search_vector_db"
    AGENT = "agent"
    STORE_AGENT_RESULT = "store_agent_result"
    STORE_VECTOR_DB = "store_vector_db"
    BARRIER = "barrier"
    SCAN = "scan"
    ANALYSIS = "analysis"
    REPORT = "report"
    USER = "user"


class BarrierException(RuntimeError):
    def __init__(self, tool_name: str, reason: str, payload: dict | None = None):
        super().__init__(reason)
        self.tool_name = tool_name
        self.reason = reason
        self.payload = payload or {}


TOOL_TYPE_MAPPING = {
    "done": ToolType.BARRIER,
    "ask": ToolType.BARRIER,
    "ask_user": ToolType.BARRIER,
    "terminal": ToolType.ENVIRONMENT,
    "file": ToolType.ENVIRONMENT,
    "browser": ToolType.SEARCH_NETWORK,
    "google": ToolType.SEARCH_NETWORK,
    "duckduckgo": ToolType.SEARCH_NETWORK,
    "tavily": ToolType.SEARCH_NETWORK,
    "sploitus": ToolType.SEARCH_NETWORK,
    "search_in_memory": ToolType.SEARCH_VECTOR_DB,
    "graphiti_search": ToolType.SEARCH_VECTOR_DB,
    "store_guide": ToolType.STORE_VECTOR_DB,
    "store_answer": ToolType.STORE_VECTOR_DB,
    "store_code": ToolType.STORE_VECTOR_DB,
    "maintenance": ToolType.AGENT,
    "coder": ToolType.AGENT,
    "pentester": ToolType.AGENT,
    "advice": ToolType.AGENT,
    "report_result": ToolType.STORE_AGENT_RESULT,
    "subtask_list": ToolType.STORE_AGENT_RESULT,
    "subtask_patch": ToolType.STORE_AGENT_RESULT,
    "nmap": ToolType.SCAN,
    "nuclei": ToolType.SCAN,
    "httpx": ToolType.SCAN,
    "ffuf": ToolType.SCAN,
}

STATE_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_tool_type(name: str) -> ToolType:
    return TOOL_TYPE_MAPPING.get((name or "").lower(), ToolType.NONE)


def require_barrier(tool_name: str, *, reason: str, payload: dict | None = None) -> None:
    raise BarrierException(tool_name=tool_name, reason=reason, payload=payload)


def enforce_state_change_barrier(method: str, approved: bool, *, url: str = "", tool_name: str = "http") -> None:
    if method.upper() in STATE_MUTATING_METHODS and not approved:
        require_barrier(
            tool_name,
            reason=f"{method.upper()} {url} changes remote state and requires Omega or human approval.",
            payload={"method": method.upper(), "url": url},
        )


def tools_by_type(tool_type: ToolType) -> list[str]:
    return [name for name, mapped in TOOL_TYPE_MAPPING.items() if mapped == tool_type]


def is_barrier_tool(name: str) -> bool:
    return get_tool_type(name) in {ToolType.BARRIER, ToolType.USER}
