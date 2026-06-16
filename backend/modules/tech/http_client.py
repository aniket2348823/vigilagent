import difflib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from backend.core.content_boundary import content_boundary
from backend.core.database import db_manager
from backend.core.unified_knowledge_graph import knowledge_graph
from backend.core.proxy import network_interceptor
from backend.core.scope import ScopePolicy
from backend.core.stdout_watchdog import watch_output
from backend.core.tool_types import enforce_state_change_barrier


@dataclass
class HTTPRecord:
    id: str
    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Any = None
    status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    _MAX_BODY_LEN = 50000  # FIX-022: Truncate to prevent memory exhaustion
    elapsed_ms: int = 0
    created_at: float = field(default_factory=time.time)


class BoundedHTTPHistory:
    def __init__(self, max_items: int = 500):
        self.max_items = max_items
        self._items: OrderedDict[str, HTTPRecord] = OrderedDict()
        self._counter = 0

    def add(self, record: HTTPRecord) -> HTTPRecord:
        # FIX-022: Truncate oversized response bodies to prevent memory exhaustion
        if len(record.response_body) > HTTPRecord._MAX_BODY_LEN:
            record.response_body = record.response_body[:HTTPRecord._MAX_BODY_LEN] + "\n[TRUNCATED_BY_BOUNDED_HISTORY]"
        self._items[record.id] = record
        self._items.move_to_end(record.id)
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return record

    def get(self, record_id: str) -> HTTPRecord | None:
        return self._items.get(record_id)

    def next_id(self) -> str:
        self._counter += 1
        return f"REQ-{self._counter:05d}"

    def diff(self, left_id: str, right_id: str) -> str:
        left = self.get(left_id)
        right = self.get(right_id)
        if not left or not right:
            raise KeyError("Both request ids must exist in history")
        return "\n".join(difflib.unified_diff(
            left.response_body.splitlines(),
            right.response_body.splitlines(),
            fromfile=left_id,
            tofile=right_id,
            lineterm="",
        ))


class ReplayHTTPClient:
    def __init__(self, history: BoundedHTTPHistory | None = None, scope: ScopePolicy | None = None):
        self.history = history or BoundedHTTPHistory()
        self.cookie_jar: aiohttp.CookieJar | None = None
        self.scope = scope
        self._session: aiohttp.ClientSession | None = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: Any = None,
        data: Any = None,
        approved_state_change: bool = False,
        scan_id: str = "GLOBAL",
        timeout: int = 15,
    ) -> HTTPRecord:
        enforce_state_change_barrier(method, approved_state_change, url=url, tool_name="http_client")
        if self.scope:
            self.scope.assert_allowed(url, action=f"{method.upper()} request")
        if self.cookie_jar is None:
            self.cookie_jar = aiohttp.CookieJar(unsafe=False)
        start = time.time()
        # Reuse cached session for connection pooling (HIGH-1 fix)
        if self._session is None or self._session.closed:
            if self.cookie_jar is None:
                self.cookie_jar = aiohttp.CookieJar(unsafe=False)
            self._session = aiohttp.ClientSession(
                cookie_jar=self.cookie_jar,
                timeout=aiohttp.ClientTimeout(total=timeout),
            )
        try:
            response = await network_interceptor.fetch(
                method,
                url,
                session=self._session,
                headers=headers,
                json=json,
                data=data,
                timeout=timeout,
            )
            body = response.body
            safe_body = content_boundary.wrap_http_response(response.status, response.headers, body, response.url)
            watched = await watch_output(safe_body)
            record = HTTPRecord(
                id=self.history.next_id(),
                method=method.upper(),
                url=url,
                request_headers=headers or {},
                request_body=json if json is not None else data,
                status=response.status,
                response_headers=response.headers,
                response_body=watched.content,
                elapsed_ms=response.elapsed_ms,
            )
            self.history.add(record)
            await db_manager.log_http_exchange(
                scan_id=scan_id,
                request_id=record.id,
                method=record.method,
                url=record.url,
                request_headers=record.request_headers,
                request_body=record.request_body,
                status=record.status,
                response_headers=record.response_headers,
                response_body=record.response_body,
                elapsed_ms=record.elapsed_ms,
            )
            knowledge_graph.ingest_http_record(record, scan_id=scan_id)
            return record
        except Exception:
            # On connection errors, discard session so next request creates fresh one
            if self._session and not self._session.closed:
                await self._session.close()
            self._session = None
            raise

    async def replay(self, record_id: str, **overrides: Any) -> HTTPRecord:
        record = self.history.get(record_id)
        if not record:
            raise KeyError(f"Unknown request id: {record_id}")
        return await self.request(
            overrides.get("method", record.method),
            overrides.get("url", record.url),
            headers=overrides.get("headers", record.request_headers),
            json=overrides.get("json", record.request_body if isinstance(record.request_body, dict) else None),
            data=overrides.get("data", None if isinstance(record.request_body, dict) else record.request_body),
            approved_state_change=overrides.get("approved_state_change", False),
            scan_id=overrides.get("scan_id", "GLOBAL"),
            timeout=overrides.get("timeout", 15),
        )


http_history = BoundedHTTPHistory()
http_client = ReplayHTTPClient(http_history)
