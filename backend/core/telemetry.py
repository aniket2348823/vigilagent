from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class TelemetrySpan:
    name: str
    kind: str = "span"
    attrs: dict[str, Any] = field(default_factory=dict)
    start: float = field(default_factory=time.time)
    end: float | None = None
    status: str = "running"
    error: str = ""

    @property
    def duration_ms(self) -> int:
        final = self.end or time.time()
        return int((final - self.start) * 1000)


class Telemetry:
    def __init__(self, max_spans: int = 5000) -> None:
        self.max_spans = max_spans
        self.spans: list[TelemetrySpan] = []

    @contextmanager
    def span(self, name: str, *, kind: str = "span", **attrs: Any) -> Iterator[TelemetrySpan]:
        span = TelemetrySpan(name=name, kind=kind, attrs=attrs)
        self.spans.append(span)
        self.spans = self.spans[-self.max_spans :]
        try:
            yield span
            span.status = "success"
        except Exception as exc:
            span.status = "error"
            span.error = str(exc)
            raise
        finally:
            span.end = time.time()

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.spans[-limit:]
        return [
            {
                "name": span.name,
                "kind": span.kind,
                "attrs": span.attrs,
                "status": span.status,
                "error": span.error,
                "duration_ms": span.duration_ms,
            }
            for span in rows
        ]


telemetry = Telemetry()
