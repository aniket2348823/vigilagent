from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

SUMMARIZATION_TOOL_NAME = "execute_task_and_return_summary"
FALLBACK_RESPONSE_CONTENT = "the call was not handled, please try again"


@dataclass
class BodyPair:
    ai_message: dict[str, Any]
    tool_messages: list[dict[str, Any]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return message_size(self.ai_message) + sum(message_size(item) for item in self.tool_messages)

    def tool_call_ids(self) -> set[str]:
        ids: set[str] = set()
        for call in self.ai_message.get("tool_calls", []) or []:
            if call.get("id"):
                ids.add(call["id"])
        return ids

    def response_ids(self) -> set[str]:
        return {msg.get("tool_call_id") for msg in self.tool_messages if msg.get("tool_call_id")}


@dataclass
class ChainSection:
    header: list[dict[str, Any]] = field(default_factory=list)
    body: list[BodyPair] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(message_size(item) for item in self.header) + sum(pair.size for pair in self.body)


@dataclass
class ConversationAST:
    sections: list[ChainSection] = field(default_factory=list)

    @classmethod
    def from_messages(cls, messages: list[dict[str, Any]], *, force: bool = True) -> ConversationAST:
        ast = cls()
        current: ChainSection | None = None
        current_pair: BodyPair | None = None

        for msg in messages:
            role = msg.get("role")
            if role in {"system", "user"}:
                if current is None or current.body:
                    current = ChainSection(header=[dict(msg)])
                    ast.sections.append(current)
                else:
                    current.header.append(dict(msg))
                current_pair = None
            elif role == "assistant":
                if current is None:
                    if not force:
                        raise ValueError("assistant message without header")
                    current = ChainSection()
                    ast.sections.append(current)
                current_pair = BodyPair(dict(msg), [])
                current.body.append(current_pair)
            elif role == "tool":
                if current_pair is None:
                    if not force:
                        raise ValueError("tool message without assistant tool call")
                    continue
                current_pair.tool_messages.append(dict(msg))

        if force:
            ast.repair_tool_pairs()
        return ast

    def to_messages(self) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        for section in self.sections:
            messages.extend(section.header)
            for pair in section.body:
                messages.append(pair.ai_message)
                messages.extend(pair.tool_messages)
        return messages

    @property
    def size(self) -> int:
        return sum(section.size for section in self.sections)

    def repair_tool_pairs(self) -> None:
        for section in self.sections:
            for pair in section.body:
                missing = pair.tool_call_ids() - pair.response_ids()
                for call_id in sorted(missing):
                    pair.tool_messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": _tool_name(pair.ai_message, call_id),
                            "content": FALLBACK_RESPONSE_CONTENT,
                        }
                    )
                unmatched = pair.response_ids() - pair.tool_call_ids()
                for call_id in sorted(unmatched):
                    pair.ai_message.setdefault("tool_calls", []).append(
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": "unknown_tool", "arguments": "{}"},
                        }
                    )

    def normalize_tool_call_ids(self, prefix: str = "call") -> dict[str, str]:
        mapping: dict[str, str] = {}
        for section in self.sections:
            for pair in section.body:
                for call in pair.ai_message.get("tool_calls", []) or []:
                    old = call.get("id")
                    if not old or not str(old).startswith(f"{prefix}_"):
                        new = f"{prefix}_{uuid.uuid4().hex[:16]}"
                        if old:
                            mapping[old] = new
                        call["id"] = new
                for msg in pair.tool_messages:
                    old = msg.get("tool_call_id")
                    if old in mapping:
                        msg["tool_call_id"] = mapping[old]
        return mapping


def message_size(msg: dict[str, Any]) -> int:
    return len(str(msg.get("content", "")).encode("utf-8", errors="replace")) + len(
        str(msg.get("tool_calls", "")).encode("utf-8", errors="replace")
    )


def _tool_name(ai_message: dict[str, Any], call_id: str) -> str:
    for call in ai_message.get("tool_calls", []) or []:
        if call.get("id") == call_id:
            return (call.get("function") or {}).get("name") or "unknown_tool"
    return "unknown_tool"
