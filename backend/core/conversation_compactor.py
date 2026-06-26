from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from backend.core.conversation_ast import BodyPair, ConversationAST

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger("ConversationCompactor")


MAX_CHAIN_BYTES = 64 * 1024
MAX_BODY_PAIR_BYTES = 16 * 1024
PRESERVE_LAST_SECTION_BYTES = 50 * 1024


async def compact_messages(
    messages: list[dict],
    *,
    max_bytes: int = MAX_CHAIN_BYTES,
    summarizer: Callable[[str], Awaitable[str]] | None = None,
) -> list[dict]:
    ast = ConversationAST.from_messages(messages, force=True)
    if ast.size <= max_bytes:
        return ast.to_messages()

    if len(ast.sections) > 1:
        old_sections = ast.sections[:-1]
        summary = await _summarize_text(_sections_text(old_sections), summarizer)
        ast.sections = ast.sections[-1:]
        ast.sections.insert(0, _summary_section(summary))

    last = ast.sections[-1] if ast.sections else None
    if last and last.size > PRESERVE_LAST_SECTION_BYTES:
        compacted: list[BodyPair] = []
        overflow: list[BodyPair] = []
        running = sum(len(str(msg)) for msg in last.header)
        for pair in reversed(last.body):
            if pair.size > MAX_BODY_PAIR_BYTES:
                summary = await _summarize_text(str(pair.tool_messages), summarizer)
                pair.tool_messages = [
                    {
                        "role": "tool",
                        "tool_call_id": next(iter(pair.tool_call_ids()), "summary"),
                        "name": "summarized_tool_output",
                        "content": summary,
                    }
                ]
            if running + pair.size <= PRESERVE_LAST_SECTION_BYTES:
                compacted.insert(0, pair)
                running += pair.size
            else:
                overflow.insert(0, pair)
        if overflow:
            summary = await _summarize_text(str([pair.ai_message for pair in overflow]), summarizer)
            compacted.insert(
                0, BodyPair({"role": "assistant", "content": f"[Older interaction summary]\n{summary}"}, [])
            )
        last.body = compacted

    return ast.to_messages()


async def _summarize_text(text: str, summarizer: Callable[[str], Awaitable[str]] | None) -> str:
    if summarizer:
        try:
            return await summarizer(text)
        except Exception as exc:
            logger.debug(f"[ConversationCompactor] summarizer failed: {exc}")
            # Summarizer failure is non-fatal; fall through to fallback.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    head = " ".join(lines[:12])
    return head[:1800] or "Older conversation/tool output summarized due to context limits."


def _sections_text(sections) -> str:
    chunks: list[str] = []
    for section in sections:
        chunks.extend(str(msg) for msg in section.header)
        for pair in section.body:
            chunks.append(str(pair.ai_message))
            chunks.extend(str(msg) for msg in pair.tool_messages)
    return "\n".join(chunks)


def _summary_section(summary: str):
    from backend.core.conversation_ast import ChainSection

    return ChainSection(header=[{"role": "system", "content": f"[Conversation summary]\n{summary}"}], body=[])
