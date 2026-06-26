from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class InteractiveElement:
    ref: str
    role: str
    name: str
    tag: str
    selector: str
    value: str = ""
    checked: bool | None = None
    disabled: bool = False
    bounding_box: dict | None = None


@dataclass
class SemanticSnapshot:
    url: str
    title: str
    elements: list[InteractiveElement]
    raw_yaml: str
    forms: list[dict]
    timestamp: float


class DomParser:
    """
    Playwright ariaSnapshot handler mirroring OpenClaw's Semantic Playwright Perception.
    Converts raw HTML into semantic, clickable refs for the agents to attack SPAs.
    Bypasses raw HTML scraping by utilizing Playwright's Accessibility Tree.
    """

    def __init__(self):
        self._ref_counter = 0
        self._ref_map: dict[str, InteractiveElement] = {}

    def _generate_ref(self) -> str:
        self._ref_counter += 1
        return f"e{self._ref_counter}"

    async def get_semantic_snapshot(self, page: Any) -> SemanticSnapshot:
        """Captures full semantic state of the page."""
        logger.info("DOM Parser: Capturing full SemanticSnapshot...")
        url = page.url
        title = await page.title()

        # Native aria snapshot (fallback if not available)
        try:
            raw_yaml = await page.locator("body").aria_snapshot()
        except AttributeError:
            tree = await page.accessibility.snapshot()
            raw_yaml = self._parse_accessibility_tree(tree, 0)

        elements = await self.get_interactive_elements(page)
        forms = await self.detect_forms(page)

        snapshot = SemanticSnapshot(
            url=url, title=title, elements=elements, raw_yaml=raw_yaml, forms=forms, timestamp=time.time()
        )
        return snapshot

    async def get_interactive_elements(self, page: Any) -> list[InteractiveElement]:
        """Extracts all clickable/typable elements with unique refs."""
        elements = []
        tree = await page.accessibility.snapshot()

        def traverse(node: dict):
            role = node.get("role", "")
            if role in ["button", "link", "textbox", "checkbox", "combobox", "searchbox", "menuitem"]:
                ref = self._generate_ref()
                # Basic selector estimation based on role and name
                name = node.get("name", "")
                selector = self._build_selector(node)

                el = InteractiveElement(
                    ref=ref,
                    role=role,
                    name=name,
                    tag=node.get("tag", "unknown"),
                    selector=selector,
                    value=node.get("value", ""),
                    checked=node.get("checked"),
                    disabled=node.get("disabled", False),
                )
                elements.append(el)
                self._ref_map[ref] = el

            for child in node.get("children", []):
                traverse(child)

        traverse(tree)
        return elements

    async def click_element(self, page: Any, ref: str):
        """Clicks element by ref using page.mouse.click() with true hardware events."""
        if ref not in self._ref_map:
            raise ValueError(f"Unknown element reference: {ref}")

        el = self._ref_map[ref]
        logger.info(f"DOM Parser: Hardware clicking {el.role} '{el.name}' ({ref})")

        # If we have a selector, locate it, get bounding box, and click center
        locator = page.locator(el.selector).first
        box = await locator.bounding_box()
        if box:
            x = box["x"] + box["width"] / 2
            y = box["y"] + box["height"] / 2
            await page.mouse.click(x, y)
        else:
            # Fallback to standard click
            await locator.click()

    async def type_into_element(self, page: Any, ref: str, text: str):
        """Types text into input by ref using page.keyboard.type()."""
        if ref not in self._ref_map:
            raise ValueError(f"Unknown element reference: {ref}")

        el = self._ref_map[ref]
        logger.info(f"DOM Parser: Typing into {el.role} '{el.name}' ({ref})")

        locator = page.locator(el.selector).first
        await locator.focus()
        await page.keyboard.type(text)

    async def detect_forms(self, page: Any) -> list[dict]:
        """Detects form structures with action URLs and input fields."""
        forms = await page.evaluate("""() => {
            return Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                id: f.id,
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name,
                    type: e.type,
                    id: e.id
                }))
            }));
        }""")
        return forms

    def _parse_accessibility_tree(self, node: dict, indent: int = 0) -> str:
        """Recursively converts the accessibility tree into a textual format."""
        lines = []
        role = node.get("role", "unknown")
        name = node.get("name", "")

        if role in ["button", "link", "textbox", "checkbox", "combobox", "heading", "menuitem"]:
            indent_str = "  " * indent
            lines.append(f'{indent_str}- {role}: "{name}"')

        for child in node.get("children", []):
            child_text = self._parse_accessibility_tree(child, indent + 1)
            if child_text:
                lines.append(child_text)

        return "\n".join(lines)

    def _build_selector(self, node: dict) -> str:
        """Builds a CSS selector from an accessibility node."""
        role = node.get("role", "")
        name = node.get("name", "")

        # This is an approximation. Real Playwright locators are better.
        if name:
            return f'{role}[name="{name}" i]'
        return role

    def format_for_agent(self, snapshot: SemanticSnapshot) -> str:
        """Formats the snapshot as a clean text representation for LLM agents."""
        lines = [f"Page: {snapshot.title} ({snapshot.url})", "--- Interactive Elements ---"]
        for el in snapshot.elements:
            status = []
            if el.disabled:
                status.append("DISABLED")
            if el.checked is not None:
                status.append("CHECKED" if el.checked else "UNCHECKED")
            if el.value:
                status.append(f"value='{el.value}'")

            status_str = f" [{', '.join(status)}]" if status else ""
            lines.append(f'[{el.ref}] {el.role.upper()} "{el.name}"{status_str}')

        return "\n".join(lines)
