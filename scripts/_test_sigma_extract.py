"""Test Sigma's per-tool finding extractors against real captured tool outputs."""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, ".")

# --- extractor logic copied from sigma._run_cli_validation for isolated testing ---
class _Bus:
    def __init__(self):
        self.events = []

    async def publish(self, ev):
        self.events.append(ev)


class _Ctx:
    def __init__(self, bus, tool, url):
        self.bus = bus
        self.tool = tool
        self.url = url
        self.events = []

    async def _publish(self, finding_type, f_url, severity, data, evidence):
        self.events.append(
            {
                "type": f"{self.tool.upper()}:{finding_type}",
                "url": f_url or self.url,
                "severity": str(severity).title(),
                "data": data,
            }
        )

    async def extract(self, raw):
        tool = self.tool
        if tool in ("nuclei", "dalfox"):
            for ln in raw.splitlines()[:50]:
                try:
                    finding = json.loads(ln)
                except Exception:
                    continue
                if not isinstance(finding, dict) or not finding.get("info"):
                    continue
                info = finding.get("info", {}) or {}
                tid = str(finding.get("template-id") or info.get("name") or tool)
                sev = str(info.get("severity") or "high").lower()
                await self._publish(tid, str(finding.get("matched-at") or self.url), sev, {}, finding)
        elif tool == "nikto":
            for ln in raw.splitlines():
                ln = ln.strip()
                if not ln.startswith("+"):
                    continue
                m = re.match(r"\+\s*\[\s*([0-9A-Za-z]+)\s*\]\s*(\S+):\s*(.+)", ln)
                if not m:
                    continue
                _id, _path, _msg = m.group(1), m.group(2), m.group(3)
                if _id.upper() in ("SSL", "OSVDB", "SERVER"):
                    continue
                await self._publish(f"nikto-{_id}", str(urljoin(self.url, _path)), "medium", {}, ln)
        elif tool == "wpscan":
            try:
                doc = json.loads(raw)
            except Exception:
                doc = None
            if isinstance(doc, dict) and doc.get("scan_aborted"):
                pass
            elif isinstance(doc, dict):
                version = doc.get("version") or {}
                vl = []
                if isinstance(doc.get("vulnerabilities"), list):
                    vl = doc["vulnerabilities"]
                if isinstance(version.get("vulnerabilities"), list):
                    vl += version["vulnerabilities"]
                for v in vl[:30]:
                    v_id = str(v.get("id") or v.get("title") or "wpscan-finding")
                    sev = str(v.get("severity") or (v.get("cvss") or {}).get("severity") or "high").lower()
                    await self._publish(v_id, self.url, sev, {}, v)
        elif tool == "sqlmap":
            lines = raw.splitlines()
            for i, ln in enumerate(lines):
                m = re.search(r"parameter '([^']+)' is vulnerable", ln, re.IGNORECASE)
                if not m:
                    continue
                _param = m.group(1)
                _detail = [ln]
                for nxt in lines[i : i + 8]:
                    if re.match(r"\s*(Parameter|Type|Payload|Title|Vector):", nxt):
                        _detail.append(nxt.strip())
                _block = "\n".join(_detail)[:600]
                await self._publish(f"sqli:{_param}", self.url, "critical", {}, _block)


async def main():
    d = Path("data/scans/NEWTOOLS/sigma")

    # 1. sqlmap text output
    sqlmap_raw = (d / "sqlmap.out").read_text(encoding="utf-8", errors="replace")
    bus = _Bus()
    ctx = _Ctx(bus, "sqlmap", "http://localhost:8888/vulnerabilities/sqli/?id=1")
    await ctx.extract(sqlmap_raw)
    print("sqlmap findings:", len(ctx.events))
    for e in ctx.events[:3]:
        print("  -", e["type"], e["severity"])
    assert any("sqli" in e["type"] for e in ctx.events), "sqlmap finding missing!"

    # 2. nikto text report
    nikto_raw = (d / "nikto.out").read_text(encoding="utf-8", errors="replace")
    ctx2 = _Ctx(bus, "nikto", "http://localhost:8888/login.php")
    await ctx2.extract(nikto_raw)
    print("nikto findings:", len(ctx2.events))
    for e in ctx2.events[:3]:
        print("  -", e["type"], "|", e["url"])
    assert len(ctx2.events) > 0, "nikto findings missing!"

    # 3. wpscan non-WP (should be 0 findings, no crash)
    wp_raw = (d / "wpscan.out").read_text(encoding="utf-8", errors="replace")
    ctx3 = _Ctx(bus, "wpscan", "http://localhost:8888/login.php")
    await ctx3.extract(wp_raw)
    print("wpscan findings (non-WP target):", len(ctx3.events))
    assert len(ctx3.events) == 0

    # 4. wpscan with a fake WP doc containing vulnerabilities
    fake_wp = json.dumps({
        "version": {"number": "6.4.3", "vulnerabilities": [
            {"id": "CVE-2024-0001", "title": "Core XSS", "severity": "high"}
        ]}
    })
    ctx4 = _Ctx(bus, "wpscan", "http://localhost:8888/login.php")
    await ctx4.extract(fake_wp)
    print("wpscan findings (WP target):", len(ctx4.events))
    assert len(ctx4.events) == 1 and ctx4.events[0]["type"].endswith("CVE-2024-0001")

    # 5. nuclei JSONL
    nuclei_raw = (d.parent.parent / "scans/HIVE-V5-c5766c4cc8/raw/nuclei_default_login.jsonl")
    if nuclei_raw.exists():
        ctx5 = _Ctx(bus, "nuclei", "http://localhost:8888")
        await ctx5.extract(nuclei_raw.read_text(encoding="utf-8", errors="replace"))
        print("nuclei findings:", len(ctx5.events))
        assert len(ctx5.events) == 1 and "dvwa-default-login" in ctx5.events[0]["type"]

    print("ALL_EXTRACT_OK")


import asyncio

asyncio.run(main())
