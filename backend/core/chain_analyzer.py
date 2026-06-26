import math
from typing import Any


class ChainAnalyzer:
    """
    RESEARCH-GRADE ATTACK CHAIN CORRELATOR (V2 — Enhanced)
    Transcribes atomic vulnerabilities into multi-step execution graphs
    mapping the lateral movement path of an attacker.

    V2 Enhancements:
    - Expanded chaining rules (JWT, path traversal, race condition)
    - Weighted confidence scoring (depth + severity + exploit complexity)
    - Chain simulation with attacker progression narrative
    """

    # ─── Enhanced Chain Transition Matrix ──────────────────────────────────
    TRANSITION_MATRIX = {
        "SQL_INJECTION": {"targets": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "IDOR", "DATA_LEAK"], "complexity": 0.7},
        "COMMAND_INJECTION": {"targets": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "RCE"], "complexity": 0.9},
        "SSRF": {"targets": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "IDOR", "INTERNAL_ACCESS"], "complexity": 0.8},
        "IDOR": {"targets": ["UNAUTHORIZED_ACCESS", "BROKEN_AUTH", "LOGIC_ESCALATION", "DATA_LEAK"], "complexity": 0.5},
        "XSS": {"targets": ["CSRF", "PROMPT_INJECTION", "SESSION_HIJACK"], "complexity": 0.4},
        "CROSS_SITE_SCRIPTING": {"targets": ["CSRF", "PROMPT_INJECTION", "SESSION_HIJACK"], "complexity": 0.4},
        "BROKEN_AUTH": {"targets": ["LOGIC_ESCALATION", "DATA_LEAK", "ADMIN_TAKEOVER"], "complexity": 0.6},
        "JWT_BYPASS": {"targets": ["BROKEN_AUTH", "UNAUTHORIZED_ACCESS", "ADMIN_TAKEOVER"], "complexity": 0.8},
        "PATH_TRAVERSAL": {"targets": ["DATA_LEAK", "RCE", "CONFIG_EXPOSURE"], "complexity": 0.6},
        "RACE_CONDITION": {"targets": ["LOGIC_ESCALATION", "FINANCIAL_MANIPULATION"], "complexity": 0.9},
        "UNAUTHORIZED_ACCESS": {"targets": ["DATA_LEAK", "ADMIN_TAKEOVER", "LOGIC_ESCALATION"], "complexity": 0.5},
    }

    IMPACT_WEIGHTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 1}

    def __init__(self, findings: list[dict[str, Any]]):
        self.raw_findings = findings
        self.nodes = []
        self._build_nodes()

    def _build_nodes(self):
        for f in self.raw_findings:
            payload = f.get("payload", {})
            vid = payload.get("id", str(hash(payload.get("url", ""))))
            vtype = str(payload.get("type", "Unknown")).upper()
            vurl = str(payload.get("url", "Target")).split("?")[0].lower()
            vimpact = payload.get("severity", "LOW").upper()
            self.nodes.append({"id": vid, "type": vtype, "endpoint": vurl, "impact": vimpact, "raw": f})

    def can_chain(self, src: dict[str, Any], dst: dict[str, Any]) -> bool:
        """Determines if an offensive step logically proceeds into another."""
        stype = src["type"]
        dtype = dst["type"]

        # Check transition matrix
        entry = self.TRANSITION_MATRIX.get(stype, {})
        if dtype in entry.get("targets", []):
            return True

        # Target Proximity: Same Endpoint (Chain of bugs on one parameter)
        return bool(src["endpoint"] == dst["endpoint"] and src["id"] != dst["id"] and stype != dtype)

    def build_chains(self) -> list[list[dict[str, Any]]]:
        """Uses DFS to extract full attack paths."""
        for a in self.nodes:
            a["edges"] = []
            for b in self.nodes:
                if a["id"] != b["id"] and self.can_chain(a, b):
                    a["edges"].append(b)

        chains = []

        def dfs(node, path):
            path.append(node)
            if not node.get("edges") or len(path) >= 5:
                if len(path) > 1:
                    chains.append(path.copy())
            else:
                for n in node["edges"]:
                    if n not in path:
                        dfs(n, path)
            path.pop()

        for n in self.nodes:
            dfs(n, [])

        # Deduplicate
        unique_chains = []
        seen = set()
        for c in chains:
            sig = "->".join([x["id"] for x in c])
            if sig not in seen:
                seen.add(sig)
                unique_chains.append(c)

        return sorted(unique_chains, key=lambda x: len(x), reverse=True)

    def score_chain(self, chain: list[dict[str, Any]]) -> int:
        """Basic impact score (backward compatible)."""
        score = 0
        for node in chain:
            score += self.IMPACT_WEIGHTS.get(node["impact"], 0)
        score += len(chain) * 15
        return min(score, 100)

    # ─── V2 UPGRADE: Weighted Confidence Scoring ──────────────────────────

    def confidence_score(self, chain: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Multi-factor confidence scoring for attack chains.
        Factors: depth bonus, severity escalation, transition complexity, endpoint diversity.
        Returns dict with numeric score and breakdown.
        """
        if len(chain) < 2:
            return {"score": 0, "grade": "N/A", "factors": {}}

        # Factor 1: Depth bonus (diminishing returns via log)
        depth_score = min(40, int(math.log2(len(chain) + 1) * 20))

        # Factor 2: Severity escalation (higher severity later = realistic chain)
        severity_vals = [self.IMPACT_WEIGHTS.get(n["impact"], 0) for n in chain]
        escalation_bonus = 0
        for i in range(1, len(severity_vals)):
            if severity_vals[i] >= severity_vals[i - 1]:
                escalation_bonus += 5
        escalation_bonus = min(25, escalation_bonus)

        # Factor 3: Transition complexity (how hard each hop is)
        complexity_total = 0
        for i in range(len(chain) - 1):
            entry = self.TRANSITION_MATRIX.get(chain[i]["type"], {})
            complexity_total += entry.get("complexity", 0.5)
        complexity_score = min(20, int((complexity_total / max(len(chain) - 1, 1)) * 20))

        # Factor 4: Endpoint diversity (chains spanning multiple endpoints are more realistic)
        unique_endpoints = len(set(n["endpoint"] for n in chain))
        diversity_score = min(15, unique_endpoints * 5)

        total = depth_score + escalation_bonus + complexity_score + diversity_score
        total = min(100, total)

        grade = "CRITICAL" if total >= 80 else "HIGH" if total >= 60 else "MEDIUM" if total >= 40 else "LOW"

        return {
            "score": total,
            "grade": grade,
            "factors": {
                "depth": depth_score,
                "escalation": escalation_bonus,
                "complexity": complexity_score,
                "diversity": diversity_score,
            },
        }

    # ─── V2 UPGRADE: Chain Simulation ─────────────────────────────────────

    def simulate_chain(self, chain: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Simulate an attack chain and generate a human-readable narrative
        describing the attacker's progression through each step.
        """
        if len(chain) < 2:
            return {"narrative": "Single finding — no chain to simulate.", "steps": []}

        steps = []
        for i, node in enumerate(chain):
            if i == 0:
                action = f"INITIAL ACCESS: Attacker exploits {node['type']} at {node['endpoint']}"
            elif i == len(chain) - 1:
                action = f"OBJECTIVE ACHIEVED: Attacker leverages {node['type']} at {node['endpoint']} for final impact"
            else:
                action = f"LATERAL MOVE: Attacker pivots via {node['type']} at {node['endpoint']}"

            steps.append(
                {
                    "step": i + 1,
                    "action": action,
                    "vuln_type": node["type"],
                    "endpoint": node["endpoint"],
                    "severity": node["impact"],
                }
            )

        narrative = " → ".join(f"{s['vuln_type']}({s['endpoint']})" for s in steps)
        conf = self.confidence_score(chain)

        return {
            "narrative": narrative,
            "steps": steps,
            "chain_length": len(chain),
            "confidence": conf,
            "risk_grade": conf["grade"],
        }
