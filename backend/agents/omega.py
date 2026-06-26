import asyncio
import logging

from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskPriority, TaskTarget
from backend.core.queue import command_lane
from backend.core.unified_knowledge_graph import graph_engine

logger = logging.getLogger("AgentOmega")


class OmegaAgent(BrowserEnabledAgent):
    """
    AGENT OMEGA: THE STRATEGIST
    Role: Campaign Intelligence & Attack Chain Orchestration with Browser-Aware Strategies.

    Advanced Capabilities:
    1. LLM strategy reasoning (gpt-oss-20b) with deterministic evidence-weighted fallback
    2. Dynamic Campaign Chaining
    3. Graph-Driven Attack Prioritization (V6 Phase 2)
    4. Mid-Scan Strategy Adaptation
    5. Mission Planner Integration
    6. Browser-aware campaign planning for SPAs
    7. SPA detection and specialized strategies
    """

    def __init__(self, bus):
        super().__init__("agent_omega", bus)
        self._cortex = None  # Lazy-init via _get_cortex()

        # Campaign State
        self._active_campaigns = {}  # scan_id -> campaign state
        self._confirmed_vulns = []  # Accumulator for mid-scan adaptation
        self._job_results = {}  # job_id -> result tracking

        # Iterative reasoning-loop knobs (Hermes-style observe -> decide -> act).
        # `_max_campaign_actions` is Omega's analog of Hermes's IterationBudget:
        # the loop dispatches at most this many next-actions per campaign.
        self._max_campaign_actions = 12  # action/iteration budget
        self._min_action_value = 0.15  # value floor — stop when nothing clears it
        self._defense_pressure_stop = 0.5  # WAF/block pressure that halts expansion
        self._campaign_step_delay = 0.05  # yield so async evidence lands between steps

    def _get_cortex(self):
        if self._cortex is None:
            from backend.ai.cortex import get_cortex_engine

            try:
                self._cortex = get_cortex_engine()
            except Exception as e:
                logger.debug(f"[{self.name}] Cortex AI init deferred: {e}")
                self._cortex = None
        return self._cortex

    async def setup(self):
        self.bus.subscribe(EventType.TARGET_ACQUIRED, self.handle_target)
        self.bus.subscribe(EventType.VULN_CONFIRMED, self.handle_confirmed_vuln)
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_job_completed)
        self.bus.subscribe(EventType.PATTERN_LEARNED, self.handle_pattern_learned)

    async def handle_pattern_learned(self, event: HiveEvent):
        """PROBLEM 6: Receive intelligence from Kappa and boost relevant attack priority."""
        pattern = event.payload.get("pattern", {})
        vuln_type = pattern.get("vuln_type", "")
        logger.debug(
            f"[{self.name}] [ADAPT] Received pattern intelligence: {vuln_type} (confidence: {pattern.get('confidence', 0):.2f})"
        )
        # Boost priority of the attack type that just confirmed a hit
        for strategy_name, profile in self.STRATEGY_PROFILES.items():
            for module in profile.get("modules", []):
                if vuln_type.lower() in module.lower():
                    profile["aggression"] = min(10, profile.get("aggression", 5) + 2)
                    logger.debug(
                        f"[{self.name}] [BOOST] Strategy '{strategy_name}' aggression boosted to {profile['aggression']}"
                    )

    # --- STRATEGY SELECTION ---

    STRATEGY_PROFILES = {
        "E_COMMERCE_BLITZ": {
            "description": "Financial logic attack chain targeting pricing, coupons, and cart manipulation",
            "modules": ["logic_tycoon", "logic_escalator", "logic_skipper"],
            "aggression": 8,
            "priority": TaskPriority.CRITICAL,
        },
        "BLITZKRIEG": {
            "description": "Maximum aggression, all modules fire simultaneously",
            "modules": [
                "tech_sqli",
                "tech_fuzzer",
                "tech_jwt",
                "tech_auth_bypass",
                "logic_tycoon",
                "logic_doppelganger",
                "logic_skipper",
            ],
            "aggression": 10,
            "priority": TaskPriority.CRITICAL,
        },
        "LOW_AND_SLOW": {
            "description": "Stealth-focused sequential probing to avoid WAF detection",
            "modules": ["tech_fuzzer", "logic_chronomancer", "logic_doppelganger"],
            "aggression": 3,
            "priority": TaskPriority.LOW,
        },
        "MULTI_STEP_EXPLOIT": {
            "description": "Research-grade multi-vector pipeline with AI payload generation",
            "modules": ["sigma_generative_blast", "beta_direct_assault"],
            "aggression": 7,
            "priority": TaskPriority.HIGH,
        },
        "GRAPH_DRIVEN": {
            "description": "Prioritizes modules based on historical attack graph intelligence",
            "modules": [],  # Dynamically populated from graph predictions
            "aggression": 6,
            "priority": TaskPriority.HIGH,
        },
        "BROWSER_DEEP_RECON": {
            "description": "Browser-based deep reconnaissance for SPAs and modern web apps",
            "modules": ["alpha_browser_recon", "sigma_browser_payloads", "beta_browser_xss"],
            "aggression": 7,
            "priority": TaskPriority.HIGH,
            "browser_required": True,
        },
        "SPA_ASSAULT": {
            "description": "Specialized strategy for Single Page Applications",
            "modules": ["alpha_spa_recon", "beta_dom_xss", "sigma_framework_exploits"],
            "aggression": 8,
            "priority": TaskPriority.HIGH,
            "browser_required": True,
        },
    }

    def _select_strategy(self, target_url: str, ai_strategy: str = None, scan_id: str = "GLOBAL") -> str:
        """Selects optimal strategy from LLM recommendation + graph evidence.

        Order (Architecture §5.2, §29.4): (1) a valid LLM recommendation from
        gpt-oss-20b, (2) graph-driven historical confidence, (3) a deterministic
        evidence-weighted fallback (NOT random) based on defense pressure."""

        # 1. If the LLM gave a valid recommendation, use it
        if ai_strategy and ai_strategy in self.STRATEGY_PROFILES:
            return ai_strategy

        # 2. Check graph intelligence for historical patterns
        predictions = graph_engine.predict_next("TARGET_ACQUIRED", target_url)
        if predictions and predictions[0].get("confidence", 0) > 40:
            return "GRAPH_DRIVEN"

        # 3. Deterministic evidence-weighted selection (replaces fake "Nash"
        #    random.choices — Architecture §25, §29.4).
        return self._select_by_evidence(self._defense_pressure(scan_id))

    def _select_by_evidence(self, defense_pressure: float = 0.0) -> str:
        """Deterministic strategy selection by defense pressure (no randomness).

        Under high defense pressure (WAF/rate-limit signals) prefer stealth;
        otherwise prefer a balanced multi-vector pipeline. This is an explainable
        heuristic, not a game-theoretic randomization."""
        if defense_pressure >= 0.5:
            return "LOW_AND_SLOW"
        if defense_pressure >= 0.15:
            return "MULTI_STEP_EXPLOIT"
        return "MULTI_STEP_EXPLOIT"

    def _defense_pressure(self, scan_id: str) -> float:
        ctx = getattr(self.bus, "scan_contexts", {}).get(scan_id)
        transcript = ctx.transcript_text(tail=120).lower() if ctx and hasattr(ctx, "transcript_text") else ""
        if not transcript:
            return 0.0
        block_markers = transcript.count("403") + transcript.count("429") + transcript.count("blocked")
        return min(1.0, block_markers / 20.0)

    def _build_graph_driven_modules(self, target_url: str) -> list:
        """Queries the attack graph for the highest-confidence next modules."""
        MODULE_TYPE_MAP = {
            "SQL_INJECTION": "tech_sqli",
            "XSS": "tech_fuzzer",
            "CROSS_SITE_SCRIPTING": "tech_fuzzer",
            "JWT_BYPASS": "tech_jwt",
            "BROKEN_AUTH": "tech_auth_bypass",
            "IDOR": "logic_doppelganger",
            "RACE_CONDITION": "logic_chronomancer",
            "LOGIC_ESCALATION": "logic_escalator",
            "FINANCIAL_MANIPULATION": "logic_tycoon",
            "COMMAND_INJECTION": "tech_cmdi",
            "RCE": "tech_cmdi",
        }

        predictions = graph_engine.predict_next("TARGET_ACQUIRED", target_url)
        modules = []
        for pred in predictions[:5]:  # Top 5 predictions
            suggestion = pred.get("suggestion", "").upper()
            module = MODULE_TYPE_MAP.get(suggestion)
            if module and module not in modules:
                modules.append(module)

        # Always include at least one fallback
        if not modules:
            modules = ["tech_fuzzer", "logic_doppelganger"]

        return modules

    # --- ITERATIVE REASONING LOOP (Hermes observe -> decide -> act port) ---

    def _gather_live_evidence(self, target_url: str, scan_id: str, recommendations: dict) -> dict:
        """OBSERVE step: re-read live state before EVERY decision.

        This is Omega's analog of Hermes re-reading the message/tool-result
        history each iteration of ``run_conversation``. Rather than trusting a
        static up-front plan, Omega re-reads the knowledge graph, the confirmed
        findings accumulated so far, and the WAF/scope/budget pressure signals
        before picking the next action."""
        campaign = self._active_campaigns.get(scan_id, {})
        return {
            # Fresh attack-graph predictions (recomputed each iteration).
            "graph_predictions": graph_engine.predict_next("TARGET_ACQUIRED", target_url),
            # Confirmed findings that landed since the last decision.
            "confirmed_vulns": list(campaign.get("confirmed_vulns", [])),
            # WAF / rate-limit / block pressure derived from the live transcript.
            "defense_pressure": self._defense_pressure(scan_id),
            # Skill recommendations consumed for planning (skill_library read path).
            "skills": recommendations.get("skills", []) or [],
            # Learned high-value vuln classes for this target.
            "priority_vulns": recommendations.get("priority_vulns", []) or [],
            # Modules already fired this campaign (avoid redundant re-dispatch).
            "dispatched_modules": set(campaign.get("dispatched_modules", [])),
        }

    def _decide_next_action(self, evidence: dict, base_modules: list):
        """DECIDE step: pick the SINGLE highest-value next action from evidence.

        Deterministic, evidence-weighted scoring (NOT random / fake-Nash / fake
        RL — Architecture §25). Candidate modules are scored against current
        attack-graph confidence, learned success rates, base-strategy weight and
        skill relevance, with a diminishing-returns penalty for vuln classes that
        are already confirmed. Returns the best not-yet-dispatched action as
        ``(module_id, value, reasons)`` or ``None`` when nothing remains."""
        scores: dict[str, list] = {}  # module -> [value, [reasons]]

        def _bump(module: str, value: float, reason: str):
            if not module:
                return
            slot = scores.setdefault(module, [0.0, []])
            slot[0] += value
            slot[1].append(reason)

        # 1. Attack-graph predictions (historical chain confidence).
        for pred in evidence["graph_predictions"][:5]:
            module = self._resolve_module_from_type(str(pred.get("suggestion", "")).upper())
            conf = float(pred.get("confidence", 0) or 0) / 100.0
            _bump(module, 0.5 + conf, f"graph {conf:.0%}")

        # 2. Learned priority vulns (success-rate weighted).
        for rec in evidence["priority_vulns"][:5]:
            module = self._resolve_module_from_type(str(rec.get("type", "")).upper())
            sr = float(rec.get("success_rate", 0) or 0)
            _bump(module, 0.4 + sr, f"learned {sr:.0%}")

        # 3. Base strategy modules (floor weight so the chosen strategy matters).
        for module in base_modules:
            _bump(module, 0.2, "strategy")

        # 4. Skill recommendations boost the modules they relate to.
        for skill in evidence["skills"][:8]:
            text = (f"{skill.get('skill_type', '')} {skill.get('name', '')} {skill.get('description', '')}").lower()
            for module in list(scores.keys()):
                if any(tok and tok in text for tok in module.split("_")[1:]):
                    _bump(module, float(skill.get("score", 0) or 0) * 0.3, "skill")

        # Diminishing returns: deprioritize modules whose vuln class is already
        # confirmed (stop low-value, redundant re-runs — requirement 3).
        confirmed_types = {str(v.get("type", "")).upper() for v in evidence["confirmed_vulns"]}
        for ct in confirmed_types:
            m = self._resolve_module_from_type(ct)
            if m in scores:
                scores[m][0] *= 0.3
                scores[m][1].append("already-confirmed")

        candidates = [(m, slot[0], slot[1]) for m, slot in scores.items() if m not in evidence["dispatched_modules"]]
        if not candidates:
            return None
        # Deterministic tie-break: highest value, then module name.
        candidates.sort(key=lambda c: (c[1], c[0]), reverse=True)
        return candidates[0]

    # --- EVENT HANDLERS ---

    async def handle_target(self, event: HiveEvent):
        """Triggered when the system identifies a new target."""
        payload = event.payload
        target_url = payload.get("url")
        scan_id = event.scan_id
        if not target_url:
            return

        # Register campaign
        self._active_campaigns[scan_id] = {
            "target_url": target_url,
            "strategy": None,
            "dispatched_jobs": [],
            "dispatched_modules": [],  # modules already fired (avoid re-dispatch)
            "confirmed_vulns": [],
            "actions_taken": 0,  # iterative-loop action counter (budget)
            "adapted": False,
        }

        await self.initiate_campaign(target_url, scan_id)

    async def handle_confirmed_vuln(self, event: HiveEvent):
        """
        Mid-Scan Adaptation: When vulnerabilities are confirmed,
        Omega reassesses and potentially dispatches follow-up chains.
        """
        scan_id = event.scan_id
        campaign = self._active_campaigns.get(scan_id)
        if not campaign:
            return

        vuln_data = event.payload
        campaign["confirmed_vulns"].append(vuln_data)

        # Check for chain opportunities using the graph engine
        vuln_type = str(vuln_data.get("type", "")).upper()
        vuln_url = str(vuln_data.get("url", ""))

        if not vuln_type or campaign.get("adapted"):
            return

        # Query graph for follow-up attack vectors
        chains = graph_engine.find_chains(max_depth=3)
        relevant_chains = [
            c for c in chains if any(step.get("type", "").upper() == vuln_type for step in c.get("chain", []))
        ]

        if relevant_chains and not campaign["adapted"]:
            campaign["adapted"] = True
            best_chain = relevant_chains[0]

            logger.info(
                f"[{self.name}] [CHAIN ADAPT] Confirmed {vuln_type} → Deploying chain escalation (depth={best_chain['depth']})"
            )

            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=scan_id,
                    payload={
                        "url": vuln_url,
                        "arsenal": "Chain Escalation",
                        "action": f"Adapting strategy: {vuln_type} → Chain depth {best_chain['depth']}",
                        "payload": str(best_chain.get("chain", [])[:2])[:80],
                    },
                )
            )

            # Dispatch follow-up jobs based on chain prediction
            for step in best_chain.get("chain", [])[1:]:  # Skip the already-confirmed first step
                step_type = step.get("type", "").upper()
                module = self._resolve_module_from_type(step_type)
                if module:
                    follow_up = JobPacket(
                        priority=TaskPriority.HIGH,
                        target=TaskTarget(url=campaign["target_url"]),
                        config=ModuleConfig(
                            module_id=module,
                            agent_id=AgentID.SIGMA,
                            aggression=8,
                            params={"chain_source": vuln_type, "escalation": True},
                        ),
                    )
                    await self.dispatch_job(follow_up, scan_id)

    async def handle_job_completed(self, event: HiveEvent):
        """Tracks job completion for campaign progress monitoring."""
        job_id = event.payload.get("job_id", "")
        status = event.payload.get("status", "")
        self._job_results[job_id] = status

    def _resolve_module_from_type(self, vuln_type: str) -> str:
        """Maps vulnerability type names back to module IDs."""
        TYPE_TO_MODULE = {
            "SQL_INJECTION": "tech_sqli",
            "XSS": "tech_fuzzer",
            "JWT_BYPASS": "tech_jwt",
            "BROKEN_AUTH": "tech_auth_bypass",
            "IDOR": "logic_doppelganger",
            "RACE_CONDITION": "logic_chronomancer",
            "LOGIC_ESCALATION": "logic_escalator",
            "FINANCIAL_MANIPULATION": "logic_tycoon",
            "DATA_LEAK": "tech_fuzzer",
            "UNAUTHORIZED_ACCESS": "logic_skipper",
            "COMMAND_INJECTION": "tech_cmdi",
            "RCE": "tech_cmdi",
        }
        return TYPE_TO_MODULE.get(vuln_type)

    # --- CAMPAIGN EXECUTION ---

    async def initiate_campaign(self, target_url: str, scan_id: str = "GLOBAL"):
        """Core campaign orchestration logic with graph-driven intelligence."""

        # 1. GET LEARNING ENGINE RECOMMENDATIONS
        from backend.core.learning_engine import learning_engine

        recommendations = await learning_engine.get_recommendations(target_url, {"scan_id": scan_id})

        # 1b. CONSUME SKILL LIBRARY RECOMMENDATIONS (Architecture §29.9: skills
        # consumed by Omega; §29.12: query skills before every meaningful plan).
        try:
            from backend.core.skill_library import skill_library

            skill_recs = skill_library.get_recommendations(target_url=target_url, limit=8)
            if skill_recs:
                recommendations.setdefault("skills", skill_recs)
                logger.debug(f"[{self.name}] [SKILLS] {len(skill_recs)} skill recommendation(s) for planning")
        except Exception as _ke:
            logger.debug(f"[{self.name}] Skill library recall failed: {_ke}")

        # 1c. PREFETCH FENCED MEMORY CONTEXT before planning (Architecture §13.1:
        # Memory Manager prefetch + context fencing, used in agent execution).
        try:
            from backend.core.memory_manager import memory_manager

            mem_ctx = await memory_manager.build_context({"scan_id": scan_id, "query": target_url, "vuln_class": ""})
            if mem_ctx:
                recommendations["memory_context"] = mem_ctx
                logger.debug(f"[{self.name}] [MEMORY] prefetched fenced memory context ({len(mem_ctx)} chars)")
        except Exception as _me:
            logger.debug(f"[{self.name}] Memory prefetch failed: {_me}")

        if recommendations.get("confidence", 0) > 0.5:
            logger.debug(
                f"[{self.name}] [LEARNING] Using learned patterns (confidence: {recommendations['confidence']:.2f})"
            )
            logger.debug(
                f"[{self.name}] [LEARNING] Priority vulns: {[v['type'] for v in recommendations['priority_vulns'][:3]]}"
            )

        # 2. STRATEGY GENERATION (AI-Powered + Graph Intelligence + Learning)
        ai_strategy = None
        cortex = self._get_cortex()
        if cortex and cortex.enabled:
            try:
                ai_strategy = await cortex.select_attack_strategy(target_url)
                logger.debug(f"[{self.name}] [CORTEX AI] Strategy recommendation: {ai_strategy}")
            except Exception as e:
                logger.warning(f"[{self.name}] CORTEX strategy failed: {e}")

        strategy_name = self._select_strategy(target_url, ai_strategy, scan_id)
        profile = self.STRATEGY_PROFILES[strategy_name]

        # Update campaign state
        if scan_id in self._active_campaigns:
            self._active_campaigns[scan_id]["strategy"] = strategy_name

        logger.info(f"[{self.name}] ▶ Campaign Strategy: {strategy_name} | {profile['description']}")

        # 3. HYPOTHESIS GENERATION — derived from recon/graph evidence first,
        #    with a base list as fallback (Architecture §6.5: evidence-derived,
        #    not a random pick from a hardcoded list).
        base_hypotheses = [
            "Changing user_id may expose another user's data (IDOR)",
            "Negative price may bypass payment validation (Logic Flaw)",
            "JWT algorithm change may bypass verification (Auth Bypass)",
            "Auth bypass → IDOR → Data Extraction (Chain Attack)",
            "Race condition on coupon application (Financial Exploit)",
            "Path traversal in file upload (Config Exposure)",
        ]

        # Evidence-derived hypotheses from learned recommendations + graph.
        evidence_hypotheses: list[str] = []
        for vuln_rec in recommendations.get("priority_vulns", [])[:3]:
            vuln_type = vuln_rec["type"]
            success_rate = vuln_rec.get("success_rate", 0)
            evidence_hypotheses.append(f"{vuln_type} vulnerability likely (learned: {success_rate:.0%} success rate)")
        for pred in graph_engine.predict_next("TARGET_ACQUIRED", target_url)[:2]:
            sug = pred.get("suggestion")
            if sug:
                evidence_hypotheses.append(
                    f"{sug} suggested by attack graph (confidence: {pred.get('confidence', 0):.0f}%)"
                )

        hypotheses = evidence_hypotheses + base_hypotheses
        # Deterministic: prefer the strongest evidence-derived hypothesis;
        # otherwise the first base hypothesis. No randomness.
        selected_hypothesis = hypotheses[0]

        # Broadcast campaign start
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=scan_id,
                payload={
                    "url": target_url,
                    "arsenal": "Campaign Strategy",
                    "action": f"Strategy: {strategy_name}",
                    "payload": f"{profile['description'][:60]} | Hypothesis: {selected_hypothesis[:40]}",
                },
            )
        )

        await self.bus.publish(
            HiveEvent(
                type=EventType.LOG,
                source=self.name,
                scan_id=scan_id,
                payload={
                    "message": f"👑 OMEGA: Campaign '{target_url}' | Strategy: {strategy_name} | Hypothesis: {selected_hypothesis}"
                },
            )
        )

        # Log to ScanContext transcript
        ctx = getattr(self.bus, "scan_contexts", {}).get(scan_id)
        if ctx and hasattr(ctx, "append_event"):
            ctx.append_event(
                HiveEvent(
                    type=EventType.LOG,
                    source=self.name,
                    scan_id=scan_id,
                    payload={"message": f"Omega campaign initiated: strategy={strategy_name}, target={target_url}"},
                )
            )

        # 4. RESOLVE BASE MODULE SET (strategy + graph + learned priorities).
        #    This is now only the candidate pool the iterative loop scores
        #    against each step — NOT a static dispatch list.
        if strategy_name == "GRAPH_DRIVEN":
            base_modules = self._build_graph_driven_modules(target_url)
            logger.debug(f"[{self.name}] [GRAPH AI] Predicted modules: {base_modules}")
        else:
            base_modules = profile["modules"].copy()

        for vuln_rec in recommendations.get("priority_vulns", [])[:3]:
            module = self._resolve_module_from_type(str(vuln_rec.get("type", "")).upper())
            if module and module not in base_modules:
                base_modules.append(module)
        if "sigma_forge" not in base_modules:
            base_modules.append("sigma_forge")  # novel-vector discovery candidate

        # 5. ITERATIVE REASON -> ACT -> OBSERVE -> RE-PLAN LOOP
        #    (Hermes ``run_conversation`` pattern, Architecture §5.2/§6.5).
        #    Instead of dispatching a static batch, Omega re-reads live evidence
        #    each step, picks the single highest-value next action, acts, then
        #    re-observes — stopping early on unsafe (WAF) or low-value paths.
        target = TaskTarget(url=target_url)
        campaign = self._active_campaigns.get(scan_id, {})

        while campaign.get("actions_taken", 0) < self._max_campaign_actions:
            # OBSERVE: re-read graph state, confirmed findings, defense pressure.
            evidence = self._gather_live_evidence(target_url, scan_id, recommendations)

            # STOP (unsafe): defense pressure crossed the halt threshold. Hand
            # off to LOW_AND_SLOW adaptation rather than keep hammering a WAF.
            if evidence["defense_pressure"] >= self._defense_pressure_stop:
                logger.info(
                    f"[{self.name}] [STOP] Defense pressure "
                    f"{evidence['defense_pressure']:.2f} >= {self._defense_pressure_stop} -- "
                    f"halting expansion (stealth handoff)."
                )
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.LOG,
                        source=self.name,
                        scan_id=scan_id,
                        payload={
                            "message": f"👑 OMEGA: halting expansion under WAF pressure "
                            f"({evidence['defense_pressure']:.2f}); deferring to stealth."
                        },
                    )
                )
                break

            # DECIDE: pick the single highest-value next action from evidence.
            decision = self._decide_next_action(evidence, base_modules)
            if not decision:
                logger.debug(f"[{self.name}] [STOP] No remaining candidate actions.")
                break
            module_id, value, reasons = decision

            # STOP (low value): nothing clears the value floor — don't waste budget.
            if value < self._min_action_value:
                logger.debug(
                    f"[{self.name}] [STOP] Best next action '{module_id}' value "
                    f"{value:.2f} < floor {self._min_action_value} -- ending campaign."
                )
                break

            # ACT: dispatch the single chosen action.
            agent_id = AgentID.BETA if module_id.startswith("beta_") else AgentID.SIGMA
            packet = JobPacket(
                priority=profile["priority"],
                target=target,
                config=ModuleConfig(
                    module_id=module_id,
                    agent_id=agent_id,
                    aggression=profile["aggression"],
                    ai_mode=True,
                    params={"attack_hypothesis": selected_hypothesis, "strategy": strategy_name},
                ),
            )
            logger.debug(
                f"[{self.name}] [STEP {campaign.get('actions_taken', 0) + 1}] "
                f"-> {module_id} (value={value:.2f}; {', '.join(reasons[:3])})"
            )
            await self.dispatch_job(packet, scan_id)

            # Record the action so the next OBSERVE step won't re-pick it.
            campaign.setdefault("dispatched_modules", []).append(module_id)
            campaign["actions_taken"] = campaign.get("actions_taken", 0) + 1

            # Yield so async evidence (confirmed findings, transcript events)
            # can land before the next observe step — keeps the loop reactive.
            await asyncio.sleep(self._campaign_step_delay)

        # 6. Learn from this campaign dispatch (feed the graph)
        await graph_engine.learn_from_chain(
            [
                {"payload": {"type": "TARGET_ACQUIRED", "url": target_url}},
                {"payload": {"type": strategy_name, "url": target_url}},
            ]
        )

    async def dispatch_job(self, packet: JobPacket, scan_id: str = "GLOBAL"):
        """Dispatches a job with CommandLane backpressure awareness."""
        # CommandLane saturation check — defer if queue is overloaded
        telemetry = command_lane.telemetry
        if telemetry["waiting_count"] > 20:
            logger.debug(
                f"[{self.name}] CommandLane saturated (waiting={telemetry['waiting_count']}). Deferring dispatch."
            )
            await asyncio.sleep(1.0)

        await self.bus.publish(
            HiveEvent(type=EventType.JOB_ASSIGNED, source=self.name, scan_id=scan_id, payload=packet.model_dump())
        )

        # Track in campaign
        campaign = self._active_campaigns.get(scan_id)
        if campaign:
            campaign["dispatched_jobs"].append(packet.id)

    # ============ BROWSER CAMPAIGN PLANNING (Phase 3) ============

    async def _detect_spa(self, url: str) -> bool:
        """Detect if target is a Single Page Application."""
        try:
            # Quick framework detection
            framework = await self.browser.detect_framework(url)
            return framework in ["react", "vue", "angular", "svelte"]
        except Exception as e:
            logger.debug(f"[{self.name}] SPA detection failed: {e}")
            return False

    async def _plan_browser_campaign(self, url: str, scan_id: str) -> dict:
        """Plan browser-based campaign for SPAs and modern web apps."""
        try:
            logger.debug(f"[{self.name}] Planning browser-based campaign for {url}")

            # Detect if SPA
            is_spa = await self._detect_spa(url)

            if is_spa:
                strategy = "SPA_ASSAULT"
                logger.debug(f"[{self.name}] SPA detected - using specialized strategy")
            else:
                strategy = "BROWSER_DEEP_RECON"

            campaign_plan = {
                "strategy": strategy,
                "is_spa": is_spa,
                "modules": self.STRATEGY_PROFILES[strategy]["modules"],
                "browser_required": True,
                "phases": [
                    {
                        "phase": 1,
                        "name": "Browser Reconnaissance",
                        "modules": ["alpha_browser_recon"],
                        "description": "Deep endpoint discovery via browser",
                    },
                    {
                        "phase": 2,
                        "name": "Browser-Aware Payload Generation",
                        "modules": ["sigma_browser_payloads"],
                        "description": "Generate payloads based on DOM structure",
                    },
                    {
                        "phase": 3,
                        "name": "Browser Exploitation",
                        "modules": ["beta_browser_xss", "beta_dom_xss"],
                        "description": "Test exploits in real browser",
                    },
                    {
                        "phase": 4,
                        "name": "Browser Verification",
                        "modules": ["gamma_browser_verify"],
                        "description": "Visual verification with forensic evidence",
                    },
                ],
            }

            return campaign_plan

        except Exception as e:
            logger.error(f"[{self.name}] Browser campaign planning failed: {e}")
            return {}
