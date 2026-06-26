# ═══════════════════════════════════════════════════════════════════════════════
# VIGILAGENT :: AUTO REMEDIATION ENGINE & PATCH GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Generates framework-specific, developer-ready code patches
#          in unified diff format. Powered by GPT-OSS-20B via OpenRouter.
#
# FLOW: Finding → Framework Detection → GPT-OSS-20B → Patch → Unified Diff
# ═══════════════════════════════════════════════════════════════════════════════

import difflib
import json
import logging
from typing import Any

logger = logging.getLogger("REMEDIATION")


# ─── Framework Detection ──────────────────────────────────────────────────────


class FrameworkDetector:
    """
    Infers backend framework from HTTP headers, URL patterns, and response content.
    """

    @staticmethod
    def detect(finding: dict[str, Any]) -> str:
        """Detect the likely backend framework from finding metadata."""
        headers = finding.get("response_headers", {})
        url = str(finding.get("url", finding.get("endpoint", ""))).lower()
        body = str(finding.get("response", finding.get("response_body", ""))).lower()

        # Check server header
        server = str(headers.get("server", headers.get("Server", ""))).lower()
        x_powered = str(headers.get("x-powered-by", headers.get("X-Powered-By", ""))).lower()

        if "django" in server or "django" in x_powered or "csrfmiddlewaretoken" in body:
            return "django"
        if "express" in x_powered or "node" in server:
            return "express"
        if "spring" in server or "java" in x_powered or "x-spring" in str(headers).lower():
            return "spring"
        if "flask" in server or "werkzeug" in server:
            return "flask"
        if "laravel" in x_powered or "php" in x_powered:
            return "laravel"
        if "asp.net" in x_powered or "iis" in server:
            return "aspnet"
        if "fastapi" in body or "starlette" in server:
            return "fastapi"

        # URL pattern heuristics
        if "/api/v" in url:
            return "rest_api"

        return "generic"


# ─── Framework-Specific Fix Templates ─────────────────────────────────────────

FRAMEWORK_FIXES: dict[str, dict[str, dict[str, str]]] = {
    "IDOR": {
        "django": {
            "before": """def get_user(request, user_id):
    user = User.objects.get(id=user_id)
    return JsonResponse(user.to_dict())""",
            "after": """def get_user(request, user_id):
    if request.user.id != user_id:
        return HttpResponseForbidden("Access denied")
    user = User.objects.get(id=user_id)
    return JsonResponse(user.to_dict())""",
        },
        "express": {
            "before": """app.get("/api/user/:id", (req, res) => {
  const user = getUser(req.params.id);
  res.json(user);
});""",
            "after": """app.get("/api/user/:id", (req, res) => {
  if (req.user.id !== req.params.id) {
    return res.status(403).send("Forbidden");
  }
  const user = getUser(req.params.id);
  res.json(user);
});""",
        },
        "fastapi": {
            "before": """@app.get("/api/user/{user_id}")
async def get_user(user_id: int):
    return await db.fetch_user(user_id)""",
            "after": """@app.get("/api/user/{user_id}")
async def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return await db.fetch_user(user_id)""",
        },
        "generic": {
            "before": """def get_resource(resource_id):
    return db.query(f"SELECT * FROM resources WHERE id = {resource_id}")""",
            "after": """def get_resource(resource_id, current_user_id):
    resource = db.query("SELECT * FROM resources WHERE id = %s", (resource_id,))
    if resource and resource['owner_id'] != current_user_id:
        raise PermissionError("Access denied")
    return resource""",
        },
    },
    "SQL_INJECTION": {
        "django": {
            "before": """User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")""",
            "after": """User.objects.raw("SELECT * FROM users WHERE name = %s", [name])""",
        },
        "express": {
            "before": """db.query(`SELECT * FROM users WHERE name = '${name}'`, callback);""",
            "after": """db.query("SELECT * FROM users WHERE name = ?", [name], callback);""",
        },
        "generic": {
            "before": """cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")""",
            "after": """cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))""",
        },
    },
    "XSS": {
        "django": {
            "before": """return HttpResponse(f"<h1>Hello {user_input}</h1>")""",
            "after": """from django.utils.html import escape
return HttpResponse(f"<h1>Hello {escape(user_input)}</h1>")""",
        },
        "express": {
            "before": """res.send(`<h1>Hello ${userInput}</h1>`);""",
            "after": """const escapeHtml = require('escape-html');
res.send(`<h1>Hello ${escapeHtml(userInput)}</h1>`);""",
        },
        "generic": {
            "before": """output = f"<div>{user_input}</div>" """,
            "after": """import html
output = f"<div>{html.escape(user_input)}</div>" """,
        },
    },
    "AUTH_BYPASS": {
        "generic": {
            "before": """def protected_route(request):
    return get_sensitive_data()""",
            "after": """def protected_route(request):
    token = request.headers.get("Authorization", "")
    if not verify_jwt(token):
        return {"error": "Unauthorized"}, 401
    return get_sensitive_data()""",
        },
    },
}


# ─── Patch Generator ─────────────────────────────────────────────────────────


class PatchGenerator:
    """Generates unified diff patches from before/after code."""

    @staticmethod
    def create_diff(before: str, after: str, filename: str = "endpoint.py") -> str:
        """Generate a unified diff string."""
        before_lines = before.strip().splitlines(keepends=True)
        after_lines = after.strip().splitlines(keepends=True)

        diff = difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
        return "\n".join(diff)


# ─── Remediation Engine ──────────────────────────────────────────────────────


class RemediationEngine:
    """
    Auto Remediation Engine for generating framework-specific,
    developer-ready code patches with unified diffs.
    """

    def __init__(self):
        self.detector = FrameworkDetector()
        self.patch_gen = PatchGenerator()
        self._openrouter = None  # Lazy import to avoid circular deps

    def _get_openrouter(self):
        """Lazy-load OpenRouter client."""
        if self._openrouter is None:
            try:
                from backend.ai.openrouter import openrouter_client

                self._openrouter = openrouter_client
            except ImportError:
                logger.warning("REMEDIATION: OpenRouter client not available.")
        return self._openrouter

    def generate_local_fix(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Generate a remediation using local templates (instant, no API call).
        Falls back to generic if framework/vuln type not in templates.
        """
        vuln_type = str(finding.get("vuln_type", finding.get("type", ""))).upper()
        framework = self.detector.detect(finding)

        # Normalize vuln type
        vuln_key = vuln_type
        if "SQL" in vuln_type:
            vuln_key = "SQL_INJECTION"
        elif "XSS" in vuln_type or "CROSS_SITE" in vuln_type:
            vuln_key = "XSS"
        elif "IDOR" in vuln_type or "UNAUTHORIZED" in vuln_type:
            vuln_key = "IDOR"
        elif "AUTH" in vuln_type:
            vuln_key = "AUTH_BYPASS"

        # Look up template
        templates = FRAMEWORK_FIXES.get(vuln_key, {})
        fix = templates.get(framework, templates.get("generic", None))

        if fix:
            ext = self._get_extension(framework)
            diff = self.patch_gen.create_diff(fix["before"], fix["after"], f"endpoint{ext}")
            return {
                "vuln_type": vuln_type,
                "framework": framework,
                "root_cause": f"Missing security controls for {vuln_type} at this endpoint.",
                "fix_strategy": f"Apply {framework}-specific security pattern.",
                "code_before": fix["before"],
                "code_after": fix["after"],
                "patch_diff": diff,
                "source": "local_template",
            }

        # Generic fallback
        return {
            "vuln_type": vuln_type,
            "framework": framework,
            "root_cause": f"Insufficient input validation for {vuln_type}.",
            "fix_strategy": "Apply OWASP recommended security controls.",
            "code_before": "# Vulnerable code pattern not available for this type",
            "code_after": "# Apply framework-specific security measures",
            "patch_diff": "",
            "source": "generic_fallback",
        }

    async def generate_ai_fix(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Generate remediation using GPT-OSS-20B via OpenRouter (high quality, async).
        Falls back to local templates if OpenRouter is unavailable.
        """
        openrouter = self._get_openrouter()
        if not openrouter or not openrouter.is_available:
            logger.info("REMEDIATION: OpenRouter unavailable, using local templates.")
            return self.generate_local_fix(finding)

        framework = self.detector.detect(finding)

        try:
            raw_result = await openrouter.generate_remediation(finding, framework=framework)

            # Parse the JSON response
            if "```json" in raw_result:
                raw_result = raw_result.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_result:
                raw_result = raw_result.split("```")[1].split("```")[0].strip()

            data = json.loads(raw_result)

            # Generate unified diff from the AI's before/after code
            code_before = data.get("code_before", "")
            code_after = data.get("code_after", "")
            ext = self._get_extension(data.get("framework", framework))

            patch_diff = ""
            if code_before and code_after:
                patch_diff = self.patch_gen.create_diff(code_before, code_after, f"endpoint{ext}")

            return {
                "vuln_type": finding.get("vuln_type", finding.get("type", "")),
                "framework": data.get("framework", framework),
                "root_cause": data.get("root_cause", ""),
                "fix_strategy": data.get("fix_strategy", ""),
                "code_before": code_before,
                "code_after": code_after,
                "api_hardening": data.get("api_hardening", ""),
                "edge_cases": data.get("edge_cases", []),
                "patch_diff": patch_diff,
                "source": "gpt_oss_20b",
            }

        except json.JSONDecodeError:
            logger.warning("REMEDIATION: Failed to parse AI response, falling back to local.")
            return self.generate_local_fix(finding)
        except Exception as e:
            logger.error(f"REMEDIATION: AI fix generation failed — {e}")
            return self.generate_local_fix(finding)

    @staticmethod
    def _get_extension(framework: str) -> str:
        """Get file extension for framework."""
        ext_map = {
            "django": ".py",
            "flask": ".py",
            "fastapi": ".py",
            "express": ".js",
            "spring": ".java",
            "laravel": ".php",
            "aspnet": ".cs",
            "generic": ".py",
            "rest_api": ".py",
        }
        return ext_map.get(framework, ".py")

    def generate_batch(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate local fixes for a batch of findings (sync, instant)."""
        return [self.generate_local_fix(f) for f in findings]


# ─── Global Singleton ─────────────────────────────────────────────────────────
remediation_engine = RemediationEngine()
