"""
Live HTTP Recon Test — Runs against a local test server.

Spins up a local Flask-like HTTP server with realistic API endpoints,
then tests the Alpha V6 probe, scoring, and dedup pipeline against it.

Usage:
  python -m pytest tests/test_live_recon.py -v -s --tb=short
"""
import asyncio
import threading
import time
import pytest
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("live_recon_test")

# ── Local Test Server ──────────────────────────────────────────────────
PAGES = {
    "/": (200, "text/html", "<html><head><title>Test App</title></head><body><h1>Welcome</h1><a href='/login'>Login</a></body></html>"),
    "/api": (200, "application/json", '{"status":"ok","version":"1.0"}'),
    "/api/v1": (200, "application/json", '{"endpoints":["/users","/orders"]}'),
    "/api/v1/users": (200, "application/json", '[{"id":1,"name":"admin"}]'),
    "/api/v2": (200, "application/json", '{"endpoints":["/accounts"]}'),
    "/api/health": (200, "application/json", '{"healthy":true}'),
    "/api/status": (200, "application/json", '{"uptime":99.9}'),
    "/swagger": (200, "text/html", '<html><body>Swagger UI</body></html>'),
    "/swagger.json": (200, "application/json", '{"openapi":"3.0","info":{"title":"TestAPI"}}'),
    "/docs": (200, "text/html", '<html><body>API Documentation</body></html>'),
    "/openapi.json": (200, "application/json", '{"openapi":"3.0.0","paths":{"/users":{"get":{}}}}'),
    "/api-docs": (200, "text/html", '<html><body>API Docs</body></html>'),
    "/graphql": (200, "application/json", '{"data":{"__schema":{"types":[]}}}'),
    "/admin": (403, "text/html", '<html><body>Forbidden</body></html>'),
    "/login": (200, "text/html", '<html><body><form method="POST"><input name="username"><input name="password" type="password"></form></body></html>'),
    "/auth": (401, "application/json", '{"error":"unauthorized"}'),
    "/token": (405, "application/json", '{"error":"method_not_allowed"}'),
    "/users": (200, "application/json", '[{"id":1},{"id":2}]'),
    "/search": (200, "text/html", '<html><body>Search results</body></html>'),
    "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /config"),
    "/sitemap.xml": (200, "application/xml", '<?xml version="1.0"?><urlset><url><loc>/</loc></url></urlset>'),
    "/.env": (200, "text/plain", "DB_HOST=localhost\nDB_PASS=secret123\nAPI_KEY=sk-test-key"),
    "/config": (200, "application/json", '{"debug":true,"database":"postgres://localhost/test"}'),
    "/.git/config": (200, "text/plain", "[core]\n\trepositoryformatversion = 0"),
    "/products": (200, "application/json", '[{"id":1,"name":"Widget","price":9.99}]'),
    "/export": (200, "application/json", '{"format":"csv","rows":100}'),
    "/wp-admin": (301, "text/html", '<html><body>Redirect to wp-login</body></html>'),
    "/wp-login.php": (200, "text/html", '<html><body>WordPress Login</body></html>'),
}


class LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]  # Strip query params
        if path in PAGES:
            status, ctype, body = PAGES[path]
        else:
            status, ctype, body = 404, "text/plain", "Not Found"

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "TestServer/1.0 (Vigilagent)")
        self.send_header("X-Powered-By", "Python/3.13")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # Suppress server logs during tests


@pytest.fixture(scope="module")
def local_server():
    """Spin up a local HTTP server for the duration of the test module."""
    server = HTTPServer(("127.0.0.1", 0), LocalHandler)  # Random available port
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    logger.info(f"Local test server started at {url}")
    yield url
    server.shutdown()


# ─── TEST: Full Live Probe ─────────────────────────────────────────────
class TestLiveHTTPProbe:
    """Tests the Alpha V6 HTTP probe against a local test server."""

    @pytest.mark.asyncio
    async def test_http_probe_finds_services(self, local_server):
        """Probe should discover all live endpoints on the local server."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"LIVE-PROBE-{int(time.time())}"

        scope = ScopePolicy.from_target(local_server)
        scope.allow_private_networks = True
        http_client.scope = scope

        services = await orch._http_probe(local_server, scan_id)

        logger.info(f"\n{'='*60}")
        logger.info(f"HTTP PROBE RESULTS: {len(services)} services discovered")
        logger.info(f"{'='*60}")
        for svc in sorted(services, key=lambda s: s.status_code):
            logger.info(f"  [{svc.status_code}] {svc.url:50s} | {svc.content_type:30s} | {svc.response_time_ms}ms")

        assert len(services) > 10, f"Expected >10 services, got {len(services)}"

        # Verify we found key paths
        found_paths = {s.url.split(str(local_server))[-1] or "/" for s in services}
        critical_paths = ["/", "/api", "/api/v1", "/login", "/admin", "/robots.txt"]
        for path in critical_paths:
            assert path in found_paths, f"Missing critical path: {path}"

    @pytest.mark.asyncio
    async def test_service_to_endpoint_conversion(self, local_server):
        """Each HTTPServiceFinding should convert to an EndpointFinding."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"CONVERT-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)
        assert len(services) > 0

        for svc in services:
            ep = orch._service_to_endpoint(svc)
            assert ep.url == svc.url
            assert ep.method == "GET"
            assert ep.status_code == svc.status_code
            assert ep.endpoint_type != ""
            assert ep.risk_class != ""

        logger.info(f"✅ All {len(services)} services converted to endpoints")

    @pytest.mark.asyncio
    async def test_scoring_pipeline(self, local_server):
        """Score all probed endpoints and verify priority ordering."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.agents.alpha_recon.scoring import score_endpoint
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"SCORE-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        scored = []
        for svc in services:
            ep = orch._service_to_endpoint(svc)
            ep = score_endpoint(ep)
            scored.append(ep)

        scored.sort(key=lambda e: e.priority_score, reverse=True)

        logger.info(f"\n{'='*60}")
        logger.info(f"SCORED ENDPOINTS ({len(scored)} total)")
        logger.info(f"{'='*60}")
        for ep in scored:
            reasons_str = ", ".join(ep.score_reasons[:3]) if ep.score_reasons else "none"
            logger.info(f"  [{ep.priority_score:3d}] {ep.method} {ep.normalized_path:30s} | {ep.endpoint_type:15s} | {ep.risk_class:8s} | {reasons_str}")

        assert len(scored) > 10
        # The top-scored endpoint should have a meaningful score
        assert scored[0].priority_score > 20, f"Top score {scored[0].priority_score} too low"
        # API endpoints should score higher than static pages
        api_scores = [e.priority_score for e in scored if "API" in e.endpoint_type]
        static_scores = [e.priority_score for e in scored if "STATIC" in e.endpoint_type or "PAGE" in e.endpoint_type]
        if api_scores and static_scores:
            assert max(api_scores) >= min(static_scores), "API endpoints should generally score >= static"

    @pytest.mark.asyncio
    async def test_dedup_removes_duplicates(self, local_server):
        """Verify the dedup pipeline removes exact duplicates."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.agents.alpha_recon.scoring import score_endpoint
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"DEDUP-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        endpoints = [score_endpoint(orch._service_to_endpoint(s)) for s in services]
        original_count = len(endpoints)

        # Inject deliberate duplicates
        duplicated = endpoints + endpoints[:10]
        deduped = orch._dedupe_and_sort(duplicated)

        logger.info(f"Original: {original_count} | Duplicated: {len(duplicated)} | After dedup: {len(deduped)}")
        assert len(deduped) == original_count, f"Dedup should remove duplicates: {len(deduped)} != {original_count}"
        # Verify sorted by priority (descending)
        scores = [e.priority_score for e in deduped]
        assert scores == sorted(scores, reverse=True), "Results should be sorted by priority desc"

    @pytest.mark.asyncio
    async def test_tech_detection(self, local_server):
        """Verify technology detection from server headers."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"TECH-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        # At least some services should detect technologies from headers
        all_tech = set()
        for svc in services:
            all_tech.update(svc.technologies)

        logger.info(f"Detected technologies: {all_tech}")
        # Our test server sends Server: TestServer/1.0 and X-Powered-By: Python/3.13
        assert len(all_tech) > 0, "Should detect at least the Server header tech"

    @pytest.mark.asyncio
    async def test_sensitive_file_detection(self, local_server):
        """Verify that sensitive files like .env and .git/config are found."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.agents.alpha_recon.scoring import score_endpoint
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"SENSITIVE-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        scored = [score_endpoint(orch._service_to_endpoint(s)) for s in services]

        # Find sensitive files
        env_ep = [e for e in scored if ".env" in e.url]
        git_ep = [e for e in scored if ".git" in e.url]

        logger.info(f".env found: {len(env_ep) > 0}, .git found: {len(git_ep) > 0}")
        assert len(env_ep) > 0, "Should detect /.env"
        assert len(git_ep) > 0, "Should detect /.git/config"

        # These should be classified as high risk
        for ep in env_ep + git_ep:
            logger.info(f"  Sensitive: [{ep.priority_score}] {ep.url} — {ep.endpoint_type} ({ep.risk_class})")

    @pytest.mark.asyncio
    async def test_auth_endpoint_detection(self, local_server):
        """Verify auth-required endpoints (401/403) are flagged."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.agents.alpha_recon.scoring import score_endpoint
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"AUTH-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        scored = [score_endpoint(orch._service_to_endpoint(s)) for s in services]
        auth_eps = [e for e in scored if e.auth_required]

        logger.info(f"Auth-required endpoints: {len(auth_eps)}")
        for ep in auth_eps:
            logger.info(f"  [{ep.priority_score}] {ep.status_code} {ep.url}")
            assert ep.status_code in {401, 403}

        assert len(auth_eps) >= 2, "Should find /admin (403) and /auth (401)"

    @pytest.mark.asyncio
    async def test_openapi_swagger_detection(self, local_server):
        """Verify Swagger/OpenAPI endpoints are found and tech-tagged."""
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
        from backend.core.hive import EventBus
        from backend.core.scope import ScopePolicy
        from backend.modules.tech.http_client import http_client

        bus = EventBus()
        orch = AlphaOrchestrator(bus)
        scan_id = f"OPENAPI-{int(time.time())}"

        http_client.scope = ScopePolicy.from_target(local_server)
        services = await orch._http_probe(local_server, scan_id)

        swagger_svcs = [s for s in services if "swagger" in s.url or "openapi" in s.url]
        logger.info(f"Swagger/OpenAPI endpoints: {len(swagger_svcs)}")
        for svc in swagger_svcs:
            logger.info(f"  [{svc.status_code}] {svc.url} — tech: {svc.technologies}")

        assert len(swagger_svcs) >= 2, "Should find /swagger.json and /openapi.json"
        # At least one should detect OpenAPI tech
        all_tech = set()
        for svc in swagger_svcs:
            all_tech.update(svc.technologies)
        assert "OpenAPI" in all_tech, "Should detect OpenAPI from swagger.json content"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
