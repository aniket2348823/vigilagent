from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


class SeenSet:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def add(self, key: str) -> bool:
        normalized = key.lower().strip()
        if normalized in self._seen:
            return False
        self._seen.add(normalized)
        return True

    def __contains__(self, key: str) -> bool:
        return key.lower().strip() in self._seen

    def __len__(self) -> int:
        return len(self._seen)


def normalize_url(url: str, *, keep_query: bool = True) -> str:
    """Normalize a URL for deduplication. Handles bare hostnames gracefully."""
    url = url.strip()
    # Handle bare hostnames without scheme
    if url and not url.startswith(("http://", "https://", "//")):
        url = f"https://{url}"

    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    # Collapse duplicate slashes in path
    path = re.sub(r"/+", "/", parsed.path or "/")
    query = ""
    if keep_query and parsed.query:
        pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        query = urlencode(pairs, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def normalize_endpoint_key(url: str, method: str = "GET") -> str:
    """Generate a deduplication key for an endpoint (method + normalized URL without query)."""
    normalized = normalize_url(url, keep_query=False)
    return f"{method.upper()} {normalized}"


def classify_path(path: str) -> tuple[str, str]:
    """Classify an endpoint path into a type and risk level."""
    lower = path.lower()

    # Debug/config (highest risk)
    if any(part in lower for part in ["/debug", "/actuator", "/trace", "/_debug", "/__debug"]):
        return "DEBUG_ENDPOINT", "CRITICAL"
    if any(part in lower for part in [".env", ".config", "/config", "/.git", "/wp-config"]):
        return "CONFIG_ENDPOINT", "CRITICAL"
    if any(part in lower for part in ["/internal", "/_internal", "/private"]):
        return "INTERNAL_ENDPOINT", "CRITICAL"

    # Admin
    if any(part in lower for part in ["/admin", "/dashboard", "/manage", "/console", "/panel"]):
        return "ADMIN_ENDPOINT", "CRITICAL"

    # Auth
    if any(
        part in lower
        for part in ["/login", "/auth", "/token", "/oauth", "/session", "/signin", "/signup", "/register", "/password"]
    ):
        return "AUTH_ENDPOINT", "HIGH"

    # Payment
    if any(part in lower for part in ["/payment", "/checkout", "/billing", "/invoice", "/stripe"]):
        return "PAYMENT_ENDPOINT", "HIGH"

    # Upload
    if any(part in lower for part in ["/upload", "/import", "/attach"]):
        return "UPLOAD_ENDPOINT", "HIGH"

    # GraphQL
    if any(part in lower for part in ["/graphql", "/graphiql", "/gql"]):
        return "GRAPHQL_ENDPOINT", "HIGH"

    # Webhook
    if any(part in lower for part in ["/webhook", "/callback", "/hook", "/notify"]):
        return "WEBHOOK_ENDPOINT", "MEDIUM"

    # Search
    if any(part in lower for part in ["/search", "/find", "/lookup", "/query"]):
        return "SEARCH_ENDPOINT", "MEDIUM"

    # API
    if re.search(r"/api/|/rest/|/v[0-9]+/", lower):
        return "API_ENDPOINT", "HIGH"

    # Data
    if any(part in lower for part in ["/user", "/account", "/order", "/profile", "/customer", "/payment", "/settings"]):
        return "DATA_ENDPOINT", "MEDIUM"

    # File endpoints
    if lower.endswith((".json", ".xml", ".yaml", ".yml", ".env", ".config", ".bak", ".sql", ".log", ".csv")):
        return "FILE_ENDPOINT", "HIGH"

    # JS
    if lower.endswith((".js", ".mjs", ".jsx")):
        return "JS_FILE", "LOW"

    # Static
    if any(part in lower for part in ["/static", "/assets", "/images", "/css", "/fonts"]):
        return "STATIC", "LOW"

    # Media
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".webp", ".ico")):
        return "MEDIA", "INFO"

    return "UNKNOWN", "LOW"
