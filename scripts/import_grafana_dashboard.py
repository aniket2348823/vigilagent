#!/usr/bin/env python3
"""Import the Vigilagent dashboard into a running Grafana instance.

Usage:
    python scripts/import_grafana_dashboard.py [--url http://localhost:3000] [--user admin] [--password admin]

Requirements:
    pip install requests
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required.  Install with:  pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_URL = "http://localhost:3000"
DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "grafana" / "vigilagent-dashboard.json"


def import_dashboard(base_url: str, user: str, password: str, *, overwrite: bool = True) -> dict:
    """POST the dashboard JSON to Grafana's provisioning-import endpoint."""
    if not DASHBOARD_PATH.exists():
        print(f"ERROR: Dashboard file not found at {DASHBOARD_PATH}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))

    # Strip id so Grafana assigns one; wrap in the import payload shape.
    payload = {
        "dashboard": {k: v for k, v in raw.items() if k != "id"},
        "overwrite": overwrite,
        "inputs": [],
        "folderId": 0,
    }

    url = f"{base_url.rstrip('/')}/api/dashboards/import"
    resp = requests.post(url, json=payload, auth=(user, password), timeout=15)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Vigilagent Grafana dashboard")
    parser.add_argument("--url", default=DEFAULT_URL, help="Grafana base URL")
    parser.add_argument("--user", default=os.environ.get("GF_ADMIN_USER", "admin"), help="Grafana admin username")
    parser.add_argument("--password", default=os.environ.get("GF_ADMIN_PASSWORD"), help="Grafana admin password (or set GF_ADMIN_PASSWORD env var)")
    parser.add_argument("--no-overwrite", action="store_true", help="Do not overwrite existing dashboard")
    args = parser.parse_args()
    if not args.password:
        parser.error("--password is required (or set GF_ADMIN_PASSWORD env var)")

    result = import_dashboard(args.url, args.user, args.password, overwrite=not args.no_overwrite)
    uid = result.get("uid", result.get("slug", "unknown"))
    print(f"Dashboard imported successfully — uid: {uid}")
    print(f"  URL: {args.url.rstrip('/')}/d/{uid}")


if __name__ == "__main__":
    main()
