"""
Vigilagent Recon Docker Runtime (Architecture §7 rule 3, §8).

Linux-native recon tools (nmap, masscan, nuclei, subfinder, ...) are bundled
into a single recon image so the full 39-tool arsenal runs identically on any
host — with NO per-host installs — exactly as §7 rule 3 requires:

    "Docker execution is preferred for Linux-native tools when running on
     Windows."

This module is the bridge between a ReconCommand (host argv + host paths) and a
`docker run` invocation:

  - mounts the scan artifact dir (host raw_dir) at /scan,
  - mounts the tool root (D:\\projects: SecLists, wordlists, vendored scripts)
    read-only at /tools,
  - rewrites every host path embedded in argv to its container path,
  - runs the tool inside the recon image with a bounded, recon-appropriate
    network policy (bridge — recon needs network, unlike the exploit sandbox
    which is network=none).

Execution still flows through the governed TerminalEngine: guardrails, scope
extraction, budget, watchdog, and audit all run on the original host argv before
this module ever builds a container command.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from backend.core.config import settings

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# Container mount points.
SCAN_MNT = "/scan"
TOOLS_MNT = "/tools"


def recon_image() -> str:
    """The recon tool image name (configurable)."""
    return (
        os.getenv("VIGILAGENT_RECON_IMAGE")
        or getattr(settings, "RECON_DOCKER_IMAGE", None)
        or "vigilagent/recon:latest"
    )


def recon_network() -> str:
    """Container network for recon (bridge by default; recon needs network)."""
    return os.getenv("VIGILAGENT_RECON_DOCKER_NETWORK", "bridge")


@functools.lru_cache(maxsize=1)
def docker_daemon_available() -> bool:
    """True when the docker CLI exists AND the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        p = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        return p.returncode == 0 and "linux" in (p.stdout or "").lower()
    except Exception as exc:
        logger.debug("docker_daemon_available check failed: %s", exc)
        return False


@functools.lru_cache(maxsize=8)
def recon_image_present(image: str | None = None) -> bool:
    """True when the recon image exists locally (docker image inspect)."""
    img = image or recon_image()
    if shutil.which("docker") is None:
        return False
    try:
        p = subprocess.run(
            ["docker", "image", "inspect", img],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        return p.returncode == 0
    except Exception as exc:
        logger.debug("recon_image_present check failed: %s", exc)
        return False
    return False


def docker_recon_ready() -> bool:
    """True when both the daemon and the recon image are available."""
    return docker_daemon_available() and recon_image_present()


def _container_name_env() -> str:
    return os.getenv("VIGILAGENT_RECON_CONTAINER", "")


@functools.lru_cache(maxsize=1)
def _running_recon_container_cached(image: str, override: str) -> str:
    """Find a RUNNING container started from the recon image (cached).

    Some Docker Desktop setups hit an overlay/layer bug where fresh
    ``docker run`` of an image fails with "cannot execute binary file" while a
    long-lived container from the SAME image runs fine. When such a container is
    already up we exec into it instead of spawning fresh ones — more reliable and
    faster (no per-tool container spin-up). Returns the container name or "".
    """
    if shutil.which("docker") is None:
        return ""
    # 1. Explicit override (VIGILAGENT_RECON_CONTAINER) wins if it is running.
    if override:
        try:
            p = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", override],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if p.returncode == 0 and "true" in (p.stdout or "").lower():
                return override
        except Exception as exc:
            logger.debug("container inspect failed: %s", exc)
            pass
    # 2. Otherwise pick the first running container based on the recon image.
    #    The ancestor filter matches by image ID, so it MISSES containers whose
    #    image was since re-tagged/committed (the running container then shows a
    #    bare image ID). We therefore also match by the image's repo tag AND by
    #    the image ID the tag currently resolves to.
    candidate_images = {image}
    try:
        idp = subprocess.run(
            ["docker", "image", "inspect", "-f", "{{.Id}}", image],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
        if idp.returncode == 0 and idp.stdout.strip():
            candidate_images.add(idp.stdout.strip())
            candidate_images.add(idp.stdout.strip().replace("sha256:", "")[:12])
    except Exception as exc:
        logger.debug("image inspect failed: %s", exc)
    for img in candidate_images:
        try:
            p = subprocess.run(
                ["docker", "ps", "--filter", f"ancestor={img}", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if p.returncode == 0:
                names = [n.strip() for n in (p.stdout or "").splitlines() if n.strip()]
                if names:
                    return names[0]
        except Exception as exc:
            logger.debug("docker ps ancestor filter failed: %s", exc)
    # 3. Last-resort: scan running containers and match any whose image (by
    #    name or short ID) looks like the recon image. Survives commit/re-tag.
    try:
        p = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
        if p.returncode == 0:
            image_repo = image.split(":")[0]
            short_ids = {c.replace("sha256:", "")[:12] for c in candidate_images}
            for line in (p.stdout or "").splitlines():
                if "\t" not in line:
                    continue
                name, img = (s.strip() for s in line.split("\t", 1))
                if not name:
                    continue
                if image_repo in img or img in short_ids:
                    return name
    except Exception as exc:
        logger.debug("docker ps scan failed: %s", exc)
    return ""


def running_recon_container() -> str:
    """Name of a running recon container to exec into, or "" if none."""
    return _running_recon_container_cached(recon_image(), _container_name_env())


def reset_container_cache() -> None:
    """Clear all Docker runtime caches (after start/stop/image pull)."""
    _running_recon_container_cached.cache_clear()
    docker_daemon_available.cache_clear()
    recon_image_present.cache_clear()


# ── Startup readiness probe ──────────────────────────────────────────────


async def probe_docker_readiness(
    *,
    max_retries: int = None,
    initial_delay: float = None,
    max_delay: float = None,
) -> dict:
    """Poll Docker daemon until it answers ``docker info``.

    Called once during backend startup (lifespan) so that by the time the
    first scan dispatches a tool, ``docker_daemon_available()`` caches True
    instead of a stale False from import time.  Retries with exponential
    backoff; returns a status dict for the boot log.

    If Docker never becomes ready the function still returns (non-blocking)
    so the backend starts in degraded/local-only mode.
    """
    import asyncio as _aio

    if max_retries is None:
        max_retries = int(os.getenv("VIGILAGENT_DOCKER_PROBE_RETRIES", "12"))
    if initial_delay is None:
        initial_delay = float(os.getenv("VIGILAGENT_DOCKER_PROBE_DELAY", "2"))
    if max_delay is None:
        max_delay = float(os.getenv("VIGILAGENT_DOCKER_PROBE_MAX_DELAY", "15"))

    # Reset any stale caches from a previous check (e.g. hot-reload).
    reset_container_cache()

    delay = initial_delay
    for attempt in range(1, max_retries + 1):
        # Check: CLI exists AND daemon answers
        if shutil.which("docker") is None:
            logger.info(
                "[DOCKER-PROBE] docker CLI not found on PATH — skipping probe (attempt %d/%d)", attempt, max_retries
            )
            break

        try:
            proc = await _aio.create_subprocess_exec(
                "docker",
                "info",
                "--format",
                "{{.ServerVersion}}",
                stdout=_aio.subprocess.PIPE,
                stderr=_aio.subprocess.PIPE,
            )
            stdout, _ = await _aio.wait_for(proc.communicate(), timeout=10)
            version = (stdout.decode("utf-8", errors="replace") or "").strip()
            if proc.returncode == 0 and version:
                # Daemon is live — warm the caches so every subsequent
                # ``docker_recon_ready()`` call hits True immediately.
                reset_container_cache()
                _daemon_ok = docker_daemon_available()
                _image_ok = recon_image_present()
                _container = running_recon_container()
                logger.info(
                    "[DOCKER-PROBE] Docker %s ready (daemon=%s, image=%s, container=%r) after %d attempt(s)",
                    version,
                    _daemon_ok,
                    _image_ok,
                    _container or "none",
                    attempt,
                )
                return {
                    "ready": True,
                    "version": version,
                    "daemon": _daemon_ok,
                    "image": _image_ok,
                    "container": _container or None,
                    "attempts": attempt,
                }
        except TimeoutError:
            logger.debug("[DOCKER-PROBE] attempt %d/%d timed out", attempt, max_retries)
        except Exception as exc:
            logger.debug("[DOCKER-PROBE] attempt %d/%d failed: %s", attempt, max_retries, exc)

        await _aio.sleep(delay)
        delay = min(delay * 1.5, max_delay)

    logger.warning(
        "[DOCKER-PROBE] Docker not ready after %d attempts — "
        "backend will run in local-only mode. Recon tools that require "
        "Docker will be skipped until Docker becomes available.",
        max_retries,
    )
    return {"ready": False, "attempts": max_retries}


# Container-internal working dir for exec-based runs (output written here then
# copied back to the host artifact path).
EXEC_WORKDIR = "/scan"


def build_exec_argv(
    inner_argv: Sequence[str],
    *,
    container: str,
    raw_dir: Path,
    tool_root: Path,
    container_out: str,
    has_stdin: bool = False,
    extra_raw_prefixes: Sequence[str | Path] = (),
) -> list[str]:
    """Build a ``docker exec`` argv that runs a recon tool inside a RUNNING
    container, rewriting host paths to the container's /scan + /tools layout.

    The running container does not bind-mount the host scan dir, so output is
    written under the container's EXEC_WORKDIR and copied back by the caller via
    ``docker cp``. Tool-root paths (wordlists/vendored scripts) are rewritten to
    /tools and expected to be present in the image.

    When ``has_stdin`` is set, ``-i`` is added so the tool actually receives the
    piped input (httprobe/hakrawler/gospider/feroxbuster read targets from
    stdin; without ``-i`` they see EOF immediately and exit "no urls detected").

    ``extra_raw_prefixes`` lets the caller forward the ORIGINAL (potentially
    relative) raw_dir form. The planner emits argv tokens using whatever form
    ArtifactStore was built with; passing it here ensures relative-form tokens
    are also rewritten to /scan instead of being copied verbatim into the
    container (which previously turned the entire host path into a filename).
    """
    raw_dir = raw_dir.resolve()
    container_argv = _rewrite_for_exec(
        inner_argv, raw_dir, tool_root, container_out, extra_raw_prefixes=extra_raw_prefixes
    )
    exec_flags = ["-i"] if has_stdin else []
    return ["docker", "exec", *exec_flags, "-w", EXEC_WORKDIR, container, *container_argv]


def _rewrite_for_exec(
    argv: Sequence[str],
    raw_dir: Path,
    tool_root: Path,
    container_out: str,
    *,
    extra_raw_prefixes: Sequence[str | Path] = (),
) -> list[str]:
    """Rewrite host paths for the exec backend: raw_dir paths -> /scan/<name>,
    tool_root paths -> /tools/<rel>. Other tokens pass through unchanged.

    Also rewrites loopback target references (localhost / 127.0.0.1 / [::1]) to
    ``host.docker.internal`` so tools running INSIDE the recon container reach
    services published on the Docker host (e.g. a DVWA lab on the host's
    :8080) instead of resolving loopback to the container itself. Without this,
    every recon tool silently fails or returns 0 bytes against a localhost
    target. File-path tokens are rewritten first and never host-rewritten.

    The planner builds argv tokens from the artifact store's ``raw_dir`` which
    may be RELATIVE (``data/scans/SCAN/raw``) while the caller resolves
    ``raw_dir`` to absolute before invoking us. We therefore match argv tokens
    against BOTH the absolute and the relative form so the prefix replace
    fires regardless of which form the planner used. Without this, every
    secondary file (-o results.json) ends up created in the container root with
    the literal Windows path embedded as the file NAME and the host-side cp
    back fails.
    """
    abs_raw = Path(raw_dir).resolve()
    # Build candidate prefixes: absolute + any relative forms the caller knows
    # about. All compared case-insensitively because Windows paths are
    # case-insensitive.
    prefixes_raw = {str(abs_raw)}
    try:
        # The relative form the planner stored on the command (raw_dir argument
        # may itself already be relative).
        if not Path(raw_dir).is_absolute():
            prefixes_raw.add(str(raw_dir))
    except Exception as exc:
        logger.debug("path normalization failed: %s", exc)
    for extra in extra_raw_prefixes or ():
        if extra:
            prefixes_raw.add(str(extra))
    prefixes_raw = {p for p in prefixes_raw if p}
    tool_s = str(tool_root)
    out: list[str] = []
    for tok in argv:
        s = str(tok)
        # Normalize windows separators so "data\scans\..." matches "data/scans/...".
        norm = s.replace("\\", "/")
        norm_low = norm.lower()
        replaced = False
        # raw_dir prefix match (any candidate form). Pick the LONGEST match so
        # a token like "data/scans/X/raw/x.json" doesn't accidentally bind to
        # "data" alone.
        best_prefix: str | None = None
        for pref in prefixes_raw:
            pref_norm = pref.replace("\\", "/")
            if norm_low.startswith(pref_norm.lower()):
                if best_prefix is None or len(pref_norm) > len(best_prefix):
                    best_prefix = pref_norm
        if best_prefix is not None:
            rel = norm[len(best_prefix) :].lstrip("/")
            out.append(f"{EXEC_WORKDIR}/{rel}".rstrip("/"))
            replaced = True
        elif norm_low.startswith(tool_s.replace("\\", "/").lower()):
            rel = norm[len(tool_s) :].lstrip("\\/").replace("\\", "/")
            out.append(f"{TOOLS_MNT}/{rel}".rstrip("/"))
            replaced = True
        if not replaced:
            out.append(_rewrite_loopback_host(s))
    return out


def _rewrite_loopback_host(token: str) -> str:
    """Rewrite loopback host references to host.docker.internal for in-container
    execution. Handles bare hosts, host:port, and full URLs. Leaves non-loopback
    tokens untouched."""
    # Fast path: only touch tokens that mention a loopback reference.
    low = token.lower()
    if not any(h in low for h in ("localhost", "127.0.0.1", "[::1]", "::1")):
        return token
    replaced = token
    # URL or host:port forms — replace the host component only.
    for needle in ("127.0.0.1", "localhost", "[::1]"):
        replaced = re.sub(
            rf"(?<![\w.-]){re.escape(needle)}(?![\w.-])", "host.docker.internal", replaced, flags=re.IGNORECASE
        )
    return replaced


# Tools that live INSIDE the recon image, owned by Alpha (recon commander).
# 34 recon tools — Alpha-exclusive. Sigma NEVER dispatches these.
DOCKER_RECON_TOOLS: set[str] = {
    "subfinder",
    "amass",
    "assetfinder",
    "github-subdomains",
    "gau",
    "waybackurls",
    "cloudlist",
    "spiderfoot",
    "dnsx",
    "shuffledns",
    "puredns",
    "cdncheck",
    "naabu",
    "masscan",
    "nmap",
    "tlsx",
    "testssl",
    "httprobe",
    "katana",
    "gospider",
    "hakrawler",
    "linkfinder",
    "secretfinder",
    "arjun",
    "paramspider",
    "feroxbuster",
    "ffuf",
    "dirsearch",
    "gobuster",
    "kiterunner",
    "inql",
    "gowitness",
    "aquatone",
    "interactsh",
}

# Tools that live INSIDE the recon image, owned by Sigma (validation commander).
# 5 validation tools — Sigma-exclusive. Alpha NEVER dispatches these.
DOCKER_SIGMA_TOOLS: set[str] = {
    "nuclei",
    "dalfox",  # vulnerability validation
    "httpx",
    "whatweb",
    "wafw00f",  # fingerprinting & WAF detection
}

# Combined set for availability checks (all 39 tools in the image).
DOCKER_ALL_TOOLS: set[str] = DOCKER_RECON_TOOLS | DOCKER_SIGMA_TOOLS


def _to_container_path(host_path: str, raw_dir: Path, tool_root: Path) -> str | None:
    """Map a host path under raw_dir/tool_root to its container path, else None.

    Handles both absolute and relative ``raw_dir`` forms because the planner can
    use either depending on how ArtifactStore is configured.
    """
    raw_s_abs = str(Path(raw_dir).resolve())
    raw_candidates = {raw_s_abs}
    try:
        if not Path(raw_dir).is_absolute():
            raw_candidates.add(str(raw_dir))
    except Exception as path_exc:
        logger.debug("path normalization failed: %s", path_exc)
    tool_s = str(tool_root)
    norm = host_path.replace("\\", "/")
    norm_low = norm.lower()

    def _rel_posix(child: str, parent: str) -> str:
        rel = child[len(parent) :].lstrip("/")
        return rel

    best: tuple[int, str] | None = None
    for pref in raw_candidates:
        pref_norm = pref.replace("\\", "/")
        if norm_low.startswith(pref_norm.lower()) and (best is None or len(pref_norm) > best[0]):
            best = (len(pref_norm), pref_norm)
    if best is not None:
        return f"{SCAN_MNT}/{_rel_posix(norm, best[1])}".rstrip("/")
    if norm_low.startswith(tool_s.replace("\\", "/").lower()):
        return f"{TOOLS_MNT}/{_rel_posix(norm, tool_s.replace(chr(92), '/'))}".rstrip("/")
    return None


def rewrite_argv(argv: Sequence[str], raw_dir: Path, tool_root: Path) -> list[str]:
    """Rewrite host paths embedded in argv tokens to their container paths."""
    out: list[str] = []
    for tok in argv:
        s = str(tok)
        mapped = _to_container_path(s, raw_dir, tool_root)
        out.append(mapped if mapped is not None else s)
    return out


def build_docker_argv(
    inner_argv: Sequence[str],
    *,
    raw_dir: Path,
    tool_root: Path,
    scan_id: str = "GLOBAL",
    image: str | None = None,
    network: str | None = None,
    memory: str = "1g",
    cpus: str = "2.0",
) -> list[str]:
    """Build the full `docker run ...` argv for a recon tool.

    The scan dir is mounted read-write at /scan; the tool root (wordlists,
    vendored scripts) is mounted read-only at /tools. argv host paths are
    rewritten to container paths.
    """
    img = image or recon_image()
    net = network or recon_network()
    raw_dir = raw_dir.resolve()
    tool_root = Path(tool_root)
    raw_dir.mkdir(parents=True, exist_ok=True)

    container_argv = rewrite_argv(inner_argv, raw_dir, tool_root)
    name = f"vigil-recon-{scan_id.lower().replace('/', '-')}-{os.urandom(4).hex()}"

    docker_argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        net,
        "--memory",
        memory,
        "--cpus",
        cpus,
        "-v",
        f"{raw_dir}:{SCAN_MNT}",
    ]
    if tool_root.exists():
        docker_argv += ["-v", f"{tool_root}:{TOOLS_MNT}:ro"]
    # Pass through optional credentials some tools use, when present.
    for env_key in ("GITHUB_TOKEN",):
        if os.getenv(env_key):
            docker_argv += ["-e", env_key]
    docker_argv += ["-w", SCAN_MNT, img]
    docker_argv += container_argv
    return docker_argv
