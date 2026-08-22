# Vigilagent Recon Arsenal Image (Architecture §7 rule 3, §8)
# =============================================================================
# Bundles 34 Alpha recon tools + 5 Sigma validation tools = 39 total into one
# Linux image so both agents run every tool identically on any host, with NO
# per-host installs. Built once, runs everywhere the Docker daemon is available.
#
#   Alpha (recon):  34 tools — passive intel, DNS, HTTP, dirs, API, visual, OOB
#   Sigma (validation): 5 tools — nuclei, dalfox, httpx, whatweb, wafw00f
#
# Build:  docker build -t vigilagent/recon:latest docker/recon
# Use:    the TerminalEngine Docker backend mounts the scan dir at /scan and the
#         tool root (wordlists/SecLists/vendored scripts) read-only at /tools.
# =============================================================================

# ---- Stage 1: build the Go tools -------------------------------------------
FROM golang:1.24-bookworm AS gobuild
ENV GOBIN=/out CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto
RUN mkdir -p /out
# ProjectDiscovery + community Go recon tools.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
 && go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
 && go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest
RUN go install -v github.com/owasp-amass/amass/v4/...@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest \
 && go install -v github.com/tomnomnom/waybackurls@latest \
 && go install -v github.com/tomnomnom/assetfinder@latest \
 && go install -v github.com/gwen001/github-subdomains@latest \
 && go install -v github.com/OJ/gobuster/v3@latest \
 && go install -v github.com/ffuf/ffuf/v2@latest \
 && go install -v github.com/sensepost/gowitness@latest \
 && go install -v github.com/hahwul/dalfox/v2@latest \
 && go install -v github.com/jaeles-project/gospider@latest \
 && go install -v github.com/d3mondev/puredns/v2@latest
# kiterunner has a non-standard module layout: build from source.
RUN git clone --depth 1 https://github.com/assetnote/kiterunner.git /src/kr \
 && cd /src/kr && go build -o /out/kr ./cmd/kiterunner

# ---- Stage 2: runtime -------------------------------------------------------
FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive
# System recon tools + interpreters. masscan/nmap/whatweb come from apt; amass built in Go stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip build-essential make gcc \
      nmap masscan whatweb nikto \
      python3 python3-pip python3-venv pipx \
      ruby bash dnsutils \
      libpcap0.8 \
      chromium \
 && rm -rf /var/lib/apt/lists/*

# massdns (C) — the DNS-bruteforce backbone that puredns wraps. Not in Debian
# repos, so build from source. REQUIRED — without it puredns silently fails.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
 && cd /tmp/massdns && make -s && cp bin/massdns /usr/local/bin/massdns && chmod +x /usr/local/bin/massdns \
 && rm -rf /tmp/massdns

# puredns default resolvers file (puredns refuses to run without one).
RUN mkdir -p /home/recon/.config/puredns /root/.config/puredns \
 && printf "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n9.9.9.9\n149.112.112.112\n208.67.222.222\n208.67.220.220\n" \
      | tee /root/.config/puredns/resolvers.txt > /home/recon/.config/puredns/resolvers.txt

# Go binaries from the build stage.
COPY --from=gobuild /out/ /usr/local/bin/

# Rust tool: feroxbuster (prebuilt release binary).
RUN curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz \
      -o /tmp/ferox.tar.gz \
 && tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster \
 && chmod +x /usr/local/bin/feroxbuster \
 && rm -f /tmp/ferox.tar.gz

# Python tools via pipx (isolated) — arjun, wafw00f, inql.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PATH="/usr/local/bin:${PATH}"
RUN pipx install arjun \
 && pipx install wafw00f \
 && pipx install inql \
 && pip3 install --break-system-packages dnsgen

# sqlmap — the definitive SQLi validator (Sigma validation arsenal).
# Self-contained Python; pinned to a stable release tag.
RUN git clone --depth 1 --branch v1.8.12 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
 && chmod +x /usr/local/bin/sqlmap

# wpscan — WordPress scanner (target-aware; runs only when WP is detected).
RUN gem install wpscan --no-document 2>/dev/null || true

# testssl.sh + vendored Python scripts (LinkFinder, SecretFinder, ParamSpider, SpiderFoot).
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder \
 && git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder \
 && git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider \
 && git clone --depth 1 https://github.com/smicallef/spiderfoot.git /opt/spiderfoot \
 && pip3 install --no-cache-dir --break-system-packages \
      -r /opt/LinkFinder/requirements.txt \
      -r /opt/spiderfoot/requirements.txt || true

# Wrapper shims so vendored Python scripts are callable by bare name, matching
# the host registry's `python <script>` resolution.
RUN printf '#!/bin/sh\nexec python3 /opt/LinkFinder/linkfinder.py "$@"\n'   > /usr/local/bin/linkfinder   && chmod +x /usr/local/bin/linkfinder \
 && printf '#!/bin/sh\nexec python3 /opt/SecretFinder/SecretFinder.py "$@"\n' > /usr/local/bin/secretfinder && chmod +x /usr/local/bin/secretfinder \
 && printf '#!/bin/sh\nexec python3 /opt/ParamSpider/paramspider.py "$@"\n'   > /usr/local/bin/paramspider  && chmod +x /usr/local/bin/paramspider \
 && printf '#!/bin/sh\nexec python3 /opt/spiderfoot/sf.py "$@"\n'             > /usr/local/bin/spiderfoot   && chmod +x /usr/local/bin/spiderfoot

WORKDIR /scan
# FIX-014: Run as non-root user for container security
RUN useradd -m -s /bin/bash recon && chown -R recon:recon /scan
USER recon
# ENTRYPOINT allows TerminalEngine to exec any tool via `docker exec`.
# CMD keeps the container alive when started standalone or from Docker Desktop.
ENTRYPOINT ["/bin/bash"]
CMD ["-c", "echo '🛡️ Vigilagent Arsenal Active — recon (Alpha) + validation (Sigma) tools ready' && tail -f /dev/null"]
