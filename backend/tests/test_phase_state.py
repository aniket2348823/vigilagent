"""
Regression tests for PhaseState entity ingestion.

Covers the nmap parser emitting kind="service" while downstream phases
expect discovered ports in state.open_ports (was: total_open_ports always 0).
"""

from pathlib import Path

from backend.agents.alpha_recon.phase_controller import PhaseState
from backend.parsers.recon.nmap import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.65.254" addrtype="ipv4"/>
    <hostnames><hostname name="lab" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8888">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.62"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _write_sample(tmp_path: Path) -> Path:
    p = tmp_path / "nmap_scan.xml"
    p.write_text(SAMPLE_XML, encoding="utf-8")
    return p


def test_nmap_service_entities_populate_open_ports(tmp_path):
    entities = parse_nmap_xml(_write_sample(tmp_path))
    kinds = {e.kind for e in entities}
    assert "service" in kinds  # parser contract: nmap emits kind="service"

    state = PhaseState()
    state.add_entities(entities)

    # Only the open port is recorded; closed ports are skipped by the parser.
    assert state.open_ports == {"192.168.65.254": [8888]}
    assert sum(len(p) for p in state.open_ports.values()) == 1


def test_build_http_targets_includes_discovered_ports(tmp_path):
    entities = parse_nmap_xml(_write_sample(tmp_path))
    state = PhaseState()
    state.add_entities(entities)

    targets = state.build_http_targets(tmp_path).read_text(encoding="utf-8")
    # 8888 is not 80/443, so it must appear as an explicit host:port probe.
    assert "192.168.65.254:8888" in targets
