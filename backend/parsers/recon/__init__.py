"""
Alpha V6 Recon Parser Registry.

Every external tool output goes through a deterministic parser before
any normalized entity is created. Parsers are fixture-tested and never
call external services.
"""

from backend.parsers.recon.amass import parse_amass_json
from backend.parsers.recon.aquatone import parse_aquatone_json
from backend.parsers.recon.arjun import parse_arjun_json
from backend.parsers.recon.cdncheck import parse_cdncheck_jsonl
from backend.parsers.recon.cloudlist import parse_cloudlist_lines
from backend.parsers.recon.dalfox import parse_dalfox_json
from backend.parsers.recon.dirsearch import parse_dirsearch_json
from backend.parsers.recon.dnsx import parse_dnsx_jsonl
from backend.parsers.recon.feroxbuster import parse_feroxbuster_jsonl
from backend.parsers.recon.ffuf import parse_ffuf_json
from backend.parsers.recon.gobuster import parse_gobuster_lines
from backend.parsers.recon.gospider import parse_gospider_jsonl
from backend.parsers.recon.gowitness import parse_gowitness_json
from backend.parsers.recon.hakrawler import parse_hakrawler_lines
from backend.parsers.recon.httprobe import parse_httprobe_lines
from backend.parsers.recon.httpx import parse_httpx_jsonl
from backend.parsers.recon.inql import parse_inql_output
from backend.parsers.recon.interactsh import parse_interactsh_jsonl
from backend.parsers.recon.katana import parse_katana_jsonl
from backend.parsers.recon.kiterunner import parse_kiterunner_lines
from backend.parsers.recon.linkfinder import parse_linkfinder_output
from backend.parsers.recon.masscan import parse_masscan_json
from backend.parsers.recon.naabu import parse_naabu_jsonl
from backend.parsers.recon.nmap import parse_nmap_xml
from backend.parsers.recon.nuclei import parse_nuclei_jsonl
from backend.parsers.recon.secretfinder import parse_secretfinder_output
from backend.parsers.recon.spiderfoot import parse_spiderfoot_json
from backend.parsers.recon.subdomain_lines import (
    parse_assetfinder_lines,
    parse_github_subdomains_lines,
    parse_puredns_lines,
    parse_shuffledns_lines,
)
from backend.parsers.recon.subfinder import parse_subfinder_jsonl
from backend.parsers.recon.testssl import parse_testssl_json
from backend.parsers.recon.tlsx import parse_tlsx_jsonl
from backend.parsers.recon.url_parser import (
    classify_historical_paths,
    extract_params_from_urls,
    extract_subdomains_from_urls,
    parse_url_lines,
)
from backend.parsers.recon.wafw00f import parse_wafw00f_json
from backend.parsers.recon.whatweb import parse_whatweb_json

PARSER_REGISTRY = {
    "subfinder": parse_subfinder_jsonl,
    "amass": parse_amass_json,
    "assetfinder": parse_assetfinder_lines,
    "github-subdomains": parse_github_subdomains_lines,
    "gau": parse_url_lines,
    "waybackurls": parse_url_lines,
    "paramspider": parse_url_lines,
    "dnsx": parse_dnsx_jsonl,
    "shuffledns": parse_shuffledns_lines,
    "puredns": parse_puredns_lines,
    "cdncheck": parse_cdncheck_jsonl,
    "masscan": parse_masscan_json,
    "testssl": parse_testssl_json,
    "httpx": parse_httpx_jsonl,
    "httprobe": parse_httprobe_lines,
    "whatweb": parse_whatweb_json,
    "wafw00f": parse_wafw00f_json,
    "katana": parse_katana_jsonl,
    "gospider": parse_gospider_jsonl,
    "hakrawler": parse_hakrawler_lines,
    "arjun": parse_arjun_json,
    "naabu": parse_naabu_jsonl,
    "nmap": parse_nmap_xml,
    "tlsx": parse_tlsx_jsonl,
    "nuclei": parse_nuclei_jsonl,
    "dalfox": parse_dalfox_json,
    "ffuf": parse_ffuf_json,
    "feroxbuster": parse_feroxbuster_jsonl,
    "dirsearch": parse_dirsearch_json,
    "gobuster": parse_gobuster_lines,
    "linkfinder": parse_linkfinder_output,
    "secretfinder": parse_secretfinder_output,
    "kiterunner": parse_kiterunner_lines,
    "inql": parse_inql_output,
    "gowitness": parse_gowitness_json,
    "aquatone": parse_aquatone_json,
    "interactsh": parse_interactsh_jsonl,
    "cloudlist": parse_cloudlist_lines,
    "spiderfoot": parse_spiderfoot_json,
}

__all__ = [
    "PARSER_REGISTRY",
    "parse_subfinder_jsonl",
    "parse_amass_json",
    "parse_url_lines",
    "extract_subdomains_from_urls",
    "extract_params_from_urls",
    "classify_historical_paths",
    "parse_dnsx_jsonl",
    "parse_httpx_jsonl",
    "parse_katana_jsonl",
    "parse_hakrawler_lines",
    "parse_naabu_jsonl",
    "parse_nmap_xml",
    "parse_tlsx_jsonl",
    "parse_nuclei_jsonl",
    "parse_ffuf_json",
    "parse_feroxbuster_jsonl",
    "parse_dirsearch_json",
    "parse_gobuster_lines",
    "parse_linkfinder_output",
    "parse_secretfinder_output",
    "parse_kiterunner_lines",
    "parse_gowitness_json",
    "parse_interactsh_jsonl",
    "parse_cloudlist_lines",
    "parse_spiderfoot_json",
    "parse_assetfinder_lines",
    "parse_github_subdomains_lines",
    "parse_puredns_lines",
    "parse_cdncheck_jsonl",
    "parse_masscan_json",
    "parse_testssl_json",
    "parse_httprobe_lines",
    "parse_whatweb_json",
    "parse_wafw00f_json",
    "parse_gospider_jsonl",
    "parse_arjun_json",
    "parse_dalfox_json",
    "parse_aquatone_json",
    "parse_shuffledns_lines",
    "parse_inql_output",
]
