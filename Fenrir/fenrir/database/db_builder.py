# fenrir/database/db_builder.py
#
# Database build and update engine for Fenrir's offline intelligence database.
#
# Sources downloaded and imported:
#
#   Vulnerability Intelligence:
#     NVD JSON feeds         — CVE records, CVSS v2/v3, CPE matches
#     CISA KEV               — Known Exploited Vulnerabilities catalogue
#     EPSS scores            — Daily exploit probability scores from FIRST.org
#     MITRE CWE              — Common Weakness Enumeration XML
#     MITRE CAPEC            — Common Attack Pattern Enumeration XML
#     MITRE ATT&CK           — Enterprise + ICS + Mobile STIX JSON bundles
#
#   Exploit Collections:
#     Exploit-DB source      — ~57,000 source exploits (git clone)
#     Exploit-DB shellcodes  — Shellcode index (files_shellcodes.csv)
#     Exploit-DB bin-sploits — Pre-compiled binary exploits (~1.07 GB, separate repo)
#     Exploit-DB papers      — Research whitepapers (~120 MB, separate repo)
#
#   Threat Intelligence Feeds:
#     Emerging Threats       — Compromised/malicious IPs
#     Spamhaus DROP          — Botnet/spam infrastructure IPs
#     AbuseIPDB              — Scanner/attacker IPs
#     MalwareBazaar          — Malware file hashes (abuse.ch)
#     URLhaus                — Malicious URLs (abuse.ch)
#     ThreatFox IOCs         — C2/malware IOCs (abuse.ch)
#     Feodo Tracker          — Active botnet C2 infrastructure
#
#   Scanning Intelligence:
#     Nuclei templates       — 9,000+ scan templates (git clone)
#     Default credentials    — 2,000+ application default creds
#     IoT default creds      — Device-specific default creds
#     Google Hacking DB      — GHDB dork queries (from Exploit-DB repo)
#     WAF signatures         — wafw00f detection signatures
#     SecLists               — Comprehensive wordlist collection (git clone)
#     PayloadsAllTheThings   — Attack payloads and techniques (git clone)
#     FuzzDB                 — Fuzzing attack patterns (git clone)
#     rockyou.txt            — Standard password list (download)
#     HIBP passwords         — Have I Been Pwned SHA-1 hash list (optional, ~12 GB)
#
#   Network Intelligence:
#     ASN data               — IP-to-ASN mappings (iptoasn.com)
#     Tor exit nodes         — Current Tor exit node list
#     IANA port assignments  — Official port/protocol assignments
#
#   Compliance / Reporting:
#     OWASP Top 10           — Finding templates (built-in, no download)
#
# Build tiers (defined in schema.py):
#   core     — ~4.5 GB, standard pentest toolkit
#   standard — ~8 GB,   full pentest + red team
#   full     — ~25 GB+, red team + offline password cracking
#   custom   — user selects individual sources via CLI flags

import csv
import gzip
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests
try:
    import yaml  # PyYAML — for parsing Nuclei template headers
    _YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    _YAML_AVAILABLE = False

from ..config import config
from ..logging_config import get_logger
from .schema import (
    ALL_CREATE_STATEMENTS, BUILD_TIERS, SCHEMA_VERSION,
    META_ATTACK_GROUP_COUNT, META_ATTACK_LAST_UPDATED,
    META_ATTACK_TECHNIQUE_COUNT, META_ATTACK_VERSION,
    META_BINSPLOITS_COMMIT, META_BUILD_DURATION, META_BUILD_TIER,
    META_C2_COUNT, META_CAPEC_COUNT, META_CAPEC_LAST_UPDATED,
    META_CWE_COUNT, META_CWE_LAST_UPDATED,
    META_DEFAULT_CREDS_COUNT, META_EDB_COMMIT, META_EDB_EXPLOIT_COUNT,
    META_EDB_LAST_UPDATED, META_EDB_PAPER_COUNT, META_EDB_SHELLCODE_COUNT,
    META_EPSS_COUNT, META_EPSS_LAST_UPDATED,
    META_FEEDS_LAST_UPDATED, META_GHDB_COUNT,
    META_HASH_REP_COUNT, META_IANA_LAST_UPDATED, META_IANA_PORT_COUNT,
    META_IOC_THREATFOX_COUNT, META_IOC_URL_COUNT,
    META_IOT_CREDS_COUNT, META_IP_REP_COUNT,
    META_KEV_COUNT, META_KEV_LAST_UPDATED,
    META_NUCLEI_LAST_UPDATED, META_NUCLEI_TEMPLATE_COUNT,
    META_NVD_BUILD_TYPE, META_NVD_CVE_COUNT, META_NVD_LAST_UPDATED,
    META_NVD_YEAR_START, META_PAYLOADS_COMMIT,
    META_SCHEMA_VERSION, META_SECLISTS_COMMIT,
    META_TOR_COUNT, META_TOR_LAST_UPDATED,
    META_WAF_SIG_COUNT, META_WORDLISTS_COUNT, META_WORDLISTS_LAST_UPDATED,
    META_ASN_COUNT, META_ASN_LAST_UPDATED,
)
from .db_manager import DB_DIR, DB_PATH, EXPLOITS_DIR

log = get_logger()

# ---------------------------------------------------------------------------
# Progress callback type
# ---------------------------------------------------------------------------
# Signature: callback(source, current, total, message)
ProgressCallback = Callable[[str, int, int, str], None]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WORDLISTS_DIR    = DB_DIR / "wordlists"
NUCLEI_DIR       = DB_DIR / "nuclei-templates"
SECLISTS_DIR     = WORDLISTS_DIR / "SecLists"
PAYLOADS_DIR     = WORDLISTS_DIR / "PayloadsAllTheThings"
FUZZDB_DIR       = WORDLISTS_DIR / "fuzzdb"
EXPLOITDB_DIR    = DB_DIR / "exploitdb_repo"
BINSPLOITS_DIR   = DB_DIR / "exploitdb-bin-sploits"
PAPERS_DIR       = DB_DIR / "exploitdb-papers"

# ---------------------------------------------------------------------------
# Source URLs
# ---------------------------------------------------------------------------
# NVD 2.0 REST API (legacy JSON feed URLs were retired December 2023)
NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_PAGE     = 2000   # max results per page (API limit)
NVD_API_DELAY    = 6.0    # seconds between pages without API key
NVD_API_DELAY_KEY = 0.6   # seconds between pages with API key

KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL         = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CWE_URL          = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL        = "https://capec.mitre.org/data/xml/capec_latest.xml"

ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_ICS_URL        = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
ATTACK_MOBILE_URL     = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"

EXPLOITDB_REPO        = "https://gitlab.com/exploit-database/exploitdb.git"
BINSPLOITS_REPO       = "https://gitlab.com/exploit-database/exploitdb-bin-sploits.git"
PAPERS_REPO           = "https://gitlab.com/exploit-database/exploitdb-papers.git"

NUCLEI_REPO           = "https://github.com/projectdiscovery/nuclei-templates.git"
SECLISTS_REPO         = "https://github.com/danielmiessler/SecLists.git"
PAYLOADS_REPO         = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
FUZZDB_REPO           = "https://github.com/fuzzdb-project/fuzzdb.git"
DEFAULT_CREDS_URL     = "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv"
# IoT default credentials — multiple sources tried in order
# Primary: RouterSploit credential list (well-maintained, IoT-focused)
# Fallback: creds.csv from netexplo/routerdb
IOT_CREDS_URLS = [
    "https://raw.githubusercontent.com/threat9/routersploit/master/routersploit/modules/credentials/routers_generic.py",
    "https://raw.githubusercontent.com/jh0ker/mitmproxy_addon_defaultcreds/master/credentials.csv",
]
ROCKYOU_URL           = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
HIBP_URL              = "https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-hash-v8.7z"

EMERGING_THREATS_URL  = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
SPAMHAUS_DROP_URL     = "https://www.spamhaus.org/drop/drop.txt"
ABUSEIPDB_URL         = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-7d.ipv4"
MALWAREBAZAAR_URL     = "https://mb-api.abuse.ch/downloads/malwarebazaar.csv.zip"
URLHAUS_URL           = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL         = "https://threatfox.abuse.ch/export/json/recent/"
FEODO_URL             = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

IPTOASN_URL           = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
TOR_EXITS_URL         = "https://check.torproject.org/torbulkexitlist"
IANA_PORTS_URL        = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

WAFW00F_REPO          = "https://github.com/EnableSecurity/wafw00f.git"

REQUEST_TIMEOUT  = 120
CHUNK_SIZE       = 65536  # 64 KB stream chunks


class DatabaseBuilder:
    """
    Builds and updates the Fenrir offline intelligence database.

    Args:
        db_path:           Override database path. Default: data/db/fenrir.db
        progress_callback: Called with (source, current, total, message)
                           during long operations for GUI progress bars.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        self.db_path     = db_path or DB_PATH
        self.progress_cb = progress_callback or _default_progress
        self.session     = requests.Session()
        self.session.headers.update({
            "User-Agent": "Fenrir-SecurityScanner/2.0 (offline-db-builder)"
        })
        log.debug(f"DatabaseBuilder initialised. DB: {self.db_path}")

    # ===========================================================================
    # PUBLIC BUILD INTERFACE
    # ===========================================================================

    def build_all(
        self,
        tier: str = "core",
        custom_sources: Optional[list[str]] = None,
    ) -> bool:
        """
        Full database build from scratch.

        Builds into a staging file then atomically swaps to live database
        on success — the tool stays usable during a rebuild.

        Args:
            tier:           "core", "standard", "full", or "custom".
            custom_sources: If tier=="custom", list of source names to build.
                            See schema.BUILD_TIERS for available source names.

        Returns:
            True on success, False on critical failure.
        """
        if tier == "custom" and not custom_sources:
            log.error("build_all: tier='custom' requires custom_sources list.")
            return False

        sources = (
            custom_sources if tier == "custom"
            else BUILD_TIERS.get(tier, BUILD_TIERS["core"])["sources"]
        )

        log.info("=" * 60)
        log.info(f"  Fenrir DB Build — Tier: {tier.upper()}")
        log.info(f"  Sources: {len(sources)}")
        log.info("=" * 60)

        start   = time.time()
        staging = self.db_path.with_suffix(".building")

        try:
            # Ensure directories exist
            for d in [self.db_path.parent, EXPLOITS_DIR, WORDLISTS_DIR, NUCLEI_DIR]:
                d.mkdir(parents=True, exist_ok=True)

            if staging.exists():
                staging.unlink()

            self._create_schema(staging)

            # Dispatch each source
            self._run_sources(sources, staging)

            # Record build metadata
            duration = int(time.time() - start)
            self._set_meta(staging, META_BUILD_DURATION, str(duration))
            self._set_meta(staging, META_BUILD_TIER, tier)

            # Atomic swap
            if self.db_path.exists():
                self.db_path.replace(self.db_path.with_suffix(".backup"))
            staging.rename(self.db_path)

            log.info("=" * 60)
            log.info(f"  Build complete in {_fmt_duration(duration)}")
            log.info(f"  Database: {self.db_path}")
            log.info("=" * 60)
            return True

        except Exception as exc:
            log.error(f"Build failed: {exc}")
            if staging.exists():
                staging.unlink()
            return False

    def update_all(self) -> bool:
        """
        Incremental update — only fetch changed/new data since last build.

        For NVD: modified + recent feeds only.
        For Exploit-DB, Nuclei, SecLists: git pull.
        For threat feeds: full re-download (daily-updated files).
        For KEV, EPSS: full re-download (small files, always current).
        """
        if not self.db_path.exists():
            log.warning("No database found — running full core build...")
            return self.build_all("core")

        log.info("Starting incremental database update...")
        start = time.time()

        update_sources = [
            "nvd_update", "kev", "epss",
            "exploitdb_update", "nuclei_update",
            "threat_feeds", "hash_feeds", "ioc_urls", "threatfox",
            "c2_botnet", "tor_exits",
        ]

        self._run_sources(update_sources, self.db_path)

        duration = int(time.time() - start)
        self._set_meta(self.db_path, META_BUILD_DURATION, str(duration))
        log.info(f"Update complete in {_fmt_duration(duration)}.")
        return True

    def _run_sources(self, sources: list[str], db_path: Path) -> None:
        """Dispatch build methods for each source name in the list."""
        dispatch = {
            # NVD
            "nvd_lite":           lambda: self.build_nvd(lite=True,  db_path=db_path),
            "nvd_full":           lambda: self.build_nvd(lite=False, db_path=db_path),
            "nvd_update":         lambda: self._update_nvd(db_path),
            # Exploit-DB
            "exploitdb_source":   lambda: self.build_exploitdb(db_path=db_path),
            "exploitdb_shellcodes": lambda: self.build_exploitdb(db_path=db_path),  # same repo, done together
            "exploitdb_bins":     lambda: self._clone_or_pull(BINSPLOITS_REPO, BINSPLOITS_DIR, "exploitdb_bins") and self._set_meta(db_path, META_BINSPLOITS_COMMIT, _git_commit(BINSPLOITS_DIR)),
            "exploitdb_papers":   lambda: self._clone_or_pull(PAPERS_REPO, PAPERS_DIR, "exploitdb_papers"),
            "exploitdb_update":   lambda: self.build_exploitdb(db_path=db_path),
            # Vulnerability intelligence
            "kev":                lambda: self.build_kev(db_path=db_path),
            "epss":               lambda: self.build_epss(db_path=db_path),
            "cwe":                lambda: self.build_cwe(db_path=db_path),
            "capec":              lambda: self.build_capec(db_path=db_path),
            "attack":             lambda: self.build_attack(db_path=db_path),
            # Threat intel
            "threat_feeds":       lambda: self.build_threat_feeds(db_path=db_path),
            "hash_feeds":         lambda: self.build_hash_feeds(db_path=db_path),
            "ioc_urls":           lambda: self.build_ioc_urls(db_path=db_path),
            "threatfox":          lambda: self.build_threatfox(db_path=db_path),
            "c2_botnet":          lambda: self.build_c2_botnet(db_path=db_path),
            # Scanning intelligence
            "nuclei":             lambda: self.build_nuclei(db_path=db_path),
            "nuclei_update":      lambda: self.build_nuclei(db_path=db_path),
            "default_creds":      lambda: self.build_default_creds(db_path=db_path),
            "iot_creds":          lambda: self.build_iot_creds(db_path=db_path),
            "ghdb":               lambda: self.build_ghdb(db_path=db_path),
            "waf_signatures":     lambda: self.build_waf_signatures(db_path=db_path),
            # Wordlists
            "seclists":           lambda: self._build_wordlist_repo(SECLISTS_REPO, SECLISTS_DIR, "seclists", META_SECLISTS_COMMIT, db_path),
            "payloads_all_things":lambda: self._build_wordlist_repo(PAYLOADS_REPO, PAYLOADS_DIR, "payloads_all_things", META_PAYLOADS_COMMIT, db_path),
            "fuzzdb":             lambda: self._build_wordlist_repo(FUZZDB_REPO, FUZZDB_DIR, "fuzzdb", None, db_path),
            "rockyou":            lambda: self.build_rockyou(db_path=db_path),
            "hibp_passwords":     lambda: self.build_hibp_passwords(db_path=db_path),
            # Network intelligence
            "asn_data":           lambda: self.build_asn_data(db_path=db_path),
            "tor_exits":          lambda: self.build_tor_exits(db_path=db_path),
            "iana_ports":         lambda: self.build_iana_ports(db_path=db_path),
            # Compliance
            "owasp":              lambda: self.build_owasp(db_path=db_path),
        }

        # Deduplicate — exploitdb_source and exploitdb_shellcodes are one operation
        deduped = []
        edb_done = False
        for source in sources:
            if source in ("exploitdb_source", "exploitdb_shellcodes"):
                if not edb_done:
                    deduped.append("exploitdb_source")
                    edb_done = True
            else:
                deduped.append(source)

        total = len(deduped)
        for i, source in enumerate(deduped):
            fn = dispatch.get(source)
            if fn is None:
                log.warning(f"Unknown source '{source}' — skipping.")
                continue
            log.info(f"[{i+1}/{total}] Building: {source}")
            try:
                fn()
            except Exception as exc:
                log.error(f"Source '{source}' failed: {exc}")

    # ===========================================================================
    # NVD
    # ===========================================================================

    def build_nvd(self, lite: bool = True, db_path: Optional[Path] = None) -> bool:
        """
        Download CVE records from the NVD 2.0 REST API and import into database.

        The legacy JSON feed URLs (nvdcve-1.1-YYYY.json.gz) were retired by NIST
        in December 2023 and now return 403. This method uses the current 2.0 API:
          https://services.nvd.nist.gov/rest/json/cves/2.0

        IMPORTANT: The NVD 2.0 API requires date windows of <=120 days per request.
        Wider ranges (e.g. 2022-01-01 to 2026-12-31) return HTTP 404 "Not Found".
        We query one calendar year at a time (Jan 01 – Dec 31), which stays within
        limits. If a full-year request fails, it falls back to two 6-month windows.

        Pagination: API returns max 2000 results per page; we loop until done.
        Rate limiting: 6s between requests without API key, 0.6s with key.
        """
        target     = db_path or self.db_path
        year_now   = datetime.now(timezone.utc).year
        year_start = (year_now - 4) if lite else 2002
        years      = list(range(year_start, year_now + 1))

        log.info(f"Building NVD via 2.0 API ({year_start}\u2013{year_now}, {'lite' if lite else 'full'})...")
        log.info("  Note: NVD legacy JSON feeds were retired Dec 2023. Using REST API.")
        log.info(f"  Querying {len(years)} year(s) individually to respect the 120-day API window limit.")

        api_key    = getattr(config, "NVD_API_KEY", None)
        delay      = NVD_API_DELAY_KEY if api_key else NVD_API_DELAY
        headers    = {"apiKey": api_key} if api_key else {}
        total_cves = 0

        for year_idx, year in enumerate(years):
            year_cves = self._fetch_nvd_year(
                year, headers, delay, target, year_idx, len(years),
            )
            total_cves += year_cves
            log.info(f"  Year {year}: {year_cves:,} CVEs (running total: {total_cves:,})")

        self._set_meta(target, META_NVD_LAST_UPDATED, _now())
        self._set_meta(target, META_NVD_BUILD_TYPE, "lite" if lite else "full")
        self._set_meta(target, META_NVD_YEAR_START, str(year_start))
        self._set_meta(target, META_NVD_CVE_COUNT, str(total_cves))

        log.info(f"NVD complete: {total_cves:,} CVEs")
        return total_cves > 0

    def _fetch_nvd_year(
        self,
        year: int,
        headers: dict,
        delay: float,
        target: "Path",
        year_idx: int,
        total_years: int,
    ) -> int:
        """
        Fetch all CVEs published in a single calendar year from NVD 2.0 API.

        The NVD 2.0 API enforces a strict 120-day maximum window per request.
        A full year (365 days) always exceeds this limit and returns 404.
        We therefore always use four quarterly windows (Q1–Q4), each ~90 days.

        Date format: plain ISO 8601 without timezone suffix.
        NVD treats all times as UTC and does NOT accept timezone notation in
        pubStartDate/pubEndDate params — including neither " +0000" nor "+00:00".
        Using requests params={} is correct; no manual URL construction needed.

        Returns the number of CVEs successfully imported.
        """
        import time as _time

        def _fetch_window(start_date: str, end_date: str) -> int:
            """Fetch one date window, paging through all results."""
            count     = 0
            start_idx = 0
            while True:
                params = {
                    "pubStartDate":   start_date,
                    "pubEndDate":     end_date,
                    "startIndex":     start_idx,
                    "resultsPerPage": NVD_API_PAGE,
                }
                try:
                    resp = self.session.get(
                        NVD_API_BASE, params=params,
                        headers=headers, timeout=REQUEST_TIMEOUT,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:
                    log.warning(
                        f"NVD request failed ({start_date[:10]}..{end_date[:10]}, "
                        f"idx={start_idx}): {exc}"
                    )
                    return count   # partial result is better than nothing

                total_results   = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                imported   = self._import_nvd_v2_items(vulnerabilities, target)
                count     += imported
                start_idx += len(vulnerabilities)

                self.progress_cb(
                    "nvd",
                    year_idx * NVD_API_PAGE + start_idx,
                    total_years * NVD_API_PAGE,
                    f"NVD {year} [{start_date[:10]}..{end_date[:10]}]: {count:,}/{total_results:,}",
                )

                if start_idx >= total_results:
                    break
                _time.sleep(delay)
            return count

        # NVD maximum window = 120 days — always use quarterly windows (≤92 days each).
        # Full-year probe is removed: it always returns 404 for a 365-day range.
        quarters = [
            (f"{year}-01-01T00:00:00.000", f"{year}-03-31T23:59:59.999"),  # Q1
            (f"{year}-04-01T00:00:00.000", f"{year}-06-30T23:59:59.999"),  # Q2
            (f"{year}-07-01T00:00:00.000", f"{year}-09-30T23:59:59.999"),  # Q3
            (f"{year}-10-01T00:00:00.000", f"{year}-12-31T23:59:59.999"),  # Q4
        ]
        total = 0
        for q_start, q_end in quarters:
            total += _fetch_window(q_start, q_end)
            _time.sleep(delay)
        return total


    def _update_nvd(self, db_path: Path) -> bool:
        """Update NVD using lastModStartDate filter covering the past 8 days."""
        import time as _time
        from datetime import timedelta
        log.info("Updating NVD via 2.0 API (last 8 days of modifications)...")

        api_key = getattr(config, "NVD_API_KEY", None)
        delay   = NVD_API_DELAY_KEY if api_key else NVD_API_DELAY
        headers = {"apiKey": api_key} if api_key else {}

        week_ago = (datetime.now(timezone.utc) - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%S.000")
        now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.999")

        total     = 0
        start_idx = 0
        while True:
            params = {
                "lastModStartDate": week_ago,
                "lastModEndDate":   now_str,
                "startIndex":       start_idx,
                "resultsPerPage":   NVD_API_PAGE,
            }
            try:
                resp = self.session.get(
                    NVD_API_BASE, params=params,
                    headers=headers, timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.warning(f"NVD update request failed: {exc}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            total    += self._import_nvd_v2_items(vulns, db_path)
            start_idx += len(vulns)
            if start_idx >= data.get("totalResults", 0):
                break
            _time.sleep(delay)

        log.info(f"NVD update complete: {total:,} CVEs refreshed")
        self._set_meta(db_path, META_NVD_LAST_UPDATED, _now())
        return True
    def _import_nvd_v2_items(self, vulnerabilities: list, db_path: Path) -> int:
        """
        Parse NVD 2.0 API vulnerability entries and bulk-insert CVEs + CPE matches.

        NVD 2.0 format (differs from retired 1.1 feed format):
          - Each entry: {"cve": {"id": "CVE-...", "metrics": {...}, ...}}
          - CVSS: cve.metrics.cvssMetricV31[0].cvssData  (or V30, V2)
          - Descriptions: cve.descriptions[{"lang": "en", "value": "..."}]
          - CPE matches: cve.configurations[].nodes[].cpeMatch[]
        """
        cve_rows = []
        cpe_rows = []

        for entry in vulnerabilities:
            try:
                cve    = entry.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # English description
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # CVSS scores: v3.1 preferred, fallback v3.0, then v2
                metrics = cve.get("metrics", {})
                v3s = v3sv = v3v = None
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    bucket = metrics.get(key, [])
                    if bucket:
                        m    = bucket[0].get("cvssData", {})
                        v3s  = m.get("baseScore")
                        v3sv = m.get("baseSeverity")
                        v3v  = m.get("vectorString")
                        break

                v2s = v2sv = v2v = None
                bucket2 = metrics.get("cvssMetricV2", [])
                if bucket2:
                    m    = bucket2[0].get("cvssData", {})
                    v2s  = m.get("baseScore")
                    v2sv = bucket2[0].get("baseSeverity")
                    v2v  = m.get("vectorString")

                # References
                refs = [r.get("url", "") for r in cve.get("references", [])]

                # CWE IDs
                cwe_ids = []
                for w in cve.get("weaknesses", []):
                    for d in w.get("description", []):
                        val = d.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

                # CPE matches
                cpe_list = []
                for cfg in cve.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for cm in node.get("cpeMatch", []):
                            cs = cm.get("criteria", "")
                            if cs:
                                cpe_list.append(cs)
                                cpe_rows.append((cs, cve_id, int(cm.get("vulnerable", True))))

                cve_rows.append((
                    cve_id,
                    cve.get("published", ""),
                    cve.get("lastModified", ""),
                    desc,
                    v3s, v3sv, v3v,
                    v2s, v2sv, v2v,
                    None, None, None, None,   # epss_score, epss_percentile, kev_date_added, kev_required_action
                    json.dumps(cpe_list),
                    json.dumps(refs),
                    json.dumps(cwe_ids),
                    cve.get("sourceIdentifier", ""),
                ))
            except Exception as exc:
                log.debug(f"Skipping malformed NVD 2.0 entry: {exc}")

        if not cve_rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO cves
                    (cve_id, published, modified, description,
                     cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                     cvss_v2_score, cvss_v2_severity, cvss_v2_vector,
                     epss_score, epss_percentile, kev_date_added, kev_required_action,
                     cpe_matches, ref_urls, cwe_ids, assigner)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    cve_rows,
                )
                if cpe_rows:
                    conn.executemany(
                        "INSERT OR IGNORE INTO cpe_matches (cpe_string, cve_id, vulnerable) VALUES (?,?,?)",
                        cpe_rows,
                    )
            conn.close()
            return len(cve_rows)
        except sqlite3.Error as exc:
            log.error(f"NVD DB insert error: {exc}")
            return -1


    # ===========================================================================
    # CISA KEV
    # ===========================================================================

    def build_kev(self, db_path: Optional[Path] = None) -> bool:
        """Download CISA Known Exploited Vulnerabilities catalogue."""
        target = db_path or self.db_path
        log.info("Downloading CISA KEV catalogue...")
        self.progress_cb("kev", 0, 1, "Downloading CISA KEV...")

        try:
            resp = self.session.get(KEV_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            rows  = []
            today = _now()

            for v in vulns:
                cve_id = v.get("cveID", "")
                if not cve_id:
                    continue
                rows.append((
                    cve_id,
                    v.get("vendorProject", ""),
                    v.get("product", ""),
                    v.get("vulnerabilityName", ""),
                    v.get("dateAdded", ""),
                    v.get("shortDescription", ""),
                    v.get("requiredAction", ""),
                    v.get("dueDate", ""),
                    v.get("knownRansomwareCampaignUse", ""),
                    v.get("notes", ""),
                ))

            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO kev
                    (cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, required_action,
                     due_date, known_ransomware, notes)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
                # Also update the kev columns in cves table
                conn.executemany(
                    """UPDATE cves SET kev_date_added=?, kev_required_action=?
                    WHERE cve_id=?""",
                    [(r[4], r[6], r[0]) for r in rows],
                )
            conn.close()

            self._set_meta(target, META_KEV_LAST_UPDATED, today)
            self._set_meta(target, META_KEV_COUNT, str(len(rows)))
            self.progress_cb("kev", 1, 1, f"KEV complete: {len(rows):,} entries")
            log.info(f"KEV complete: {len(rows):,} known exploited vulnerabilities")
            return True

        except Exception as exc:
            log.error(f"KEV build failed: {exc}")
            return False

    # ===========================================================================
    # EPSS
    # ===========================================================================

    def build_epss(self, db_path: Optional[Path] = None) -> bool:
        """Download EPSS daily scores from FIRST.org and update CVE table."""
        target = db_path or self.db_path
        log.info("Downloading EPSS scores...")
        self.progress_cb("epss", 0, 1, "Downloading EPSS scores...")

        try:
            resp = self.session.get(EPSS_URL, stream=True, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            buf = io.BytesIO()
            for chunk in resp.iter_content(CHUNK_SIZE):
                buf.write(chunk)
            buf.seek(0)

            with gzip.GzipFile(fileobj=buf) as gz:
                content = gz.read().decode("utf-8")

            rows  = []
            lines = content.splitlines()
            # First line is a comment with date, second is header
            for line in lines[2:]:
                parts = line.strip().split(",")
                if len(parts) >= 3:
                    cve_id     = parts[0].strip()
                    score      = float(parts[1].strip())
                    percentile = float(parts[2].strip())
                    if cve_id.startswith("CVE-"):
                        rows.append((cve_id, score, percentile, _now()))

            if not rows:
                log.warning("EPSS: no rows parsed.")
                return False

            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO epss (cve_id, score, percentile, date) VALUES (?,?,?,?)",
                    rows,
                )
                # Update epss columns in cves table
                conn.executemany(
                    "UPDATE cves SET epss_score=?, epss_percentile=? WHERE cve_id=?",
                    [(r[1], r[2], r[0]) for r in rows],
                )
            conn.close()

            self._set_meta(target, META_EPSS_LAST_UPDATED, _now())
            self._set_meta(target, META_EPSS_COUNT, str(len(rows)))
            self.progress_cb("epss", 1, 1, f"EPSS complete: {len(rows):,} scores")
            log.info(f"EPSS complete: {len(rows):,} scores")
            return True

        except Exception as exc:
            log.error(f"EPSS build failed: {exc}")
            return False

    # ===========================================================================
    # CWE
    # ===========================================================================

    def build_cwe(self, db_path: Optional[Path] = None) -> bool:
        """Download and parse the MITRE CWE XML database."""
        target = db_path or self.db_path
        log.info("Downloading MITRE CWE database...")
        self.progress_cb("cwe", 0, 1, "Downloading CWE XML...")

        try:
            resp = self.session.get(CWE_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            # CWE is a ZIP containing an XML file
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
                xml_data = zf.read(xml_name).decode("utf-8")

            root = ET.fromstring(xml_data)
            ns   = {"cwe": "http://cwe.mitre.org/cwe-7"}
            rows = []

            for weakness in root.findall(".//cwe:Weakness", ns):
                cwe_id  = "CWE-" + weakness.get("ID", "")
                name    = weakness.get("Name", "")
                abstraction = weakness.get("Abstraction", "")

                desc_el = weakness.find("cwe:Description", ns)
                desc    = (desc_el.text or "").strip() if desc_el is not None else ""

                ext_el  = weakness.find("cwe:Extended_Description", ns)
                ext     = (ext_el.text or "").strip() if ext_el is not None else ""

                like_el = weakness.find(".//cwe:Likelihood_Of_Exploit", ns)
                likelihood = like_el.text.strip() if like_el is not None and like_el.text else ""

                # Consequences
                consequences = []
                for c in weakness.findall(".//cwe:Consequence", ns):
                    scope = [s.text for s in c.findall("cwe:Scope", ns) if s.text]
                    impact = [i.text for i in c.findall("cwe:Impact", ns) if i.text]
                    consequences.append({"scope": scope, "impact": impact})

                # Mitigations
                mitigations = []
                for m in weakness.findall(".//cwe:Mitigation", ns):
                    desc_m = m.find("cwe:Description", ns)
                    if desc_m is not None and desc_m.text:
                        mitigations.append(desc_m.text.strip())

                # Related CWEs
                related = [
                    r.get("CWE_ID", "")
                    for r in weakness.findall(".//cwe:Related_Weakness", ns)
                ]

                # Applicable platforms
                platforms = [
                    p.get("Name", "") or p.get("Class", "")
                    for p in weakness.findall(".//cwe:Language", ns)
                ]

                rows.append((
                    cwe_id, name, abstraction, desc, ext, likelihood,
                    json.dumps(consequences),
                    json.dumps(mitigations),
                    json.dumps(related),
                    json.dumps(platforms),
                ))

            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO cwe
                    (cwe_id, name, abstraction, description, extended_desc,
                     likelihood, consequences, mitigations, related_cwes, platforms)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()

            self._set_meta(target, META_CWE_LAST_UPDATED, _now())
            self._set_meta(target, META_CWE_COUNT, str(len(rows)))
            self.progress_cb("cwe", 1, 1, f"CWE complete: {len(rows):,} weaknesses")
            log.info(f"CWE complete: {len(rows):,} weakness definitions")
            return True

        except Exception as exc:
            log.error(f"CWE build failed: {exc}")
            return False

    # ===========================================================================
    # CAPEC
    # ===========================================================================

    def build_capec(self, db_path: Optional[Path] = None) -> bool:
        """Download and parse the MITRE CAPEC XML database."""
        target = db_path or self.db_path
        log.info("Downloading MITRE CAPEC database...")
        self.progress_cb("capec", 0, 1, "Downloading CAPEC XML...")

        try:
            resp = self.session.get(CAPEC_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            root = ET.fromstring(resp.content)
            ns   = {"capec": "http://capec.mitre.org/capec-3"}
            rows = []

            for pattern in root.findall(".//capec:Attack_Pattern", ns):
                capec_id = "CAPEC-" + pattern.get("ID", "")
                name     = pattern.get("Name", "")
                abstraction = pattern.get("Abstraction", "")

                desc_el = pattern.find("capec:Description", ns)
                desc    = (desc_el.text or "").strip() if desc_el is not None else ""

                ext_el  = pattern.find("capec:Extended_Description", ns)
                ext     = (ext_el.text or "").strip() if ext_el is not None else ""

                like_el = pattern.find(".//capec:Likelihood_Of_Attack", ns)
                likelihood = like_el.text.strip() if like_el is not None and like_el.text else ""

                sev_el  = pattern.find(".//capec:Typical_Severity", ns)
                severity = sev_el.text.strip() if sev_el is not None and sev_el.text else ""

                # Prerequisites
                prereqs = [
                    p.text.strip() for p in pattern.findall(".//capec:Prerequisite", ns)
                    if p.text
                ]

                # Skills required
                skills = [
                    f"{s.get('Level', '')}: {s.text.strip()}"
                    for s in pattern.findall(".//capec:Skill", ns)
                    if s.text
                ]

                # Mitigations
                mitigations = [
                    m.text.strip() for m in pattern.findall(".//capec:Mitigation", ns)
                    if m.text
                ]

                # Related CWEs
                related_cwes = [
                    "CWE-" + c.get("CWE_ID", "")
                    for c in pattern.findall(".//capec:CWE", ns)
                ]

                # Related CAPECs
                related_capecs = [
                    "CAPEC-" + r.get("CAPEC_ID", "")
                    for r in pattern.findall(".//capec:Related_Attack_Pattern", ns)
                ]

                # Attack execution steps
                steps = []
                for step in pattern.findall(".//capec:Attack_Step", ns):
                    step_desc = step.find("capec:Description", ns)
                    if step_desc is not None and step_desc.text:
                        steps.append(step_desc.text.strip())

                rows.append((
                    capec_id, name, abstraction, desc, ext,
                    likelihood, severity,
                    json.dumps(prereqs),
                    json.dumps(skills),
                    json.dumps(mitigations),
                    json.dumps(related_cwes),
                    json.dumps(related_capecs),
                    json.dumps(steps),
                ))

            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO capec
                    (capec_id, name, abstraction, description, extended_desc,
                     likelihood, severity, prerequisites, skills_required,
                     mitigations, related_cwes, related_capecs, attack_steps)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()

            self._set_meta(target, META_CAPEC_LAST_UPDATED, _now())
            self._set_meta(target, META_CAPEC_COUNT, str(len(rows)))
            self.progress_cb("capec", 1, 1, f"CAPEC complete: {len(rows):,} patterns")
            log.info(f"CAPEC complete: {len(rows):,} attack patterns")
            return True

        except Exception as exc:
            log.error(f"CAPEC build failed: {exc}")
            return False

    # ===========================================================================
    # MITRE ATT&CK
    # ===========================================================================

    def build_attack(self, db_path: Optional[Path] = None) -> bool:
        """Download MITRE ATT&CK STIX bundles (Enterprise, ICS, Mobile)."""
        target = db_path or self.db_path
        domains = [
            ("Enterprise", ATTACK_ENTERPRISE_URL),
            ("ICS",        ATTACK_ICS_URL),
            ("Mobile",     ATTACK_MOBILE_URL),
        ]

        log.info("Downloading MITRE ATT&CK framework...")
        self.progress_cb("attack", 0, len(domains), "Downloading ATT&CK STIX bundles...")

        total_techniques = 0
        total_groups     = 0
        attack_version   = "unknown"

        for i, (domain_name, url) in enumerate(domains):
            self.progress_cb("attack", i, len(domains), f"Importing ATT&CK {domain_name}...")
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                bundle = resp.json()

                t, g, v = self._import_attack_bundle(bundle, domain_name, target)
                total_techniques += t
                total_groups     += g
                if v:
                    attack_version = v
                log.info(f"  ATT&CK {domain_name}: {t} techniques, {g} groups")

            except Exception as exc:
                log.error(f"ATT&CK {domain_name} failed: {exc}")

        self._set_meta(target, META_ATTACK_LAST_UPDATED, _now())
        self._set_meta(target, META_ATTACK_VERSION, attack_version)
        self._set_meta(target, META_ATTACK_TECHNIQUE_COUNT, str(total_techniques))
        self._set_meta(target, META_ATTACK_GROUP_COUNT, str(total_groups))
        self.progress_cb("attack", len(domains), len(domains),
                         f"ATT&CK complete: {total_techniques} techniques, {total_groups} groups")
        log.info(f"ATT&CK complete: {total_techniques} techniques, {total_groups} groups")
        return total_techniques > 0

    def _import_attack_bundle(
        self,
        bundle: dict,
        domain: str,
        db_path: Path,
    ) -> tuple[int, int, str]:
        """Parse a STIX 2.x ATT&CK bundle and insert into all four ATT&CK tables."""
        objects = bundle.get("objects", [])
        techniques  = []
        groups      = []
        software    = []
        mitigations = []
        version     = ""

        for obj in objects:
            obj_type = obj.get("type", "")

            # Version from x-mitre-collection
            if obj_type == "x-mitre-collection":
                version = obj.get("x_mitre_version", "")

            elif obj_type == "attack-pattern":
                technique_id = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id", "")
                        break
                if not technique_id:
                    continue

                # Tactics from kill chain phases
                tactics = [
                    p.get("phase_name", "")
                    for p in obj.get("kill_chain_phases", [])
                ]

                parent_id = None
                is_sub    = "." in technique_id
                if is_sub:
                    parent_id = technique_id.split(".")[0]

                techniques.append((
                    technique_id,
                    obj.get("name", ""),
                    json.dumps(tactics),
                    domain,
                    _stix_text(obj.get("description", "")),
                    _stix_text(obj.get("x_mitre_detection", "")),
                    json.dumps(obj.get("x_mitre_mitigations", [])),
                    json.dumps(obj.get("x_mitre_data_sources", [])),
                    json.dumps(obj.get("x_mitre_platforms", [])),
                    json.dumps(obj.get("x_mitre_permissions_required", [])),
                    json.dumps(obj.get("x_mitre_defense_bypassed", [])),
                    int(is_sub),
                    parent_id,
                    next((r.get("url", "") for r in obj.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), ""),
                    obj.get("x_mitre_version", ""),
                ))

            elif obj_type == "intrusion-set":
                group_id = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        group_id = ref.get("external_id", "")
                        break
                if not group_id:
                    continue

                aliases = obj.get("aliases", [])
                country = ""
                # Try to infer country from description
                desc = obj.get("description", "")

                groups.append((
                    group_id,
                    obj.get("name", ""),
                    json.dumps(aliases),
                    _stix_text(desc),
                    country,
                    "[]", "[]",
                    next((r.get("url", "") for r in obj.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), ""),
                ))

            elif obj_type in ("tool", "malware"):
                sw_id = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        sw_id = ref.get("external_id", "")
                        break
                if not sw_id:
                    continue
                software.append((
                    sw_id,
                    obj.get("name", ""),
                    obj_type,
                    json.dumps(obj.get("x_mitre_aliases", [])),
                    _stix_text(obj.get("description", "")),
                    json.dumps(obj.get("x_mitre_platforms", [])),
                    "[]", "[]",
                    next((r.get("url", "") for r in obj.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), ""),
                ))

            elif obj_type == "course-of-action":
                mit_id = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        mit_id = ref.get("external_id", "")
                        break
                if not mit_id:
                    continue
                mitigations.append((
                    mit_id,
                    obj.get("name", ""),
                    _stix_text(obj.get("description", "")),
                    "[]",
                    next((r.get("url", "") for r in obj.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), ""),
                ))

        conn = _fast_conn(db_path)
        with conn:
            if techniques:
                conn.executemany(
                    """INSERT OR REPLACE INTO attack_techniques
                    (technique_id, name, tactic, domain, description, detection,
                     mitigations, data_sources, platforms, permissions,
                     defenses_bypassed, is_subtechnique, parent_id, url, version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    techniques,
                )
            if groups:
                conn.executemany(
                    """INSERT OR REPLACE INTO attack_groups
                    (group_id, name, aliases, description, country,
                     techniques_used, software_used, url)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    groups,
                )
            if software:
                conn.executemany(
                    """INSERT OR REPLACE INTO attack_software
                    (software_id, name, software_type, aliases, description,
                     platforms, techniques_used, groups_using, url)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    software,
                )
            if mitigations:
                conn.executemany(
                    """INSERT OR REPLACE INTO attack_mitigations
                    (mitigation_id, name, description, techniques, url)
                    VALUES (?,?,?,?,?)""",
                    mitigations,
                )
        conn.close()

        return len(techniques), len(groups), version

    # ===========================================================================
    # EXPLOIT-DB (source + shellcodes + papers + bin-sploits)
    # ===========================================================================

    def build_exploitdb(self, db_path: Optional[Path] = None) -> bool:
        """Clone/update Exploit-DB and import exploits + shellcodes + GHDB."""
        target = db_path or self.db_path

        if not shutil.which("git"):
            log.error("git not found. Install git to build the Exploit-DB.")
            return False

        self.progress_cb("exploitdb", 0, 4, "Setting up Exploit-DB repository...")
        self._clone_or_pull(EXPLOITDB_REPO, EXPLOITDB_DIR, "exploitdb")

        commit = _git_commit(EXPLOITDB_DIR)
        self.progress_cb("exploitdb", 1, 4, "Importing exploit index...")
        exploit_count = self._import_exploitdb_csv(
            EXPLOITDB_DIR / "files_exploits.csv",
            EXPLOITDB_DIR, "exploits",
            target,
        )

        self.progress_cb("exploitdb", 2, 4, "Importing shellcode index...")
        shellcode_count = self._import_shellcodes_csv(
            EXPLOITDB_DIR / "files_shellcodes.csv",
            EXPLOITDB_DIR,
            target,
        )

        self.progress_cb("exploitdb", 3, 4, "Importing GHDB dorks...")
        # GHDB is inside the Exploit-DB repo.
        # File name varies by repo version — check multiple candidate paths.
        _ghdb_candidates = [
            EXPLOITDB_DIR / "files_ghdb.csv",
            EXPLOITDB_DIR / "ghdb" / "files_ghdb.csv",
            EXPLOITDB_DIR / "ghdb.csv",
            EXPLOITDB_DIR / "ghdb" / "ghdb.csv",
        ]
        _ghdb_path = next((p for p in _ghdb_candidates if p.exists()), None)
        if _ghdb_path is None:
            log.info(
                "GHDB file not found in Exploit-DB clone — "
                "dorks skipped (not all repo versions include this file)."
            )
            ghdb_count = 0
        else:
            ghdb_count = self._import_ghdb(_ghdb_path, target)

        self._set_meta(target, META_EDB_LAST_UPDATED, _now())
        self._set_meta(target, META_EDB_COMMIT, commit)
        self._set_meta(target, META_EDB_EXPLOIT_COUNT, str(exploit_count))
        self._set_meta(target, META_EDB_SHELLCODE_COUNT, str(shellcode_count))
        self._set_meta(target, META_GHDB_COUNT, str(ghdb_count))

        self.progress_cb("exploitdb", 4, 4,
                         f"Exploit-DB complete: {exploit_count:,} exploits, "
                         f"{shellcode_count:,} shellcodes, {ghdb_count:,} GHDB dorks")
        log.info(
            f"Exploit-DB complete: {exploit_count:,} exploits | "
            f"{shellcode_count:,} shellcodes | {ghdb_count:,} GHDB dorks"
        )
        return exploit_count > 0

    def build_ghdb(self, db_path: Optional[Path] = None) -> bool:
        """
        Build/refresh GHDB dork database from the Exploit-DB repo.

        Called as a standalone source (e.g. when 'ghdb' appears in BUILD_TIERS
        or via --db-build-source ghdb). Requires the Exploit-DB repo to be
        cloned first (build_exploitdb() handles that). If the repo is not
        present, clones it first.
        """
        target = db_path or self.db_path
        log.info("Building GHDB dork database...")
        self.progress_cb("ghdb", 0, 1, "Setting up GHDB...")

        # Ensure the Exploit-DB repo is present
        if not EXPLOITDB_DIR.exists() or not (EXPLOITDB_DIR / ".git").exists():
            log.info("Exploit-DB repo not found — cloning for GHDB...")
            if not self._clone_or_pull(EXPLOITDB_REPO, EXPLOITDB_DIR, "exploitdb"):
                log.error("Cannot clone Exploit-DB repo for GHDB build.")
                return False
        else:
            self._clone_or_pull(EXPLOITDB_REPO, EXPLOITDB_DIR, "exploitdb")

        _ghdb_candidates = [
            EXPLOITDB_DIR / "files_ghdb.csv",
            EXPLOITDB_DIR / "ghdb" / "files_ghdb.csv",
            EXPLOITDB_DIR / "ghdb.csv",
            EXPLOITDB_DIR / "ghdb" / "ghdb.csv",
        ]
        ghdb_path = next((p for p in _ghdb_candidates if p.exists()), None)
        if ghdb_path is None:
            log.info(
                "GHDB file not found in Exploit-DB repo — "
                "this repo clone does not include the GHDB dataset."
            )
            return True   # not a fatal error

        count = self._import_ghdb(ghdb_path, target)
        self._set_meta(target, META_GHDB_COUNT, str(count))
        self.progress_cb("ghdb", 1, 1, f"GHDB complete: {count:,} dorks")
        log.info(f"GHDB complete: {count:,} dorks imported")
        return True

    def _import_exploitdb_csv(
        self,
        csv_path: Path,
        repo_dir: Path,
        table: str,
        db_path: Path,
    ) -> int:
        """Parse files_exploits.csv and import records + copy files to EXPLOITS_DIR."""
        if not csv_path.exists():
            log.warning(f"Exploit-DB CSV not found: {csv_path}")
            return 0

        rows = []
        files_to_copy = []

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for rec in reader:
                    try:
                        eid      = int(rec.get("id", 0) or 0)
                        if not eid:
                            continue
                        file_rel = rec.get("file", "").strip()
                        title    = rec.get("description", "").strip()
                        etype    = rec.get("type", "").strip()
                        platform = rec.get("platform", "").strip()
                        date_pub = rec.get("date_published", "").strip()
                        author   = rec.get("author", "").strip()
                        verified = int(rec.get("verified", 0) or 0)
                        codes    = rec.get("codes", "").strip()
                        port_str = rec.get("port", "").strip()
                        tags     = rec.get("tags", "").strip()

                        cve_ids  = [c.strip() for c in codes.split(";")
                                    if c.strip().upper().startswith("CVE-")]
                        port_val = int(port_str) if port_str.isdigit() else None

                        src = repo_dir / file_rel
                        if src.exists():
                            files_to_copy.append((src, file_rel))

                        rows.append((
                            eid, title, file_rel, etype, platform,
                            date_pub, author, verified,
                            json.dumps(cve_ids),
                            f"https://www.exploit-db.com/exploits/{eid}",
                            title, port_val, tags,
                        ))
                    except Exception:
                        continue
        except OSError as exc:
            log.error(f"Cannot read CSV {csv_path}: {exc}")
            return 0

        # Copy exploit files
        self._copy_files_parallel(files_to_copy, EXPLOITS_DIR)

        if not rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO exploits
                    (exploit_id, title, file_path, type, platform,
                     date_published, author, verified, cve_ids,
                     edb_url, description, port, tags)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()
            return len(rows)
        except sqlite3.Error as exc:
            log.error(f"Exploit insert error: {exc}")
            return 0

    def _import_shellcodes_csv(
        self,
        csv_path: Path,
        repo_dir: Path,
        db_path: Path,
    ) -> int:
        """Parse files_shellcodes.csv and import shellcode index."""
        if not csv_path.exists():
            log.warning(f"Shellcodes CSV not found: {csv_path}")
            return 0

        rows = []
        files_to_copy = []

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for rec in reader:
                    try:
                        sid      = int(rec.get("id", 0) or 0)
                        if not sid:
                            continue
                        file_rel = rec.get("file", "").strip()
                        title    = rec.get("description", "").strip()
                        stype    = rec.get("type", "").strip()
                        platform = rec.get("platform", "").strip()
                        date_pub = rec.get("date_published", "").strip()
                        author   = rec.get("author", "").strip()
                        verified = int(rec.get("verified", 0) or 0)
                        arch     = rec.get("architecture", "").strip()

                        src = repo_dir / file_rel
                        if src.exists():
                            files_to_copy.append((src, file_rel))

                        rows.append((
                            sid, title, file_rel, stype, platform,
                            date_pub, author, verified,
                            f"https://www.exploit-db.com/shellcodes/{sid}",
                            title, arch,
                        ))
                    except Exception:
                        continue
        except OSError as exc:
            log.error(f"Cannot read shellcodes CSV: {exc}")
            return 0

        self._copy_files_parallel(files_to_copy, EXPLOITS_DIR)

        if not rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO shellcodes
                    (shellcode_id, title, file_path, type, platform,
                     date_published, author, verified,
                     edb_url, description, architecture)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()
            return len(rows)
        except sqlite3.Error as exc:
            log.error(f"Shellcode insert error: {exc}")
            return 0

    def _import_ghdb(self, csv_path: Path, db_path: Path) -> int:
        """Parse ghdb.csv from the Exploit-DB repo and import GHDB dorks."""
        if not csv_path.exists():
            log.debug(f"GHDB CSV not found at {csv_path}")
            return 0

        rows = []
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for rec in reader:
                    try:
                        ghdb_id  = int(rec.get("id", 0) or 0)
                        category = rec.get("category_name", "").strip()
                        query    = rec.get("query", "").strip()
                        desc     = rec.get("description", "").strip()
                        date_add = rec.get("date_added", "").strip()
                        author   = rec.get("author_name", "").strip()
                        url      = f"https://www.exploit-db.com/ghdb/{ghdb_id}"
                        if ghdb_id and query:
                            rows.append((ghdb_id, category, query, desc, date_add, author, url))
                    except Exception:
                        continue
        except OSError as exc:
            log.warning(f"Cannot read GHDB CSV: {exc}")
            return 0

        if not rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO ghdb (ghdb_id, category, query, description, date_added, author, url) VALUES (?,?,?,?,?,?,?)",
                    rows,
                )
            conn.close()
            return len(rows)
        except sqlite3.Error as exc:
            log.error(f"GHDB insert error: {exc}")
            return 0

    # ===========================================================================
    # THREAT INTELLIGENCE FEEDS
    # ===========================================================================

    def build_threat_feeds(self, db_path: Optional[Path] = None) -> bool:
        """Download IP reputation feeds (Emerging Threats, Spamhaus, AbuseIPDB)."""
        target = db_path or self.db_path
        feeds  = [
            (EMERGING_THREATS_URL, "emerging_threats", "malware/compromised"),
            (SPAMHAUS_DROP_URL,    "spamhaus_drop",    "spam/botnet"),
            (ABUSEIPDB_URL,        "abuseipdb",        "scanner/attacker"),
        ]

        total = 0
        for i, (url, source, category) in enumerate(feeds):
            self.progress_cb("feeds", i, len(feeds), f"Downloading {source}...")
            count = self._import_ip_feed(url, source, category, target)
            if count >= 0:
                total += count
                log.info(f"  {source}: {count:,} IPs")

        self._set_meta(target, META_FEEDS_LAST_UPDATED, _now())
        self._set_meta(target, META_IP_REP_COUNT, str(total))
        log.info(f"Threat feeds complete: {total:,} IPs")
        return True

    def _import_ip_feed(self, url: str, source: str, category: str, db_path: Path) -> int:
        """Download a text IP feed and insert rows into ip_reputation."""
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            today = _now()[:10]
            rows  = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                ip = line.split()[0].split("/")[0]
                if _valid_ipv4(ip):
                    rows.append((ip, category, source, today, ""))
            if not rows:
                return 0
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO ip_reputation (ip_address, category, source, added_date, notes) VALUES (?,?,?,?,?)",
                    rows,
                )
            conn.close()
            return len(rows)
        except Exception as exc:
            log.warning(f"{source} feed failed: {exc}")
            return -1

    def build_hash_feeds(self, db_path: Optional[Path] = None) -> bool:
        """
        Download MalwareBazaar hash feed and import into hash_reputation table.

        Uses the free daily CSV dump (no API key required):
          https://mb-api.abuse.ch/downloads/malwarebazaar.csv.zip

        The ZIP contains malwarebazaar.csv with ~1M+ records.
        We import the most recent 50,000 to keep build time reasonable.
        """
        import zipfile as _zipfile
        target = db_path or self.db_path
        log.info("Downloading MalwareBazaar hash feed (daily CSV dump)...")
        self.progress_cb("hashes", 0, 1, "Downloading MalwareBazaar CSV...")
        try:
            resp = self.session.get(MALWAREBAZAAR_URL, stream=True, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            # Download to memory
            buf = io.BytesIO()
            for chunk in resp.iter_content(CHUNK_SIZE):
                buf.write(chunk)
            buf.seek(0)

            today  = _now()[:10]
            rows   = []
            limit  = 50000  # cap to avoid extremely long build time

            with _zipfile.ZipFile(buf) as zf:
                csv_name = next((n for n in zf.namelist() if n.endswith(".csv")), None)
                if not csv_name:
                    log.warning("MalwareBazaar ZIP contains no CSV file.")
                    return False

                with zf.open(csv_name) as csv_fh:
                    text_wrapper = io.TextIOWrapper(csv_fh, encoding="utf-8", errors="replace")
                    # Skip comment lines starting with #
                    lines = (l for l in text_wrapper if not l.startswith("#"))
                    reader = csv.DictReader(lines)
                    for rec in reader:
                        if len(rows) >= limit:
                            break
                        sha256 = (rec.get("sha256_hash") or "").strip().lower()
                        if not sha256:
                            continue
                        rows.append((
                            sha256,
                            (rec.get("md5_hash") or "").strip().lower(),
                            (rec.get("sha1_hash") or "").strip().lower(),
                            (rec.get("signature") or "").strip(),
                            (rec.get("file_type") or "").strip(),
                            "malwarebazaar",
                            today,
                            (rec.get("tags") or "").strip(),
                        ))

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        """INSERT OR REPLACE INTO hash_reputation
                        (hash_sha256, hash_md5, hash_sha1, malware_family,
                         malware_type, source, added_date, signature)
                        VALUES (?,?,?,?,?,?,?,?)""",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_HASH_REP_COUNT, str(len(rows)))
            self.progress_cb("hashes", 1, 1, f"Hash feeds complete: {len(rows):,} hashes")
            log.info(f"Hash feeds complete: {len(rows):,} hashes from MalwareBazaar")
            return True

        except Exception as exc:
            log.error(f"Hash feed failed: {exc}")
            return False

    def build_ioc_urls(self, db_path: Optional[Path] = None) -> bool:
        """Download URLhaus malicious URL feed."""
        target = db_path or self.db_path
        log.info("Downloading URLhaus feed...")
        self.progress_cb("ioc_urls", 0, 1, "Downloading URLhaus CSV...")
        try:
            resp = self.session.get(URLHAUS_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            rows = []
            for line in resp.text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) < 7:
                    continue
                try:
                    uid, date_add, url_val, url_status, threat, tags, host = (
                        parts[0], parts[1], parts[2], parts[3],
                        parts[4], parts[5], parts[6] if len(parts) > 6 else "",
                    )
                    ip  = parts[7].strip('"') if len(parts) > 7 else ""
                    rows.append((url_val, host, ip, url_status, date_add[:10], threat, tags, "", uid))
                except Exception:
                    continue

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        """INSERT OR IGNORE INTO ioc_urls
                        (url, host, ip_address, url_status, date_added,
                         threat, tags, reporter, urlhaus_id)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_IOC_URL_COUNT, str(len(rows)))
            self.progress_cb("ioc_urls", 1, 1, f"URLhaus complete: {len(rows):,} URLs")
            log.info(f"URLhaus complete: {len(rows):,} malicious URLs")
            return True

        except Exception as exc:
            log.error(f"URLhaus failed: {exc}")
            return False

    def build_threatfox(self, db_path: Optional[Path] = None) -> bool:
        """Download ThreatFox IOC feed."""
        target = db_path or self.db_path
        log.info("Downloading ThreatFox IOC feed...")
        self.progress_cb("threatfox", 0, 1, "Downloading ThreatFox...")
        try:
            resp = self.session.get(THREATFOX_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            rows = []
            for ioc_id_str, entries in data.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    try:
                        rows.append((
                            int(ioc_id_str) if ioc_id_str.isdigit() else None,
                            entry.get("ioc", ""),
                            entry.get("ioc_type", ""),
                            entry.get("threat_type", ""),
                            entry.get("malware", ""),
                            entry.get("malware_alias", ""),
                            int(entry.get("confidence_level", 0) or 0),
                            entry.get("first_seen", "")[:10] if entry.get("first_seen") else "",
                            entry.get("reporter", ""),
                            json.dumps(entry.get("tags") or []),
                            entry.get("reference", ""),
                        ))
                    except Exception:
                        continue

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        """INSERT OR IGNORE INTO ioc_threatfox
                        (ioc_id, ioc_value, ioc_type, threat_type, malware,
                         malware_alias, confidence, date_added, reporter,
                         tags, reference)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_IOC_THREATFOX_COUNT, str(len(rows)))
            self.progress_cb("threatfox", 1, 1, f"ThreatFox complete: {len(rows):,} IOCs")
            log.info(f"ThreatFox complete: {len(rows):,} IOCs")
            return True

        except Exception as exc:
            log.error(f"ThreatFox failed: {exc}")
            return False

    def build_c2_botnet(self, db_path: Optional[Path] = None) -> bool:
        """Download Feodo Tracker C2/botnet infrastructure list."""
        target = db_path or self.db_path
        log.info("Downloading Feodo Tracker C2 list...")
        self.progress_cb("c2_botnet", 0, 1, "Downloading Feodo Tracker...")
        try:
            resp = self.session.get(FEODO_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            rows = []
            for entry in data:
                rows.append((
                    entry.get("ip_address", ""),
                    int(entry.get("port", 0) or 0),
                    entry.get("status", ""),
                    entry.get("malware", ""),
                    entry.get("first_seen", ""),
                    entry.get("last_seen", ""),
                    entry.get("country", ""),
                    entry.get("as_number", ""),
                    "feodo_tracker",
                ))

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        """INSERT OR IGNORE INTO c2_botnet
                        (ip_address, port, status, malware, first_seen,
                         last_seen, country, asn, source)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_C2_COUNT, str(len(rows)))
            self.progress_cb("c2_botnet", 1, 1, f"Feodo Tracker complete: {len(rows):,} C2s")
            log.info(f"Feodo Tracker complete: {len(rows):,} C2 entries")
            return True

        except Exception as exc:
            log.error(f"Feodo Tracker failed: {exc}")
            return False

    # ===========================================================================
    # SCANNING INTELLIGENCE
    # ===========================================================================

    def build_nuclei(self, db_path: Optional[Path] = None) -> bool:
        """Clone/update Nuclei templates and index metadata into database."""
        target = db_path or self.db_path
        log.info("Setting up Nuclei templates...")
        self.progress_cb("nuclei", 0, 2, "Cloning/updating Nuclei templates...")

        self._clone_or_pull(NUCLEI_REPO, NUCLEI_DIR, "nuclei")

        self.progress_cb("nuclei", 1, 2, "Indexing Nuclei template metadata...")
        count = self._index_nuclei_templates(NUCLEI_DIR, target)

        self._set_meta(target, META_NUCLEI_LAST_UPDATED, _now())
        self._set_meta(target, META_NUCLEI_TEMPLATE_COUNT, str(count))
        self.progress_cb("nuclei", 2, 2, f"Nuclei complete: {count:,} templates indexed")
        log.info(f"Nuclei complete: {count:,} templates")
        return count > 0

    def _index_nuclei_templates(self, templates_dir: Path, db_path: Path) -> int:
        """Walk Nuclei template directory and parse YAML headers for metadata."""
        if not _YAML_AVAILABLE:
            log.warning("PyYAML not installed — Nuclei template indexing skipped. Install with: pip install PyYAML")
            return 0
        rows = []
        for yaml_file in templates_dir.rglob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                # Parse YAML front matter
                try:
                    data = yaml.safe_load(content)
                except Exception:
                    continue

                if not isinstance(data, dict):
                    continue

                info = data.get("info", {})
                if not info:
                    continue

                template_id = data.get("id", yaml_file.stem)
                name        = info.get("name", "")
                severity    = (info.get("severity") or "").lower()
                description = info.get("description", "") or ""
                tags        = info.get("tags", "")
                author      = info.get("author", "")
                protocol    = data.get("requests") and "http" or \
                              data.get("network") and "tcp" or \
                              data.get("dns") and "dns" or "other"

                # Extract CVE IDs from tags or classification
                classification = info.get("classification", {}) or {}
                cve_ids = []
                if isinstance(tags, list):
                    cve_ids = [t for t in tags if str(t).upper().startswith("CVE-")]
                    tags    = json.dumps(tags)
                elif isinstance(tags, str):
                    cve_ids = re.findall(r"CVE-\d{4}-\d+", tags, re.IGNORECASE)

                cwe_ids = classification.get("cwe-id", []) or []
                if isinstance(cwe_ids, str):
                    cwe_ids = [cwe_ids]

                # Check if CVE is in KEV (will be updated after KEV build)
                is_kev = 0

                # Relative path from nuclei dir root
                rel_path = str(yaml_file.relative_to(templates_dir))
                category = rel_path.split(os.sep)[0]

                # Date modified from git or file stat
                try:
                    mtime = yaml_file.stat().st_mtime
                    date_mod = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
                except Exception:
                    date_mod = ""

                rows.append((
                    template_id, name, rel_path, severity, category,
                    tags if isinstance(tags, str) else json.dumps(tags),
                    description[:500],
                    json.dumps(cve_ids), json.dumps(cwe_ids),
                    author if isinstance(author, str) else json.dumps(author),
                    is_kev, protocol, date_mod,
                ))

            except Exception:
                continue

        if not rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO nuclei_templates
                    (template_id, name, file_path, severity, category,
                     tags, description, cve_ids, cwe_ids, author,
                     is_kev, protocol, date_modified)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()
            return len(rows)
        except sqlite3.Error as exc:
            log.error(f"Nuclei index insert error: {exc}")
            return 0

    def build_default_creds(self, db_path: Optional[Path] = None) -> bool:
        """Download default credentials list from ihebski/DefaultCreds-cheat-sheet."""
        target = db_path or self.db_path
        log.info("Downloading default credentials list...")
        self.progress_cb("default_creds", 0, 1, "Downloading DefaultCreds-cheat-sheet...")
        try:
            resp = self.session.get(DEFAULT_CREDS_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            rows   = []
            reader = csv.DictReader(io.StringIO(resp.text))
            for rec in reader:
                try:
                    rows.append((
                        rec.get("Vendor", "").strip(),
                        rec.get("Product Name", "").strip(),
                        rec.get("Device Type", "").strip(),
                        rec.get("Username", "").strip(),
                        rec.get("Password", "").strip(),
                        rec.get("Notes", "").strip(),
                        "defaultcreds-cheatsheet",
                    ))
                except Exception:
                    continue

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        "INSERT OR IGNORE INTO default_creds (vendor, product, device_type, username, password, notes, source) VALUES (?,?,?,?,?,?,?)",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_DEFAULT_CREDS_COUNT, str(len(rows)))
            self.progress_cb("default_creds", 1, 1, f"Default creds complete: {len(rows):,} entries")
            log.info(f"Default creds complete: {len(rows):,} entries")
            return True

        except Exception as exc:
            log.error(f"Default creds failed: {exc}")
            return False

    def build_iot_creds(self, db_path: Optional[Path] = None) -> bool:
        """
        Build IoT/ICS device default credentials database.

        Sources tried in order:
          1. creds.csv from jh0ker/mitmproxy_addon_defaultcreds (IoT focused)
          2. Hardcoded seed list of ~60 most common IoT device default credentials
             (always imported as a baseline regardless of network availability)
        """
        target = db_path or self.db_path
        log.info("Downloading IoT default credentials...")
        self.progress_cb("iot_creds", 0, 1, "Downloading IoT default credentials...")

        rows: list[tuple] = []

        # ── Try external sources ─────────────────────────────────────────
        for url in IOT_CREDS_URLS:
            try:
                resp = self.session.get(url, timeout=30)
                resp.raise_for_status()
                text = resp.text

                # Detect format
                if url.endswith(".csv") or "," in text[:200]:
                    reader = csv.DictReader(io.StringIO(text))
                    for rec in reader:
                        try:
                            vendor   = (rec.get("Manufacturer") or rec.get("vendor") or rec.get("manufacturer") or "").strip()
                            model    = (rec.get("Model") or rec.get("model") or "").strip()
                            username = (rec.get("Username") or rec.get("username") or "").strip()
                            password = (rec.get("Password") or rec.get("password") or "").strip()
                            service  = (rec.get("Protocol") or rec.get("service") or rec.get("protocol") or "").strip()
                            port_str = (rec.get("Port") or rec.get("port") or "").strip()
                            port_val = int(port_str) if port_str.isdigit() else None
                            if vendor or model:
                                rows.append((vendor, model, "IoT/ICS", service, port_val, username, password, ""))
                        except Exception:
                            continue
                    log.info(f"IoT creds: {len(rows)} entries from {url}")
                    break  # success — stop trying further URLs
            except Exception as exc:
                log.debug(f"IoT creds URL failed ({url}): {exc}")
                continue

        if not rows:
            log.info("External IoT creds sources unavailable — using built-in seed list.")

        # ── Always add built-in seed ────────────────────────────────────
        # Format: (vendor, model, device_type, service, port, username, password, notes)
        _SEED = [
            ("Cisco",       "IOS Router",     "IoT/ICS", "ssh",   22,   "cisco",  "cisco",    ""),
            ("Cisco",       "IOS Router",     "IoT/ICS", "telnet",23,   "cisco",  "cisco",    ""),
            ("Cisco",       "IOS Router",     "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Cisco",       "ASA Firewall",   "IoT/ICS", "http",  80,   "admin",  "",         "blank password"),
            ("Netgear",     "Router",         "IoT/ICS", "http",  80,   "admin",  "password", ""),
            ("Netgear",     "Router",         "IoT/ICS", "telnet",23,   "admin",  "password", ""),
            ("D-Link",      "Router",         "IoT/ICS", "http",  80,   "admin",  "",         "blank password"),
            ("D-Link",      "Router",         "IoT/ICS", "telnet",23,   "admin",  "",         "blank password"),
            ("TP-Link",     "Router",         "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("TP-Link",     "Router",         "IoT/ICS", "telnet",23,   "admin",  "admin",    ""),
            ("Linksys",     "Router",         "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("ASUS",        "Router",         "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Ubiquiti",    "UniFi AP",       "IoT/ICS", "ssh",   22,   "ubnt",   "ubnt",     ""),
            ("Ubiquiti",    "AirOS",          "IoT/ICS", "http",  80,   "ubnt",   "ubnt",     ""),
            ("MikroTik",    "RouterOS",       "IoT/ICS", "ssh",   22,   "admin",  "",         "blank password"),
            ("MikroTik",    "RouterOS",       "IoT/ICS", "telnet",23,   "admin",  "",         "blank password"),
            ("Hikvision",   "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "12345",    ""),
            ("Hikvision",   "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Dahua",       "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Axis",        "IP Camera",      "IoT/ICS", "http",  80,   "root",   "pass",     ""),
            ("Axis",        "IP Camera",      "IoT/ICS", "http",  80,   "root",   "",         "blank password"),
            ("Foscam",      "IP Camera",      "IoT/ICS", "http",  88,   "admin",  "",         "blank password"),
            ("Samsung",     "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "4321",     ""),
            ("Hanwha",      "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Bosch",       "IP Camera",      "IoT/ICS", "http",  80,   "service","service",  ""),
            ("FLIR",        "Camera",         "IoT/ICS", "http",  80,   "admin",  "fliradmin",""),
            ("Pelco",       "IP Camera",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Siemens",     "S7-300 PLC",     "IoT/ICS", "s7comm",102,  "",       "",         "no auth by default"),
            ("Siemens",     "LOGO! PLC",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Allen-Bradley","MicroLogix",    "IoT/ICS", "http",  80,   "",       "",         "no auth by default"),
            ("Schneider",   "Modicon M340",   "IoT/ICS", "http",  80,   "USER",   "USER",     ""),
            ("Schneider",   "Modicon M340",   "IoT/ICS", "http",  80,   "USER",   "",         "blank password"),
            ("ABB",         "Panel 800",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("GE",          "PACSystems",     "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Emerson",     "DeltaV",         "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Honeywell",   "Experion",       "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Moxa",        "NPort",          "IoT/ICS", "telnet",23,   "admin",  "moxa",     ""),
            ("Moxa",        "NPort",          "IoT/ICS", "http",  80,   "admin",  "moxa",     ""),
            ("Advantech",   "ADAM-6000",      "IoT/ICS", "http",  80,   "root",   "00000000", ""),
            ("Phoenix",     "FL mGuard",      "IoT/ICS", "ssh",   22,   "admin",  "nAdmin",   ""),
            ("Wago",        "750-881",        "IoT/ICS", "http",  80,   "admin",  "wago",     ""),
            ("Wago",        "750-881",        "IoT/ICS", "ftp",   21,   "admin",  "wago",     ""),
            ("BACnet",      "Device",         "IoT/ICS", "bacnet",47808,  "",     "",         "no auth by default"),
            ("Tridium",     "Niagara AX",     "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Johnson",     "Metasys",        "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Digi",        "ConnectPort",    "IoT/ICS", "http",  80,   "root",   "dbps",     ""),
            ("Digi",        "ConnectPort",    "IoT/ICS", "telnet",23,   "root",   "dbps",     ""),
            ("Lantronix",   "Device Server",  "IoT/ICS", "telnet",9999, "",       "",         "blank password"),
            ("Peplink",     "Balance Router", "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Crestron",    "AirMedia",       "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("AMX",         "NI Controller",  "IoT/ICS", "http",  80,   "administrator","password",""),
            ("Extron",      "Control Proc.",  "IoT/ICS", "ssh",   22,   "admin",  "extron",   ""),
            ("Polycom",     "Phone",          "IoT/ICS", "http",  80,   "admin",  "456",      ""),
            ("Grandstream", "GXP Phone",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Yealink",     "SIP Phone",      "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("Shoretel",    "Phone",          "IoT/ICS", "http",  80,   "admin",  "changeme", ""),
            ("Eaton",       "Network Card",   "IoT/ICS", "http",  80,   "admin",  "admin",    ""),
            ("APC",         "UPS NMC",        "IoT/ICS", "http",  80,   "apc",    "apc",      ""),
            ("Raritan",     "KVM",            "IoT/ICS", "http",  80,   "admin",  "raritan",  ""),
            ("iDRAC",       "Dell iDRAC",     "IoT/ICS", "http",  80,   "root",   "calvin",   ""),
            ("iLO",         "HP iLO",         "IoT/ICS", "http",  80,   "Administrator","",    "blank password"),
        ]
        rows.extend(_SEED)

        try:
            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO iot_default_creds (vendor, model, device_type, service, port, username, password, notes) VALUES (?,?,?,?,?,?,?,?)",
                    rows,
                )
            conn.close()

            self._set_meta(target, META_IOT_CREDS_COUNT, str(len(rows)))
            self.progress_cb("iot_creds", 1, 1, f"IoT creds complete: {len(rows):,} entries")
            log.info(f"IoT creds complete: {len(rows):,} entries")
            return True

        except Exception as exc:
            log.error(f"IoT creds failed: {exc}")
            return False

    def build_waf_signatures(self, db_path: Optional[Path] = None) -> bool:
        """Clone wafw00f and extract WAF detection signatures."""
        target = db_path or self.db_path
        log.info("Building WAF signatures from wafw00f...")
        self.progress_cb("waf", 0, 1, "Cloning wafw00f repository...")

        waf_dir = DB_DIR / "wafw00f_repo"
        if not self._clone_or_pull(WAFW00F_REPO, waf_dir, "wafw00f"):
            log.warning("wafw00f clone failed — using pip fallback.")
            try:
                import wafw00f.wafdb as wafdb
                waf_dir = Path(wafdb.__file__).parent
            except ImportError:
                log.warning("wafw00f not available — skipping WAF signatures.")
                return False

        # Parse wafw00f plugin files
        rows        = []
        plugins_dir = waf_dir / "wafw00f" / "plugins"
        if not plugins_dir.exists():
            plugins_dir = waf_dir / "plugins"

        if plugins_dir.exists():
            for py_file in plugins_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                try:
                    content  = py_file.read_text(encoding="utf-8", errors="replace")
                    waf_name = py_file.stem.replace("_", " ").title()

                    # Extract cookie/header patterns from source
                    cookie_pats = re.findall(r'["\']([^"\']{5,50})["\'].*cookie', content, re.IGNORECASE)
                    header_pats = re.findall(r'["\']([^"\']{5,50})["\'].*header', content, re.IGNORECASE)

                    for pat in set(cookie_pats[:5]):
                        rows.append((waf_name, "cookie", pat, 80, "wafw00f"))
                    for pat in set(header_pats[:5]):
                        rows.append((waf_name, "header", pat, 80, "wafw00f"))
                    if not cookie_pats and not header_pats:
                        rows.append((waf_name, "plugin", py_file.stem, 100, "wafw00f"))

                except Exception:
                    continue

        if rows:
            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO waf_signatures (waf_name, indicator_type, indicator_value, confidence, source) VALUES (?,?,?,?,?)",
                    rows,
                )
            conn.close()

        self._set_meta(target, META_WAF_SIG_COUNT, str(len(rows)))
        self.progress_cb("waf", 1, 1, f"WAF signatures complete: {len(rows):,} entries")
        log.info(f"WAF signatures complete: {len(rows):,} entries")
        return True

    # ===========================================================================
    # WORDLISTS
    # ===========================================================================

    def _build_wordlist_repo(
        self,
        repo_url: str,
        dest_dir: Path,
        source_name: str,
        meta_commit_key: Optional[str],
        db_path: Path,
    ) -> bool:
        """Clone/update a wordlist git repository and index its files."""
        log.info(f"Setting up {source_name} wordlists...")
        self.progress_cb("wordlists", 0, 2, f"Cloning/updating {source_name}...")

        self._clone_or_pull(repo_url, dest_dir, source_name)
        commit = _git_commit(dest_dir)

        if meta_commit_key:
            self._set_meta(db_path, meta_commit_key, commit)

        self.progress_cb("wordlists", 1, 2, f"Indexing {source_name} files...")
        count = self._index_wordlist_directory(dest_dir, source_name, db_path)

        self._set_meta(db_path, META_WORDLISTS_LAST_UPDATED, _now())
        self._set_meta(db_path, META_WORDLISTS_COUNT, str(count))
        self.progress_cb("wordlists", 2, 2, f"{source_name} complete: {count:,} files indexed")
        log.info(f"{source_name} complete: {count:,} wordlist files indexed")
        return True

    def _index_wordlist_directory(
        self,
        root_dir: Path,
        source: str,
        db_path: Path,
    ) -> int:
        """Walk a directory and add .txt wordlist files to the wordlist_index table."""
        rows = []
        for txt_file in root_dir.rglob("*.txt"):
            try:
                stat      = txt_file.stat()
                rel_path  = str(txt_file.relative_to(root_dir.parent))
                parts     = txt_file.relative_to(root_dir).parts
                category  = parts[0] if len(parts) > 1 else "misc"

                # Count lines (fast estimate)
                line_count = 0
                try:
                    with open(txt_file, "rb") as f:
                        line_count = sum(1 for _ in f)
                except Exception:
                    pass

                rows.append((
                    txt_file.name,
                    rel_path,
                    category,
                    "",
                    line_count,
                    stat.st_size,
                    source,
                    "",
                ))
            except Exception:
                continue

        if not rows:
            return 0

        try:
            conn = _fast_conn(db_path)
            with conn:
                conn.executemany(
                    """INSERT OR IGNORE INTO wordlist_index
                    (name, file_path, category, description,
                     line_count, file_size_bytes, source, tags)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()
            return len(rows)
        except sqlite3.Error as exc:
            log.error(f"Wordlist index insert error: {exc}")
            return 0

    def build_rockyou(self, db_path: Optional[Path] = None) -> bool:
        """Download rockyou.txt and register it in the wordlist index."""
        target   = db_path or self.db_path
        dest     = WORDLISTS_DIR / "rockyou.txt"
        log.info("Downloading rockyou.txt...")
        self.progress_cb("rockyou", 0, 1, "Downloading rockyou.txt (~133 MB)...")

        if dest.exists():
            log.info("rockyou.txt already exists — skipping download.")
        else:
            try:
                resp = self.session.get(ROCKYOU_URL, stream=True, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as f:
                    for chunk in resp.iter_content(CHUNK_SIZE):
                        f.write(chunk)
            except Exception as exc:
                log.warning(f"rockyou.txt download failed: {exc}. "
                            "Download manually from https://github.com/brannondorsey/naive-hashcat")

        if dest.exists():
            stat = dest.stat()
            conn = _fast_conn(target)
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO wordlist_index
                    (name, file_path, category, description,
                     line_count, file_size_bytes, source, tags)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    ("rockyou.txt", str(dest), "passwords",
                     "RockYou 2009 breach password list",
                     14344391, stat.st_size, "rockyou", "passwords,wordlist"),
                )
            conn.close()

        self.progress_cb("rockyou", 1, 1, "rockyou.txt complete")
        return dest.exists()

    def build_hibp_passwords(self, db_path: Optional[Path] = None) -> bool:
        """
        Register HIBP password hash list in wordlist index.

        The HIBP SHA-1 hash list is ~12 GB compressed (.7z) and contains
        847M+ hashed passwords. Due to its size, Fenrir does NOT auto-download
        it. This method registers a placeholder and prints download instructions.

        Users who want offline HIBP lookup should download the file manually
        from https://haveibeenpwned.com/Passwords and place it in:
        data/db/wordlists/hibp/
        """
        target  = db_path or self.db_path
        hibp_dir = WORDLISTS_DIR / "hibp"

        # Check if already downloaded
        existing = list(hibp_dir.glob("*.txt")) + list(hibp_dir.glob("*.7z"))

        if existing:
            log.info(f"HIBP password files found in {hibp_dir}.")
            conn = _fast_conn(target)
            with conn:
                for f in existing:
                    stat = f.stat()
                    conn.execute(
                        """INSERT OR REPLACE INTO wordlist_index
                        (name, file_path, category, description,
                         line_count, file_size_bytes, source, tags)
                        VALUES (?,?,?,?,?,?,?,?)""",
                        (f.name, str(f), "passwords/hibp",
                         "Have I Been Pwned SHA-1 password hashes",
                         0, stat.st_size, "hibp", "passwords,hashes,hibp"),
                    )
            conn.close()
        else:
            log.warning(
                "\n" + "=" * 60 +
                "\n  HIBP Password Hashes — Manual Download Required" +
                "\n  Size: ~12 GB | Records: 847M+ SHA-1 hashes" +
                "\n" +
                "\n  Download from:" +
                "\n  https://haveibeenpwned.com/Passwords" +
                "\n  (choose 'SHA-1 ordered by hash' for best performance)" +
                "\n" +
                f"\n  Place files in: {hibp_dir}" +
                "\n  Then re-run: fenrir --db-build-source hibp_passwords" +
                "\n" + "=" * 60
            )

        return True

    # ===========================================================================
    # NETWORK INTELLIGENCE
    # ===========================================================================

    def build_asn_data(self, db_path: Optional[Path] = None) -> bool:
        """Download IP-to-ASN mapping from iptoasn.com."""
        target = db_path or self.db_path
        log.info("Downloading IP-to-ASN data (~15 MB)...")
        self.progress_cb("asn", 0, 1, "Downloading IP-to-ASN TSV...")
        try:
            resp = self.session.get(IPTOASN_URL, stream=True, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            buf = io.BytesIO()
            for chunk in resp.iter_content(CHUNK_SIZE):
                buf.write(chunk)
            buf.seek(0)

            rows = []
            with gzip.GzipFile(fileobj=buf) as gz:
                for line in gz:
                    line = line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 5:
                        rows.append((
                            parts[0], parts[1], parts[2],
                            parts[3], parts[4],
                        ))

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO asn_data (ip_from, ip_to, asn, country, org_name) VALUES (?,?,?,?,?)",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_ASN_LAST_UPDATED, _now())
            self._set_meta(target, META_ASN_COUNT, str(len(rows)))
            self.progress_cb("asn", 1, 1, f"ASN data complete: {len(rows):,} entries")
            log.info(f"ASN data complete: {len(rows):,} entries")
            return True

        except Exception as exc:
            log.error(f"ASN data failed: {exc}")
            return False

    def build_tor_exits(self, db_path: Optional[Path] = None) -> bool:
        """Download current Tor exit node list."""
        target = db_path or self.db_path
        log.info("Downloading Tor exit node list...")
        self.progress_cb("tor", 0, 1, "Downloading Tor exit nodes...")
        try:
            resp  = self.session.get(TOR_EXITS_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            today = _now()[:10]
            rows  = [
                (line.strip(), today)
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#") and _valid_ipv4(line.strip())
            ]
            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO tor_exits (ip_address, added_date) VALUES (?,?)",
                        rows,
                    )
                conn.close()
            self._set_meta(target, META_TOR_LAST_UPDATED, _now())
            self._set_meta(target, META_TOR_COUNT, str(len(rows)))
            self.progress_cb("tor", 1, 1, f"Tor exits complete: {len(rows):,} nodes")
            log.info(f"Tor exits complete: {len(rows):,} exit nodes")
            return True
        except Exception as exc:
            log.error(f"Tor exits failed: {exc}")
            return False

    def build_iana_ports(self, db_path: Optional[Path] = None) -> bool:
        """Download IANA service name and port number assignments."""
        target = db_path or self.db_path
        log.info("Downloading IANA port assignments...")
        self.progress_cb("iana", 0, 1, "Downloading IANA port/protocol CSV...")
        try:
            resp = self.session.get(IANA_PORTS_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            rows   = []
            reader = csv.DictReader(io.StringIO(resp.text))
            for rec in reader:
                try:
                    service  = (rec.get("Service Name") or "").strip()
                    port_str = (rec.get("Port Number") or "").strip()
                    protocol = (rec.get("Transport Protocol") or "").strip().lower()
                    desc     = (rec.get("Description") or "").strip()

                    if not port_str or not port_str.isdigit():
                        continue
                    port = int(port_str)
                    if 0 < port <= 65535 and protocol in ("tcp", "udp"):
                        rows.append((port, protocol, service, desc))
                except Exception:
                    continue

            if rows:
                conn = _fast_conn(target)
                with conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO iana_ports (port, protocol, service, description) VALUES (?,?,?,?)",
                        rows,
                    )
                conn.close()

            self._set_meta(target, META_IANA_LAST_UPDATED, _now())
            self._set_meta(target, META_IANA_PORT_COUNT, str(len(rows)))
            self.progress_cb("iana", 1, 1, f"IANA ports complete: {len(rows):,} entries")
            log.info(f"IANA ports complete: {len(rows):,} entries")
            return True

        except Exception as exc:
            log.error(f"IANA ports failed: {exc}")
            return False

    # ===========================================================================
    # COMPLIANCE / REPORTING
    # ===========================================================================

    def build_owasp(self, db_path: Optional[Path] = None) -> bool:
        """Insert OWASP Top 10 (2021) finding templates — built-in, no download."""
        target = db_path or self.db_path
        log.info("Inserting OWASP Top 10 finding templates...")

        rows = [
            ("A01:2021", "Broken Access Control", 2021,
             "Broken Access Control",
             "Access control enforces policy such that users cannot act outside of their intended permissions.",
             "Critical", "High", "High",
             "Implement deny-by-default access control. Log and alert on failures. Rate-limit API and controller access.",
             json.dumps(["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]),
             json.dumps(["CWE-200", "CWE-201", "CWE-352"])),

            ("A02:2021", "Cryptographic Failures", 2021,
             "Cryptographic Failures",
             "Failures related to cryptography which often lead to exposure of sensitive data.",
             "High", "Medium", "High",
             "Classify data processed, stored, or transmitted. Encrypt all sensitive data at rest. Use strong up-to-date algorithms.",
             json.dumps(["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]),
             json.dumps(["CWE-259", "CWE-327", "CWE-331"])),

            ("A03:2021", "Injection", 2021,
             "Injection",
             "SQL, NoSQL, OS, LDAP, and other injection flaws occur when untrusted data is sent to an interpreter.",
             "Critical", "High", "High",
             "Use a safe API. Use parameterised queries. Validate, filter, and sanitise all input server-side.",
             json.dumps(["https://owasp.org/Top10/A03_2021-Injection/"]),
             json.dumps(["CWE-79", "CWE-89", "CWE-73"])),

            ("A04:2021", "Insecure Design", 2021,
             "Insecure Design",
             "Missing or ineffective control design — distinct from implementation defects.",
             "High", "Medium", "High",
             "Use threat modelling. Establish secure design patterns and paved road methodology.",
             json.dumps(["https://owasp.org/Top10/A04_2021-Insecure_Design/"]),
             json.dumps(["CWE-209", "CWE-256", "CWE-501"])),

            ("A05:2021", "Security Misconfiguration", 2021,
             "Security Misconfiguration",
             "Missing appropriate security hardening, unnecessary features enabled, default credentials unchanged.",
             "High", "High", "Medium",
             "Implement a repeatable hardening process. Minimal platform: no unnecessary features. Review and update configurations.",
             json.dumps(["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]),
             json.dumps(["CWE-16", "CWE-611"])),

            ("A06:2021", "Vulnerable and Outdated Components", 2021,
             "Vulnerable and Outdated Components",
             "Components such as libraries, frameworks, and other software modules run with the same privileges as the application.",
             "High", "Medium", "High",
             "Remove unused dependencies. Continuously inventory versions. Monitor NVD and CVE feeds. Subscribe to security bulletins.",
             json.dumps(["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]),
             json.dumps(["CWE-1104"])),

            ("A07:2021", "Identification and Authentication Failures", 2021,
             "Identification and Authentication Failures",
             "Confirmation of the user's identity, authentication, and session management is critical.",
             "High", "High", "High",
             "Implement MFA. Do not deploy with default credentials. Implement weak password checks. Limit failed login attempts.",
             json.dumps(["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"]),
             json.dumps(["CWE-297", "CWE-287", "CWE-384"])),

            ("A08:2021", "Software and Data Integrity Failures", 2021,
             "Software and Data Integrity Failures",
             "Code and infrastructure that does not protect against integrity violations.",
             "High", "Low", "High",
             "Use digital signatures to verify software. Ensure CI/CD pipeline has integrity controls. Use SRI for CDN content.",
             json.dumps(["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"]),
             json.dumps(["CWE-829", "CWE-494", "CWE-502"])),

            ("A09:2021", "Security Logging and Monitoring Failures", 2021,
             "Security Logging and Monitoring Failures",
             "Without logging and monitoring, breaches cannot be detected and responded to.",
             "Medium", "Low", "Medium",
             "Ensure all login, access control, and server-side input validation failures are logged with sufficient context.",
             json.dumps(["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"]),
             json.dumps(["CWE-778", "CWE-117", "CWE-223"])),

            ("A10:2021", "Server-Side Request Forgery", 2021,
             "Server-Side Request Forgery (SSRF)",
             "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
             "High", "High", "High",
             "Sanitise and validate all client-supplied input data. Enforce the URL schema, port, and destination with a positive allow list. Disable HTTP redirections.",
             json.dumps(["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"]),
             json.dumps(["CWE-918"])),
        ]

        try:
            conn = _fast_conn(target)
            with conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO owasp_findings
                    (finding_id, category, owasp_year, title, description,
                     risk_rating, likelihood, impact, remediation,
                     ref_urls, cwe_ids)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            conn.close()
            log.info(f"OWASP Top 10 complete: {len(rows)} findings inserted")
            return True
        except sqlite3.Error as exc:
            log.error(f"OWASP insert error: {exc}")
            return False

    # ===========================================================================
    # UTILITY
    # ===========================================================================

    def _clone_or_pull(self, repo_url: str, dest: Path, name: str) -> bool:
        """Git clone if not present, git pull if it exists."""
        if not shutil.which("git"):
            log.error(f"git not found — cannot clone {name}")
            return False
        try:
            if dest.exists():
                result = subprocess.run(
                    ["git", "-C", str(dest), "pull", "--depth=1", "--rebase"],
                    capture_output=True, text=True, timeout=600,
                )
                if result.returncode != 0:
                    log.warning(f"git pull failed for {name}: {result.stderr[:200]}")
                    shutil.rmtree(dest)
                    return self._clone_fresh(repo_url, dest, name)
            else:
                return self._clone_fresh(repo_url, dest, name)
            return True
        except subprocess.TimeoutExpired:
            log.error(f"git operation timed out for {name}")
            return False
        except Exception as exc:
            log.error(f"git error for {name}: {exc}")
            return False

    def _clone_fresh(self, repo_url: str, dest: Path, name: str) -> bool:
        """Perform a fresh shallow git clone."""
        log.info(f"Cloning {name} from {repo_url}...")
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, str(dest)],
            capture_output=True, text=True, timeout=1200,
        )
        if result.returncode != 0:
            log.error(f"git clone failed for {name}: {result.stderr[:300]}")
            return False
        return True

    def _copy_files_parallel(
        self,
        files: list[tuple[Path, str]],
        dest_root: Path,
    ) -> int:
        """Copy a list of (src_path, rel_path) tuples to dest_root, preserving structure."""
        copied = 0
        for src, rel in files:
            dest = dest_root / rel.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src, dest)
                copied += 1
            except OSError:
                pass
        return copied

    def _create_schema(self, db_path: Path) -> None:
        """Create all tables, FTS indexes, and triggers in a new database."""
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        for stmt in ALL_CREATE_STATEMENTS:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as exc:
                log.debug(f"Schema note: {exc}")
        _set_meta_conn(conn, META_SCHEMA_VERSION, SCHEMA_VERSION)
        conn.commit()
        conn.close()

    def _set_meta(self, db_path: Path, key: str, value: str) -> None:
        """Write a metadata key-value to db_meta."""
        try:
            conn = sqlite3.connect(str(db_path))
            _set_meta_conn(conn, key, value)
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            log.debug(f"_set_meta({key}) error: {exc}")


# ===========================================================================
# MODULE-LEVEL HELPERS
# ===========================================================================

def _fast_conn(db_path: Path) -> sqlite3.Connection:
    """Open a SQLite connection with bulk-insert optimised settings."""
    conn = sqlite3.connect(str(db_path), timeout=60)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-128000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA locking_mode=EXCLUSIVE")
    return conn


def _set_meta_conn(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO db_meta (key, value, updated_at) VALUES (?,?,?)",
        (key, value, _now()),
    )


def _parse_cvss_v3(impact: dict) -> tuple:
    try:
        v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
        if v3:
            return float(v3.get("baseScore") or 0), v3.get("baseSeverity", ""), v3.get("vectorString", "")
    except Exception:
        pass
    return None, "", ""


def _parse_cvss_v2(impact: dict) -> tuple:
    try:
        v2 = impact.get("baseMetricV2", {})
        if v2:
            cvss = v2.get("cvssV2", {})
            return float(cvss.get("baseScore") or 0), v2.get("severity", ""), cvss.get("vectorString", "")
    except Exception:
        pass
    return None, "", ""


def _stix_text(text: str) -> str:
    """Strip STIX-style citation markers like (Citation: ...) from ATT&CK descriptions."""
    if not text:
        return ""
    return re.sub(r"\(Citation:[^)]+\)", "", text).strip()


def _valid_ipv4(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def _git_commit(repo_dir: Path) -> str:
    """Return the short HEAD commit hash of a git repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _fmt_duration(seconds: int) -> str:
    h, r = divmod(seconds, 3600)
    m, s = divmod(r, 60)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _default_progress(source: str, current: int, total: int, message: str) -> None:
    pct = f"{int(current/total*100):3d}%" if total > 0 else "   "
    log.info(f"  [{source.upper():12}] {pct}  {message}")