# fenrir/cli.py
#
# Fix 22 — Complete rewrite of cli.py
#
# Changes from original stub:
#   - Full argparse implementation of every flag defined in fenrir.1 man page
#   - fenrir <target> with no module flags → runs port scan + vuln scan (default)
#   - fenrir --gui → launches GUI
#   - Database management: --db-build, --db-update, --db-status,
#     --db-build-source <source>, --db-tier <tier>
#   - -p/--ports wired to parse_ports() from port_scanner.py
#   - All configurable parameters passed through (cve-limit, wordlist, ot-duration,
#     rf-range, rf-threshold, spray-service, ble-duration)
#   - Soft API key warning printed to console; user prompted (--no-confirm skips)
#   - Modules run in correct dependency order (port first, then parallel recon,
#     then sequential heavy modules)
#   - Verbose / quiet flags control logging level
#   - --version prints version from config and exits
#   - Exit code 0 on success, 1 on scan error, 2 on argument error

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

from .config import config
from .fenrir_gui import launch_gui
from .logging_config import get_logger, setup_logging
from .modules import (
    MODULE_REGISTRY,
    DEFAULT_PORTS,
    WEB_PORTS,
    SSH_PORT,
    parse_ports,
    PortScanner,
    VulnerabilityScanner,
    WebScanner,
    DirBruteForcer,
    TechDetector,
    SubdomainScanner,
    DnsScanner,
    WhoisScanner,
    OsintScanner,
    ThreatIntelScanner,
    ExploitScanner,
    PasswordSprayer,
    IotScanner,
    OtScanner,
    MobileScanner,
    RfScanner,
)
from .report_manager import ReportManager

log = get_logger()


# =============================================================================
# Argument parser
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fenrir",
        description=(
            "Fenrir Security Scanner — modular penetration testing toolkit.\n"
            "Run with no module flags to perform a default port + vulnerability scan."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fenrir 192.168.1.10                       Default scan (port + vuln)
  fenrir 192.168.1.10 -sV                   Vulnerability scan
  fenrir example.com -sS -sN -sH            Subdomain + DNS + WHOIS
  fenrir 192.168.1.10 -p 80,443,8080 -sW    Web recon on specified ports
  fenrir -sE "Apache 2.4.51"                Exploit search (no target needed)
  fenrir 192.168.1.10 -U root,admin -sP passwd  Password spray
  fenrir --db-build --db-tier standard      Build standard database tier
  fenrir --gui                              Launch graphical interface
""",
    )

    # ── Positional ────────────────────────────────────────────────────────────
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        metavar="TARGET",
        help="Target IP address, hostname, or domain.",
    )

    # ── Meta ──────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the graphical user interface.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level output.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress INFO messages; show WARNING and above only.",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Skip API key / privilege confirmation prompts.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        default=".",
        help="Output directory for reports. Default: current directory.",
    )

    # ── Port scanning ─────────────────────────────────────────────────────────
    portscan = parser.add_argument_group("Port Scanning")
    portscan.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        default=None,
        help=(
            "Ports to scan. Accepts comma-separated values and ranges.\n"
            "Examples: 80,443   22,80,1024-2048\n"
            "Default: nmap top-1000 ports."
        ),
    )

    # ── Vulnerability analysis ────────────────────────────────────────────────
    vuln = parser.add_argument_group("Vulnerability Analysis")
    vuln.add_argument(
        "-sV", "--scan-vulns",
        action="store_true",
        help="Service detection + CVE lookup against NVD / offline database.",
    )
    vuln.add_argument(
        "--cve-limit",
        type=int,
        default=5,
        metavar="N",
        help="Maximum CVEs to display per service. Default: 5.",
    )

    # ── Exploitation ──────────────────────────────────────────────────────────
    exploit = parser.add_argument_group("Exploit Search")
    exploit.add_argument(
        "-sE", "--scan-exploits",
        metavar="QUERY",
        default=None,
        help=(
            "Search offline Exploit-DB for a query string.\n"
            "Example: 'Apache 2.4.51'  or  'CVE-2021-44228'\n"
            "Does not require a target."
        ),
    )
    exploit.add_argument(
        "--exploit-mirror",
        action="store_true",
        help="Copy matched exploit files into the output directory.",
    )
    exploit.add_argument(
        "--exploit-verified",
        action="store_true",
        help="Only show verified exploits.",
    )
    exploit.add_argument(
        "--exploit-platform",
        metavar="PLATFORM",
        default=None,
        help="Filter exploits by platform (e.g. linux, windows, php).",
    )
    exploit.add_argument(
        "--exploit-type",
        metavar="TYPE",
        default=None,
        help="Filter exploits by type (e.g. remote, local, webapps).",
    )
    exploit.add_argument(
        "--exploit-limit",
        type=int,
        default=20,
        metavar="N",
        help="Maximum exploit results to show. Default: 20.",
    )

    # ── Web modules ───────────────────────────────────────────────────────────
    web = parser.add_argument_group("Web Application Modules")
    web.add_argument(
        "-sW", "--scan-web",
        action="store_true",
        help="Web recon: headers, security header analysis, cookie flags.",
    )
    web.add_argument(
        "-sD", "--scan-dirs",
        action="store_true",
        help="Directory / file brute-force scan.",
    )
    web.add_argument(
        "-sT", "--scan-tech",
        action="store_true",
        help="Web technology fingerprinting (webtech + header analysis).",
    )
    web.add_argument(
        "-w", "--wordlist",
        metavar="FILE",
        default=None,
        help="Path to wordlist file for dir brute-force or subdomain scan.",
    )

    # ── Reconnaissance ────────────────────────────────────────────────────────
    recon = parser.add_argument_group("Reconnaissance Modules")
    recon.add_argument(
        "-sS", "--scan-subdomains",
        action="store_true",
        help="Subdomain enumeration (DNS brute-force with wordlist).",
    )
    recon.add_argument(
        "-sN", "--scan-dns",
        action="store_true",
        help="DNS record enumeration (A, MX, TXT, SOA, AXFR attempt, etc.).",
    )
    recon.add_argument(
        "-sH", "--scan-whois",
        action="store_true",
        help="WHOIS lookup for domain or IP.",
    )
    recon.add_argument(
        "-sO", "--scan-osint",
        action="store_true",
        help="OSINT scan: public documents, email addresses, theHarvester.",
    )
    recon.add_argument(
        "-sI", "--scan-intel",
        action="store_true",
        help="Threat intelligence: VirusTotal, OTX, offline IP/IOC lookup.",
    )

    # ── Offensive ─────────────────────────────────────────────────────────────
    offensive = parser.add_argument_group("Offensive Modules")
    offensive.add_argument(
        "-U", "--user-list",
        metavar="USERNAMES",
        default=None,
        help="Comma-separated list of usernames for password spraying.",
    )
    offensive.add_argument(
        "-sP", "--spray-pass",
        metavar="PASSWORD",
        default=None,
        help="Single password to spray across all usernames. Requires -U.",
    )
    offensive.add_argument(
        "--spray-service",
        metavar="SERVICE",
        default="ssh",
        choices=["ssh", "ftp", "http-basic", "http-form"],
        help="Service to spray against: ssh, ftp, http-basic, http-form. Default: ssh.",
    )
    offensive.add_argument(
        "--spray-port",
        type=int,
        default=None,
        metavar="PORT",
        help="Port for spray service. Default: 22 (ssh), 21 (ftp), 80 (http).",
    )
    offensive.add_argument(
        "--spray-concurrency",
        type=int,
        default=5,
        metavar="N",
        help="Concurrent spray attempts. Default: 5.",
    )
    offensive.add_argument(
        "--spray-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between spray attempts for evasion. Default: 0.",
    )
    offensive.add_argument(
        "--spray-url",
        metavar="URL",
        default=None,
        help="Full URL for http-basic / http-form spray (overrides target:port).",
    )

    # ── Specialised ───────────────────────────────────────────────────────────
    special = parser.add_argument_group("Specialised Modules")
    special.add_argument(
        "-sIoT", "--scan-iot",
        action="store_true",
        help="IoT scan: MQTT anonymous login, default creds, BLE discovery.",
    )
    special.add_argument(
        "--ble-duration",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="BLE discovery scan duration in seconds. Default: 10.",
    )
    special.add_argument(
        "-sOT", "--scan-ot",
        action="store_true",
        help="Passive OT/ICS network scan (requires root). Falls back to active probe.",
    )
    special.add_argument(
        "--ot-duration",
        type=int,
        default=30,
        metavar="SECONDS",
        help="OT passive sniff duration in seconds. Default: 30.",
    )
    special.add_argument(
        "--ot-interface",
        metavar="IFACE",
        default=None,
        help="Network interface for OT passive scan (e.g. eth0). Default: system default.",
    )
    special.add_argument(
        "--ot-mode",
        choices=["passive", "active"],
        default="passive",
        help="OT scan mode: passive (sniff) or active (port probe). Default: passive.",
    )
    special.add_argument(
        "-sM", "--scan-mobile",
        metavar="FILE_PATH",
        default=None,
        help="Static analysis of a mobile application (.apk).",
    )
    special.add_argument(
        "-sRF", "--scan-rf",
        action="store_true",
        help="RF signal scan (requires RTL-SDR or SoapySDR hardware).",
    )
    special.add_argument(
        "--rf-range",
        metavar="RANGE",
        default="24M:1.7G",
        help="RF frequency range as start:stop (e.g. 433M:434M). Default: 24M:1.7G.",
    )
    special.add_argument(
        "--rf-threshold",
        type=float,
        default=-20.0,
        metavar="DBM",
        help="Minimum signal power in dBm to report. Default: -20.",
    )
    special.add_argument(
        "--rf-duration",
        type=int,
        default=20,
        metavar="SECONDS",
        help="RF scan duration in seconds. Default: 20.",
    )

    # ── Database management ───────────────────────────────────────────────────
    db = parser.add_argument_group("Database Management")
    db.add_argument(
        "--db-build",
        action="store_true",
        help="Build the offline intelligence database from scratch.",
    )
    db.add_argument(
        "--db-update",
        action="store_true",
        help="Incrementally update an existing offline database.",
    )
    db.add_argument(
        "--db-status",
        action="store_true",
        help="Print database build status and record counts.",
    )
    db.add_argument(
        "--db-tier",
        metavar="TIER",
        default="core",
        choices=["core", "standard", "full"],
        help="Build tier: core (~4.5 GB), standard (~8 GB), full (~25 GB+). Default: core.",
    )
    db.add_argument(
        "--db-build-source",
        metavar="SOURCE",
        default=None,
        help=(
            "Build or update a single source only.\n"
            "Examples: nvd_lite, exploitdb_source, kev, epss, attack, nuclei, "
            "seclists, threat_feeds, tor_exits"
        ),
    )

    return parser


# =============================================================================
# Scan orchestrator
# =============================================================================

async def _run_scans(args: argparse.Namespace) -> int:
    """
    Orchestrate module execution based on parsed arguments.
    Returns exit code: 0 = success, 1 = error.
    """
    target     = args.target
    output_dir = Path(args.output).expanduser().resolve()

    if not output_dir.is_dir():
        log.error(f"Output directory does not exist: {output_dir}")
        return 1

    # Determine which modules to run
    # Default mode: if no module flags, run port + vuln
    any_module_flag = any([
        args.scan_vulns, args.scan_exploits, args.scan_web, args.scan_dirs,
        args.scan_tech, args.scan_subdomains, args.scan_dns, args.scan_whois,
        args.scan_osint, args.scan_intel, args.spray_pass,
        args.scan_iot, args.scan_ot, args.scan_mobile, args.scan_rf,
    ])

    run_port_scan  = True   # Always run unless only exploit search
    run_vuln_scan  = args.scan_vulns or not any_module_flag

    # Exploit search doesn't need a target
    if args.scan_exploits and not target:
        report  = ReportManager(str(output_dir), "exploit_search")
        results = await ExploitScanner().run(
            args.scan_exploits,
            platform=args.exploit_platform,
            exploit_type=args.exploit_type,
            verified_only=args.exploit_verified,
            limit=args.exploit_limit,
            mirror=args.exploit_mirror,
            mirror_dir=output_dir if args.exploit_mirror else None,
            report=report,
        )
        report.finalize()
        return 0

    if not target:
        log.error("A target is required. Use: fenrir <target> [options]")
        return 2

    # ── API key warnings ──────────────────────────────────────────────────────
    warnings = []
    if args.scan_intel:
        for key in ("virustotal", "alienvault"):
            ok, msg = config.validate_key(key)
            if not ok:
                warnings.append(msg)
    if run_vuln_scan:
        ok, msg = config.validate_key("nvd")
        if not ok:
            warnings.append(msg)

    if warnings and not args.no_confirm:
        print("\n⚠  API Key Notice:")
        for w in warnings:
            print(f"   • {w}")
        print("   Affected modules will use offline data where available.")
        try:
            ans = input("   Continue? [Y/n]: ").strip().lower()
            if ans in ("n", "no"):
                print("Aborted.")
                return 0
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 0

    # ── Parse ports ───────────────────────────────────────────────────────────
    try:
        requested_ports = parse_ports(args.ports) if args.ports else None
    except ValueError as exc:
        log.error(f"Invalid port specification: {exc}")
        return 2

    report = ReportManager(str(output_dir), target)
    log.info("=" * 58)
    log.info(f"  Fenrir  |  Target: {target}")
    log.info("=" * 58)

    # ── Phase 1: Port scan ────────────────────────────────────────────────────
    open_ports: list[int] = []

    if run_port_scan and not args.scan_exploits:
        log.info("[Phase 1] Port scan")
        open_ports = await PortScanner().run(
            target, ports=requested_ports, report=report
        )

    found_web_ports = [p for p in open_ports if p in WEB_PORTS]
    found_ssh_ports = [p for p in open_ports if p == SSH_PORT]

    # ── Phase 2: Parallel recon / analysis ───────────────────────────────────
    phase2_tasks = []
    log.info("[Phase 2] Analysis & recon")

    if run_vuln_scan and open_ports:
        phase2_tasks.append(
            VulnerabilityScanner(cve_limit=args.cve_limit).run(
                target, open_ports, report=report
            )
        )

    if args.scan_web and found_web_ports:
        phase2_tasks.append(WebScanner().run(target, found_web_ports, report=report))

    if args.scan_tech and found_web_ports:
        phase2_tasks.append(TechDetector().run(target, found_web_ports, report=report))

    if args.scan_dns:
        phase2_tasks.append(DnsScanner().run(target, report=report))

    if args.scan_whois:
        phase2_tasks.append(WhoisScanner().run(target, report=report))

    if args.scan_subdomains:
        phase2_tasks.append(
            SubdomainScanner(wordlist_path=args.wordlist).run(target, report=report)
        )

    if args.scan_intel:
        phase2_tasks.append(ThreatIntelScanner().run(target, report=report))

    if args.scan_osint:
        phase2_tasks.append(OsintScanner().run(target, report=report))

    if phase2_tasks:
        await asyncio.gather(*phase2_tasks, return_exceptions=True)

    # ── Phase 3: Directory brute-force ────────────────────────────────────────
    if args.scan_dirs and found_web_ports:
        log.info("[Phase 3] Directory brute-force")
        await DirBruteForcer(wordlist_path=args.wordlist).run(
            target, found_web_ports, report=report
        )

    # ── Phase 4: Exploit search ───────────────────────────────────────────────
    if args.scan_exploits:
        log.info("[Phase 4] Exploit search")
        await ExploitScanner().run(
            args.scan_exploits,
            platform=args.exploit_platform,
            exploit_type=args.exploit_type,
            verified_only=args.exploit_verified,
            limit=args.exploit_limit,
            mirror=args.exploit_mirror,
            mirror_dir=output_dir if args.exploit_mirror else None,
            report=report,
        )

    # ── Phase 5: Specialised / blocking modules ───────────────────────────────
    phase5_tasks = []

    if args.scan_iot:
        phase5_tasks.append(
            IotScanner().run(
                target, open_ports,
                ble_duration=args.ble_duration,
                report=report,
            )
        )

    if args.scan_rf:
        phase5_tasks.append(
            RfScanner().run(
                freq_range=args.rf_range,
                threshold=args.rf_threshold,
                duration=args.rf_duration,
                report=report,
            )
        )

    if phase5_tasks:
        await asyncio.gather(*phase5_tasks, return_exceptions=True)

    # Password spray (sequential — generates traffic bursts)
    if args.spray_pass:
        if not args.user_list:
            log.error("--spray-pass requires -U/--user-list")
        else:
            usernames  = [u.strip() for u in args.user_list.split(",") if u.strip()]
            spray_port = (
                args.spray_port
                or (found_ssh_ports[0] if found_ssh_ports and args.spray_service == "ssh" else None)
                or _default_port(args.spray_service)
            )
            log.info(f"[Phase 5] Password spray ({args.spray_service})")
            await PasswordSprayer().run(
                target, spray_port, usernames, args.spray_pass,
                service=args.spray_service,
                concurrency=args.spray_concurrency,
                delay=args.spray_delay,
                http_url=args.spray_url,
                report=report,
            )

    # OT scan (long blocking sniff)
    if args.scan_ot:
        log.info(f"[Phase 5] OT/ICS scan ({args.ot_mode}, {args.ot_duration}s)")
        await OtScanner().run(
            target_ip=target,
            duration=args.ot_duration,
            mode=args.ot_mode,
            interface=args.ot_interface,
            report=report,
        )

    # Mobile APK analysis
    if args.scan_mobile:
        log.info(f"[Phase 5] Mobile APK analysis")
        await MobileScanner().run(args.scan_mobile, report=report)

    # ── Finalize ──────────────────────────────────────────────────────────────
    paths = report.finalize()
    log.info("=" * 58)
    log.info("  Scan complete.")
    for p in (paths or []):
        log.info(f"  Report saved: {p}")
    log.info("=" * 58)
    return 0


# =============================================================================
# Database management
# =============================================================================

def _handle_db_commands(args: argparse.Namespace) -> int:
    """Handle --db-* commands. Returns exit code."""
    from .database import get_db_manager
    from .database import get_db_builder
    DatabaseBuilder = get_db_builder()

    if args.db_status:
        db = get_db_manager()
        if not db.is_available():
            print("Database not built. Run: fenrir --db-build")
            return 0
        status = db.get_db_status()
        print("\nFenrir Offline Database Status")
        print("─" * 40)
        for k, v in status.items():
            print(f"  {k:<32} {v}")
        return 0

    if args.db_build or args.db_build_source:
        builder = DatabaseBuilder()
        if args.db_build_source:
            print(f"Building source: {args.db_build_source}")
            ok = builder.build_all(tier="custom", custom_sources=[args.db_build_source])
        else:
            print(f"Building database — tier: {args.db_tier}")
            ok = builder.build_all(tier=args.db_tier)
        return 0 if ok else 1

    if args.db_update:
        builder = DatabaseBuilder()
        print("Updating database...")
        ok = builder.update_all()
        return 0 if ok else 1

    return 0


# =============================================================================
# Default port by service
# =============================================================================

def _default_port(service: str) -> int:
    return {"ssh": 22, "ftp": 21, "http-basic": 80, "http-form": 80}.get(service, 22)


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Version ───────────────────────────────────────────────────────────────
    if args.version:
        print(f"Fenrir Security Scanner v{config.APP_VERSION}")
        sys.exit(0)

    # ── Logging level ─────────────────────────────────────────────────────────
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    setup_logging(log_level=level)

    # ── GUI ───────────────────────────────────────────────────────────────────
    if args.gui:
        launch_gui()
        sys.exit(0)

    # ── Database commands ─────────────────────────────────────────────────────
    if args.db_build or args.db_update or args.db_status or args.db_build_source:
        sys.exit(_handle_db_commands(args))

    # ── Validate output directory ─────────────────────────────────────────────
    output_dir = Path(args.output).expanduser().resolve()
    if not output_dir.is_dir():
        print(f"Error: output directory does not exist: {output_dir}", file=sys.stderr)
        sys.exit(2)

    # ── Exploit-search-only mode (no target required) ─────────────────────────
    # Handled inside _run_scans when target is None

    # ── Run scans ─────────────────────────────────────────────────────────────
    try:
        exit_code = asyncio.run(_run_scans(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()