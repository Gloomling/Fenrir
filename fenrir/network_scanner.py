# fenrir/modules/network_scanner.py
#
# NetworkScanner — Multi-host network discovery and deep per-device assessment.
#
# Overview:
#   Accepts CIDR ranges (192.168.1.0/24), hyphen ranges (192.168.1.1-50),
#   comma-separated IPs, or mixed combinations. For each live host discovered:
#
#   Phase A — Host Discovery
#     - ARP sweep (scapy, requires root) for LAN targets — fastest, most reliable
#     - ICMP ping sweep fallback (asyncio TCP probe on common ports if ICMP blocked)
#     - Reverse DNS lookup for each discovered host
#
#   Phase B — OS and Service Fingerprinting (per host, parallel)
#     - nmap -sV -O (service version + OS detection) if available
#     - Fallback: asyncio TCP banner grab + TTL-based OS heuristic
#     - CPE extraction from nmap output for precise CVE matching
#
#   Phase C — Device Classification
#     Rules-based classifier assigns each host to a device class:
#     mobile (Android/iOS), iot (camera/printer/embedded), network
#     (router/switch/firewall/WAP), server, workstation, or unknown.
#     Classification uses OS name, open ports, banners, and MAC vendor.
#
#   Phase D — Deep Assessment (per host, semi-parallel)
#     - VulnerabilityScanner: CVE lookup for every detected service
#     - AndroidScanner: auto-triggered for hosts with port 5555 open
#     - IoT checks: default cred testing on IoT-classified devices
#     - Web scan: headers + tech fingerprint on web-serving devices
#     - Exploit auto-matching against all CVEs found
#
#   Phase E — Report
#     - Per-host section in ReportManager
#     - Network-wide summary: host count, device types, total CVEs,
#       critical hosts, top vulnerabilities
#
# Dependencies:
#   Required : asyncio, socket (stdlib)
#   Optional : scapy (ARP sweep), nmap binary (OS/service detection)
#   nmap install: sudo apt install nmap
#   scapy install: pip install scapy
#
# Usage:
#   scanner = NetworkScanner()
#   summary = await scanner.run(
#       "192.168.1.0/24",
#       modules={"vuln", "web", "iot", "android"},
#       max_concurrent_hosts=5,
#       report=report,
#   )

import asyncio
import ipaddress
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional



def _get_db_manager():
    """
    Return the shared DatabaseManager singleton.
    Tries relative import first (installed package), then path-based fallback
    for checkouts where the package root is not registered as fenrir.
    """
    try:
        from fenrir.database import get_db_manager as _gdm
        return _gdm()
    except (ImportError, ValueError):
        pass
    try:
        import importlib.util, sys
        from pathlib import Path
        db_init = Path(__file__).resolve().parent.parent / "database" / "__init__.py"
        if db_init.exists():
            spec = importlib.util.spec_from_file_location(
                "fenrir.database", str(db_init),
                submodule_search_locations=[str(db_init.parent)],
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules.setdefault("fenrir.database", mod)
            spec.loader.exec_module(mod)
            return mod.get_db_manager()
    except Exception:
        pass
    return None


from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# Scapy optional — only needed for ARP sweep
try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HostInfo:
    """All discovered information about a single host."""
    ip:               str
    hostname:         str         = ""
    mac:              str         = ""
    mac_vendor:       str         = ""
    ttl:              int         = 0
    os_name:          str         = ""
    os_version:       str         = ""
    os_family:        str         = ""
    os_accuracy:      int         = 0
    os_cpe:           list        = field(default_factory=list)
    device_class:     str         = "unknown"   # mobile|iot|network|server|workstation|unknown
    device_subclass:  str         = ""          # android|ios|router|camera|printer|wap|firewall|switch
    open_ports:       list[int]   = field(default_factory=list)
    services:         dict        = field(default_factory=dict)  # port -> {name,version,banner,cpe}
    cves:             list        = field(default_factory=list)
    exploits:         list        = field(default_factory=list)
    security_findings:list        = field(default_factory=list)
    scan_duration:    float       = 0.0
    scan_error:       str         = ""
    is_up:            bool        = True
    status:           str         = "done"  # done|error|cancelled


# ---------------------------------------------------------------------------
# Port/service tables for device classification
# ---------------------------------------------------------------------------

# Ports that indicate a mobile device
_MOBILE_PORTS     = {5555, 5554, 5556, 5558, 62078, 7000}
# iOS lockdownd / usbmuxd
_IOS_PORTS        = {62078, 49152}
# Common IoT/embedded ports
_IOT_PORTS        = {80, 443, 554, 1883, 4786, 5683, 8080, 8443, 8883, 47808, 502, 102}
# Network infrastructure
_NETWORK_PORTS    = {22, 23, 179, 520, 521, 646, 8291, 8728, 8729, 17}
# High-risk server services
_SERVER_PORTS     = {21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 5432, 6379, 27017}

# MAC OUI prefix → vendor (compact subset for common device types)
_MAC_VENDORS: dict[str, str] = {
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:1a:11": "Google",
    "f4:f5:d8": "Google Nest",
    "54:60:09": "Apple",
    "ac:de:48": "Apple",
    "f0:18:98": "Apple",
    "d8:bb:c1": "Apple",
    "00:17:f2": "Apple",
    "3c:22:fb": "Apple",
    "b8:e8:56": "Apple",
    "78:31:c1": "Apple",
    "20:3c:ae": "Samsung",
    "00:16:32": "Samsung",
    "18:1e:78": "Samsung",
    "50:32:75": "Samsung",
    "cc:b2:55": "Samsung",
    "a4:c3:f0": "Google Pixel",
    "a0:af:bd": "Huawei",
    "28:6e:d4": "Huawei",
    "00:e0:fc": "Huawei",
    "d4:6e:5c": "Xiaomi",
    "0c:1d:cf": "Xiaomi",
    "34:ce:00": "Xiaomi",
    "50:ec:50": "DJI",
    "60:60:1f": "DJI",
    "18:68:cb": "DJI",
    "00:13:49": "Cisco",
    "00:1a:a2": "Cisco",
    "f8:72:ea": "Cisco",
    "00:18:0a": "D-Link",
    "1c:7e:e5": "D-Link",
    "14:d6:4d": "TP-Link",
    "50:d4:f7": "TP-Link",
    "54:af:97": "TP-Link",
    "e8:48:b8": "TP-Link",
    "c4:6e:1f": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "00:1a:c4": "Netgear",
    "00:09:5b": "Netgear",
    "20:4e:7f": "Mikrotik",
    "d4:ca:6d": "Mikrotik",
    "00:0b:86": "Aruba",
    "00:24:6c": "Aruba",
    "68:7f:74": "Aruba",
    "00:1c:c0": "Hikvision",
    "bc:ad:28": "Hikvision",
    "44:19:b6": "Axis",
    "ac:cc:8e": "Axis",
}


# ---------------------------------------------------------------------------
# NetworkScanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    Multi-host network scanner with OS fingerprinting and deep per-device
    vulnerability assessment.
    """

    def __init__(self) -> None:
        self._db     = _get_db_manager()
        self._nmap   = shutil.which("nmap")
        if not self._nmap:
            log.warning(
                "NetworkScanner: 'nmap' not found on PATH. "
                "OS detection and service version scanning will use basic TCP banner grab. "
                "Install with: sudo apt install nmap"
            )

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def discover_hosts(
        self,
        target_spec: str,
        port_timeout: float = 1.5,
        progress_callback=None,
        cancel_event=None,
    ) -> list[dict]:
        """
        Fast network discovery only — no port scan, no CVE lookup.
        For each live host returns: ip, hostname, mac, vendor, ttl, os_family
        (TTL-based guess), device_class hint.

        Suitable for the "Network Discovery" tab where the user picks hosts
        to deep-scan afterwards.

        Returns:
            List of host dicts sorted by IP.
        """
        log.info(f"{'─' * 56}")
        log.info(f"  Network Discovery — {target_spec}")
        log.info(f"{'─' * 56}")

        try:
            target_ips = _parse_target_spec(target_spec)
        except ValueError as exc:
            log.error(f"Invalid target spec: {exc}")
            return []

        log.info(f"  Scanning {len(target_ips)} address(es)…")
        live_ips = await self._discover_hosts(target_ips, timeout=port_timeout)
        log.info(f"  Found {len(live_ips)} live host(s).")

        results = []
        sem = asyncio.Semaphore(20)

        async def _identify(ip: str) -> dict:
            if cancel_event and cancel_event.is_set():
                return {"ip": ip, "status": "cancelled"}
            async with sem:
                info = HostInfo(ip=ip)
                # Reverse DNS
                try:
                    info.hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
                except Exception:
                    pass
                # TTL-based OS guess (sends one ICMP probe)
                await _guess_os_from_ttl(ip, info)
                # Quick probe of a handful of highly-diagnostic ports
                # to improve device classification without a full port scan
                _QUICK_PORTS = [22, 23, 80, 443, 445, 3389, 5555, 8080, 8443,
                                 62078, 554, 1883, 502, 161]
                open_quick = []
                async def _quick_probe(p: int):
                    try:
                        r, w = await asyncio.wait_for(
                            asyncio.open_connection(ip, p), timeout=port_timeout)
                        w.close()
                        try:
                            await w.wait_closed()
                        except Exception:
                            pass
                        open_quick.append(p)
                    except Exception:
                        pass
                await asyncio.gather(*[_quick_probe(p) for p in _QUICK_PORTS],
                                     return_exceptions=True)
                info.open_ports = sorted(open_quick)
                # Use quick ports for classification hint
                _classify_device(info)
                host_dict = self._host_to_dict(info)
                host_dict["discovery_only"] = True
                log.debug(f"[discovery] {ip}: hostname={info.hostname or '—'} "
                         f"ttl={info.ttl or '—'} os_family={info.os_family or '—'} "
                         f"class={info.device_class} quick_ports={open_quick}")
                log.info(
                    f"  {ip}  hostname={info.hostname or '—'}  "
                    f"os_family={info.os_family or '—'}  "
                    f"class={info.device_class}  "
                    f"quick_ports={open_quick}"
                )
                if progress_callback:
                    try:
                        progress_callback(len(results) + 1, len(live_ips),
                                          ip, host_dict)
                    except Exception:
                        pass
                return host_dict

        tasks = [_identify(ip) for ip in live_ips]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        for r in raw:
            if isinstance(r, dict):
                results.append(r)

        results.sort(key=lambda h: _ip_sort_key(h.get("ip", "")))
        return results

    async def run(
        self,
        target_spec: str,
        modules: Optional[set[str]] = None,
        max_concurrent_hosts: int = 5,
        port_timeout: float = 1.5,
        skip_discovery: bool = False,
        include_mobile: bool = True,
        include_iot: bool = True,
        ports: Optional[list[int]] = None,
        report: Optional[ReportManager] = None,
        progress_callback=None,
        cancel_event=None,
    ) -> dict:
        """
        Discover and deeply assess all hosts in target_spec.

        Args:
            target_spec:          CIDR, range, or comma-separated IPs.
                                  e.g. "192.168.1.0/24", "10.0.0.1-50",
                                       "192.168.1.1,192.168.1.5"
            modules:              Set of module names to run per host.
                                  Options: "vuln", "web", "iot", "android",
                                  "exploit", "os"  Default: {"vuln", "os"}
            max_concurrent_hosts: Max parallel host assessments. Default 5.
            port_timeout:         Per-port TCP timeout in seconds. Default 1.5.
            skip_discovery:       If True, assume all IPs in spec are up.
            include_mobile:       Run AndroidScanner on mobile-classified hosts.
            include_iot:          Run IoT checks on IoT-classified hosts.
            ports:                Override port list. Default: top-1000.
            report:               Optional ReportManager for structured output.
            progress_callback:    Optional callable(done, total, host_ip) for UI.

        Returns:
            Dict with keys: hosts (list[HostInfo]), summary (dict),
            total_hosts, live_hosts, total_cves, critical_hosts.
        """
        if modules is None:
            modules = {"port_scan", "vuln", "os", "exploit"}

        # If port_scan not in modules, host discovery is also pointless —
        # caller is supplying a known list and wants assessment only.
        if "port_scan" not in modules and not skip_discovery:
            skip_discovery = True
            log.info("port_scan not in modules — host discovery skipped.")

        start_time = time.monotonic()
        log.info(f"{'═' * 60}")
        log.info(f"  Network Scan — {target_spec}")
        log.info(f"  Modules: {', '.join(sorted(modules))}")
        log.info(f"{'═' * 60}")

        # Parse targets
        try:
            target_ips = _parse_target_spec(target_spec)
        except ValueError as exc:
            log.error(f"Invalid target specification: {exc}")
            return {"error": str(exc), "hosts": [], "summary": {}}

        log.info(f"Target IP count: {len(target_ips)}")

        # Phase A: Host discovery
        if skip_discovery:
            live_ips = target_ips
            log.info(f"Phase A: skipped — assuming all {len(live_ips)} host(s) up.")
        else:
            log.info("Phase A: Host discovery (ARP sweep / TCP probe)…")
            live_ips = await self._discover_hosts(target_ips, timeout=port_timeout)
            log.info(f"  Live hosts: {len(live_ips)} / {len(target_ips)}")

        if not live_ips:
            log.warning("No live hosts found.")
            result = {"hosts": [], "summary": {"total_ips": len(target_ips),
                                                "live_hosts": 0}, "total_cves": 0}
            if report:
                report.add_section("Network Scan Summary", [result["summary"]])
            return result

        # Phase B–E: Per-host deep assessment (with concurrency limit)
        log.info(f"Phase B–E: Deep assessment of {len(live_ips)} host(s)…")
        sem = asyncio.Semaphore(max_concurrent_hosts)
        hosts: list[HostInfo] = []
        done_count = 0

        async def assess_one(ip: str) -> HostInfo:
            nonlocal done_count
            async with sem:
                if cancel_event and cancel_event.is_set():
                    log.info(f"Network scan cancelled — skipping {ip}")
                    # Return a minimal HostInfo stub
                    info = HostInfo(ip=ip)
                    info.status = "cancelled"
                    return info
                info = await self._assess_host(
                    ip, modules, port_timeout, include_mobile, include_iot,
                    ports, report
                )
                done_count += 1
                if progress_callback:
                    try:
                        progress_callback(done_count, len(live_ips), ip,
                                          self._host_to_dict(info))
                    except Exception as cb_exc:
                        log.debug(f"[network] progress_callback error for {ip}: {cb_exc}")
                return info

        results = await asyncio.gather(
            *[assess_one(ip) for ip in live_ips],
            return_exceptions=True
        )

        for r in results:
            if isinstance(r, HostInfo):
                hosts.append(r)
            elif isinstance(r, Exception):
                log.error(f"Host assessment raised: {r}")

        # Sort by IP
        hosts.sort(key=lambda h: _ip_sort_key(h.ip))

        # Phase E: Summary
        summary = self._build_summary(hosts, target_spec, time.monotonic() - start_time)

        log.info(f"{'═' * 60}")
        log.info(f"  Network scan complete in {summary['duration_s']:.0f}s")
        log.info(f"  Hosts: {summary['live_hosts']} live / {summary['total_ips']} scanned")
        log.info(f"  CVEs found: {summary['total_cves']}  |  Critical hosts: {summary['critical_hosts']}")
        log.info(f"  Device types: {summary['device_types']}")
        log.info(f"{'═' * 60}")

        if report:
            report.add_section("Network Scan Summary", [summary])
            report.add_section("Network Host Inventory", [
                self._host_to_dict(h) for h in hosts
            ])

        return {
            "hosts":         hosts,
            "summary":       summary,
            "total_hosts":   len(target_ips),
            "live_hosts":    len(hosts),
            "total_cves":    summary["total_cves"],
            "critical_hosts": summary["critical_hosts"],
        }

    # =========================================================================
    # Phase A: Host Discovery
    # =========================================================================

    async def _discover_hosts(
        self, ips: list[str], timeout: float = 1.5
    ) -> list[str]:
        """
        Discover live hosts using ARP sweep (root/scapy) or TCP probe fallback.
        Returns list of responding IP addresses.
        """
        # Try ARP sweep first if scapy available and target looks like LAN
        if _SCAPY_AVAILABLE and ips and _is_private_ip(ips[0]):
            log.info("  Using ARP sweep (scapy)...")
            try:
                live = await asyncio.to_thread(self._arp_sweep, ips)
                if live:
                    log.info(f"  ARP sweep found {len(live)} host(s).")
                    return live
                log.debug("  ARP sweep returned no results — falling back to TCP probe.")
            except Exception as exc:
                log.debug(f"  ARP sweep failed: {exc} — falling back to TCP probe.")

        # TCP probe sweep: try a handful of common ports
        log.info("  Using TCP probe sweep...")
        probe_ports = [22, 23, 80, 443, 8080, 135, 445, 3389, 5555]
        sem = asyncio.Semaphore(200)

        async def _probe_ip(ip: str) -> Optional[str]:
            async with sem:
                for port in probe_ports:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=timeout
                        )
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        return ip
                    except Exception:
                        pass
                return None

        results = await asyncio.gather(*[_probe_ip(ip) for ip in ips],
                                        return_exceptions=True)
        return [r for r in results if isinstance(r, str)]

    def _arp_sweep(self, ips: list[str]) -> list[str]:
        """Synchronous ARP sweep using scapy. Run via asyncio.to_thread."""
        # Build a CIDR-like target string from the list
        # scapy srp takes a packet and returns (answered, unanswered)
        live = []
        # Process in batches of 256 to avoid single huge ARP request
        batch_size = 256
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            target_str = " ".join(batch)
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
                answered, _ = srp(pkt, timeout=2, verbose=False)
                for _, rcv in answered:
                    live.append(rcv.psrc)
            except Exception as exc:
                log.debug(f"ARP batch error: {exc}")
        return list(set(live))

    # =========================================================================
    # Phase B–D: Per-host assessment
    # =========================================================================

    async def _assess_host(
        self,
        ip: str,
        modules: set[str],
        port_timeout: float,
        include_mobile: bool,
        include_iot: bool,
        ports: Optional[list[int]],
        report: Optional[ReportManager],
    ) -> HostInfo:
        """
        Full per-host assessment pipeline:
          Phase B — Port scan  (TCP connect, nmap -sV or banner grab)
          Phase C — OS fingerprint  (nmap -O, TTL heuristic, CPE)
          Phase D — Device classification
          Phase E — Deep assessment (CVE, web, IoT, Android)
        """
        info    = HostInfo(ip=ip)
        t_start = time.monotonic()
        log.info(f"  [{ip}] Starting assessment…")

        # Reverse DNS
        try:
            info.hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
        except Exception:
            info.hostname = ""

        # ── Phase B: Port scan ────────────────────────────────────────────────
        # Always run unless caller explicitly excluded it.  We need the open port
        # list for everything that follows (classification, CVE lookup, etc.).
        run_port_scan = "port_scan" in modules or not modules
        if run_port_scan:
            log.info(f"  [{ip}] Phase B: port scan…")
            await self._port_scan(ip, info, port_timeout, ports)
            log.info(f"  [{ip}] {len(info.open_ports)} open port(s): "
                     f"{info.open_ports[:10]}{'…' if len(info.open_ports) > 10 else ''}")
        else:
            log.info(f"  [{ip}] Port scan skipped (not in modules).")

        # ── Phase C: OS fingerprint ───────────────────────────────────────────
        run_os = "os" in modules or run_port_scan
        if run_os and self._nmap:
            log.info(f"  [{ip}] Phase C: OS fingerprint via nmap…")
            await self._nmap_os_fingerprint(ip, info, ports)
        elif run_os:
            await _guess_os_from_ttl(ip, info)
        # Always try banner inference — fills gaps when nmap -O fails (no root)
        if not info.os_name and info.services:
            _infer_os_from_service_banners(info)
        # If still no OS and port 445 is open, try smb-os-discovery script
        if not info.os_name and 445 in info.open_ports and self._nmap and run_os:
            log.info(f"  [{ip}] Phase C: SMB OS discovery…")
            await self._nmap_smb_os(ip, info)
        # TTL as last resort
        if not info.os_name:
            await _guess_os_from_ttl(ip, info)
        log.info(f"  [{ip}] OS: {info.os_name or 'unknown'} {info.os_version or ''} "
                 f"[family: {info.os_family or '—'}]")

        # ── Phase D: Device classification ────────────────────────────────────
        _classify_device(info)
        log.info(f"  [{ip}] Class: {info.device_class}/{info.device_subclass}")

        # ── Phase E: Deep assessment ──────────────────────────────────────────
        try:
            from .vulnerability_scanner import VulnerabilityScanner
            from .web_scanner import WebScanner
            from .tech_detector import TechDetector
            from .iot_scanner import IotScanner
            from .android_scanner import AndroidScanner
            from fenrir.modules import WEB_PORTS
        except ImportError as exc:
            log.debug(f"  [{ip}] Module import error: {exc}")
            info.scan_error = str(exc)
            info.scan_duration = time.monotonic() - t_start
            return info

        # Vulnerability + CVE scan
        if "vuln" in modules and info.open_ports:
            log.info(f"  [{ip}] Phase E: CVE lookup…")
            try:
                port_cve_map = await asyncio.wait_for(
                    VulnerabilityScanner().run(ip, info.open_ports),
                    timeout=180,
                )
                for cve_list in port_cve_map.values():
                    info.cves.extend(cve_list)
                if "exploit" in modules:
                    await self._auto_exploit_match(info)
            except asyncio.TimeoutError:
                log.warning(f"  [{ip}] Vulnerability scan timed out.")
            except Exception as exc:
                log.debug(f"  [{ip}] Vuln scan error: {exc}")

        # Web recon
        web_ports = [p for p in info.open_ports
                     if p in (80, 443, 8080, 8443, 8000, 8888, 3000)]
        if "web" in modules and web_ports:
            log.info(f"  [{ip}] Phase E: web recon on {web_ports}…")
            try:
                await asyncio.wait_for(
                    WebScanner().run(ip, web_ports), timeout=60)
                await asyncio.wait_for(
                    TechDetector().run(ip, web_ports), timeout=60)
            except (asyncio.TimeoutError, Exception) as exc:
                log.debug(f"  [{ip}] Web scan error: {exc}")

        # IoT default credential check
        if (include_iot and "iot" in modules and
                info.device_class in ("iot", "network", "unknown") and
                info.open_ports):
            log.info(f"  [{ip}] Phase E: IoT cred check…")
            try:
                iot_results = await asyncio.wait_for(
                    IotScanner().run(ip, info.open_ports), timeout=120)
                for hit in iot_results.get("default_creds", []):
                    if hit.get("confirmed"):
                        info.security_findings.append({
                            "severity": "CRITICAL",
                            "check":    "default_credentials",
                            "detail": (
                                f"{hit.get('vendor')} {hit.get('model')}: "
                                f"{hit.get('service')}:{hit.get('port')} "
                                f"accepts '{hit.get('username')}' / '{hit.get('password')}'"
                            ),
                        })
            except (asyncio.TimeoutError, Exception) as exc:
                log.debug(f"  [{ip}] IoT scan error: {exc}")

        # Android ADB assessment
        adb_ports = [p for p in info.open_ports if p in (5555, 5554, 5556, 5558)]
        if (include_mobile and "mobile" in modules and adb_ports):
            log.info(f"  [{ip}] Phase E: Android assessment on port {adb_ports[0]}…")
            try:
                android_results = await asyncio.wait_for(
                    AndroidScanner().run(ip, port=adb_ports[0]), timeout=120)
                for f_item in android_results.get("findings", []):
                    f_item["source"] = "android"
                    info.security_findings.append(f_item)
                info.cves.extend(android_results.get("cve_matches", []))
                info.exploits.extend(android_results.get("exploit_matches", []))
            except (asyncio.TimeoutError, Exception) as exc:
                log.debug(f"  [{ip}] Android scan error: {exc}")

        info.scan_duration = time.monotonic() - t_start
        if report:
            self._write_host_report(ip, info, report)

        log.info(
            f"  [{ip}] Done in {info.scan_duration:.1f}s — "
            f"{len(info.open_ports)} ports | {len(info.cves)} CVEs | "
            f"{len(info.exploits)} exploits | {len(info.security_findings)} findings"
        )
        return info

    # =========================================================================
    # Phase B: Port Scan
    # =========================================================================

    async def _port_scan(
        self,
        ip: str,
        info: HostInfo,
        port_timeout: float,
        ports: Optional[list[int]],
    ) -> None:
        """
        Discover open ports and grab service banners.
        Tries nmap -sV first (richer output). If nmap returns 0 open ports
        (common when running without root/CAP_NET_RAW), falls through to the
        asyncio TCP-connect banner-grab which works without privileges.
        Both paths populate info.open_ports and info.services.
        """
        if self._nmap:
            await self._nmap_port_scan(ip, info, ports, port_timeout)
        # Always run banner scan when nmap found nothing — nmap may have failed
        # silently due to privilege issues (SYN scan requires root).
        if not info.open_ports:
            log.debug(f"  [{ip}] nmap returned 0 ports — running TCP connect fallback.")
            await self._banner_fingerprint(ip, info, port_timeout, ports)

    async def _nmap_port_scan(
        self,
        ip: str,
        info: HostInfo,
        ports: Optional[list[int]],
        port_timeout: float = 1.5,
    ) -> None:
        """
        nmap -sV --unprivileged: service/version detection on top-1000 ports.
        Uses --unprivileged so it always falls back to TCP-connect scan even
        without root, avoiding the silent-zero-result SYN-scan problem.
        """
        try:
            port_arg = ("-p " + ",".join(str(p) for p in ports)) if ports \
                       else "--top-ports 1000"
            # --unprivileged  → TCP connect scan (works without root)
            # --host-timeout  → per-host ceiling so we don't stall
            host_timeout_ms = int(port_timeout * 1000 * 1200)  # ~port_timeout * 1200 ports
            cmd_parts = (
                f"{self._nmap} -sV --unprivileged --version-intensity 5 -T4 "
                f"--host-timeout {host_timeout_ms}ms "
                f"--script banner,http-title,ssh-hostkey,ftp-banner,smtp-banner "
                f"-oX - {port_arg} {ip}"
            ).split()
            log.debug(f"  [{ip}] nmap cmd: {' '.join(cmd_parts)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            stderr_str = stderr.decode(errors="replace").strip()
            if stderr_str:
                log.debug(f"  [{ip}] nmap stderr: {stderr_str[:300]}")
            _parse_nmap_xml(stdout.decode(errors="replace"), info)
            if info.open_ports:
                log.info(f"  [{ip}] nmap found {len(info.open_ports)} open port(s).")
        except asyncio.TimeoutError:
            log.warning(f"  [{ip}] nmap port scan timed out.")
        except Exception as exc:
            log.debug(f"  [{ip}] nmap port scan error: {exc}")

    # =========================================================================
    # Phase C: OS Fingerprint
    # =========================================================================

    async def _nmap_os_fingerprint(
        self,
        ip: str,
        info: HostInfo,
        ports: Optional[list[int]],
    ) -> None:
        """
        nmap -O --osscan-guess: OS detection against already-known open ports.
        Only adds OS fields to info — does not re-scan ports.
        Requires root/CAP_NET_RAW; gracefully skips if nmap returns no OS match.
        """
        # Use the open ports we already discovered so nmap doesn't re-probe
        if info.open_ports:
            port_arg = "-p " + ",".join(str(p) for p in info.open_ports[:20])
        elif ports:
            port_arg = "-p " + ",".join(str(p) for p in ports)
        else:
            port_arg = "--top-ports 100"

        try:
            cmd_str  = (
                f"{self._nmap} -O --osscan-guess --osscan-limit "
                f"-T4 -oX - {port_arg} {ip}"
            )
            cmd_flat = cmd_str.split()
            proc = await asyncio.create_subprocess_exec(
                *cmd_flat,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            xml = stdout.decode(errors="replace")

            # Parse only the OS fields — don't overwrite services already found
            _parse_nmap_xml_os_only(xml, info)

            stderr_str = stderr.decode(errors="replace")
            if "requires root" in stderr_str or "requires privileged" in stderr_str:
                log.debug(f"  [{ip}] OS detection requires root — using TTL heuristic.")
                await _guess_os_from_ttl(ip, info)
        except asyncio.TimeoutError:
            log.debug(f"  [{ip}] OS fingerprint timed out — using TTL heuristic.")
            await _guess_os_from_ttl(ip, info)
        except Exception as exc:
            log.debug(f"  [{ip}] OS fingerprint error: {exc}")
            await _guess_os_from_ttl(ip, info)


    async def _nmap_smb_os(self, ip: str, info: HostInfo) -> None:
        """
        Use nmap --script smb-os-discovery to get Windows OS name from SMB.
        Much more reliable than -O for Windows hosts without root.
        """
        try:
            cmd = (f"{self._nmap} -p 445 --script smb-os-discovery "
                   f"--unprivileged -T4 -oX - {ip}").split()
            log.debug(f"  [{ip}] nmap SMB cmd: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            xml = stdout.decode(errors="replace")
            # Parse smb-os-discovery script output
            m = re.search(r"OS:\s*([^\r\n<\\]+)", xml)
            if m:
                os_str = m.group(1).strip()
                info.os_name   = os_str
                info.os_family = _os_family_from_name(os_str)
                info.os_version = _os_version_from_name(os_str)
                log.info(f"  [{ip}] SMB OS discovery: {os_str}")
            stderr_str = stderr.decode(errors="replace").strip()
            if stderr_str:
                log.debug(f"  [{ip}] SMB script stderr: {stderr_str[:200]}")
        except asyncio.TimeoutError:
            log.debug(f"  [{ip}] SMB OS discovery timed out")
        except Exception as exc:
            log.debug(f"  [{ip}] SMB OS discovery error: {exc}")


    async def _banner_fingerprint(
        self,
        ip: str,
        info: HostInfo,
        port_timeout: float,
        ports: Optional[list[int]],
    ) -> None:
        """
        Fallback: scan top ports with TCP connect + banner grab.
        Uses TTL from OS to make educated OS guess.
        """
        from .port_scanner import DEFAULT_PORTS
        scan_ports = ports or DEFAULT_PORTS

        sem = asyncio.Semaphore(200)

        async def _probe_port(port: int) -> Optional[tuple[int, str]]:
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=port_timeout,
                    )
                    # Try to read a banner (some services send immediately)
                    try:
                        banner_bytes = await asyncio.wait_for(
                            reader.read(512), timeout=2
                        )
                        banner = banner_bytes.decode(errors="replace").strip()
                    except Exception:
                        banner = ""
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return port, banner
                except Exception:
                    return None

        results = await asyncio.gather(
            *[_probe_port(p) for p in scan_ports],
            return_exceptions=True
        )

        from .port_scanner import _COMMON_PORT_NAMES  # type: ignore
        for r in results:
            if isinstance(r, tuple):
                port, banner = r
                info.open_ports.append(port)
                service_name = _COMMON_PORT_NAMES.get(port, "unknown")
                info.services[port] = {
                    "name":    service_name,
                    "version": "",
                    "banner":  banner[:200],
                    "cpe":     [],
                }
                # Extract version hints from banner
                if banner:
                    _extract_version_from_banner(port, banner, info.services[port])

        info.open_ports.sort()

        # TTL-based OS heuristic (get TTL via ICMP/TCP)
        await _guess_os_from_ttl(ip, info)

    # =========================================================================
    # Exploit auto-matching
    # =========================================================================

    async def _auto_exploit_match(self, info: HostInfo) -> None:
        """Search offline DB for exploits matching every CVE found on this host."""
        if not self._db.is_available() or not info.cves:
            return
        seen: set = set()
        for cve in info.cves:
            cve_id = cve.get("id") or cve.get("cve_id", "")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            try:
                exploits = await asyncio.to_thread(
                    self._db.search_exploits, cve_id, None, None, False, 5
                )
                for ex in exploits:
                    eid = ex.get("exploit_id")
                    if eid not in {e.get("id") for e in info.exploits}:
                        info.exploits.append({
                            "source":          "exploit_db",
                            "id":              eid,
                            "edb_id":          eid,
                            "title":           ex.get("title", ""),
                            "type":            ex.get("type", ""),
                            "platform":        ex.get("platform", ""),
                            "verified":        bool(ex.get("verified")),
                            "cve_ids":         ex.get("cve_ids", []),
                            "edb_url":         ex.get("edb_url", "")
                                                or (f"https://www.exploit-db.com/exploits/{eid}"
                                                    if eid else ""),
                            "local_file_path": ex.get("local_file_path"),
                            "author":          ex.get("author", ""),
                            "date_published":  ex.get("date_published", ""),
                            "matched_cve":     cve_id,
                            "matched_service": cve.get("service", ""),
                            "matched_port":    cve.get("port", ""),
                        })
            except Exception as exc:
                log.debug(f"[exploit_match] error for {cve_id}: {exc}")

    # =========================================================================
    # Summary and reporting
    # =========================================================================

    def _build_summary(self, hosts: list[HostInfo], spec: str, duration: float) -> dict:
        total_cves        = sum(len(h.cves) for h in hosts)
        total_exploits    = sum(len(h.exploits) for h in hosts)
        critical_hosts    = sum(
            1 for h in hosts
            if any(str(c.get("severity", "")).upper() == "CRITICAL" for c in h.cves)
            or any(f.get("severity") == "CRITICAL" for f in h.security_findings)
        )
        device_types: dict[str, int] = {}
        for h in hosts:
            key = h.device_class if not h.device_subclass else f"{h.device_class}/{h.device_subclass}"
            device_types[key] = device_types.get(key, 0) + 1

        os_breakdown: dict[str, int] = {}
        for h in hosts:
            os_key = h.os_family or h.os_name or "Unknown"
            os_breakdown[os_key] = os_breakdown.get(os_key, 0) + 1

        # Top CVEs by severity
        all_cves = []
        for h in hosts:
            for c in h.cves:
                c["_host"] = h.ip
                all_cves.append(c)
        all_cves.sort(
            key=lambda c: float(c.get("score") or 0),
            reverse=True
        )

        return {
            "target_spec":    spec,
            "total_ips":      0,    # filled by caller
            "live_hosts":     len(hosts),
            "duration_s":     round(duration, 1),
            "total_cves":     total_cves,
            "total_exploits": total_exploits,
            "critical_hosts": critical_hosts,
            "device_types":   device_types,
            "os_breakdown":   os_breakdown,
            "top_cves":       all_cves[:10],
        }

    def _write_host_report(
        self, ip: str, info: HostInfo, report: ReportManager
    ) -> None:
        """Write per-host sections to report."""
        label = f"Host: {ip}" + (f" ({info.hostname})" if info.hostname else "")
        report.add_section(
            f"{label} — Identity",
            [self._host_to_dict(info)]
        )
        if info.cves:
            report.add_section(f"{label} — CVE Findings", info.cves)
        if info.exploits:
            report.add_section(f"{label} — Exploit Matches", info.exploits)
        if info.security_findings:
            report.add_section(f"{label} — Security Findings", info.security_findings)

    def _host_to_dict(self, h: HostInfo) -> dict:
        crit_count = sum(1 for c in h.cves
                         if str(c.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for c in h.cves
                         if str(c.get("severity", "")).upper() == "HIGH")
        # Convert services dict (port -> {name,version,banner,cpe}) to list
        services_list = []
        for port, svc in (h.services or {}).items():
            services_list.append({
                "port":    port,
                "name":    svc.get("name", ""),
                "version": svc.get("version", ""),
                "banner":  svc.get("banner", ""),
            })
        return {
            "ip":              h.ip,
            "hostname":        h.hostname,
            "mac":             h.mac,
            "vendor":          h.mac_vendor,
            "os_name":         h.os_name,
            "os_version":      h.os_version,
            "os_family":       h.os_family,
            "os_accuracy":     h.os_accuracy,
            "cpe":             ", ".join(h.os_cpe) if h.os_cpe else "",
            "device_type":     h.device_class,
            "device_subtype":  h.device_subclass,
            "device_class":    h.device_class,    # legacy key
            "device_subclass": h.device_subclass, # legacy key
            "open_ports":      h.open_ports,
            "services":        services_list,
            "cves":            h.cves,
            "exploits":        h.exploits,
            "cve_count":       len(h.cves),
            "critical_count":  crit_count,
            "high_count":      high_count,
            "exploit_count":   len(h.exploits),
            "android_findings": [f for f in h.security_findings
                                 if f.get("source") == "android"],
            "device_props":    {f.get("check", ""): f.get("detail", "")
                                for f in h.security_findings
                                if f.get("source") != "android"},
            "status":          "done" if not h.scan_error else "error",
            "scan_duration_s": round(h.scan_duration, 1),
        }


# =============================================================================
# Device Classifier
# =============================================================================

def _classify_device(info: HostInfo) -> None:
    """
    Classify the host into device_class / device_subclass using:
    - OS name / family
    - Open ports
    - MAC vendor
    - Service banners
    """
    os_lower  = (info.os_name + " " + info.os_family + " " + info.os_version).lower()
    vendor_l  = info.mac_vendor.lower()
    ports     = set(info.open_ports)
    banners   = " ".join(
        svc.get("banner", "") for svc in info.services.values()
    ).lower()

    # ── Mobile devices ───────────────────────────────────────────────────────
    if ports & _MOBILE_PORTS or "android" in os_lower or "android" in banners:
        info.device_class    = "mobile"
        info.device_subclass = "android"
        return
    if ports & _IOS_PORTS or "iphone" in os_lower or "ipad" in os_lower or \
       any(v in vendor_l for v in ("apple",)):
        if not any(p in ports for p in (22, 25, 53, 80, 443)):
            info.device_class    = "mobile"
            info.device_subclass = "ios"
            return

    # ── Network infrastructure ───────────────────────────────────────────────
    if any(k in os_lower for k in ("ios", "junos", "routeros", "vyos",
                                    "pfsense", "openwrt", "dd-wrt", "fortios",
                                    "arubaos", "extremexos", "cumulus")):
        info.device_class    = "network"
        if any(k in os_lower for k in ("firewall", "asa", "fortios", "pfsense")):
            info.device_subclass = "firewall"
        elif any(k in os_lower for k in ("routeros", "vyos", "ios")):
            info.device_subclass = "router"
        else:
            info.device_subclass = "router"
        return

    if any(v in vendor_l for v in ("cisco", "juniper", "mikrotik", "fortinet",
                                    "palo alto", "sophos", "checkpoint")):
        info.device_class = "network"
        if any(k in banners for k in ("firewall", "asa", "fortigate")):
            info.device_subclass = "firewall"
        else:
            info.device_subclass = "router"
        return

    if any(v in vendor_l for v in ("ubiquiti", "aruba", "ruckus")):
        info.device_class    = "network"
        info.device_subclass = "wap"
        return

    # Port-based network infrastructure
    if {179, 520} & ports:   # BGP, RIP
        info.device_class    = "network"
        info.device_subclass = "router"
        return
    if {8291, 8728, 8729} & ports:  # Mikrotik Winbox
        info.device_class    = "network"
        info.device_subclass = "router"
        return

    # ── IoT and embedded devices ─────────────────────────────────────────────
    if any(k in os_lower for k in ("embedded", "uclinux", "vxworks",
                                    "threadx", "freertos", "openwrt")):
        info.device_class    = "iot"
        info.device_subclass = _iot_subclass(ports, banners, vendor_l)
        return

    if 554 in ports or any(k in banners for k in ("rtsp", "ipcam", "dvr", "nvr",
                                                    "camera", "hikvision", "dahua",
                                                    "axis", "hanwha")):
        info.device_class    = "iot"
        info.device_subclass = "camera"
        return

    if 1883 in ports or 8883 in ports:  # MQTT = IoT gateway/sensor
        info.device_class    = "iot"
        info.device_subclass = "mqtt_device"
        return

    if 502 in ports or 47808 in ports or 102 in ports:  # Modbus/BACnet/S7
        info.device_class    = "iot"
        info.device_subclass = "plc_ics"
        return

    if any(v in vendor_l for v in ("raspberry", "arduino", "espressif",
                                    "hikvision", "dahua", "axis", "dji",
                                    "xiaomi", "samsung")):
        info.device_class    = "iot"
        info.device_subclass = _iot_subclass(ports, banners, vendor_l)
        return

    # ── Printers ─────────────────────────────────────────────────────────────
    if 9100 in ports or 631 in ports or any(k in banners for k in
                                             ("printer", "laserjet", "cups")):
        info.device_class    = "iot"
        info.device_subclass = "printer"
        return

    # ── Servers ──────────────────────────────────────────────────────────────
    if any(k in os_lower for k in ("linux", "ubuntu", "debian", "centos",
                                    "rhel", "fedora", "windows server",
                                    "freebsd", "openbsd")):
        if any(p in ports for p in (22, 25, 53, 3306, 5432, 27017, 6379)):
            info.device_class    = "server"
            info.device_subclass = _server_subclass(ports, banners)
            return
        info.device_class = "workstation"
        return

    if any(k in os_lower for k in ("windows 10", "windows 11", "windows 7",
                                    "macos", "mac os x")):
        info.device_class    = "workstation"
        return

    # Default: use port fingerprint
    if len(ports & _SERVER_PORTS) >= 3:
        info.device_class    = "server"
        info.device_subclass = _server_subclass(ports, banners)
    elif len(ports & _IOT_PORTS) >= 2 and len(ports) < 6:
        info.device_class    = "iot"
    elif len(ports) > 0:
        info.device_class    = "unknown"


def _iot_subclass(ports: set, banners: str, vendor: str) -> str:
    if 554 in ports or any(k in banners for k in ("camera", "rtsp")):
        return "camera"
    if 9100 in ports or 631 in ports or "printer" in banners:
        return "printer"
    if 1883 in ports or 8883 in ports:
        return "mqtt_device"
    if 502 in ports or 47808 in ports:
        return "plc_ics"
    if "drone" in vendor or any(v in vendor for v in ("dji",)):
        return "drone"
    if any(v in vendor for v in ("raspberry",)):
        return "sbc"
    return "embedded"


def _server_subclass(ports: set, banners: str) -> str:
    if {3306, 5432, 1433, 1521, 27017, 6379} & ports:
        return "database_server"
    if 25 in ports or 143 in ports or 110 in ports:
        return "mail_server"
    if 53 in ports:
        return "dns_server"
    if {80, 443, 8080, 8443} & ports:
        return "web_server"
    if 22 in ports:
        return "linux_server"
    return "server"


# =============================================================================
# nmap XML parser
# =============================================================================

def _parse_nmap_xml(xml: str, info: HostInfo) -> None:
    """
    Parse nmap XML output and populate HostInfo.
    Uses regex rather than xml.etree (avoids lxml dependency).
    Extracts: open ports, services, version strings, banners, OS matches,
    ostype hints from service elements, OS CPE, and MAC address.
    """
    if not xml or "<nmaprun" not in xml:
        return

    # Extract open ports and services
    port_re = re.compile(
        r'<port protocol="(\w+)" portid="(\d+)">'
        r'.*?<state state="(\w+)"[^/]*/>'
        r'.*?<service name="([^"]*)"[^>]*'
        r'(?:product="([^"]*)")?[^>]*'
        r'(?:version="([^"]*)")?[^>]*'
        r'(?:extrainfo="([^"]*)")?[^>]*'
        r'(?:ostype="([^"]*)")?[^>]*'
        r'(?:cpe>([^<]*)</cpe>)?',
        re.DOTALL
    )
    for m in port_re.finditer(xml):
        proto, portid, state, svc_name, product, version, extra, ostype, cpe = m.groups()
        if state != "open":
            continue
        port = int(portid)
        info.open_ports.append(port)
        ver_str = " ".join(filter(None, [product, version, extra])).strip()
        info.services[port] = {
            "name":    svc_name or "unknown",
            "version": ver_str,
            "banner":  "",
            "cpe":     [cpe] if cpe else [],
        }
        # ostype from service element is a strong OS hint when -O isn't available
        if ostype and not info.os_name:
            log.debug(f"[nmap_parse] service ostype hint: {ostype!r} from port {port}")
            info.os_name   = ostype
            info.os_family = _os_family_from_name(ostype)
            info.os_version = _os_version_from_name(ostype)

    info.open_ports = sorted(set(info.open_ports))

    # Script output — banners, titles, SSH keys etc.
    # Map port number from enclosing <port> element so banners attach correctly
    port_block_re = re.compile(
        r'<port[^>]*portid="(\d+)"[^>]*>.*?</port>', re.DOTALL
    )
    for pb in port_block_re.finditer(xml):
        port_num = int(pb.group(1))
        if port_num not in info.services:
            continue
        svc = info.services[port_num]
        # Extract all script outputs within this port block
        for sm in re.finditer(r'<script id="([^"]+)"[^>]*output="([^"]*)"',
                               pb.group(0)):
            script_id, output = sm.groups()
            output = output.replace("\\n", "\n").strip()
            if "banner" in script_id or "ftp-banner" in script_id \
                    or "smtp-banner" in script_id:
                if not svc.get("banner"):
                    svc["banner"] = output[:300]
            elif "http-title" in script_id:
                svc["http_title"] = output[:200]
            elif "ssh-hostkey" in script_id:
                svc["ssh_hostkey"] = output[:400]

    # OS detection from -O
    os_re = re.compile(
        r'<osmatch name="([^"]*)" accuracy="(\d+)"[^>]*/>'
    )
    best_accuracy = 0
    for m in os_re.finditer(xml):
        name, accuracy = m.groups()
        acc_int = int(accuracy)
        if acc_int > best_accuracy:
            best_accuracy = acc_int
            info.os_name     = name
            info.os_accuracy = acc_int
            info.os_family   = _os_family_from_name(name)
            info.os_version  = _os_version_from_name(name)

    # OS CPE
    os_cpe_re = re.compile(r'<osclass[^>]*cpe="([^"]+)"')
    for m in os_cpe_re.finditer(xml):
        info.os_cpe.append(m.group(1))

    # MAC address
    mac_re = re.compile(r'<address addr="([0-9A-Fa-f:]{17})" addrtype="mac"'
                        r'(?:\s+vendor="([^"]*)")?')
    m = mac_re.search(xml)
    if m:
        info.mac        = m.group(1)
        info.mac_vendor = m.group(2) or _lookup_mac_vendor(m.group(1))

    # Fallback: infer OS from SSH banner (very reliable)
    if not info.os_name:
        _infer_os_from_service_banners(info)



def _parse_nmap_xml_os_only(xml: str, info: HostInfo) -> None:
    """
    Extract ONLY the OS detection fields from nmap XML output.
    Does not touch info.open_ports or info.services — those were already
    populated by the port scan phase and must not be overwritten.
    """
    if not xml or "<nmaprun" not in xml:
        return

    # OS match
    os_re = re.compile(r'<osmatch name="([^"]*)" accuracy="(\d+)"[^>]*/>')
    best_accuracy = 0
    for m in os_re.finditer(xml):
        name, accuracy = m.groups()
        acc_int = int(accuracy)
        if acc_int > best_accuracy:
            best_accuracy = acc_int
            info.os_name     = name
            info.os_accuracy = acc_int
            info.os_family   = _os_family_from_name(name)
            info.os_version  = _os_version_from_name(name)

    # OS CPE
    os_cpe_re = re.compile(r'<osclass[^>]*cpe="([^"]+)"')
    for m in os_cpe_re.finditer(xml):
        cpe = m.group(1)
        if cpe not in info.os_cpe:
            info.os_cpe.append(cpe)

    # MAC (may not have been present in port-scan XML)
    if not info.mac:
        mac_re = re.compile(r'<address addr="([0-9A-Fa-f:]{17})" addrtype="mac"'
                            r'(?:\s+vendor="([^"]*)")?')
        m = mac_re.search(xml)
        if m:
            info.mac        = m.group(1)
            info.mac_vendor = m.group(2) or _lookup_mac_vendor(m.group(1))


# =============================================================================
# Banner-based version extraction
# =============================================================================

def _extract_version_from_banner(port: int, banner: str, svc: dict) -> None:
    """Extract product/version strings from raw service banners."""
    patterns = [
        (r"SSH-[\d.]+-OpenSSH[_\s]+([\w.]+)",             "OpenSSH"),
        (r"220[- ].*?vsftpd\s+([\d.]+)",                  "vsftpd"),
        (r"220[- ].*?ProFTPD\s+([\d.]+)",                 "ProFTPD"),
        (r"220[- ].*?FileZilla\s+([\d.]+)",               "FileZilla"),
        (r"Server:\s*Apache/([\d.]+)",                    "Apache httpd"),
        (r"Server:\s*nginx/([\d.]+)",                     "nginx"),
        (r"Server:\s*Microsoft-IIS/([\d.]+)",             "Microsoft IIS"),
        (r"X-Powered-By:\s*PHP/([\d.]+)",                 "PHP"),
        (r"220.*?Postfix",                                None),
        (r"Android Debug Bridge device.*?model:\s*(\S+)", "ADB"),
    ]
    for pattern, product_name in patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            if product_name:
                svc["version"] = product_name + " " + (m.group(1) if m.lastindex else "")
            break


def _infer_os_from_service_banners(info: HostInfo) -> None:
    """
    Infer OS from service banners when nmap -O is unavailable or returns nothing.
    Checks: SSH version string, HTTP Server header, FTP/SMTP/Telnet banners,
    SMB native OS field, and CPE strings already attached to services.
    Sets info.os_name / os_family / os_version if confident.
    """
    # Rules: (regex, os_name_template, os_family)
    SSH_PATTERNS = [
        (r"SSH-\d\.\d-OpenSSH[_\s]+([\d.p]+)[^\r\n]*Ubuntu",   "Ubuntu Linux",       "Linux"),
        (r"SSH-\d\.\d-OpenSSH[_\s]+([\d.p]+)[^\r\n]*Debian",   "Debian Linux",       "Linux"),
        (r"SSH-\d\.\d-OpenSSH[_\s]+([\d.p]+)[^\r\n]*raspbian", "Raspbian Linux",      "Linux"),
        (r"SSH-\d\.\d-OpenSSH[_\s]+([\d.p]+)",                  "Linux (OpenSSH)",    "Linux"),
        (r"SSH-\d\.\d-dropbear",                                 "Embedded Linux (Dropbear)", "Linux"),
        (r"SSH-\d\.\d-Cisco",                                    "Cisco IOS",          "Cisco IOS"),
        (r"SSH-\d\.\d-ROSSSH",                                   "MikroTik RouterOS",  "RouterOS"),
        (r"SSH-\d\.\d-.*[Ww]indows",                             "Windows",            "Windows"),
    ]
    HTTP_PATTERNS = [
        (r"Server:\s*Microsoft-IIS/([\d.]+)",         lambda m: f"Windows (IIS {m.group(1)})", "Windows"),
        (r"Server:\s*Apache/([\d.]+)[^\r\n]*\(Ubuntu","Ubuntu Linux",                           "Linux"),
        (r"Server:\s*Apache/([\d.]+)[^\r\n]*\(Debian","Debian Linux",                           "Linux"),
        (r"Server:\s*Apache/([\d.]+)[^\r\n]*\(CentOS","CentOS Linux",                           "Linux"),
        (r"Server:\s*Apache/([\d.]+)[^\r\n]*\(Red Hat","Red Hat Linux",                         "Linux"),
        (r"X-Powered-By:\s*ASP\.NET",                 "Windows",                                "Windows"),
        (r"X-AspNet-Version:",                         "Windows",                                "Windows"),
    ]
    SMB_PATTERNS = [
        (r"Windows\s+(Server\s+\d{4}[^\r\n]*)",  lambda m: f"Windows {m.group(1)}", "Windows"),
        (r"Windows\s+(\d+\.\d+)",                 lambda m: f"Windows {m.group(1)}", "Windows"),
        (r"Samba\s+([\d.]+)",                     lambda m: f"Linux (Samba {m.group(1)})", "Linux"),
    ]

    all_banners: list[str] = []
    for port, svc in info.services.items():
        b = svc.get("banner", "") or ""
        v = svc.get("version", "") or ""
        t = svc.get("http_title", "") or ""
        all_banners.append(b + " " + v + " " + t)

    combined = "\n".join(all_banners)

    # SSH (most reliable — directly identifies OS build)
    ssh_banner = ""
    for port in (22, 2222, 22222):
        if port in info.services:
            ssh_banner = (info.services[port].get("banner", "") or "") + \
                         (info.services[port].get("version", "") or "")
    if ssh_banner:
        for pattern, os_name, os_family in SSH_PATTERNS:
            m = re.search(pattern, ssh_banner, re.IGNORECASE)
            if m:
                info.os_name   = os_name if isinstance(os_name, str) else os_name(m)
                info.os_family = os_family
                log.debug(f"[banner_os] SSH banner → {info.os_name}")
                return

    # HTTP Server header
    http_banner = ""
    for port in (80, 443, 8080, 8443, 8000, 8888):
        if port in info.services:
            http_banner += (info.services[port].get("banner", "") or "") + \
                           (info.services[port].get("version", "") or "")
    if http_banner:
        for pattern, os_name, os_family in HTTP_PATTERNS:
            m = re.search(pattern, http_banner, re.IGNORECASE)
            if m:
                info.os_name   = os_name if isinstance(os_name, str) else os_name(m)
                info.os_family = os_family
                log.debug(f"[banner_os] HTTP banner → {info.os_name}")
                return

    # SMB (port 445)
    if 445 in info.services:
        smb_banner = (info.services[445].get("banner", "") or "") + \
                     (info.services[445].get("version", "") or "")
        for pattern, os_name, os_family in SMB_PATTERNS:
            m = re.search(pattern, smb_banner, re.IGNORECASE)
            if m:
                info.os_name   = os_name if isinstance(os_name, str) else os_name(m)
                info.os_family = os_family
                log.debug(f"[banner_os] SMB → {info.os_name}")
                return

    # CPE strings already on services
    for port, svc in info.services.items():
        for cpe in (svc.get("cpe") or []):
            # cpe:/o:microsoft:windows_server_2019
            m = re.search(r"cpe:/o:([^:]+):([^:]+)(?::([^:]+))?", cpe)
            if m:
                vendor, product, version = m.groups()
                os_name = f"{vendor.title()} {product.replace('_',' ').title()}"
                if version:
                    os_name += f" {version.replace('_','.')}"
                info.os_name   = os_name
                info.os_family = _os_family_from_name(os_name)
                log.debug(f"[banner_os] CPE → {info.os_name}")
                return

    # FTP/SMTP banner OS hints
    for port in (21, 25):
        if port in info.services:
            b = (info.services[port].get("banner", "") or "").lower()
            if "ubuntu" in b:
                info.os_name = "Ubuntu Linux"; info.os_family = "Linux"; return
            if "debian" in b:
                info.os_name = "Debian Linux"; info.os_family = "Linux"; return
            if "windows" in b:
                info.os_name = "Windows"; info.os_family = "Windows"; return


async def _guess_os_from_ttl(ip: str, info: HostInfo) -> None:
    """
    Guess OS family from ICMP TTL.  Linux initial TTL=64, Windows=128, Cisco=255.
    Also calls _infer_os_from_service_banners first as a higher-quality source.
    """
    log.debug(f"[ttl_guess] Probing {ip} TTL…")
    # Try banner inference first — more specific than TTL
    if not info.os_name:
        _infer_os_from_service_banners(info)
    if info.os_name:
        log.debug(f"[ttl_guess] {ip} OS resolved via banners: {info.os_name}")
        return
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
        output = stdout.decode(errors="replace")
        m = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            info.ttl = ttl
            if ttl <= 64:
                info.os_family = "Linux/Unix"
                if not info.os_name:
                    info.os_name = "Linux/Unix (TTL≤64)"
            elif ttl <= 128:
                info.os_family = "Windows"
                if not info.os_name:
                    info.os_name = "Windows (TTL≤128)"
            elif ttl <= 255:
                info.os_family = "Network device / Unix"
                if not info.os_name:
                    info.os_name = "Network Device (TTL≤255)"
            log.debug(f"[ttl_guess] {ip} TTL={ttl} → {info.os_family}")
    except Exception as exc:
        log.debug(f"[ttl_guess] {ip} ping failed: {exc}")


# =============================================================================
# IP range parsing
# =============================================================================

def _parse_target_spec(spec: str) -> list[str]:
    """
    Parse a target specification into a flat list of IP strings.

    Accepts:
      - CIDR:           192.168.1.0/24
      - Hyphen range:   192.168.1.1-50  or  192.168.1.1-192.168.1.50
      - Single IP:      10.0.0.1
      - Comma-separated combination of the above
    """
    ips: list[str] = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        if "/" in part:
            # CIDR
            try:
                network = ipaddress.ip_network(part, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR '{part}': {exc}")

        elif "-" in part:
            # Hyphen range
            parts = part.split("-", 1)
            start_str, end_str = parts[0].strip(), parts[1].strip()
            try:
                start_ip = ipaddress.ip_address(start_str)
            except ValueError:
                raise ValueError(f"Invalid start address '{start_str}'")

            if "." in end_str:
                # Full end IP e.g. 192.168.1.1-192.168.1.50
                try:
                    end_ip = ipaddress.ip_address(end_str)
                except ValueError:
                    raise ValueError(f"Invalid end address '{end_str}'")
            else:
                # Short form e.g. 192.168.1.1-50
                try:
                    last_octet = int(end_str)
                except ValueError:
                    raise ValueError(f"Invalid range end '{end_str}'")
                base = str(start_ip).rsplit(".", 1)[0]
                end_ip = ipaddress.ip_address(f"{base}.{last_octet}")

            start_int = int(start_ip)
            end_int   = int(end_ip)
            if start_int > end_int:
                raise ValueError(f"Range start {start_ip} > end {end_ip}")
            if end_int - start_int > 65535:
                raise ValueError(f"Range too large (max 65536 hosts per range)")
            for i in range(start_int, end_int + 1):
                ips.append(str(ipaddress.ip_address(i)))

        else:
            # Single IP or hostname
            try:
                ipaddress.ip_address(part)
                ips.append(part)
            except ValueError:
                # Could be a hostname — resolve it
                try:
                    resolved = socket.gethostbyname(part)
                    ips.append(resolved)
                except socket.gaierror:
                    raise ValueError(f"Cannot resolve host '{part}'")

    if not ips:
        raise ValueError("No valid targets in specification.")
    return ips


# =============================================================================
# Utility helpers
# =============================================================================

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _ip_sort_key(ip: str):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def _lookup_mac_vendor(mac: str) -> str:
    prefix = mac[:8].lower()
    return _MAC_VENDORS.get(prefix, "")


def _os_family_from_name(name: str) -> str:
    n = name.lower()
    if "windows" in n:   return "Windows"
    if "linux" in n:     return "Linux"
    if "macos" in n or "mac os" in n or "darwin" in n: return "macOS"
    if "freebsd" in n:   return "FreeBSD"
    if "android" in n:   return "Android"
    if "ios" in n or "iphone" in n or "ipad" in n:    return "iOS"
    if "cisco" in n:     return "Cisco IOS"
    if "junos" in n:     return "JunOS"
    if "routeros" in n:  return "RouterOS"
    return name.split()[0] if name else "Unknown"


def _os_version_from_name(name: str) -> str:
    m = re.search(r"([\d]{1,2}(?:\.\d+)+)", name)
    return m.group(1) if m else ""
