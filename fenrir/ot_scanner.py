# fenrir/modules/ot_scanner.py
#
# Fix 18 — Changes from original:
#   - Replaced pkt[1].src/dst with pkt[IP].src/dst (pkt[1] was incorrect —
#     index 1 is the second layer, not always IP; caused IndexError on non-IP frames)
#   - Added haslayer(IP) guard before all IP field access
#   - Added duration as configurable parameter (default 30s)
#   - Expanded protocol detection: Modbus, Siemens S7, DNP3, BACnet,
#     EtherNet/IP, Profinet, IEC 60870-5-104, OPC-UA, FINS
#   - Added passive UDP protocol detection (BACnet, DNP3, FINS use UDP)
#   - Structured findings dict with protocol, src, dst, port, timestamp
#   - ReportManager integration
#   - run() returns dict of findings keyed by protocol name
#   - Root privilege check with clear error before attempting sniff
#   - Added active port scan mode as fallback when passive sniff fails
#     (sends TCP SYN to OT ports to check reachability)

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# Scapy optional — requires root/admin privileges
try:
    from scapy.all import IP, TCP, UDP, sniff
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    log.debug("scapy not installed — passive OT sniffing unavailable.")

# ---------------------------------------------------------------------------
# OT/ICS protocol port definitions
# ---------------------------------------------------------------------------

# TCP protocols: port -> (protocol_name, severity, description)
_OT_TCP_PORTS: dict[int, tuple[str, str, str]] = {
    102:   ("Siemens S7",      "CRITICAL", "Siemens S7comm — Siemens PLC programming protocol"),
    502:   ("Modbus TCP",      "CRITICAL", "Modbus TCP — widely used PLC/RTU control protocol"),
    1911:  ("Niagara Fox",     "HIGH",     "Tridium Niagara Fox protocol"),
    2222:  ("EtherNet/IP",     "HIGH",     "EtherNet/IP — Rockwell/Allen-Bradley PLCs"),
    2404:  ("IEC 60870-5-104", "CRITICAL", "IEC 104 — SCADA telecontrol standard"),
    4840:  ("OPC-UA",          "HIGH",     "OPC Unified Architecture — industrial data exchange"),
    20000: ("DNP3",            "CRITICAL", "DNP3 — Distributed Network Protocol (SCADA/utilities)"),
    44818: ("EtherNet/IP",     "HIGH",     "EtherNet/IP (alternate port)"),
    62900: ("Profinet",        "HIGH",     "PROFINET — Siemens industrial Ethernet"),
}

# UDP protocols
_OT_UDP_PORTS: dict[int, tuple[str, str, str]] = {
    47808: ("BACnet",  "HIGH",     "BACnet — Building Automation and Control Network"),
    20000: ("DNP3",    "CRITICAL", "DNP3 UDP — Distributed Network Protocol"),
    9600:  ("FINS",    "HIGH",     "FINS — OMRON Factory Interface Network Service"),
    1911:  ("Fox",     "HIGH",     "Tridium Niagara Fox UDP"),
    34980: ("Profinet","HIGH",     "PROFINET UDP"),
}


class OtScanner:
    """
    Scans for Operational Technology (OT) / Industrial Control System (ICS) protocols.

    Two modes:
      passive — Sniffs live network traffic for OT protocol signatures.
                Requires root/Administrator privileges and scapy.
      active  — Probes target IP for open OT ports with TCP connect scan.
                Does not require root. Used as fallback when passive fails.
    """

    def __init__(self) -> None:
        log.debug("OtScanner initialised.")
        self._detected: dict[str, list[dict]] = {}

    def packet_handler(self, pkt) -> None:
        """
        Scapy packet callback for passive mode.
        Safely accesses IP layer fields using haslayer() guard.
        """
        # --- TCP ---
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport  = pkt[TCP].sport
            dport  = pkt[TCP].dport

            for port, (proto, severity, desc) in _OT_TCP_PORTS.items():
                if dport == port or sport == port:
                    direction = "→" if dport == port else "←"
                    key = f"{src_ip}_{proto}"
                    if key not in self._detected:
                        self._detected[key] = []
                        lvl = log.critical if severity == "CRITICAL" else log.warning
                        lvl(
                            f"[OT PASSIVE] {proto} traffic detected: "
                            f"{src_ip}:{sport} {direction} {dst_ip}:{dport} | {desc}"
                        )
                    self._detected[key].append({
                        "protocol":  proto,
                        "severity":  severity,
                        "src_ip":    src_ip,
                        "dst_ip":    dst_ip,
                        "src_port":  sport,
                        "dst_port":  dport,
                        "direction": "inbound" if dport == port else "outbound",
                        "layer":     "tcp",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "description": desc,
                    })

        # --- UDP ---
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport  = pkt[UDP].sport
            dport  = pkt[UDP].dport

            for port, (proto, severity, desc) in _OT_UDP_PORTS.items():
                if dport == port or sport == port:
                    key = f"{src_ip}_{proto}_udp"
                    if key not in self._detected:
                        self._detected[key] = []
                        lvl = log.critical if severity == "CRITICAL" else log.warning
                        lvl(
                            f"[OT PASSIVE] {proto}/UDP traffic: "
                            f"{src_ip}:{sport} → {dst_ip}:{dport} | {desc}"
                        )
                    self._detected[key].append({
                        "protocol":    proto,
                        "severity":    severity,
                        "src_ip":      src_ip,
                        "dst_ip":      dst_ip,
                        "src_port":    sport,
                        "dst_port":    dport,
                        "layer":       "udp",
                        "timestamp":   datetime.now(timezone.utc).isoformat(),
                        "description": desc,
                    })

    async def run(
        self,
        target_ip: Optional[str] = None,
        duration: int = 30,
        mode: str = "passive",
        interface: Optional[str] = None,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run the OT/ICS scan.

        Args:
            target_ip: Target IP for active mode, or None for passive (network-wide).
            duration:  Passive sniff duration in seconds. Default 30.
            mode:      "passive" (traffic sniffing) or "active" (port probing).
                       Falls back to active if scapy unavailable or not root.
            interface: Network interface for passive sniffing (e.g. "eth0").
            report:    Optional ReportManager.

        Returns:
            Dict of protocol name → list of finding dicts.
        """
        self._detected = {}
        effective_mode = mode

        # --- Determine effective mode ---
        if mode == "passive":
            if not _SCAPY_AVAILABLE:
                log.warning(
                    "scapy not installed — falling back to active OT port scan."
                )
                effective_mode = "active"
            elif os.geteuid() != 0 if hasattr(os, "geteuid") else True:
                log.warning(
                    "Passive OT sniffing requires root privileges — "
                    "falling back to active OT port scan."
                )
                effective_mode = "active"

        # --- Run selected mode ---
        if effective_mode == "passive":
            await self._run_passive(duration, interface)
        else:
            if not target_ip:
                log.error(
                    "Active OT scan requires a target IP address. "
                    "Provide --target or use passive mode."
                )
                return {}
            await self._run_active(target_ip)

        # --- Flatten results ---
        findings: dict[str, list[dict]] = {}
        for key, items in self._detected.items():
            proto = items[0]["protocol"] if items else key
            findings.setdefault(proto, []).extend(items)

        # --- Summary ---
        total = sum(len(v) for v in findings.values())
        if findings:
            log.warning(
                f"OT scan complete: {len(findings)} protocol(s) detected, "
                f"{total} event(s) total."
            )
            for proto, events in findings.items():
                sample = events[0]
                log.warning(
                    f"  {proto} ({sample['severity']}): "
                    f"{sample['src_ip']} → {sample['dst_ip']}:{sample['dst_port']}"
                )
        else:
            log.info(
                "OT scan complete: no OT/ICS protocol traffic or open ports detected."
            )

        # --- ReportManager ---
        if report:
            if findings:
                flat = [e for events in findings.values() for e in events]
                report.add_section("OT/ICS Protocol Detection", flat)
            else:
                report.add_section(
                    "OT/ICS Protocol Detection",
                    ["No OT/ICS protocol traffic or open ports detected."],
                )

        return findings

    # ------------------------------------------------------------------
    # Passive mode
    # ------------------------------------------------------------------

    async def _run_passive(self, duration: int, interface: Optional[str]) -> None:
        """Passive traffic sniffing via scapy."""
        log.info(
            f"Passive OT scan: sniffing for {duration}s "
            f"(interface: {interface or 'default'})..."
        )
        log.info(
            f"Monitoring {len(_OT_TCP_PORTS)} TCP + {len(_OT_UDP_PORTS)} UDP "
            "OT protocol signatures..."
        )
        log.warning("Passive sniffing requires root privileges.")

        sniff_kwargs = {
            "prn":     self.packet_handler,
            "filter":  "tcp or udp",
            "store":   0,
            "timeout": duration,
        }
        if interface:
            sniff_kwargs["iface"] = interface

        try:
            await asyncio.to_thread(sniff, **sniff_kwargs)
        except PermissionError:
            log.error(
                "Permission denied — passive OT sniffing requires root. "
                "Re-run with sudo."
            )
        except Exception as exc:
            log.error(f"Passive OT scan error: {exc}")

    # ------------------------------------------------------------------
    # Active mode
    # ------------------------------------------------------------------

    async def _run_active(self, target_ip: str) -> None:
        """Active TCP/UDP port probe for OT ports."""
        log.info(f"Active OT scan: probing {target_ip} for OT/ICS ports...")

        all_ports = list(_OT_TCP_PORTS.keys()) + list(_OT_UDP_PORTS.keys())
        tasks     = [self._probe_tcp(target_ip, port) for port in _OT_TCP_PORTS]
        results   = await asyncio.gather(*tasks, return_exceptions=True)

        for port, result in zip(_OT_TCP_PORTS.keys(), results):
            if result is True:
                proto, severity, desc = _OT_TCP_PORTS[port]
                key = f"{target_ip}_{proto}"
                self._detected[key] = [{
                    "protocol":    proto,
                    "severity":    severity,
                    "src_ip":      "scanner",
                    "dst_ip":      target_ip,
                    "src_port":    0,
                    "dst_port":    port,
                    "layer":       "tcp",
                    "mode":        "active",
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "description": desc,
                }]
                lvl = log.critical if severity == "CRITICAL" else log.warning
                lvl(
                    f"[OT ACTIVE] Open port: {target_ip}:{port}/tcp — "
                    f"{proto} ({desc})"
                )

    async def _probe_tcp(self, host: str, port: int) -> bool:
        """TCP connect probe — returns True if port is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False
