# fenrir/mobile_scanner.py
#
# Live mobile device scanner — interrogates mobile devices over the network.
#
# Detection methods:
#   Android (ADB over TCP):
#     - Connects to port 5555 (ADB default)
#     - Runs: adb connect, then adb shell commands to extract device info
#     - Extracts: device model, Android version, build fingerprint, installed
#       packages count, developer options state, USB debugging state,
#       running services, open network connections, SELinux mode
#
#   iOS (lockdownd / Bonjour):
#     - Detects port 62078 (lockdownd) and 49152 (usbmuxd)
#     - Banner grab to confirm Apple device
#     - Checks for common iOS management ports (2195 APN, 5223 APNs)
#
#   MDM / Enterprise Mobile Management:
#     - Checks ports 443, 8443, 9090 for MDM enrollment endpoints
#     - Detects SCEP, APNS, and MDM profile endpoints via HTTP probe
#
#   General mobile fingerprinting:
#     - User-Agent pattern matching on HTTP response
#     - Bonjour/mDNS service detection (_apple-mobdev2, _airdrop)
#     - Checks for common mobile hotspot/tethering signatures

import asyncio
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# ── Port sets ──────────────────────────────────────────────────────────────────
_ADB_PORTS        = [5555, 5554, 5556, 5558]
_IOS_PORTS        = [62078, 49152]
_MDM_PORTS        = [443, 8443, 9090, 2195, 5223]
_HOTSPOT_PORTS    = [53, 67, 68, 8080]
_ALL_MOBILE_PORTS = _ADB_PORTS + _IOS_PORTS + _MDM_PORTS

# ── ADB shell commands to run once connected ───────────────────────────────────
_ADB_COMMANDS = {
    "model":          "getprop ro.product.model",
    "manufacturer":   "getprop ro.product.manufacturer",
    "android_ver":    "getprop ro.build.version.release",
    "sdk_ver":        "getprop ro.build.version.sdk",
    "build":          "getprop ro.build.fingerprint",
    "serial":         "getprop ro.serialno",
    "selinux":        "getenforce",
    "usb_debug":      "getprop persist.sys.usb.config",
    "dev_options":    "getprop persist.settings.developer_options_enabled",
    "adb_enabled":    "getprop persist.service.adb.enable",
    "wifi_interface": "getprop wifi.interface",
    "hostname":       "getprop net.hostname",
    "packages_count": "pm list packages | wc -l",
    "running_svcs":   "dumpsys activity services | grep -c ServiceRecord",
    "inet_conns":     "cat /proc/net/tcp | wc -l",
    "battery":        "dumpsys battery | grep level",
    "screen_state":   "dumpsys power | grep 'Display Power'",
}

# ── Dangerous ADB states ───────────────────────────────────────────────────────
_DANGEROUS_ADB_STATES = {
    "usb_debug":   ("adb", "USB debugging enabled — ADB accessible over network"),
    "selinux":     ("Permissive", "SELinux in Permissive mode — reduced kernel protection"),
    "dev_options": ("1", "Developer options enabled"),
    "adb_enabled": ("1", "ADB daemon enabled"),
}


@dataclass
class MobileDevice:
    ip:           str
    platform:     str  = "unknown"   # android|ios|mdm|unknown
    model:        str  = ""
    manufacturer: str  = ""
    os_version:   str  = ""
    sdk_version:  str  = ""
    hostname:     str  = ""
    adb_open:     bool = False
    mdm_present:  bool = False
    props:        dict = field(default_factory=dict)
    findings:     list = field(default_factory=list)
    open_ports:   list = field(default_factory=list)


class MobileScanner:
    """
    Scans live mobile devices on the network.

    Detects Android (ADB), iOS (lockdownd), and MDM-managed devices.
    When ADB is accessible, extracts full device properties and flags
    dangerous security misconfigurations.
    """

    def __init__(self) -> None:
        log.debug("MobileScanner initialised.")
        self._adb_available = self._check_adb()

    @staticmethod
    def _check_adb() -> bool:
        try:
            r = subprocess.run(["adb", "version"], capture_output=True, timeout=5)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ── Public entry point ─────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        open_ports: Optional[list] = None,
        output_dir: Optional[str] = None,
    ) -> list[dict]:
        """
        Scan a target for mobile device characteristics.

        Args:
            target:     IP address or hostname.
            open_ports: Already-scanned open ports (skips port check if provided).
            output_dir: If provided, writes a mobile_findings.json report.

        Returns:
            list of finding dicts.
        """
        log.info(f"[mobile] Scanning {target} for mobile device indicators...")
        device = MobileDevice(ip=target)

        # Step 1 — check which mobile ports are open
        ports_to_check = open_ports if open_ports is not None else await self._probe_ports(target)
        device.open_ports = [p for p in ports_to_check
                              if p in set(_ALL_MOBILE_PORTS + _HOTSPOT_PORTS)]

        if not device.open_ports:
            log.info(f"[mobile] No mobile-indicative ports open on {target}")
            return []

        log.info(f"[mobile] Mobile-relevant ports on {target}: {device.open_ports}")

        # Step 2 — platform detection
        await self._detect_platform(target, device)

        # Step 3 — deep interrogation based on platform
        if device.platform == "android" and self._adb_available:
            await self._interrogate_adb(target, device)
        elif device.platform == "ios":
            await self._interrogate_ios(target, device)

        # Step 4 — MDM check (runs for all platforms)
        if any(p in device.open_ports for p in _MDM_PORTS):
            await self._check_mdm(target, device)

        # Step 5 — HTTP mobile fingerprint
        await self._http_fingerprint(target, device)

        # Step 6 — build findings list
        findings = self._build_findings(device)

        if output_dir:
            self._write_report(findings, device, output_dir)

        log.info(f"[mobile] Scan complete for {target}: platform={device.platform} "
                 f"findings={len(findings)}")
        return findings

    # ── Port probe ─────────────────────────────────────────────────────────────

    async def _probe_ports(self, target: str) -> list[int]:
        """Quick async TCP connect check against all mobile port candidates."""
        open_ports = []
        sem = asyncio.Semaphore(20)

        async def check(port):
            async with sem:
                try:
                    conn = asyncio.open_connection(target, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.5)
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(port)
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in set(_ALL_MOBILE_PORTS + _HOTSPOT_PORTS)])
        return sorted(open_ports)

    # ── Platform detection ─────────────────────────────────────────────────────

    async def _detect_platform(self, target: str, device: MobileDevice) -> None:
        """Determine if the device is Android, iOS, or MDM-managed."""
        # ADB port open → Android
        if any(p in device.open_ports for p in _ADB_PORTS):
            device.platform = "android"
            device.adb_open = True
            log.info(f"[mobile] {target}: ADB port open → Android device")
            return

        # iOS lockdownd port
        if any(p in device.open_ports for p in _IOS_PORTS):
            device.platform = "ios"
            log.info(f"[mobile] {target}: lockdownd port open → iOS device")
            return

        # MDM-only ports
        if any(p in device.open_ports for p in [2195, 5223]):
            device.platform = "mdm"
            device.mdm_present = True
            log.info(f"[mobile] {target}: APNS ports → MDM-managed device")

    # ── Android / ADB interrogation ────────────────────────────────────────────

    async def _interrogate_adb(self, target: str, device: MobileDevice) -> None:
        """Connect via ADB over TCP and extract device properties."""
        adb_port = next((p for p in _ADB_PORTS if p in device.open_ports), 5555)
        log.info(f"[mobile] Connecting via ADB to {target}:{adb_port}...")

        # Connect
        connected = await self._adb_connect(target, adb_port)
        if not connected:
            device.findings.append({
                "type": "adb_refused",
                "severity": "info",
                "title": "ADB port open but connection refused",
                "detail": f"Port {adb_port} is open but ADB handshake failed. "
                           "Device may require USB authorisation.",
            })
            return

        log.info(f"[mobile] ADB connected to {target}:{adb_port}")

        # Run all property commands
        for key, cmd in _ADB_COMMANDS.items():
            value = await self._adb_shell(target, adb_port, cmd)
            if value:
                device.props[key] = value.strip()

        # Populate device fields
        device.model        = device.props.get("model", "")
        device.manufacturer = device.props.get("manufacturer", "")
        device.os_version   = device.props.get("android_ver", "")
        device.sdk_version  = device.props.get("sdk_ver", "")
        device.hostname     = device.props.get("hostname", "")

        log.info(f"[mobile] {target}: {device.manufacturer} {device.model} "
                 f"Android {device.os_version} (SDK {device.sdk_version})")

        # Check dangerous states
        for prop_key, (danger_val, description) in _DANGEROUS_ADB_STATES.items():
            val = device.props.get(prop_key, "")
            if danger_val.lower() in val.lower():
                device.findings.append({
                    "type":     "dangerous_config",
                    "severity": "high",
                    "title":    description,
                    "detail":   f"Property {prop_key} = {val!r}",
                    "prop":     prop_key,
                    "value":    val,
                })

        # Android version risk assessment
        sdk = int(device.props.get("sdk_ver", "0") or "0")
        if sdk and sdk < 28:   # Android < 9.0
            device.findings.append({
                "type":     "outdated_android",
                "severity": "critical" if sdk < 23 else "high",
                "title":    f"Outdated Android SDK {sdk} (Android {device.os_version})",
                "detail":   (f"SDK {sdk} is end-of-life and no longer receives security patches. "
                              "Upgrade to Android 12+ (SDK 31) recommended."),
            })

        # ADB over network is itself a critical finding
        device.findings.append({
            "type":     "adb_network_access",
            "severity": "critical",
            "title":    "ADB accessible over network without authentication",
            "detail":   (f"ADB TCP port {adb_port} is open and accepted connection from scanner. "
                          "Any host on the network can execute arbitrary shell commands as root "
                          "on this device. Disable 'Wireless debugging' / ADB over network."),
            "remediation": "Settings → Developer options → Disable Wireless debugging",
        })

        # Disconnect cleanly
        await self._adb_disconnect(target, adb_port)

    async def _adb_connect(self, target: str, port: int) -> bool:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    subprocess.run,
                    ["adb", "connect", f"{target}:{port}"],
                    capture_output=True, text=True, timeout=8
                ),
                timeout=10
            )
            output = result.stdout + result.stderr
            return "connected" in output.lower() or "already connected" in output.lower()
        except Exception as exc:
            log.debug(f"[mobile] ADB connect failed: {exc}")
            return False

    async def _adb_shell(self, target: str, port: int, cmd: str) -> str:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    subprocess.run,
                    ["adb", "-s", f"{target}:{port}", "shell", cmd],
                    capture_output=True, text=True, timeout=6
                ),
                timeout=8
            )
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            return ""

    async def _adb_disconnect(self, target: str, port: int) -> None:
        try:
            await asyncio.to_thread(
                subprocess.run,
                ["adb", "disconnect", f"{target}:{port}"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    # ── iOS interrogation ──────────────────────────────────────────────────────

    async def _interrogate_ios(self, target: str, device: MobileDevice) -> None:
        """Banner-grab iOS lockdownd and check for management profiles."""
        log.info(f"[mobile] Probing iOS lockdownd on {target}:62078...")
        try:
            conn = asyncio.open_connection(target, 62078)
            reader, writer = await asyncio.wait_for(conn, timeout=3)
            # lockdownd sends an XML plist on connect
            banner = await asyncio.wait_for(reader.read(512), timeout=2)
            writer.close()
            await writer.wait_closed()
            banner_str = banner.decode("utf-8", errors="ignore")

            device.findings.append({
                "type":     "ios_lockdownd",
                "severity": "info",
                "title":    "iOS lockdownd service detected",
                "detail":   f"Device responded on port 62078. "
                             f"Banner snippet: {banner_str[:120]!r}",
            })

            if "DeviceClass" in banner_str or "ProductType" in banner_str:
                device.findings.append({
                    "type":     "ios_plist_exposed",
                    "severity": "medium",
                    "title":    "iOS device plist accessible without pairing",
                    "detail":   "The lockdownd service returned device information "
                                "before pairing was established.",
                })
        except Exception as exc:
            log.debug(f"[mobile] iOS probe: {exc}")

    # ── MDM detection ──────────────────────────────────────────────────────────

    async def _check_mdm(self, target: str, device: MobileDevice) -> None:
        """Check for MDM enrollment endpoints via HTTP."""
        import urllib.request
        mdm_paths = [
            "/devicemanagement/api/101/mdm/checkin",
            "/mdm/enroll",
            "/enrollment",
            "/.well-known/mobileconfig",
            "/mobileconfig",
        ]
        for port in [443, 8443]:
            if port not in device.open_ports:
                continue
            for path in mdm_paths:
                url = f"https://{target}:{port}{path}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "MDMClient/1.0"})
                    ctx = __import__("ssl").create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = __import__("ssl").CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                        if resp.status in (200, 400, 401):
                            device.mdm_present = True
                            device.findings.append({
                                "type":     "mdm_endpoint",
                                "severity": "medium",
                                "title":    f"MDM enrollment endpoint found: {path}",
                                "detail":   f"HTTP {resp.status} from {url}",
                                "url":      url,
                            })
                            break
                except Exception:
                    pass

    # ── HTTP mobile fingerprint ────────────────────────────────────────────────

    async def _http_fingerprint(self, target: str, device: MobileDevice) -> None:
        """Check HTTP responses for mobile-specific signatures."""
        for port in [80, 8080, 8443, 443]:
            if port not in device.open_ports:
                continue
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{target}:{port}/"
            try:
                import urllib.request, ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                    server = resp.headers.get("Server", "")
                    body   = resp.read(512).decode("utf-8", errors="ignore")

                    # Android hotspot / tethering detection
                    if any(s in server.lower() for s in ("android", "dalvik")):
                        device.platform = "android"
                        device.findings.append({
                            "type":     "android_http",
                            "severity": "info",
                            "title":    "Android device HTTP server detected",
                            "detail":   f"Server: {server}",
                        })

                    # iOS Bonjour/AirDrop
                    if "apple" in server.lower() or "_apple" in body.lower():
                        device.platform = "ios"
                        device.findings.append({
                            "type":     "ios_http",
                            "severity": "info",
                            "title":    "Apple/iOS HTTP service detected",
                            "detail":   f"Server: {server}",
                        })
            except Exception:
                pass

    # ── Build findings ─────────────────────────────────────────────────────────

    def _build_findings(self, device: MobileDevice) -> list[dict]:
        """Attach device metadata to all findings and return the list."""
        meta = {
            "ip":           device.ip,
            "platform":     device.platform,
            "model":        device.model,
            "manufacturer": device.manufacturer,
            "os_version":   device.os_version,
            "sdk_version":  device.sdk_version,
            "open_ports":   device.open_ports,
            "adb_exposed":  device.adb_open,
            "mdm_managed":  device.mdm_present,
        }

        # Add a summary finding at the top
        findings = [{
            "type":     "mobile_device_summary",
            "severity": "info",
            "title":    f"{device.platform.upper()} device: {device.manufacturer} {device.model}",
            "detail":   (f"OS: {device.os_version}  SDK: {device.sdk_version}  "
                          f"Open ports: {device.open_ports}  "
                          f"ADB exposed: {device.adb_open}  MDM: {device.mdm_present}"),
            **meta,
        }]

        for f in device.findings:
            findings.append({**meta, **f})

        return findings

    def _write_report(self, findings: list, device: MobileDevice, output_dir: str) -> None:
        try:
            import json
            from pathlib import Path
            out = Path(output_dir) / f"mobile_{device.ip.replace('.','_')}.json"
            out.write_text(json.dumps(findings, indent=2), encoding="utf-8")
            log.info(f"[mobile] Report written: {out}")
        except Exception as exc:
            log.debug(f"[mobile] Report write failed: {exc}")
