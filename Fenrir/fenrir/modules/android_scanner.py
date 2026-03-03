# fenrir/modules/android_scanner.py
#
# AndroidScanner — Live Android device assessment over ADB network protocol.
#
# Overview:
#   When a target exposes port 5555 (Android Debug Bridge), this module
#   connects via ADB-over-TCP and performs a comprehensive security assessment
#   of the live device — no APK file needed.
#
# Assessment categories:
#   1.  ADB authentication state  — is the device in an authorised/unauthorised
#                                   state? Can we connect at all?
#   2.  Device identity           — Android version, build, manufacturer, model,
#                                   SDK API level, kernel, hardware
#   3.  Root access               — su binary presence, root uid check,
#                                   SELinux enforcement state, Magisk detection
#   4.  Attack surface            — USB debugging enabled, developer options,
#                                   OEM unlocking, verified boot state
#   5.  Installed packages        — third-party apps, suspicious package names,
#                                   packages with dangerous installer source
#   6.  Network exposure          — open listening sockets (ss/netstat),
#                                   ADB over TCP enabled persistently
#   7.  Sensitive data exposure   — world-readable files under /sdcard,
#                                   unprotected private dirs, logcat leaks
#   8.  Security policy           — SELinux mode, full-disk / file-based
#                                   encryption status, screen lock type
#   9.  CVE/exploit search        — automatically searches the offline DB for
#                                   the exact Android build version found
#  10.  ADB auth-bypass check     — attempts connect without RSA key exchange to
#                                   detect fully open (unauthorised) ADB
#
# Dependencies:
#   - adb (Android Debug Bridge) binary must be on PATH.
#     Install on Kali: sudo apt install adb
#   - No Python library dependency — uses subprocess + asyncio.
#
# Usage (auto-triggered by the scan orchestrator when port 5555 is open):
#   scanner = AndroidScanner()
#   results = await scanner.run("192.168.56.102", report=report)

import asyncio
import re
import shutil
import subprocess
from typing import Optional

from ..database import get_db_manager
from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ADB connection timeout (seconds)
ADB_CONNECT_TIMEOUT = 8
ADB_CMD_TIMEOUT     = 12

# Packages that are suspicious if present on a non-development device
_SUSPICIOUS_PACKAGES = {
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.topjohnwu.magisk",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "com.android.vending.billing.InAppBillingService.LOCK",
    "com.chelpus.lackwifi",
    "com.ramdroid.appquarantine",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloak2",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.formyhm.hiderootPremium",
    "com.joeykrim.rootcheck",
}

# Properties that reveal security posture
_SECURITY_PROPS = [
    "ro.secure",
    "ro.debuggable",
    "service.adb.root",
    "ro.build.type",
    "ro.build.tags",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.hardware",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "persist.sys.usb.config",
    "ro.adb.secure",
    "persist.adb.notify",
    "ro.crypto.state",
    "ro.crypto.type",
    "ro.build.selinux",
]


class AndroidScanner:
    """
    Live Android device security assessment over ADB-TCP (port 5555).

    Connects to an exposed Android Debug Bridge port, gathers device
    properties, checks for root, misconfigurations, and suspicious packages,
    then cross-references the exact Android build against the offline CVE/
    exploit database.
    """

    def __init__(self) -> None:
        self._db = get_db_manager()
        self._adb = shutil.which("adb")
        if not self._adb:
            log.warning(
                "AndroidScanner: 'adb' binary not found on PATH. "
                "Install with: sudo apt install adb  (Kali/Debian)"
            )

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def run(
        self,
        target_ip: str,
        port: int = 5555,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run a full Android device security assessment over ADB-TCP.

        Args:
            target_ip:  IP address of the Android device.
            port:       ADB port (default 5555).
            report:     Optional ReportManager for structured findings.

        Returns:
            Dict with keys: connected, device_info, security_props, root,
            attack_surface, packages, network, data_exposure, policy,
            cve_matches, exploit_matches, findings.
        """
        log.info(f"{'─' * 50}")
        log.info(f"  Android Device Scanner — {target_ip}:{port}")
        log.info(f"{'─' * 50}")

        results: dict = {
            "connected":      False,
            "authorised":     None,
            "device_info":    {},
            "security_props": {},
            "root":           {},
            "attack_surface": {},
            "packages":       {"third_party": [], "suspicious": []},
            "network":        {},
            "data_exposure":  {},
            "policy":         {},
            "cve_matches":    [],
            "exploit_matches":[],
            "findings":       [],   # structured high-level findings
        }

        if not self._adb:
            self._add_finding(results, "CRITICAL",
                "adb_not_found",
                "ADB binary not found on PATH — install with: sudo apt install adb")
            self._write_report(report, target_ip, port, results)
            return results

        # Kill any existing server to clear stale connections, then restart
        await self._adb_server_restart()

        # Connect to device
        connected, authorised = await self._connect(target_ip, port)
        results["connected"]  = connected
        results["authorised"] = authorised

        if not connected:
            self._add_finding(results, "INFO",
                "connect_failed",
                f"Could not connect to ADB on {target_ip}:{port}. "
                f"Device may not expose ADB over TCP or a firewall is blocking port {port}.")
            log.warning(f"ADB connection to {target_ip}:{port} failed.")
            self._write_report(report, target_ip, port, results)
            return results

        if not authorised:
            self._add_finding(results, "CRITICAL",
                "adb_unauthorised",
                f"ADB port {port} is OPEN and accepts connections without RSA key "
                f"authorisation — any attacker can control this device over the network. "
                f"Disable ADB over TCP immediately (adb usb).")
            log.warning(
                f"ADB UNAUTHORISED on {target_ip}:{port} — device is fully open to "
                f"unauthenticated remote control."
            )
            # We may still get some info before auth prompt terminates
        else:
            log.info(f"ADB connected and authorised to {target_ip}:{port}")

        # Run all assessment tasks
        await asyncio.gather(
            self._gather_device_info(target_ip, results),
            self._check_root(target_ip, results),
            self._check_attack_surface(target_ip, results),
            self._check_packages(target_ip, results),
            self._check_network_exposure(target_ip, results),
            self._check_data_exposure(target_ip, results),
            self._check_security_policy(target_ip, results),
            return_exceptions=True,
        )

        # CVE + exploit search based on Android version/build found
        await self._cve_and_exploit_search(results)

        # Disconnect cleanly
        await self._adb_cmd(f"disconnect {target_ip}:{port}")

        # Summarise
        total_findings = len(results["findings"])
        crits = sum(1 for f in results["findings"] if f["severity"] == "CRITICAL")
        highs = sum(1 for f in results["findings"] if f["severity"] == "HIGH")
        log.info(
            f"Android assessment complete — "
            f"{total_findings} finding(s): {crits} CRITICAL, {highs} HIGH"
        )

        self._write_report(report, target_ip, port, results)
        return results

    # =========================================================================
    # ADB connectivity
    # =========================================================================

    async def _adb_server_restart(self) -> None:
        """Kill and restart the local ADB server to clear stale state."""
        try:
            await asyncio.create_subprocess_exec(
                self._adb, "kill-server",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(0.5)
            await asyncio.create_subprocess_exec(
                self._adb, "start-server",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(0.5)
        except Exception as exc:
            log.debug(f"ADB server restart error: {exc}")

    async def _connect(self, host: str, port: int) -> tuple[bool, bool]:
        """
        Attempt ADB-TCP connection.

        Returns:
            (connected: bool, authorised: bool)
            connected=True means TCP socket accepted.
            authorised=True means we got a shell prompt (not just 'unauthorized').
        """
        try:
            out = await self._adb_cmd(f"connect {host}:{port}",
                                       timeout=ADB_CONNECT_TIMEOUT)
            if not out:
                return False, False

            out_lower = out.lower()
            if "connected" in out_lower or "already connected" in out_lower:
                # Check authorisation state
                auth_out = await self._adb_cmd(
                    f"-s {host}:{port} get-state", timeout=ADB_CONNECT_TIMEOUT
                )
                if auth_out and "unauthorized" in auth_out.lower():
                    return True, False
                elif auth_out and "device" in auth_out.lower():
                    return True, True
                # Try a simple shell command to confirm
                shell_out = await self._adb_cmd(
                    f"-s {host}:{port} shell echo fenrir_probe",
                    timeout=ADB_CONNECT_TIMEOUT
                )
                if shell_out and "fenrir_probe" in shell_out:
                    return True, True
                elif shell_out and "unauthorized" in shell_out.lower():
                    return True, False
                return True, True   # Connected but unclear — optimistic
            elif "refused" in out_lower or "cannot connect" in out_lower:
                return False, False
            elif "offline" in out_lower:
                return True, False
            return False, False

        except Exception as exc:
            log.debug(f"ADB connect error: {exc}")
            return False, False

    async def _shell(self, target: str, command: str,
                     timeout: int = ADB_CMD_TIMEOUT) -> str:
        """Run a shell command on the remote device."""
        return await self._adb_cmd(f"-s {target} shell {command}", timeout=timeout)

    async def _adb_cmd(self, args: str, timeout: int = ADB_CMD_TIMEOUT) -> str:
        """Run an arbitrary ADB command and return stdout as string."""
        try:
            cmd = [self._adb] + args.split()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (stdout or b"").decode(errors="replace").strip()
        except asyncio.TimeoutError:
            log.debug(f"ADB command timed out: adb {args}")
            return ""
        except Exception as exc:
            log.debug(f"ADB command error ({args}): {exc}")
            return ""

    # =========================================================================
    # Assessment modules
    # =========================================================================

    async def _gather_device_info(self, target: str, results: dict) -> None:
        """Collect device identity and build information via getprop."""
        log.info("  Gathering device information...")

        props = {}
        for prop in _SECURITY_PROPS:
            val = await self._shell(target, f"getprop {prop}")
            if val:
                props[prop] = val

        results["security_props"] = props

        # Build structured device_info from props
        info = {
            "manufacturer": props.get("ro.product.manufacturer", "Unknown"),
            "model":         props.get("ro.product.model", "Unknown"),
            "brand":         props.get("ro.product.brand", "Unknown"),
            "android_version": props.get("ro.build.version.release", "Unknown"),
            "sdk_level":     props.get("ro.build.version.sdk", "Unknown"),
            "build_id":      props.get("ro.build.id", "Unknown"),
            "build_type":    props.get("ro.build.type", "Unknown"),
            "build_tags":    props.get("ro.build.tags", "Unknown"),
            "fingerprint":   props.get("ro.build.fingerprint", "Unknown"),
            "hardware":      props.get("ro.hardware", "Unknown"),
            "kernel":        await self._shell(target, "uname -r"),
            "hostname":      await self._shell(target, "getprop net.hostname"),
            "uptime":        await self._shell(target, "uptime"),
        }
        results["device_info"] = info

        log.info(
            f"  Device: {info['manufacturer']} {info['model']} | "
            f"Android {info['android_version']} (SDK {info['sdk_level']}) | "
            f"Build: {info['build_id']}"
        )

        # Flag suspicious build types
        build_type = props.get("ro.build.type", "").lower()
        build_tags  = props.get("ro.build.tags", "").lower()
        if build_type in ("eng", "userdebug"):
            self._add_finding(results, "HIGH",
                "debug_build",
                f"Device is running a '{build_type}' build — "
                f"debug/engineering builds have elevated privileges and reduced "
                f"security controls. Production devices should use 'user' builds.")

        if "test-keys" in build_tags:
            self._add_finding(results, "MEDIUM",
                "test_keys",
                f"Build is signed with test-keys (ro.build.tags='{build_tags}'). "
                f"Custom/modified ROM detected — boot integrity not guaranteed.")

        # SDK level security note
        try:
            sdk = int(props.get("ro.build.version.sdk", 0))
            if sdk < 26:  # Android 8.0 Oreo
                self._add_finding(results, "CRITICAL",
                    "eol_android",
                    f"Android SDK {sdk} (Android {info['android_version']}) is "
                    f"end-of-life and no longer receives security patches. "
                    f"Numerous unpatched CVEs exist for this version.")
            elif sdk < 31:  # Android 12
                self._add_finding(results, "HIGH",
                    "old_android",
                    f"Android SDK {sdk} (Android {info['android_version']}) is "
                    f"outdated and may not receive timely security updates.")
        except (ValueError, TypeError):
            pass

    async def _check_root(self, target: str, results: dict) -> None:
        """Check for root access, su binary, SELinux, and Magisk."""
        log.info("  Checking root access...")
        root = {}

        # Attempt to run 'su -c id'
        su_id_out = await self._shell(target, "su -c id 2>/dev/null")
        root["su_works"]    = "uid=0" in su_id_out
        root["su_id_output"] = su_id_out[:200] if su_id_out else ""

        # Check uid of current shell
        current_id = await self._shell(target, "id")
        root["shell_is_root"] = "uid=0(root)" in current_id

        # su binary locations
        su_locs = ["/system/bin/su", "/system/xbin/su",
                   "/sbin/su", "/su/bin/su", "/su/xbin/su"]
        found_su = []
        for loc in su_locs:
            out = await self._shell(target, f"ls {loc} 2>/dev/null")
            if loc in out:
                found_su.append(loc)
        root["su_binaries"] = found_su

        # Magisk detection
        magisk_out = await self._shell(target,
            "pm list packages 2>/dev/null | grep magisk")
        magisk_dir = await self._shell(target, "ls /data/adb/magisk 2>/dev/null")
        root["magisk_package"] = bool(magisk_out)
        root["magisk_dir"]     = bool(magisk_dir)
        root["magisk"]         = bool(magisk_out or magisk_dir)

        # SELinux
        selinux_out = await self._shell(target, "getenforce 2>/dev/null")
        root["selinux_mode"] = selinux_out.strip() if selinux_out else "Unknown"

        results["root"] = root

        # Report findings
        if root["shell_is_root"] or root["su_works"]:
            self._add_finding(results, "CRITICAL",
                "root_access",
                f"Shell is running as root (uid=0). "
                f"{'su command works. ' if root['su_works'] else ''}"
                f"The device has full root access — any connected attacker "
                f"has unrestricted control of the entire device.")

        elif root["su_binaries"]:
            self._add_finding(results, "HIGH",
                "su_binary_present",
                f"su binary found at: {', '.join(root['su_binaries'])}. "
                f"Device may be rooted.")

        if root["magisk"]:
            self._add_finding(results, "HIGH",
                "magisk_detected",
                f"Magisk root framework detected "
                f"({'package + ' if root['magisk_package'] else ''}directory). "
                f"Magisk provides persistent root and can hide its presence from apps.")

        selinux_mode = root["selinux_mode"].lower()
        if selinux_mode == "permissive":
            self._add_finding(results, "HIGH",
                "selinux_permissive",
                "SELinux is in PERMISSIVE mode — mandatory access controls are "
                "logging but NOT enforcing. This significantly weakens the Android "
                "security model and allows privilege escalation exploits to succeed.")
        elif selinux_mode == "disabled":
            self._add_finding(results, "CRITICAL",
                "selinux_disabled",
                "SELinux is DISABLED — mandatory access controls are completely off.")
        else:
            log.info(f"  SELinux: {root['selinux_mode']}")

    async def _check_attack_surface(self, target: str, results: dict) -> None:
        """Check developer options, USB debugging, bootloader, and OEM unlock."""
        log.info("  Checking attack surface...")
        props   = results.get("security_props", {})
        surface = {}

        # ADB over TCP persistent state
        usb_config    = props.get("persist.sys.usb.config", "")
        surface["adb_tcp_persistent"] = "adb" in usb_config
        surface["usb_config"]         = usb_config

        # ro.adb.secure = 0 means no RSA auth required (very dangerous)
        adb_secure    = props.get("ro.adb.secure", "1")
        surface["adb_auth_disabled"] = (adb_secure == "0")

        # ro.debuggable
        debuggable    = props.get("ro.debuggable", "0")
        surface["debuggable_build"] = (debuggable == "1")

        # service.adb.root — ADB running as root
        adb_root      = await self._shell(target, "getprop service.adb.root")
        surface["adb_running_as_root"] = (adb_root.strip() == "1")

        # Verified boot state
        vboot         = props.get("ro.boot.verifiedbootstate", "unknown")
        surface["verified_boot_state"] = vboot

        # Bootloader locked state
        flash_locked  = props.get("ro.boot.flash.locked", "unknown")
        surface["bootloader_locked"] = flash_locked

        # Developer options (settings global)
        dev_options   = await self._shell(target,
            "settings get global development_settings_enabled 2>/dev/null")
        surface["developer_options"] = (dev_options.strip() == "1")

        # ADB over TCP enabled via settings
        adb_tcp_port  = await self._shell(target,
            "settings get global adb_wifi_enabled 2>/dev/null")
        surface["adb_wifi_enabled"] = (adb_tcp_port.strip() == "1")

        # Screen lock
        keyguard_disabled = await self._shell(target,
            "settings get secure lockscreen.disabled 2>/dev/null")
        surface["screen_lock_disabled"] = (keyguard_disabled.strip() == "1")

        results["attack_surface"] = surface

        # Report findings
        if surface["adb_auth_disabled"]:
            self._add_finding(results, "CRITICAL",
                "adb_auth_disabled",
                "ro.adb.secure=0 — ADB RSA key authentication is DISABLED. "
                "Anyone can connect over ADB without user consent. This is the "
                "highest-severity ADB misconfiguration.")

        if surface["adb_running_as_root"]:
            self._add_finding(results, "CRITICAL",
                "adb_root_daemon",
                "ADB daemon is running as root (service.adb.root=1). "
                "All ADB commands execute with full root privileges.")

        if surface["screen_lock_disabled"]:
            self._add_finding(results, "HIGH",
                "no_screen_lock",
                "Screen lock is DISABLED. Physical or ADB access requires no "
                "authentication to access the device.")

        if vboot not in ("green", "unknown"):
            self._add_finding(results, "HIGH",
                "verified_boot_failed",
                f"Verified boot state: '{vboot}'. "
                f"Expected 'green' for a verified, unmodified device. "
                f"Custom ROM or modified system partition detected.")

        if flash_locked == "0":
            self._add_finding(results, "HIGH",
                "bootloader_unlocked",
                "Bootloader is UNLOCKED (ro.boot.flash.locked=0). "
                "Attacker with physical access can flash arbitrary firmware.")

        if surface["adb_tcp_persistent"]:
            self._add_finding(results, "HIGH",
                "adb_tcp_persistent",
                f"ADB-over-TCP is configured persistently in USB config "
                f"('{usb_config}'). This setting survives reboots.")

    async def _check_packages(self, target: str, results: dict) -> None:
        """List third-party packages and flag known root/spy tools."""
        log.info("  Enumerating installed packages...")

        # List all third-party packages (not pre-installed)
        pkgs_out = await self._shell(target,
            "pm list packages -3 2>/dev/null", timeout=20)
        third_party = []
        for line in pkgs_out.splitlines():
            pkg = line.replace("package:", "").strip()
            if pkg:
                third_party.append(pkg)

        # Also list ALL packages for suspicious name search
        all_pkgs_out = await self._shell(target,
            "pm list packages 2>/dev/null", timeout=20)
        all_pkgs = set()
        for line in all_pkgs_out.splitlines():
            pkg = line.replace("package:", "").strip()
            if pkg:
                all_pkgs.add(pkg)

        suspicious = [p for p in all_pkgs if p in _SUSPICIOUS_PACKAGES]

        # Check for unknown sources installer
        unknown_sources = await self._shell(target,
            "settings get secure install_non_market_apps 2>/dev/null")

        results["packages"] = {
            "third_party":     third_party,
            "third_party_count": len(third_party),
            "suspicious":      suspicious,
            "unknown_sources": unknown_sources.strip() == "1",
        }

        log.info(f"  Packages: {len(third_party)} third-party, "
                 f"{len(suspicious)} suspicious")

        if suspicious:
            self._add_finding(results, "CRITICAL",
                "suspicious_packages",
                f"Known root/spy tool packages installed: "
                f"{', '.join(suspicious)}. "
                f"These packages indicate the device is rooted or compromised.")

        if results["packages"]["unknown_sources"]:
            self._add_finding(results, "MEDIUM",
                "unknown_sources",
                "Installation from unknown sources is ENABLED "
                "(install_non_market_apps=1). Apps can be side-loaded without "
                "Google Play verification.")

    async def _check_network_exposure(self, target: str, results: dict) -> None:
        """List open listening sockets on the device."""
        log.info("  Checking network exposure...")

        # Try ss first, fall back to netstat
        sockets_out = await self._shell(target,
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")

        listening = []
        for line in sockets_out.splitlines():
            if "LISTEN" in line or ("0.0.0.0" in line and ":" in line):
                listening.append(line.strip())

        # ADB over TCP - check if 5555 is bound on all interfaces
        adb_exposed = any("5555" in l and "0.0.0.0" in l for l in listening)

        results["network"] = {
            "listening_sockets": listening,
            "adb_exposed_globally": adb_exposed,
        }

        if adb_exposed:
            self._add_finding(results, "CRITICAL",
                "adb_globally_exposed",
                "ADB port 5555 is bound to 0.0.0.0 (all interfaces) — "
                "the device is exposed to any host on the network, not just localhost.")

        # Flag any unexpected high-risk ports
        high_risk_ports = {"21", "23", "25", "3306", "5432", "6379"}
        for socket_line in listening:
            for p in high_risk_ports:
                if f":{p}" in socket_line and "127.0.0.1" not in socket_line:
                    self._add_finding(results, "HIGH",
                        f"exposed_port_{p}",
                        f"High-risk service port {p} appears to be listening "
                        f"on a non-loopback interface: {socket_line}")

    async def _check_data_exposure(self, target: str, results: dict) -> None:
        """Check for world-readable sensitive files and logcat data leaks."""
        log.info("  Checking for sensitive data exposure...")
        exposure = {}

        # World-readable files in /sdcard (quick sample)
        sdcard_sensitive = await self._shell(target,
            "find /sdcard -maxdepth 3 -name '*.key' -o -name '*.pem' "
            "-o -name '*.p12' -o -name '*.pfx' -o -name 'passwords*' "
            "-o -name '*secret*' -o -name '*.db' 2>/dev/null | head -20",
            timeout=15)
        exposure["sdcard_sensitive_files"] = [
            l for l in sdcard_sensitive.splitlines() if l.strip()
        ]

        # Check /data/local/tmp — writable by ADB, often abused
        tmp_files = await self._shell(target,
            "ls -la /data/local/tmp 2>/dev/null")
        exposure["data_local_tmp"] = tmp_files

        # Recent logcat for passwords/tokens (redact before logging)
        logcat_sample = await self._shell(target,
            "logcat -d -t 50 2>/dev/null | grep -i "
            "'password\\|token\\|secret\\|key\\|credential\\|api_key' "
            "| head -10 2>/dev/null",
            timeout=10)
        logcat_hits = [l for l in logcat_sample.splitlines() if l.strip()]
        exposure["logcat_sensitive_lines"] = len(logcat_hits)
        exposure["logcat_sample"] = logcat_hits[:5]  # limit stored output

        results["data_exposure"] = exposure

        if exposure["sdcard_sensitive_files"]:
            n = len(exposure["sdcard_sensitive_files"])
            self._add_finding(results, "HIGH",
                "sdcard_sensitive_files",
                f"Found {n} potentially sensitive file(s) in /sdcard: "
                + ", ".join(exposure["sdcard_sensitive_files"][:5])
                + ("..." if n > 5 else ""))

        if logcat_hits:
            self._add_finding(results, "HIGH",
                "logcat_credential_leak",
                f"Logcat contains {len(logcat_hits)} line(s) matching "
                f"credential/secret keywords — sensitive data may be logged in cleartext.")

    async def _check_security_policy(self, target: str, results: dict) -> None:
        """Check encryption, screen lock type, and SELinux policy version."""
        log.info("  Checking security policy...")
        props  = results.get("security_props", {})
        policy = {}

        # Encryption
        crypto_state = props.get("ro.crypto.state", "unknown")
        crypto_type  = props.get("ro.crypto.type", "unknown")
        policy["encryption_state"] = crypto_state
        policy["encryption_type"]  = crypto_type

        # Screen lock type via keyguard
        lock_type = await self._shell(target,
            "settings get secure lockscreen.password_type 2>/dev/null")
        # Android lock type codes: 0=None, 65536=Pattern, 131072=PIN, 262144=Password
        lock_map = {
            "0":       "None",
            "65536":   "Pattern",
            "131072":  "PIN",
            "196608":  "Biometric",
            "262144":  "Password (alphanumeric)",
        }
        policy["screen_lock_type"] = lock_map.get(
            lock_type.strip(), f"Unknown ({lock_type.strip()})"
        )

        # Find all world-writable dirs in /data (quick)
        world_writable = await self._shell(target,
            "find /data -maxdepth 2 -perm -o+w -type d 2>/dev/null | head -10",
            timeout=10)
        policy["world_writable_dirs"] = [
            l for l in world_writable.splitlines() if l.strip()
        ]

        results["policy"] = policy

        if crypto_state.lower() in ("unencrypted", ""):
            self._add_finding(results, "CRITICAL",
                "unencrypted_storage",
                f"Device storage is UNENCRYPTED (ro.crypto.state='{crypto_state}'). "
                f"All data is accessible without authentication if storage is removed.")
        elif crypto_state.lower() == "encrypted":
            log.info(f"  Encryption: {crypto_type} ({crypto_state})")

        if lock_type.strip() in ("0", ""):
            self._add_finding(results, "HIGH",
                "no_screen_lock_type",
                "No screen lock is configured (lockscreen.password_type=0). "
                "Physical access provides immediate full access to the device.")

        if policy["world_writable_dirs"]:
            self._add_finding(results, "MEDIUM",
                "world_writable_dirs",
                f"World-writable directories found under /data: "
                + ", ".join(policy["world_writable_dirs"][:5]))

    # =========================================================================
    # CVE and exploit search
    # =========================================================================

    async def _cve_and_exploit_search(self, results: dict) -> None:
        """
        Search offline DB for CVEs and exploits matching the exact Android
        version and SDK level found on this device.
        """
        info = results.get("device_info", {})
        android_ver = info.get("android_version", "")
        sdk         = info.get("sdk_level", "")
        model       = info.get("model", "")
        manufacturer = info.get("manufacturer", "")

        if not self._db.is_available():
            log.info("Offline DB not available — skipping CVE/exploit search.")
            return

        queries = []
        if android_ver and android_ver != "Unknown":
            queries.append(f"Android {android_ver}")
        if sdk and sdk != "Unknown":
            queries.append(f"Android SDK {sdk}")
        # Also search for Android Debug Bridge specifically since port 5555 is open
        queries.append("Android Debug Bridge")
        queries.append("adb 5555")

        log.info(
            f"  Searching offline CVE/exploit DB for: "
            + ", ".join(f"'{q}'" for q in queries[:3])
        )

        seen_cve_ids:    set[str] = set()
        seen_exploit_ids: set    = set()
        cve_matches:     list    = []
        exploit_matches: list    = []

        for query in queries:
            # CVE search
            try:
                cves = await asyncio.to_thread(
                    self._db.search_cves, query, limit=10
                )
                for row in cves:
                    cve_id = row.get("cve_id", "")
                    if cve_id and cve_id not in seen_cve_ids:
                        seen_cve_ids.add(cve_id)
                        cve_matches.append({
                            "id":          cve_id,
                            "score":       row.get("cvss_v3_score") or row.get("cvss_v2_score", "N/A"),
                            "severity":    row.get("cvss_v3_severity") or row.get("cvss_v2_severity", "N/A"),
                            "description": row.get("description", "")[:300],
                            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "matched_query": query,
                            "source":      "offline_db",
                        })
            except Exception as exc:
                log.debug(f"CVE search '{query}' failed: {exc}")

            # Exploit search
            try:
                exploits = await asyncio.to_thread(
                    self._db.search_exploits, query, None, None, False, 10
                )
                for e in exploits:
                    eid = e.get("exploit_id")
                    if eid and eid not in seen_exploit_ids:
                        seen_exploit_ids.add(eid)
                        exploit_matches.append({
                            "source":         "exploit_db",
                            "id":             eid,
                            "title":          e.get("title", ""),
                            "type":           e.get("type", ""),
                            "platform":       e.get("platform", ""),
                            "date_published": e.get("date_published", ""),
                            "author":         e.get("author", ""),
                            "verified":       bool(e.get("verified")),
                            "cve_ids":        e.get("cve_ids", []),
                            "edb_url":        e.get("edb_url", ""),
                            "local_file_path": e.get("local_file_path"),
                            "matched_query":  query,
                        })
            except Exception as exc:
                log.debug(f"Exploit search '{query}' failed: {exc}")

        results["cve_matches"]     = cve_matches
        results["exploit_matches"] = exploit_matches

        # Log summary
        if cve_matches:
            log.warning(
                f"Found {len(cve_matches)} CVE(s) for Android "
                f"{android_ver} (SDK {sdk}):"
            )
            for cve in sorted(cve_matches,
                               key=lambda c: float(c["score"]) if str(c["score"]).replace(".","").isdigit() else 0,
                               reverse=True)[:10]:
                log.warning(
                    f"  [{cve['severity']:8}] {cve['id']}  Score: {cve['score']}  "
                    f"| {cve['description'][:80]}..."
                )

        if exploit_matches:
            log.warning(
                f"Found {len(exploit_matches)} exploit(s) matching Android version/ADB:"
            )
            for ex in exploit_matches[:10]:
                verified = " [VERIFIED]" if ex.get("verified") else ""
                log.warning(
                    f"  EDB-{ex['id']}  {ex['title'][:70]}{verified}"
                )

        if not cve_matches and not exploit_matches:
            log.info(
                "No CVE/exploit matches found in offline DB for this Android version. "
                "NVD CVE results from the port scan above still apply."
            )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _add_finding(
        self,
        results: dict,
        severity: str,
        check: str,
        detail: str,
    ) -> None:
        """Add a structured finding and log at appropriate level."""
        entry = {"severity": severity, "check": check, "detail": detail}
        results["findings"].append(entry)
        if severity in ("CRITICAL", "HIGH"):
            log.warning(f"  [{severity}] {check}: {detail[:160]}")
        else:
            log.info(f"  [{severity}] {check}: {detail[:160]}")

    def _write_report(
        self,
        report: Optional[ReportManager],
        target_ip: str,
        port: int,
        results: dict,
    ) -> None:
        """Write all findings to the ReportManager."""
        if not report:
            return

        info = results.get("device_info", {})

        # Device identity section
        report.add_section("Android Device Identity", [
            {
                "manufacturer":    info.get("manufacturer", "Unknown"),
                "model":           info.get("model", "Unknown"),
                "android_version": info.get("android_version", "Unknown"),
                "sdk_level":       info.get("sdk_level", "Unknown"),
                "build_id":        info.get("build_id", "Unknown"),
                "build_type":      info.get("build_type", "Unknown"),
                "build_tags":      info.get("build_tags", "Unknown"),
                "fingerprint":     info.get("fingerprint", "Unknown"),
                "kernel":          info.get("kernel", "Unknown"),
                "adb_connected":   results.get("connected"),
                "adb_authorised":  results.get("authorised"),
                "host":            f"{target_ip}:{port}",
            }
        ])

        # Security findings
        if results["findings"]:
            report.add_section("Android Security Findings", results["findings"])

        # Root assessment
        root = results.get("root", {})
        if root:
            report.add_section("Android Root Assessment", [root])

        # Attack surface
        surface = results.get("attack_surface", {})
        if surface:
            report.add_section("Android Attack Surface", [surface])

        # Packages
        pkgs = results.get("packages", {})
        if pkgs.get("suspicious"):
            report.add_section("Android Suspicious Packages", [
                {"package": p, "severity": "CRITICAL",
                 "note": "Known root/spy tool"}
                for p in pkgs["suspicious"]
            ])

        # CVE matches
        cve_matches = results.get("cve_matches", [])
        if cve_matches:
            report.add_section("CVE Findings", cve_matches)

        # Exploit matches
        exploit_matches = results.get("exploit_matches", [])
        if exploit_matches:
            report.add_section("Exploit Matches (Auto)", exploit_matches)

        # Policy
        policy = results.get("policy", {})
        if policy:
            report.add_section("Android Security Policy", [policy])

        # Network
        network = results.get("network", {})
        if network.get("listening_sockets"):
            report.add_section("Android Network Exposure", [
                {"socket": s} for s in network["listening_sockets"]
            ])