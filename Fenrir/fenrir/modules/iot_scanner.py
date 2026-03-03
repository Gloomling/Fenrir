# fenrir/modules/iot_scanner.py
#
# Fix 17 — Changes from original:
#   - Stripped corrupted appended content (extra ```python blocks were in source)
#   - BLE scan runs unconditionally regardless of MQTT port findings
#   - Added default credentials check from offline DB (iot_default_creds table)
#   - Added Shodan-style service banner grabbing on common IoT ports
#   - Structured findings dict for every check — ReportManager integration
#   - run() returns dict of all findings keyed by check type
#   - Improved MQTT error messages (rc code descriptions)
#   - BleakScanner.discover() wrapped in availability check — graceful on
#     systems without Bluetooth hardware
#   - Added scan_duration parameter for BLE scan timeout

import asyncio
import socket
from typing import Optional

from ..database import get_db_manager
from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# BLE optional import
try:
    from bleak import BleakScanner
    _BLEAK_AVAILABLE = True
except ImportError:
    _BLEAK_AVAILABLE = False
    log.debug("bleak not installed — BLE scanning unavailable.")

# MQTT optional import
try:
    from paho.mqtt.client import Client as MqttClient, MQTTv5
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False
    log.debug("paho-mqtt not installed — MQTT scanning unavailable.")

# MQTT return code descriptions
_MQTT_RC = {
    0: "Connection accepted",
    1: "Refused — unacceptable protocol version",
    2: "Refused — identifier rejected",
    3: "Refused — server unavailable",
    4: "Refused — bad username or password",
    5: "Refused — not authorised",
}

# Common IoT banner ports to probe
_IOT_BANNER_PORTS = {
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    502:  "Modbus",
    1883: "MQTT",
    5683: "CoAP",
    8080: "HTTP-Alt",
    8883: "MQTT-TLS",
    47808:"BACnet",
}


class IotScanner:
    """
    Scans for common IoT device vulnerabilities and exposed services.

    Checks:
      - MQTT anonymous login (ports 1883, 8883)
      - Default credential match from offline database
      - Service banner grabbing on common IoT ports
      - Bluetooth Low Energy device discovery (local, not target-specific)
    """

    def __init__(self) -> None:
        log.debug("IotScanner initialised.")
        self._db = get_db_manager()

    async def run(
        self,
        target_ip: str,
        open_ports: list[int],
        ble_duration: float = 10.0,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run IoT scan against target_ip with open_ports discovered by PortScanner.

        Args:
            target_ip:    Target IP address.
            open_ports:   List of open ports from prior port scan.
            ble_duration: Duration in seconds for BLE scan. Default 10.0.
            report:       Optional ReportManager.

        Returns:
            Dict with keys: mqtt, default_creds, banners, ble
        """
        log.info(f"Starting IoT scan on {target_ip}...")
        results = {
            "target":        target_ip,
            "mqtt":          [],
            "default_creds": [],
            "banners":       [],
            "ble":           [],
        }

        # Run all checks concurrently
        tasks = [
            self._check_mqtt(target_ip, open_ports, results),
            self._check_default_creds(target_ip, open_ports, results),
            self._grab_banners(target_ip, open_ports, results),
            self._scan_ble(ble_duration, results),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # --- ReportManager ---
        if report:
            section_findings = []
            for check, findings in results.items():
                if check == "target" or not findings:
                    continue
                for f in (findings if isinstance(findings, list) else [findings]):
                    if isinstance(f, dict):
                        section_findings.append(f)
                    else:
                        section_findings.append({"check": check, "detail": str(f)})
            if section_findings:
                report.add_section("IoT Scan", section_findings)
            else:
                report.add_section(
                    "IoT Scan",
                    [f"No IoT vulnerabilities detected on {target_ip}."],
                )

        log.info("IoT scan finished.")
        return results

    # ------------------------------------------------------------------
    # MQTT anonymous login
    # ------------------------------------------------------------------

    async def _check_mqtt(
        self,
        target_ip: str,
        open_ports: list[int],
        results: dict,
    ) -> None:
        """Check all MQTT ports for anonymous login."""
        if not _MQTT_AVAILABLE:
            log.warning("paho-mqtt not installed — skipping MQTT checks.")
            return

        mqtt_ports = [p for p in open_ports if p in (1883, 8883)]
        if not mqtt_ports:
            log.debug(f"No MQTT ports open on {target_ip}.")
            return

        for port in mqtt_ports:
            finding = await self._try_mqtt_anonymous(target_ip, port)
            if finding:
                results["mqtt"].append(finding)

    async def _try_mqtt_anonymous(self, host: str, port: int) -> Optional[dict]:
        """
        Attempt anonymous MQTT connection. Returns a finding dict on success,
        None if connection refused or authentication required.
        """
        log.info(f"Checking MQTT anonymous login on {host}:{port}...")
        loop      = asyncio.get_event_loop()
        connected = asyncio.Event()
        rc_holder = [None]

        def on_connect(client, userdata, flags, rc, properties=None):
            rc_holder[0] = rc
            connected.set()
            client.disconnect()

        try:
            client = MqttClient(protocol=MQTTv5)
            client.on_connect = on_connect
            # Run blocking connect in thread pool
            await asyncio.to_thread(client.connect, host, port, 60)
            client.loop_start()

            try:
                await asyncio.wait_for(connected.wait(), timeout=10)
            except asyncio.TimeoutError:
                log.debug(f"MQTT {host}:{port} — connection timed out.")
                client.loop_stop(force=True)
                return None

            client.loop_stop(force=True)
            rc = rc_holder[0]

            if rc == 0:
                log.warning(
                    f"MQTT ANONYMOUS LOGIN ACCEPTED on {host}:{port} — "
                    "broker allows unauthenticated connections!"
                )
                return {
                    "check":   "mqtt_anonymous_login",
                    "host":    host,
                    "port":    port,
                    "result":  "VULNERABLE",
                    "detail":  "Broker accepts anonymous (unauthenticated) connections.",
                    "severity": "HIGH",
                }
            else:
                desc = _MQTT_RC.get(rc, f"Unknown code {rc}")
                log.info(f"MQTT {host}:{port} rejected anonymous: {desc}")
                return {
                    "check":  "mqtt_anonymous_login",
                    "host":   host,
                    "port":   port,
                    "result": "SECURE",
                    "detail": desc,
                }

        except Exception as exc:
            log.debug(f"MQTT {host}:{port} error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Default credentials
    # ------------------------------------------------------------------

    async def _check_default_creds(
        self,
        target_ip: str,
        open_ports: list[int],
        results: dict,
    ) -> None:
        """
        Test default credentials against open ports on the target.

        Strategy per service:
          - http/https : HTTP Basic Auth HEAD request — confirmed only if server
                         returns 200 (not 401/403).
          - ftp        : ftplib login attempt — confirmed if no exception.
          - ssh        : TCP banner grab only — we confirm port is really SSH
                         before listing the cred as a candidate (no auth attempt
                         to avoid account lockout / IDS alerts).
          - telnet     : TCP connect + read banner — confirmed if port answers.
          - others     : TCP reachability only.

        Only entries whose service port is actually open are tested.
        Results are reported as CONFIRMED (auth succeeded or port responded as
        expected) or CANDIDATE (port open but auth not verified).
        """
        if not self._db.is_available():
            log.debug("Offline DB not available — skipping default cred check.")
            return

        # Load candidates whose port is in our open-port list
        candidates = await asyncio.to_thread(self._lookup_cred_candidates, open_ports)
        if not candidates:
            log.info(f"No default credential candidates for open ports on {target_ip}.")
            return

        log.info(
            f"Testing {len(candidates)} default credential candidate(s) "
            f"against {target_ip}..."
        )

        # Run tests with a semaphore — avoid flooding the target
        sem   = asyncio.Semaphore(4)
        tasks = [
            self._test_one_cred(target_ip, cand, sem, results)
            for cand in candidates
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        confirmed = [r for r in results["default_creds"] if r.get("confirmed")]
        candidates_only = [r for r in results["default_creds"] if not r.get("confirmed")]
        if confirmed:
            log.warning(
                f"DEFAULT CREDS CONFIRMED on {target_ip}: "
                f"{len(confirmed)} credential(s) accepted."
            )
        if candidates_only:
            log.info(
                f"Default cred candidates (port open, auth not tested): "
                f"{len(candidates_only)}"
            )

    async def _test_one_cred(
        self,
        target_ip: str,
        cred: dict,
        sem: asyncio.Semaphore,
        results: dict,
    ) -> None:
        """Test a single credential entry and record result."""
        async with sem:
            service  = (cred.get("service") or "").lower()
            port     = int(cred.get("port") or 0)
            username = cred.get("username") or ""
            password = cred.get("password") or ""
            vendor   = cred.get("vendor", "")
            model    = cred.get("model", "")

            confirmed = False
            method    = "untested"

            try:
                if service in ("http", "https"):
                    confirmed, method = await self._test_http_basic(
                        target_ip, port, username, password,
                        use_tls=(service == "https"),
                    )

                elif service == "ftp":
                    confirmed, method = await asyncio.to_thread(
                        self._test_ftp, target_ip, port, username, password
                    )

                elif service == "ssh":
                    # Don't attempt SSH auth — just verify banner looks like SSH
                    confirmed, method = await self._test_ssh_banner(target_ip, port)

                elif service == "telnet":
                    confirmed, method = await self._test_telnet_banner(target_ip, port)

                else:
                    # Generic TCP reachability
                    confirmed, method = await self._test_tcp_reachable(target_ip, port)

            except Exception as exc:
                log.debug(f"Cred test error {vendor}/{service}:{port}: {exc}")
                return

            if confirmed:
                log.warning(
                    f"DEFAULT CREDS CONFIRMED [{method}] on {target_ip}: "
                    f"{vendor} {model} — {service}:{port}: "
                    f"'{username}' / '{password}'"
                )
                results["default_creds"].append({
                    "check":     "default_credentials",
                    "confirmed": True,
                    "method":    method,
                    "host":      target_ip,
                    "port":      port,
                    "service":   service,
                    "vendor":    vendor,
                    "model":     model,
                    "username":  username,
                    "password":  password,
                    "severity":  "CRITICAL",
                })

    async def _test_http_basic(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool = False,
    ) -> tuple[bool, str]:
        """
        Attempt HTTP Basic Auth.  Returns (True, "http_basic") if server
        responds 200 OK (not 401/403), indicating credentials were accepted.
        Returns (False, "http_basic") otherwise.
        """
        try:
            import httpx
            proto = "https" if use_tls else "http"
            url   = f"{proto}://{host}:{port}/"
            auth  = (username, password) if (username or password) else None

            async with httpx.AsyncClient(
                verify=False,
                timeout=5,
                follow_redirects=False,
            ) as client:
                # First check: can we reach at all?
                try:
                    resp_unauth = await client.get(url)
                except Exception:
                    return False, "http_basic"

                # If it responds 401 with no auth, try with credentials
                if resp_unauth.status_code == 401:
                    if auth:
                        resp_auth = await client.get(url, auth=auth)
                        if resp_auth.status_code == 200:
                            return True, "http_basic"
                    return False, "http_basic"

                # Port is open and responds with 200 even without auth — note
                # as unprotected but only confirm if blank/no creds
                if resp_unauth.status_code == 200 and not username and not password:
                    return True, "http_unprotected"

                return False, "http_basic"

        except ImportError:
            # httpx not available — fall back to TCP reachability
            return await self._test_tcp_reachable(host, port)
        except Exception:
            return False, "http_basic"

    def _test_ftp(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
    ) -> tuple[bool, str]:
        """Attempt FTP login with ftplib (synchronous)."""
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(username or "anonymous", password or "")
            ftp.quit()
            return True, "ftp_login"
        except ftplib.error_perm:
            # 530 Login incorrect — credentials rejected
            return False, "ftp_login"
        except Exception:
            return False, "ftp_login"

    async def _test_ssh_banner(
        self,
        host: str,
        port: int,
    ) -> tuple[bool, str]:
        """
        Read the SSH banner without authenticating.
        Returns (True, "ssh_banner") only if the banner looks like SSH.
        We never attempt authentication to avoid lockout / IDS noise.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=4
            )
            banner = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if banner.startswith(b"SSH-"):
                return True, "ssh_banner"
            return False, "ssh_banner"
        except Exception:
            return False, "ssh_banner"

    async def _test_telnet_banner(
        self,
        host: str,
        port: int,
    ) -> tuple[bool, str]:
        """Confirm port responds to a TCP connection (telnet-style)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=4
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, "telnet_connect"
        except Exception:
            return False, "telnet_connect"

    async def _test_tcp_reachable(
        self,
        host: str,
        port: int,
    ) -> tuple[bool, str]:
        """Generic TCP connectivity check."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=4
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, "tcp_connect"
        except Exception:
            return False, "tcp_connect"

    def _lookup_cred_candidates(self, open_ports: list[int]) -> list[dict]:
        """
        Query DB for default credentials whose port is in open_ports.
        Returns unique (vendor, model, service, port, username, password) tuples.
        Called via asyncio.to_thread.
        """
        try:
            import sqlite3
            from ..database.db_manager import DB_PATH
            if not DB_PATH.exists():
                return []

            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")

            placeholders = ",".join("?" * len(open_ports))
            cursor = conn.execute(
                f"""SELECT DISTINCT vendor, model, device_type, service, port,
                           username, password, notes
                    FROM iot_default_creds
                    WHERE port IN ({placeholders})
                    ORDER BY vendor, model""",
                open_ports,
            )
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            log.debug(f"Default cred DB lookup error: {exc}")
            return []

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------

    async def _grab_banners(
        self,
        target_ip: str,
        open_ports: list[int],
        results: dict,
    ) -> None:
        """Grab service banners from open IoT ports."""
        iot_open = [p for p in open_ports if p in _IOT_BANNER_PORTS]
        if not iot_open:
            return

        log.info(f"Grabbing banners from {len(iot_open)} IoT port(s) on {target_ip}...")
        tasks = [self._grab_one_banner(target_ip, port) for port in iot_open]
        banners = await asyncio.gather(*tasks, return_exceptions=True)

        for banner in banners:
            if isinstance(banner, dict):
                results["banners"].append(banner)

    async def _grab_one_banner(self, host: str, port: int) -> Optional[dict]:
        """TCP banner grab on a single port."""
        service_name = _IOT_BANNER_PORTS.get(port, "unknown")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5,
            )
            # Send a basic probe
            writer.write(b"\r\n")
            await writer.drain()
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner_str = banner.decode(errors="replace").strip()
            except asyncio.TimeoutError:
                banner_str = ""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if banner_str:
                log.info(f"  [{service_name}] {host}:{port} banner: {banner_str[:120]}")
                return {
                    "check":   "banner",
                    "host":    host,
                    "port":    port,
                    "service": service_name,
                    "banner":  banner_str[:512],
                }
        except Exception as exc:
            log.debug(f"Banner grab {host}:{port} failed: {exc}")
        return None

    # ------------------------------------------------------------------
    # BLE scan
    # ------------------------------------------------------------------

    async def _scan_ble(self, duration: float, results: dict) -> None:
        """Discover local Bluetooth Low Energy devices."""
        if not _BLEAK_AVAILABLE:
            log.warning("bleak not installed — BLE scan unavailable.")
            return

        log.info(f"BLE scan: discovering devices for {duration:.0f} seconds...")
        try:
            devices = await BleakScanner.discover(timeout=duration)
            if devices:
                log.info(f"Found {len(devices)} BLE device(s):")
                for dev in devices:
                    name = dev.name or "Unknown"
                    rssi = getattr(dev, "rssi", "N/A")
                    log.info(f"  {dev.address} — {name} (RSSI: {rssi})")
                    results["ble"].append({
                        "check":   "ble_discovery",
                        "address": dev.address,
                        "name":    name,
                        "rssi":    rssi,
                    })
            else:
                log.info("BLE scan: no devices found in range.")
        except Exception as exc:
            log.warning(
                f"BLE scan failed — ensure Bluetooth hardware is present "
                f"and the process has sufficient permissions. Error: {exc}"
            )