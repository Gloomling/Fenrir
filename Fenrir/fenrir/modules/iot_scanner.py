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
        """Match open ports against IoT default credentials in offline DB."""
        if not self._db.is_available():
            log.debug("Offline DB not available — skipping default cred check.")
            return

        cred_hits = await asyncio.to_thread(
            self._lookup_default_creds, open_ports
        )

        for hit in cred_hits:
            log.warning(
                f"DEFAULT CREDS MATCH on {target_ip}: "
                f"{hit['vendor']} {hit['model']} — "
                f"{hit['service']} (port {hit['port']}): "
                f"{hit['username']} / {hit['password']}"
            )
            results["default_creds"].append({
                "check":    "default_credentials",
                "host":     target_ip,
                "port":     hit["port"],
                "service":  hit["service"],
                "vendor":   hit["vendor"],
                "model":    hit["model"],
                "username": hit["username"],
                "password": hit["password"],
                "severity": "CRITICAL",
            })

        if not cred_hits:
            log.info(f"No default credential matches for open ports on {target_ip}.")

    def _lookup_default_creds(self, open_ports: list[int]) -> list[dict]:
        """Synchronous DB query — called via asyncio.to_thread."""
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
                f"""SELECT * FROM iot_default_creds
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
