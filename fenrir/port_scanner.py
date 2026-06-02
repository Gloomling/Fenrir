# fenrir/modules/port_scanner.py
#
# Asynchronous TCP port scanner.
#
# Design:
#   - Pure asyncio TCP connect scan — no nmap dependency for basic scanning.
#   - Semaphore-controlled concurrency to avoid overwhelming the target or
#     exhausting local file descriptors.
#   - DEFAULT_PORTS contains the top 1000 most commonly scanned ports, matching
#     the nmap default port list. Defined here as the single source of truth —
#     imported by cli.py, fenrir_gui.py, and modules/__init__.py.
#   - parse_ports() is a standalone utility that converts user-supplied port
#     strings ("80,443,1024-2048") into sorted integer lists. Exported for
#     use by the CLI and GUI.
#   - Returns a list of open ports that the orchestrator passes to downstream
#     modules (VulnerabilityScanner, WebScanner, etc.).
#   - All findings are added to the ReportManager if one is provided.

import asyncio
from typing import Optional

from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Default port list — top 1000 ports (matches nmap default)
# ---------------------------------------------------------------------------

DEFAULT_PORTS: list[int] = sorted([
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
    37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163,
    179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464,
    465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548,
    554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667,
    668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777,
    783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903,
    911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007,
    1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
    1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053,
    1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065,
    1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
    1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102,
    1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119,
    1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145,
    1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174,
    1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217,
    1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287,
    1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433,
    1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556,
    1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718,
    1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839,
    1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974,
    1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
    2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040,
    2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100,
    2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
    2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323,
    2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525,
    2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717,
    2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968,
    2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
    3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283,
    3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370,
    3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580,
    3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826,
    3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
    3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006,
    4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444,
    4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001,
    5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080,
    5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226,
    5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544,
    5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800,
    5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900,
    5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950,
    5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000,
    6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101,
    6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565,
    6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
    6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007,
    7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496,
    7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937,
    7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022,
    8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
    8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
    8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600,
    8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001,
    9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091,
    9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
    9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666,
    9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999,
    10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
    10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
    13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003,
    15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
    16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
    19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
    21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
    32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
    32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
    44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156,
    49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
    49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
    55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
])

# Common web ports — used by WebScanner, DirBruteForcer, TechDetector
WEB_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 8888, 3000]

# Common SSH port
SSH_PORT: int = 22


# ---------------------------------------------------------------------------
# Port string parser
# ---------------------------------------------------------------------------

def parse_ports(port_string: str) -> list[int]:
    """
    Parse a user-supplied port specification into a sorted list of integers.

    Accepts:
        - Individual ports:   "80"
        - Comma-separated:    "80,443,8080"
        - Ranges:             "1024-2048"
        - Mixed:              "22,80,443,1024-2048,8080"
        - Whitespace tolerant: " 80 , 443 , 1024-2048 "

    Returns:
        Sorted list of unique port integers, clamped to valid range 1-65535.

    Raises:
        ValueError: If the string contains tokens that cannot be parsed as
                    port numbers or ranges.

    Examples:
        >>> parse_ports("80,443")
        [80, 443]
        >>> parse_ports("1024-1030")
        [1024, 1025, 1026, 1027, 1028, 1029, 1030]
        >>> parse_ports("22,80,443,8000-8010")
        [22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010]
    """
    ports: set[int] = set()
    tokens = [t.strip() for t in port_string.split(",") if t.strip()]

    if not tokens:
        raise ValueError("Port string is empty.")

    for token in tokens:
        if "-" in token:
            # Range token e.g. "1024-2048"
            parts = token.split("-", maxsplit=1)
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid port range '{token}'. Expected format: start-end"
                )
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                raise ValueError(
                    f"Invalid port range '{token}': both ends must be integers."
                )
            if start > end:
                raise ValueError(
                    f"Invalid port range '{token}': start must be <= end."
                )
            if start < 1 or end > 65535:
                raise ValueError(
                    f"Invalid port range '{token}': ports must be between 1 and 65535."
                )
            ports.update(range(start, end + 1))
        else:
            # Single port token
            try:
                port = int(token)
            except ValueError:
                raise ValueError(
                    f"Invalid port '{token}': must be an integer."
                )
            if port < 1 or port > 65535:
                raise ValueError(
                    f"Invalid port {port}: must be between 1 and 65535."
                )
            ports.add(port)

    return sorted(ports)


# ---------------------------------------------------------------------------
# PortScanner
# ---------------------------------------------------------------------------

class PortScanner:
    """
    Asynchronous TCP connect port scanner.

    Performs a TCP connect scan by attempting asyncio.open_connection() on
    each port. No raw sockets or root privileges required.

    Note: This is a connect scan — it completes the TCP handshake, which is
    logged by the target. For stealthier scanning, use VulnerabilityScanner
    which delegates to nmap with configurable scan types.

    Args:
        concurrency (int): Maximum simultaneous connection attempts.
                           Default 200. Reduce if the target drops connections.
        timeout (float):   Seconds to wait for each connection attempt.
                           Default 1.0. Increase for slow/distant targets.
    """

    def __init__(
        self,
        concurrency: int = 200,
        timeout: float = 1.0,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        log.debug(
            f"PortScanner initialised. "
            f"Concurrency: {concurrency}, Timeout: {timeout}s"
        )

    async def scan_port(
        self, target_ip: str, port: int
    ) -> tuple[int, bool]:
        """
        Attempt a TCP connection to a single port.

        Args:
            target_ip: IP address or hostname to scan.
            port:      TCP port number (1-65535).

        Returns:
            (port, True)  if the port is open (connection succeeded).
            (port, False) if the port is closed or filtered (connection failed).
        """
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=self.timeout,
            )
            # Connection succeeded — port is open. Close cleanly.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                # Ignore errors on close — the scan result is already known.
                pass
            log.debug(f"[port_scan] {target_ip}:{port} OPEN")
            return port, True

        except asyncio.TimeoutError:
            log.debug(f"[port_scan] {target_ip}:{port} filtered/timeout ({self.timeout}s)")
            # Port is filtered (no response within timeout)
            return port, False
        except ConnectionRefusedError:
            # Port is closed (RST received)
            return port, False
        except OSError as exc:
            # Handles: network unreachable, host down, too many open files, etc.
            log.debug(f"OSError scanning {target_ip}:{port} — {exc}")
            return port, False
        except Exception as exc:
            # Catch-all for unexpected errors — log at debug, don't crash.
            log.debug(f"Unexpected error scanning {target_ip}:{port} — {exc}")
            return port, False

    async def run(
        self,
        target_ip: str,
        ports: Optional[list[int]] = None,
        report: Optional[ReportManager] = None,
    ) -> list[int]:
        """
        Run a concurrent TCP port scan against the target.

        Args:
            target_ip: IP address or hostname to scan.
            ports:     List of ports to scan. Defaults to DEFAULT_PORTS (top 1000)
                       if not provided or empty.
            report:    Optional ReportManager to record findings.

        Returns:
            Sorted list of open port numbers. Empty list if none found.
        """
        # Use default port list if none provided
        if not ports:
            ports = DEFAULT_PORTS
            log.info(f"No ports specified — using default top-{len(DEFAULT_PORTS)} port list.")

        log.info(f"Starting port scan on {target_ip} ({len(ports)} ports to check)...")
        log.info(f"Concurrency: {self.concurrency} | Timeout: {self.timeout}s per port")

        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded_scan(port: int) -> tuple[int, bool]:
            async with semaphore:
                return await self.scan_port(target_ip, port)

        # Schedule all port scans concurrently
        tasks = [asyncio.create_task(bounded_scan(port)) for port in ports]

        try:
            results = await asyncio.gather(*tasks)
        except Exception as exc:
            log.error(f"Port scan encountered a fatal error: {exc}")
            return []

        # Collect and sort open ports
        open_ports = sorted([port for port, is_open in results if is_open])

        # --- Results summary ---
        log.info(
            f"Port scan complete. "
            f"Scanned: {len(ports)} | Open: {len(open_ports)} | "
            f"Closed/Filtered: {len(ports) - len(open_ports)}"
        )

        if open_ports:
            log.warning(f"Open ports on {target_ip}:")
            for port in open_ports:
                service_hint = _COMMON_PORT_NAMES.get(port, "unknown")
                log.warning(f"  {port}/tcp  open  {service_hint}")
                log.debug(f"[port_scan] {target_ip}:{port}/tcp open ({service_hint})")
        else:
            log.info(f"No open ports found on {target_ip} in the scanned range.")

        # --- Report ---
        if report:
            findings = [
                f"{port}/tcp  open  {_COMMON_PORT_NAMES.get(port, 'unknown')}"
                for port in open_ports
            ]
            if not findings:
                findings = ["No open ports found in the scanned range."]
            report.add_section("Open Ports", findings)

        return open_ports


# ---------------------------------------------------------------------------
# Common port name hints
# ---------------------------------------------------------------------------
# Used to annotate scan output with likely service names.
# Not authoritative — actual service detection is done by VulnerabilityScanner.

_COMMON_PORT_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 79: "finger",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmp-trap", 179: "bgp", 194: "irc", 199: "smux",
    389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd",
    465: "smtps", 500: "isakmp", 512: "exec", 513: "login",
    514: "shell", 515: "printer", 543: "klogin", 544: "kshell",
    548: "afp", 554: "rtsp", 587: "submission", 593: "http-rpc-epmap",
    631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync",
    990: "ftps", 992: "telnets", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "ms-sql-s", 1434: "ms-sql-m",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3306: "mysql", 3389: "ms-wbt-server",
    3690: "svn", 4369: "epmd", 5000: "upnp", 5432: "postgresql",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "kubernetes",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9090: "zeus-admin", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcache", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 27019: "mongodb", 50070: "hadoop",
    61616: "activemq",
}
