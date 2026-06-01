# fenrir/modules/web_scanner.py
#
# Web server reconnaissance module.
#
# Design:
#   - Focused purely on HTTP/S header fetching and analysis.
#   - Directory/path brute-forcing has been removed from this module and
#     delegated entirely to DirBruteForcer (dir_brute_forcer.py).
#   - For each web port on the target, fetches the server response headers
#     and analyses them for:
#       1. General server information (Server, X-Powered-By, etc.)
#       2. Missing or misconfigured security headers — each absence is
#          logged at WARNING level as a finding.
#   - Uses httpx with SSL verification disabled (verify=False) since pentest
#     targets frequently have self-signed or expired certificates.
#   - Follows redirects to capture the final response headers.
#   - All findings are added to the ReportManager.
#
# Security headers checked:
#   - Strict-Transport-Security (HSTS)
#   - Content-Security-Policy (CSP)
#   - X-Frame-Options
#   - X-Content-Type-Options
#   - Referrer-Policy
#   - Permissions-Policy
#   - X-XSS-Protection  (legacy but still noteworthy if absent or misconfigured)
#
# Note on SSL warnings:
#   httpx will emit SSL warnings when verify=False. These are suppressed via
#   the warnings module to keep output clean during a scan.

import asyncio
import warnings
from typing import Optional

import httpx

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------
# Each entry: (header_name, severity, recommendation)
# severity: "HIGH" | "MEDIUM" | "LOW"

SECURITY_HEADERS: list[tuple[str, str, str]] = [
    (
        "Strict-Transport-Security",
        "HIGH",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "to enforce HTTPS and prevent protocol downgrade attacks.",
    ),
    (
        "Content-Security-Policy",
        "HIGH",
        "Add a Content-Security-Policy header to prevent XSS and data injection attacks.",
    ),
    (
        "X-Frame-Options",
        "MEDIUM",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks.",
    ),
    (
        "X-Content-Type-Options",
        "MEDIUM",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    ),
    (
        "Referrer-Policy",
        "LOW",
        "Add a Referrer-Policy header to control information sent in the Referer header.",
    ),
    (
        "Permissions-Policy",
        "LOW",
        "Add a Permissions-Policy header to restrict access to browser features "
        "(camera, microphone, geolocation, etc.).",
    ),
    (
        "X-XSS-Protection",
        "LOW",
        "Consider adding 'X-XSS-Protection: 1; mode=block' for legacy browser support, "
        "though CSP is the modern replacement.",
    ),
]

# Headers that reveal potentially sensitive server information
INFO_DISCLOSURE_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Backend-Server",
]


class WebScanner:
    """
    Performs HTTP/S header reconnaissance against web ports.

    Fetches response headers from each web port and analyses them for:
      - Server technology disclosure
      - Missing security headers (flagged as findings)
      - Cookie security flags (Secure, HttpOnly, SameSite)
      - HTTPS redirect behaviour

    Args:
        timeout (float): Request timeout in seconds. Default 10.0.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        log.debug(f"WebScanner initialised. Timeout: {timeout}s")

    # ------------------------------------------------------------------
    # Header fetching
    # ------------------------------------------------------------------

    async def fetch_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> Optional[httpx.Response]:
        """
        Perform a GET request and return the response.

        Args:
            client: Shared httpx.AsyncClient instance.
            url:    Full URL to fetch (e.g. "http://192.168.1.10:8080").

        Returns:
            httpx.Response on success, None on any request error.
        """
        try:
            response = await client.get(
                url,
                follow_redirects=True,
                timeout=self.timeout,
            )
            log.info(
                f"  {url}  →  HTTP {response.status_code}  "
                f"(final URL: {response.url})"
            )
            return response
        except httpx.ConnectTimeout:
            log.debug(f"[web] Probing {url}")
            log.warning(f"  {url}  →  Connection timed out after {self.timeout}s.")
        except httpx.ConnectError as exc:
            log.warning(f"  {url}  →  Could not connect: {exc}")
        except httpx.TooManyRedirects:
            log.warning(f"  {url}  →  Too many redirects.")
        except httpx.RequestError as exc:
            log.warning(f"  {url}  →  Request error: {exc}")
        except Exception as exc:
            log.error(f"  {url}  →  Unexpected error: {exc}")
        return None

    # ------------------------------------------------------------------
    # Header analysis
    # ------------------------------------------------------------------

    def analyse_info_disclosure(
        self,
        url: str,
        headers: httpx.Headers,
    ) -> list[dict]:
        """
        Check for headers that disclose server technology information.

        Args:
            url:     The URL that was scanned.
            headers: Response headers from the server.

        Returns:
            List of finding dicts for each disclosure header present.
        """
        findings = []
        log.debug(f"[web] Header analysis complete for {target_ip}")
        log.info("  Information disclosure headers:")

        found_any = False
        for header_name in INFO_DISCLOSURE_HEADERS:
            value = headers.get(header_name)
            if value:
                log.warning(
                    f"    [INFO DISCLOSURE]  {header_name}: {value}"
                )
                findings.append({
                    "type":   "info_disclosure",
                    "url":    url,
                    "header": header_name,
                    "value":  value,
                    "note":   (
                        f"Server is disclosing '{header_name}' header. "
                        "Consider removing or obfuscating this value."
                    ),
                })
                found_any = True

        if not found_any:
            log.info("    None detected.")

        return findings

    def analyse_security_headers(
        self,
        url: str,
        headers: httpx.Headers,
    ) -> list[dict]:
        """
        Check for missing or present security headers.

        Args:
            url:     The URL that was scanned.
            headers: Response headers from the server.

        Returns:
            List of finding dicts for each missing security header.
        """
        findings = []
        log.info("  Security header analysis:")

        all_present = True
        for header_name, severity, recommendation in SECURITY_HEADERS:
            value = headers.get(header_name)
            if value:
                log.info(f"    [✓] {header_name}: {value}")
            else:
                log.warning(
                    f"    [✗ MISSING | {severity}]  {header_name}"
                )
                log.warning(f"        → {recommendation}")
                findings.append({
                    "type":           "missing_security_header",
                    "url":            url,
                    "header":         header_name,
                    "severity":       severity,
                    "recommendation": recommendation,
                })
                all_present = False

        if all_present:
            log.info("    All recommended security headers are present.")

        return findings

    def analyse_cookies(
        self,
        url: str,
        headers: httpx.Headers,
    ) -> list[dict]:
        """
        Check Set-Cookie headers for missing security flags.

        Flags checked: Secure, HttpOnly, SameSite.

        Args:
            url:     The URL that was scanned.
            headers: Response headers from the server.

        Returns:
            List of finding dicts for each insecure cookie found.
        """
        findings = []
        # httpx exposes multiple Set-Cookie headers via headers.get_list()
        cookies = headers.get_list("set-cookie")

        if not cookies:
            return findings

        log.info(f"  Cookie security analysis ({len(cookies)} cookie(s)):")

        for cookie_str in cookies:
            cookie_lower = cookie_str.lower()
            issues = []

            if "secure" not in cookie_lower:
                issues.append("missing Secure flag (cookie sent over HTTP)")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag (accessible via JavaScript)")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite flag (CSRF risk)")

            # Extract cookie name for display
            cookie_name = cookie_str.split("=")[0].strip()

            if issues:
                for issue in issues:
                    log.warning(
                        f"    [INSECURE COOKIE]  {cookie_name}  —  {issue}"
                    )
                    findings.append({
                        "type":   "insecure_cookie",
                        "url":    url,
                        "cookie": cookie_name,
                        "issue":  issue,
                    })
            else:
                log.info(f"    [✓] {cookie_name}  — all security flags present")

        return findings

    def check_https_redirect(
        self,
        port: int,
        response: httpx.Response,
    ) -> Optional[dict]:
        """
        Check whether an HTTP endpoint redirects to HTTPS.

        Only applicable to non-TLS ports (not 443 or 8443).

        Args:
            port:     The port that was scanned.
            response: The httpx response (after following redirects).

        Returns:
            Finding dict if the endpoint does NOT redirect to HTTPS, else None.
        """
        if port in (443, 8443):
            return None  # Already HTTPS

        final_url = str(response.url)
        if final_url.startswith("https://"):
            log.info(f"  HTTPS redirect: ✓ (redirects to {final_url})")
            return None

        log.warning(
            f"  [NO HTTPS REDIRECT]  Port {port} does not redirect to HTTPS."
        )
        return {
            "type":   "no_https_redirect",
            "port":   port,
            "url":    final_url,
            "note":   (
                f"Port {port} does not redirect HTTP traffic to HTTPS. "
                "Configure a 301 redirect to the HTTPS endpoint."
            ),
        }

    # ------------------------------------------------------------------
    # Per-port scan
    # ------------------------------------------------------------------

    async def scan_port(
        self,
        client: httpx.AsyncClient,
        target: str,
        port: int,
    ) -> dict:
        """
        Run all header analysis against a single web port.

        Args:
            client: Shared httpx.AsyncClient.
            target: IP address or hostname.
            port:   Web port to scan.

        Returns:
            Dict containing all findings for this port:
            {port, url, status_code, server, info_disclosure,
             missing_security_headers, insecure_cookies, https_redirect}
        """
        protocol = "https" if port in (443, 8443) else "http"
        url = f"{protocol}://{target}:{port}"

        log.info(f"Scanning {url}...")

        result = {
            "port":                   port,
            "url":                    url,
            "status_code":            None,
            "server":                 None,
            "info_disclosure":        [],
            "missing_security_headers": [],
            "insecure_cookies":       [],
            "https_redirect":         None,
            "reachable":              False,
        }

        response = await self.fetch_headers(client, url)
        if response is None:
            log.warning(f"  {url} is not reachable — skipping analysis.")
            return result

        result["reachable"]    = True
        result["status_code"]  = response.status_code
        result["server"]       = response.headers.get("server", "unknown")

        # Run all analyses
        result["info_disclosure"]          = self.analyse_info_disclosure(url, response.headers)
        result["missing_security_headers"] = self.analyse_security_headers(url, response.headers)
        result["insecure_cookies"]         = self.analyse_cookies(url, response.headers)
        result["https_redirect"]           = self.check_https_redirect(port, response)

        return result

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        web_ports: list[int],
        report: Optional[ReportManager] = None,
    ) -> list[dict]:
        """
        Run web header reconnaissance against all provided web ports.

        Args:
            target:    IP address or hostname to scan.
            web_ports: List of open ports known to host web services.
                       Typically filtered from PortScanner results using WEB_PORTS.
            report:    Optional ReportManager to record findings.

        Returns:
            List of per-port result dicts (see scan_port return value).
        """
        if not web_ports:
            log.warning(
                "WebScanner: no web ports provided. "
                "Pass open ports filtered against WEB_PORTS."
            )
            return []

        log.info(
            f"Starting web reconnaissance on {target} "
            f"(ports: {', '.join(str(p) for p in web_ports)})..."
        )

        # Suppress SSL warnings — pentest targets routinely have bad certs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            async with httpx.AsyncClient(verify=False) as client:
                tasks = [
                    asyncio.create_task(self.scan_port(client, target, port))
                    for port in web_ports
                ]
                try:
                    port_results = await asyncio.gather(*tasks)
                except Exception as exc:
                    log.error(f"Web scan encountered a fatal error: {exc}")
                    return []

        # ------------------------------------------------------------------
        # Build report sections
        # ------------------------------------------------------------------
        if report:
            # Flatten all findings across all ports into report sections
            all_info_disclosure        = []
            all_missing_sec_headers    = []
            all_insecure_cookies       = []
            all_https_issues           = []

            for pr in port_results:
                if not pr["reachable"]:
                    continue
                all_info_disclosure.extend(pr["info_disclosure"])
                all_missing_sec_headers.extend(pr["missing_security_headers"])
                all_insecure_cookies.extend(pr["insecure_cookies"])
                if pr["https_redirect"]:
                    all_https_issues.append(pr["https_redirect"])

            if all_info_disclosure:
                report.add_section(
                    "Web — Information Disclosure Headers",
                    all_info_disclosure,
                )
            if all_missing_sec_headers:
                report.add_section(
                    "Web — Missing Security Headers",
                    all_missing_sec_headers,
                )
            if all_insecure_cookies:
                report.add_section(
                    "Web — Insecure Cookies",
                    all_insecure_cookies,
                )
            if all_https_issues:
                report.add_section(
                    "Web — HTTPS Configuration Issues",
                    all_https_issues,
                )

            if not any([
                all_info_disclosure,
                all_missing_sec_headers,
                all_insecure_cookies,
                all_https_issues,
            ]):
                report.add_section(
                    "Web Reconnaissance",
                    ["No web security issues identified on scanned ports."],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        reachable = [pr for pr in port_results if pr["reachable"]]
        total_findings = sum(
            len(pr["info_disclosure"])
            + len(pr["missing_security_headers"])
            + len(pr["insecure_cookies"])
            + (1 if pr["https_redirect"] else 0)
            for pr in reachable
        )

        log.info(
            f"Web reconnaissance complete. "
            f"Ports scanned: {len(web_ports)} | "
            f"Reachable: {len(reachable)} | "
            f"Findings: {total_findings}"
        )

        return list(port_results)
