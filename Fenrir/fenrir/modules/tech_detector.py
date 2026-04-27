# fenrir/modules/tech_detector.py
#
# Web technology detection module.
#
# Design:
#   - Primary method:  webtech library fingerprinting.
#   - Fallback method: Manual httpx-based fingerprinting via response headers
#     and HTML meta patterns. Activates automatically if webtech raises any
#     exception (import error, parse error, timeout, etc.).
#   - Both methods produce the same output structure so downstream consumers
#     (CLI, GUI, ReportManager) are unaffected by which method ran.
#
# What is detected:
#   - Web server software (Apache, Nginx, IIS, etc.)
#   - Server-side language/framework (PHP, ASP.NET, Django, Laravel, etc.)
#   - Frontend frameworks (React, Vue, Angular, jQuery, Bootstrap, etc.)
#   - CMS platforms (WordPress, Drupal, Joomla, etc.)
#   - CDN / reverse proxy (Cloudflare, Varnish, AWS CloudFront, etc.)
#   - Analytics and tracking (Google Analytics, Hotjar, etc.)
#   - Security products (ModSecurity, Imperva, etc.)
#
# webtech API notes:
#   - Correct instantiation: WebTech(options={})
#   - Correct call:          wt.start_from_url(url, timeout=N)
#   - Returns a Report object, not a dict. Tech list is at report.tech
#   - Each tech object has .name and optionally .version
#
# Fallback fingerprinting:
#   - Checks response headers (Server, X-Powered-By, X-Generator, Via, etc.)
#   - Checks HTML <meta> generator tags
#   - Checks HTML content patterns (wp-content, Drupal.settings, etc.)
#   - Pattern database defined in _FINGERPRINTS below

import asyncio
import re
import warnings
from typing import Optional

import httpx

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# webtech import — handled gracefully if not installed
# ---------------------------------------------------------------------------

try:
    import webtech
    _WEBTECH_AVAILABLE = True
    log.debug("webtech library available.")
except ImportError:
    _WEBTECH_AVAILABLE = False
    log.debug("webtech library not available — fallback fingerprinting only.")


# ---------------------------------------------------------------------------
# Fallback fingerprint database
# ---------------------------------------------------------------------------
# Structure: list of (category, name, detection_rules)
# detection_rules: dict with optional keys:
#   "headers":  list of (header_name, pattern_regex) — checked against response headers
#   "html":     list of pattern_regex strings         — checked against HTML body
#   "cookies":  list of cookie_name_prefix strings    — checked against Set-Cookie

_FINGERPRINTS: list[dict] = [
    # --- Web Servers ---
    {
        "category": "Web Server",
        "name":     "Apache",
        "headers":  [("Server", r"Apache")],
    },
    {
        "category": "Web Server",
        "name":     "Nginx",
        "headers":  [("Server", r"nginx")],
    },
    {
        "category": "Web Server",
        "name":     "Microsoft IIS",
        "headers":  [("Server", r"Microsoft-IIS")],
    },
    {
        "category": "Web Server",
        "name":     "LiteSpeed",
        "headers":  [("Server", r"LiteSpeed")],
    },
    {
        "category": "Web Server",
        "name":     "Caddy",
        "headers":  [("Server", r"Caddy")],
    },
    {
        "category": "Web Server",
        "name":     "Tomcat",
        "headers":  [("Server", r"Apache-Coyote|Apache Tomcat")],
        "html":     [r"Apache Tomcat"],
    },

    # --- Server-side Languages & Frameworks ---
    {
        "category": "Language",
        "name":     "PHP",
        "headers":  [("X-Powered-By", r"PHP")],
        "html":     [r"\.php"],
    },
    {
        "category": "Language",
        "name":     "ASP.NET",
        "headers":  [
            ("X-Powered-By", r"ASP\.NET"),
            ("X-AspNet-Version", r".+"),
        ],
    },
    {
        "category": "Language",
        "name":     "Python / Django",
        "headers":  [("X-Powered-By", r"Django")],
        "cookies":  ["csrftoken", "sessionid"],
    },
    {
        "category": "Language",
        "name":     "Ruby on Rails",
        "headers":  [("X-Powered-By", r"Phusion Passenger")],
        "cookies":  ["_session_id"],
    },
    {
        "category": "Framework",
        "name":     "Laravel",
        "cookies":  ["laravel_session", "XSRF-TOKEN"],
    },
    {
        "category": "Framework",
        "name":     "Express.js",
        "headers":  [("X-Powered-By", r"Express")],
    },
    {
        "category": "Framework",
        "name":     "Next.js",
        "headers":  [("X-Powered-By", r"Next\.js")],
        "html":     [r"__NEXT_DATA__"],
    },

    # --- CMS ---
    {
        "category": "CMS",
        "name":     "WordPress",
        "html":     [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "cookies":  ["wordpress_", "wp-settings-"],
    },
    {
        "category": "CMS",
        "name":     "Drupal",
        "headers":  [("X-Generator", r"Drupal")],
        "html":     [r"Drupal\.settings", r"/sites/default/files/"],
        "cookies":  ["SESS", "Drupal.visitor"],
    },
    {
        "category": "CMS",
        "name":     "Joomla",
        "html":     [r"/media/jui/", r"joomla!"],
        "cookies":  ["joomla_"],
    },
    {
        "category": "CMS",
        "name":     "Magento",
        "html":     [r"Mage\.Cookies", r"/skin/frontend/"],
        "cookies":  ["frontend", "PHPSESSID"],
    },
    {
        "category": "CMS",
        "name":     "Shopify",
        "html":     [r"cdn\.shopify\.com"],
    },
    {
        "category": "CMS",
        "name":     "Ghost",
        "html":     [r"ghost\.org", r"/ghost/api/"],
    },

    # --- Frontend Frameworks & Libraries ---
    {
        "category": "Frontend",
        "name":     "React",
        "html":     [r"react(?:\.min)?\.js", r"__reactFiber", r"data-reactroot"],
    },
    {
        "category": "Frontend",
        "name":     "Vue.js",
        "html":     [r"vue(?:\.min)?\.js", r"__vue__", r"v-cloak"],
    },
    {
        "category": "Frontend",
        "name":     "Angular",
        "html":     [r"angular(?:\.min)?\.js", r"ng-version", r"\[ng-version\]"],
    },
    {
        "category": "Frontend",
        "name":     "jQuery",
        "html":     [r"jquery(?:\.min)?\.js"],
    },
    {
        "category": "Frontend",
        "name":     "Bootstrap",
        "html":     [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"],
    },

    # --- CDN / Proxy ---
    {
        "category": "CDN / Proxy",
        "name":     "Cloudflare",
        "headers":  [
            ("CF-RAY", r".+"),
            ("Server", r"cloudflare"),
        ],
        "cookies":  ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    {
        "category": "CDN / Proxy",
        "name":     "AWS CloudFront",
        "headers":  [("Via", r"CloudFront"), ("X-Amz-Cf-Id", r".+")],
    },
    {
        "category": "CDN / Proxy",
        "name":     "Varnish",
        "headers":  [("X-Varnish", r".+"), ("Via", r"varnish")],
    },
    {
        "category": "CDN / Proxy",
        "name":     "Fastly",
        "headers":  [("X-Served-By", r"cache-"), ("X-Cache", r".+")],
    },

    # --- Security Products ---
    {
        "category": "Security",
        "name":     "ModSecurity",
        "headers":  [("Server", r"mod_security"), ("X-Powered-By", r"mod_security")],
    },
    {
        "category": "Security",
        "name":     "Imperva / Incapsula",
        "headers":  [("X-Iinfo", r".+")],
        "cookies":  ["incap_ses_", "visid_incap_"],
    },
    {
        "category": "Security",
        "name":     "Sucuri WAF",
        "headers":  [("X-Sucuri-ID", r".+")],
    },

    # --- Analytics ---
    {
        "category": "Analytics",
        "name":     "Google Analytics",
        "html":     [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d{4,}-\d{1,}"],
    },
    {
        "category": "Analytics",
        "name":     "Hotjar",
        "html":     [r"hotjar\.com"],
    },

    # --- Databases / Caches (via error pages or headers) ---
    {
        "category": "Database",
        "name":     "MySQL",
        "html":     [r"mysql_connect\(", r"MySQL server version"],
    },
    {
        "category": "Database",
        "name":     "PostgreSQL",
        "html":     [r"PostgreSQL.*ERROR"],
    },
]


# ---------------------------------------------------------------------------
# TechDetector
# ---------------------------------------------------------------------------

class TechDetector:
    """
    Identifies technologies used by web servers on specified ports.

    Primary:  webtech library (comprehensive Wappalyzer-style fingerprinting).
    Fallback: Manual header and HTML pattern matching.

    Args:
        timeout (float): Request timeout in seconds. Default 10.0.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        log.debug(
            f"TechDetector initialised. Timeout: {timeout}s | "
            f"webtech: {'available' if _WEBTECH_AVAILABLE else 'not available (fallback mode)'}"
        )

    # ------------------------------------------------------------------
    # Primary: webtech
    # ------------------------------------------------------------------

    async def _detect_with_webtech(self, url: str) -> Optional[list[dict]]:
        """
        Attempt technology detection using the webtech library.

        Args:
            url: Full URL to analyse.

        Returns:
            List of technology dicts on success, None if webtech fails.
        """
        if not _WEBTECH_AVAILABLE:
            return None

        def _run_webtech() -> Optional[list[dict]]:
            """Synchronous webtech call — runs in a thread."""
            try:
                # Correct API: WebTech(options={}) then start_from_url()
                wt = webtech.WebTech(options={"json": False})
                report = wt.start_from_url(url, timeout=self.timeout)

                if not report or not hasattr(report, "tech"):
                    return []

                results = []
                for tech in report.tech:
                    name    = getattr(tech, "name", str(tech))
                    version = getattr(tech, "version", None) or ""
                    results.append({
                        "name":     name,
                        "version":  version,
                        "category": "Unknown",
                        "source":   "webtech",
                    })
                return results

            except Exception as exc:
                log.debug(f"webtech failed for {url}: {exc}")
                return None

        return await asyncio.to_thread(_run_webtech)

    # ------------------------------------------------------------------
    # Fallback: manual fingerprinting
    # ------------------------------------------------------------------

    async def _detect_with_fallback(self, url: str) -> list[dict]:
        """
        Perform manual technology fingerprinting via HTTP headers and HTML.

        Args:
            url: Full URL to analyse.

        Returns:
            List of technology dicts. Empty list if target is unreachable.
        """
        log.debug(f"Running fallback fingerprinting on {url}...")

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                async with httpx.AsyncClient(
                    verify=False,
                    follow_redirects=True,
                    timeout=self.timeout,
                ) as client:
                    response = await client.get(url)

        except httpx.RequestError as exc:
            log.warning(f"Fallback fingerprinting: could not reach {url}: {exc}")
            return []
        except Exception as exc:
            log.error(f"Fallback fingerprinting unexpected error on {url}: {exc}")
            return []

        headers  = response.headers
        html     = response.text
        cookies  = {c.name.lower() for c in response.cookies}

        detected: list[dict] = []
        seen_names: set[str] = set()

        for fp in _FINGERPRINTS:
            name     = fp["name"]
            category = fp["category"]

            # Skip duplicates
            if name in seen_names:
                continue

            matched = False

            # --- Header patterns ---
            for header_name, pattern in fp.get("headers", []):
                value = headers.get(header_name, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    matched = True
                    break

            # --- HTML patterns ---
            if not matched:
                for pattern in fp.get("html", []):
                    if re.search(pattern, html, re.IGNORECASE):
                        matched = True
                        break

            # --- Cookie patterns ---
            if not matched:
                for prefix in fp.get("cookies", []):
                    if any(c.startswith(prefix.lower()) for c in cookies):
                        matched = True
                        break

            if matched:
                # Try to extract version from Server or X-Powered-By header
                version = _extract_version_from_headers(name, headers)
                detected.append({
                    "name":     name,
                    "version":  version,
                    "category": category,
                    "source":   "fallback",
                })
                seen_names.add(name)

        return detected

    # ------------------------------------------------------------------
    # Per-port scan
    # ------------------------------------------------------------------

    async def scan_port(
        self,
        target: str,
        port: int,
    ) -> list[dict]:
        """
        Run technology detection against a single web port.

        Tries webtech first. If it fails or returns nothing, falls back to
        manual fingerprinting. Logs which method produced the results.

        Args:
            target: IP address or hostname.
            port:   Web port to scan.

        Returns:
            List of technology dicts:
            [{name, version, category, source}, ...]
        """
        protocol = "https" if port in (443, 8443) else "http"
        url = f"{protocol}://{target}:{port}"

        log.info(f"Technology detection on {url}...")

        technologies: list[dict] = []

        # --- Attempt webtech ---
        webtech_results = await self._detect_with_webtech(url)

        if webtech_results is not None and len(webtech_results) > 0:
            log.debug(f"webtech produced {len(webtech_results)} result(s) for {url}.")
            technologies = webtech_results
            method_used = "webtech"
        else:
            if webtech_results is None:
                log.debug(
                    f"webtech returned None for {url} — switching to fallback."
                )
            else:
                log.debug(
                    f"webtech returned no results for {url} — "
                    "running fallback for additional coverage."
                )
            fallback_results = await self._detect_with_fallback(url)
            technologies = fallback_results
            method_used = "fallback"

        # --- Log results ---
        if technologies:
            log.info(
                f"Technologies detected on {url} "
                f"(via {method_used}, {len(technologies)} found):"
            )
            for tech in sorted(technologies, key=lambda t: t.get("category", "")):
                version_str = f" {tech['version']}" if tech.get("version") else ""
                log.warning(
                    f"  [{tech.get('category', 'Unknown'):12}]  "
                    f"{tech['name']}{version_str}"
                )
        else:
            log.info(
                f"No technologies identified on {url} "
                f"(method: {method_used})."
            )

        return technologies

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        web_ports: list[int],
        report: Optional[ReportManager] = None,
    ) -> dict[int, list[dict]]:
        """
        Run technology detection against all provided web ports.

        Args:
            target:    IP address or hostname to scan.
            web_ports: List of open ports known to host web services.
            report:    Optional ReportManager to record findings.

        Returns:
            Dict mapping port number -> list of technology dicts.
        """
        if not web_ports:
            log.warning(
                "TechDetector: no web ports provided — skipping."
            )
            return {}

        log.info(
            f"Starting technology detection on {target} "
            f"(ports: {', '.join(str(p) for p in web_ports)})..."
        )

        # Run ports concurrently — each is an independent HTTP fetch
        tasks = {
            port: asyncio.create_task(self.scan_port(target, port))
            for port in web_ports
        }

        port_results: dict[int, list[dict]] = {}
        for port, task in tasks.items():
            try:
                port_results[port] = await task
            except Exception as exc:
                log.error(
                    f"TechDetector: unexpected error on port {port}: {exc}"
                )
                port_results[port] = []

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            all_techs = [
                {**tech, "port": port}
                for port, tech_list in port_results.items()
                for tech in tech_list
            ]
            if all_techs:
                report.add_section("Detected Technologies", all_techs)
            else:
                report.add_section(
                    "Technology Detection",
                    ["No technologies identified on scanned ports."],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        total = sum(len(v) for v in port_results.values())
        log.info(
            f"Technology detection complete. "
            f"Ports scanned: {len(web_ports)} | "
            f"Technologies identified: {total}"
        )

        return port_results


# ---------------------------------------------------------------------------
# Version extraction helper
# ---------------------------------------------------------------------------

def _extract_version_from_headers(tech_name: str, headers: httpx.Headers) -> str:
    """
    Attempt to extract a version string for a known technology from headers.

    Checks Server and X-Powered-By headers for version numbers adjacent to
    the technology name.

    Args:
        tech_name: Name of the technology (e.g. "Apache", "PHP").
        headers:   Response headers.

    Returns:
        Version string (e.g. "2.4.51") or empty string if not found.
    """
    candidates = [
        headers.get("Server", ""),
        headers.get("X-Powered-By", ""),
        headers.get("X-AspNet-Version", ""),
        headers.get("X-Generator", ""),
    ]

    for candidate in candidates:
        if not candidate:
            continue
        # Look for the tech name followed by a version number
        # e.g. "Apache/2.4.51" or "PHP/8.1.2"
        pattern = re.compile(x,
            re.escape(tech_name) + r"[/\s]*([\d]+\.[\d]+[\d.]*)",
            re.IGNORECASE,
        )
        match = pattern.search(candidate)
        if match:
            return match.group(1)

    return ""