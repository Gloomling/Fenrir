# fenrir/modules/dir_brute_forcer.py
#
# Directory and file brute-force scanner.
#
# Design:
#   - Sends async HTTP HEAD requests for each path in a wordlist against
#     every web port on the target.
#   - Any response with a status code other than 404 is considered a finding
#     and logged at WARNING level.
#   - Wordlist source priority:
#       1. User-supplied file path (--wordlist /path/to/list.txt)
#       2. Built-in default wordlist (defined in this module)
#   - Wordlist files are expected to have one path per line.
#     Lines beginning with '#' are treated as comments and skipped.
#     Leading/trailing whitespace is stripped.
#   - Semaphore-controlled concurrency (default 50) to avoid overwhelming
#     the target or triggering rate limiting / WAF rules.
#   - Uses httpx with SSL verification disabled for pentest targets.
#   - All findings are added to the ReportManager.
#
# Status code interpretation:
#   200        — resource exists and is accessible
#   301/302    — redirect (may point to interesting resource)
#   401        — exists but requires authentication (noteworthy)
#   403        — exists but access is forbidden (noteworthy)
#   500        — server error (path exists, may indicate vulnerability)
#   404        — not found (filtered out)
#   Other      — logged for manual review

import asyncio
import warnings
from pathlib import Path
from typing import Optional

import httpx

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Built-in default wordlist
# ---------------------------------------------------------------------------
# Covers the most commonly found and security-relevant paths.
# This should be the fallback — for real engagements, supply a wordlist
# such as SecLists/Discovery/Web-Content/common.txt

DEFAULT_WORDLIST: list[str] = [
    # Admin and authentication
    "admin", "admin/", "admin/login", "administrator", "administrator/",
    "login", "login.php", "login.html", "login.aspx", "signin", "auth",
    "dashboard", "dashboard/", "portal", "panel", "control",
    "wp-admin", "wp-admin/", "wp-login.php",
    "phpmyadmin", "phpmyadmin/", "pma", "pma/",
    "webadmin", "siteadmin", "adminpanel",

    # API endpoints
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "api/users", "api/admin", "api/config", "api/health",
    "rest", "rest/", "graphql", "swagger", "swagger-ui",
    "swagger-ui.html", "swagger.json", "openapi.json",
    "api-docs", "api-docs/",

    # Development and staging
    "dev", "dev/", "development", "staging", "staging/",
    "test", "test/", "testing", "beta", "demo", "demo/",
    "sandbox", "local", "localhost",

    # Backup and archive files
    "backup", "backup/", "backups", "backups/",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "db_backup.sql", "database.sql", "dump.sql",
    "old", "old/", "archive", "archive/",

    # Sensitive configuration files
    ".env", ".env.local", ".env.production", ".env.backup",
    "config", "config/", "config.php", "config.json",
    "config.yml", "config.yaml", "config.xml",
    "configuration.php", "settings.php", "settings.py",
    "application.properties", "application.yml",
    "web.config", "appsettings.json",
    ".htaccess", ".htpasswd",

    # Version control and CI/CD
    ".git", ".git/", ".git/config", ".git/HEAD",
    ".gitignore", ".gitmodules",
    ".svn", ".svn/", ".svn/entries",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", "Jenkinsfile", ".travis.yml",
    ".github", ".github/",

    # Common application files
    "robots.txt", "sitemap.xml", "sitemap.xml.gz",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    "favicon.ico",

    # Package and dependency files (info disclosure)
    "package.json", "package-lock.json",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile",
    "yarn.lock", "pom.xml",

    # Logs and monitoring
    "logs", "logs/", "log", "log/",
    "error.log", "access.log", "debug.log",
    "app.log", "server.log", "application.log",
    "phpinfo.php", "info.php", "test.php", "status",

    # Common directories
    "uploads", "uploads/", "upload", "upload/",
    "files", "files/", "file", "assets", "assets/",
    "static", "static/", "media", "media/",
    "images", "images/", "img", "img/",
    "css", "js", "scripts", "scripts/",
    "includes", "includes/", "inc", "lib", "lib/",
    "vendor", "vendor/", "node_modules",
    "downloads", "downloads/", "download",
    "temp", "temp/", "tmp", "tmp/",
    "cache", "cache/", "data", "data/",
    "public", "private", "secure", "internal",

    # User and profile
    "user", "user/", "users", "users/",
    "profile", "account", "accounts",
    "register", "signup", "logout", "reset",
    "forgot-password", "password-reset",

    # Common framework paths
    "console", "shell", "phpshell.php",
    "server-status", "server-info",   # Apache
    "nginx_status",                    # Nginx
    "health", "healthcheck", "ping",   # Load balancers / k8s
    "metrics", "actuator", "actuator/", # Spring Boot
    "jolokia", "jolokia/",             # JMX
    "manager", "manager/html",         # Tomcat
    "jmx-console", "web-console",      # JBoss

    # Database and ORM tools
    "adminer", "adminer.php",
    "adminer-4.7.9.php",               # Common versioned filename
    "db", "database", "sql",
    "mysql", "postgres", "mongodb",

    # Readme and documentation
    "README.md", "CHANGELOG.md", "LICENSE",
    "INSTALL.md", "CONTRIBUTING.md",
    "docs", "docs/", "documentation", "wiki",
]

# Status codes we consider findings (anything except explicit not-found)
FINDING_STATUS_CODES: set[int] = {
    200, 201, 204,          # Success
    301, 302, 303, 307, 308, # Redirects
    401, 403,               # Auth required / Forbidden — path exists
    405,                    # Method not allowed — path exists
    500, 501, 502, 503,     # Server errors — path exists
}

# Human-readable status code notes
STATUS_NOTES: dict[int, str] = {
    200: "OK — accessible",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found (redirect)",
    303: "See Other",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    401: "Unauthorised — authentication required",
    403: "Forbidden — path exists but access denied",
    405: "Method Not Allowed — path exists",
    500: "Internal Server Error — path exists, possible vulnerability",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


class DirBruteForcer:
    """
    Asynchronous directory and file brute-force scanner.

    Args:
        wordlist_path (str | Path | None):
            Path to a custom wordlist file (one path per line).
            If None or not provided, the built-in DEFAULT_WORDLIST is used.
        concurrency (int):
            Maximum simultaneous HTTP requests. Default 50.
            Reduce if the target has rate limiting or a WAF.
        timeout (float):
            Request timeout in seconds. Default 5.0.
    """

    def __init__(
        self,
        wordlist_path: Optional[Path | str] = None,
        concurrency: int = 50,
        timeout: float = 5.0,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.wordlist = self._load_wordlist(wordlist_path)

        log.debug(
            f"DirBruteForcer initialised. "
            f"Wordlist: {len(self.wordlist)} entries | "
            f"Concurrency: {concurrency} | Timeout: {timeout}s"
        )

    # ------------------------------------------------------------------
    # Wordlist loading
    # ------------------------------------------------------------------

    def _load_wordlist(
        self,
        wordlist_path: Optional[Path | str],
    ) -> list[str]:
        """
        Load and return the wordlist to use for this scan.

        Args:
            wordlist_path: Path to a custom wordlist file, or None to use
                           the built-in default.

        Returns:
            List of path strings to probe (leading slash stripped —
            we add it ourselves when building URLs).
        """
        if wordlist_path is None:
            log.debug("DirBruteForcer: using built-in default wordlist.")
            return DEFAULT_WORDLIST

        path = Path(wordlist_path)

        if not path.exists():
            log.warning(
                f"DirBruteForcer: wordlist file not found at '{path}'. "
                "Falling back to built-in default wordlist."
            )
            return DEFAULT_WORDLIST

        if not path.is_file():
            log.warning(
                f"DirBruteForcer: '{path}' is not a file. "
                "Falling back to built-in default wordlist."
            )
            return DEFAULT_WORDLIST

        try:
            entries = []
            skipped = 0
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        skipped += 1
                        continue
                    # Normalise: strip leading slash — we add it when building URLs
                    entries.append(line.lstrip("/"))

            if not entries:
                log.warning(
                    f"DirBruteForcer: wordlist file '{path}' is empty or "
                    "contains only comments. Falling back to built-in default."
                )
                return DEFAULT_WORDLIST

            log.info(
                f"DirBruteForcer: loaded {len(entries)} entries from '{path}' "
                f"({skipped} comment/blank lines skipped)."
            )
            return entries

        except OSError as exc:
            log.error(
                f"DirBruteForcer: could not read wordlist '{path}': {exc}. "
                "Falling back to built-in default wordlist."
            )
            return DEFAULT_WORDLIST

    # ------------------------------------------------------------------
    # Single path check
    # ------------------------------------------------------------------

    async def check_path(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
    ) -> Optional[dict]:
        """
        Send a HEAD request for a single path and return a finding if notable.

        HEAD is used instead of GET to minimise bandwidth and avoid triggering
        WAF rules for content inspection. Falls back to GET if the server
        returns 405 (Method Not Allowed) on HEAD.

        Args:
            client:   Shared httpx.AsyncClient.
            base_url: Base URL of the target (e.g. "http://192.168.1.10:8080").
            path:     Path to probe (e.g. "admin/login").

        Returns:
            Finding dict if the path returns a notable status code, else None.
        """
        # Normalise path — ensure single leading slash, no double slashes
        clean_path = "/" + path.lstrip("/")
        url = base_url.rstrip("/") + clean_path

        try:
            response = await client.head(
                url,
                follow_redirects=True,
                timeout=self.timeout,
            )

            # Some servers return 405 for HEAD but serve GET normally
            if response.status_code == 405:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=self.timeout,
                )

            status = response.status_code

            if status not in FINDING_STATUS_CODES:
                return None

            note = STATUS_NOTES.get(status, f"HTTP {status}")
            finding = {
                "url":         url,
                "path":        clean_path,
                "status_code": status,
                "note":        note,
            }

            # Choose log level based on severity of finding
            if status in (200, 401, 403, 500):
                log.warning(f"  [{status}] {url}  —  {note}")
            else:
                log.info(f"  [{status}] {url}  —  {note}")

            return finding

        except httpx.TimeoutException:
            log.debug(f"  Timeout: {url}")
            return None
        except httpx.RequestError:
            # Connection refused, DNS failure, etc. — expected for most paths
            return None
        except Exception as exc:
            log.debug(f"  Unexpected error checking {url}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Per-port scan
    # ------------------------------------------------------------------

    async def scan_port(
        self,
        client: httpx.AsyncClient,
        target: str,
        port: int,
    ) -> list[dict]:
        """
        Brute-force all wordlist paths against a single web port.

        Args:
            client: Shared httpx.AsyncClient.
            target: IP address or hostname.
            port:   Web port to scan.

        Returns:
            List of finding dicts for discovered paths.
        """
        protocol = "https" if port in (443, 8443) else "http"
        base_url = f"{protocol}://{target}:{port}"

        log.info(
            f"Directory brute-force on {base_url} "
            f"({len(self.wordlist)} paths)..."
        )

        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded_check(path: str) -> Optional[dict]:
            async with semaphore:
                return await self.check_path(client, base_url, path)

        tasks = [
            asyncio.create_task(bounded_check(path))
            for path in self.wordlist
        ]

        try:
            results = await asyncio.gather(*tasks)
        except Exception as exc:
            log.error(
                f"Directory brute-force on {base_url} encountered "
                f"a fatal error: {exc}"
            )
            return []

        findings = [r for r in results if r is not None]

        if findings:
            log.warning(
                f"Directory scan complete on {base_url}: "
                f"{len(findings)} path(s) discovered."
            )
        else:
            log.info(
                f"Directory scan complete on {base_url}: "
                "no notable paths found."
            )

        return findings

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
        Run directory brute-force against all provided web ports.

        Args:
            target:    IP address or hostname to scan.
            web_ports: List of open ports known to host web services.
            report:    Optional ReportManager to record findings.

        Returns:
            Dict mapping port number -> list of finding dicts.
            e.g. {80: [{url: "...", status_code: 200, ...}], 443: []}
        """
        if not web_ports:
            log.warning(
                "DirBruteForcer: no web ports provided — skipping."
            )
            return {}

        log.info(
            f"Starting directory brute-force on {target} "
            f"(ports: {', '.join(str(p) for p in web_ports)} | "
            f"wordlist: {len(self.wordlist)} entries)..."
        )

        # Suppress SSL warnings for self-signed certs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            async with httpx.AsyncClient(verify=False) as client:
                # Scan ports sequentially to avoid multiplying concurrency
                # (concurrency is already controlled at the path level)
                port_findings: dict[int, list[dict]] = {}
                for port in web_ports:
                    findings = await self.scan_port(client, target, port)
                    port_findings[port] = findings

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            all_findings = [
                f for findings in port_findings.values()
                for f in findings
            ]
            if all_findings:
                report.add_section(
                    "Directory Brute-Force — Discovered Paths",
                    all_findings,
                )
            else:
                report.add_section(
                    "Directory Brute-Force",
                    ["No notable paths discovered."],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        total = sum(len(v) for v in port_findings.values())
        log.info(
            f"Directory brute-force complete. "
            f"Ports scanned: {len(web_ports)} | "
            f"Total paths discovered: {total}"
        )

        return port_findings
