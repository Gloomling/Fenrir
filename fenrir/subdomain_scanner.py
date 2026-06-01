# fenrir/modules/subdomain_scanner.py
#
# Subdomain enumeration module.
#
# Design:
#   - Resolves candidate subdomains by performing DNS A record lookups.
#   - Wordlist source priority:
#       1. User-supplied file path (--wordlist /path/to/list.txt)
#       2. Built-in default wordlist (defined in this module)
#   - Resolution uses asyncio.to_thread(socket.getaddrinfo) rather than
#     socket.gethostbyname for richer return data (supports IPv4 + IPv6)
#     while remaining non-blocking.
#   - Concurrency is semaphore-controlled (default 50 simultaneous lookups).
#   - Wildcard DNS detection: before scanning, resolves a random non-existent
#     subdomain. If it resolves, the domain has wildcard DNS configured and
#     all results would be false positives — the user is warned and the scan
#     is aborted unless forced.
#   - Each found subdomain is reverse-resolved to confirm and enrich results.
#   - All findings are added to the ReportManager.
#
# Wordlist files: one subdomain prefix per line, comments with '#' are skipped.

import asyncio
import random
import socket
import string
from pathlib import Path
from typing import Optional

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Built-in default wordlist
# ---------------------------------------------------------------------------
# Common subdomain prefixes used across web applications, infrastructure,
# mail systems, APIs, and development environments.

DEFAULT_WORDLIST: list[str] = [
    # Core web
    "www", "www2", "www3", "web", "website", "site",
    # Mail
    "mail", "smtp", "pop", "pop3", "imap", "email", "mx",
    "webmail", "autodiscover", "autoconfig", "exchange",
    # DNS / infrastructure
    "ns", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2",
    "ftp", "sftp", "ftps",
    "ssh", "vpn", "remote",
    # Control panels
    "cpanel", "whm", "plesk", "directadmin", "hosting",
    "webdisk", "webdav",
    # APIs and services
    "api", "api2", "apis", "rest", "graphql",
    "ws", "websocket", "socket",
    "cdn", "cdn1", "cdn2", "static", "assets", "media",
    "img", "images", "video", "stream",
    "download", "downloads", "upload", "uploads",
    # Application environments
    "dev", "development", "develop",
    "test", "testing", "qa", "uat",
    "staging", "stage", "stg",
    "sandbox", "preview", "demo",
    "beta", "alpha", "rc",
    "old", "legacy", "archive",
    "new", "next", "v2",
    # Authentication / identity
    "auth", "login", "sso", "oauth",
    "id", "identity", "account", "accounts",
    "portal", "secure", "security",
    "admin", "administrator", "manage", "management",
    "dashboard", "panel", "cp",
    "staff", "internal", "intranet",
    "corp", "corporate",
    # Monitoring / ops
    "monitor", "monitoring", "metrics",
    "status", "health", "uptime",
    "log", "logs", "logging",
    "grafana", "kibana", "elastic", "splunk",
    "jenkins", "ci", "cd", "build", "deploy",
    "git", "gitlab", "github", "bitbucket", "svn",
    "jira", "confluence", "wiki", "docs",
    # Databases / data
    "db", "database", "mysql", "postgres", "mongo",
    "redis", "cache", "memcache", "elastic",
    "data", "analytics", "reporting", "report",
    # Cloud / containers
    "k8s", "kubernetes", "docker", "registry",
    "consul", "vault", "nomad",
    "aws", "azure", "gcp",
    # Communication
    "chat", "slack", "teams", "support",
    "help", "helpdesk", "ticket", "tickets",
    "forum", "community", "blog", "news",
    # eCommerce / payments
    "shop", "store", "cart", "checkout",
    "pay", "payment", "payments", "billing",
    # Misc common
    "app", "apps", "mobile", "m",
    "gateway", "proxy", "lb", "loadbalancer",
    "backup", "bkp", "dr", "failover",
    "noc", "ops", "sre",
    "search", "solr",
    "office", "meet", "video",
    "mx1", "mx2", "relay", "bounce",
    "smtp1", "smtp2", "mail1", "mail2",
]


class SubdomainScanner:
    """
    Performs subdomain enumeration via DNS resolution.

    Args:
        wordlist_path (str | Path | None):
            Path to a custom wordlist file (one prefix per line).
            If None, the built-in DEFAULT_WORDLIST is used.
        concurrency (int):
            Maximum simultaneous DNS lookups. Default 50.
        timeout (float):
            DNS resolution timeout per subdomain in seconds. Default 3.0.
        force (bool):
            If True, continue scanning even if wildcard DNS is detected.
            Default False.
    """

    def __init__(
        self,
        wordlist_path: Optional[Path | str] = None,
        concurrency: int = 50,
        timeout: float = 3.0,
        force: bool = False,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.force = force
        self.wordlist = self._load_wordlist(wordlist_path)

        log.debug(
            f"SubdomainScanner initialised. "
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
        Load the wordlist from a file or return the built-in default.

        Args:
            wordlist_path: Path to wordlist file, or None for built-in.

        Returns:
            List of subdomain prefix strings.
        """
        if wordlist_path is None:
            log.debug("SubdomainScanner: using built-in default wordlist.")
            return DEFAULT_WORDLIST

        path = Path(wordlist_path)

        if not path.exists():
            log.warning(
                f"SubdomainScanner: wordlist not found at '{path}'. "
                "Falling back to built-in default."
            )
            return DEFAULT_WORDLIST

        if not path.is_file():
            log.warning(
                f"SubdomainScanner: '{path}' is not a file. "
                "Falling back to built-in default."
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
                    # Strip any accidental dots — we join with domain ourselves
                    entries.append(line.strip(".").lower())

            if not entries:
                log.warning(
                    f"SubdomainScanner: wordlist '{path}' is empty. "
                    "Falling back to built-in default."
                )
                return DEFAULT_WORDLIST

            log.info(
                f"SubdomainScanner: loaded {len(entries)} entries from '{path}' "
                f"({skipped} comment/blank lines skipped)."
            )
            return entries

        except OSError as exc:
            log.error(
                f"SubdomainScanner: could not read '{path}': {exc}. "
                "Falling back to built-in default."
            )
            return DEFAULT_WORDLIST

    # ------------------------------------------------------------------
    # Wildcard DNS detection
    # ------------------------------------------------------------------

    async def _check_wildcard(self, domain: str) -> bool:
        """
        Detect whether the domain has wildcard DNS configured.

        Resolves a randomly generated subdomain that almost certainly does
        not exist. If it resolves successfully, the domain is using wildcard
        DNS and enumeration results would all be false positives.

        Args:
            domain: Root domain to test (e.g. "example.com").

        Returns:
            True if wildcard DNS is detected, False otherwise.
        """
        # Generate a random 16-character subdomain prefix
        random_prefix = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=16)
        )
        test_hostname = f"{random_prefix}.{domain}"

        try:
            await asyncio.wait_for(
                asyncio.to_thread(socket.getaddrinfo, test_hostname, None),
                timeout=self.timeout,
            )
            # If we get here, the random subdomain resolved — wildcard detected
            log.warning(
                f"Wildcard DNS detected for '{domain}'! "
                f"'{test_hostname}' resolved successfully. "
                "All subdomain results may be false positives."
            )
            return True
        except (socket.gaierror, OSError):
            # Expected — random subdomain should not resolve
            return False
        except asyncio.TimeoutError:
            # Timeout on wildcard check — assume no wildcard, continue
            return False

    # ------------------------------------------------------------------
    # Single subdomain resolution
    # ------------------------------------------------------------------

    async def resolve_subdomain(
        self,
        domain: str,
        prefix: str,
    ) -> Optional[dict]:
        """
        Attempt to resolve a single subdomain via DNS.

        Args:
            domain: Root domain (e.g. "example.com").
            prefix: Subdomain prefix to test (e.g. "mail").

        Returns:
            Finding dict if the subdomain resolves, else None.
            Dict contains: hostname, prefix, ip_addresses, reverse_hostname.
        """
        hostname = f"{prefix}.{domain}"

        try:
            # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            # sockaddr is (address, port) for IPv4, (address, port, flow, scope) for IPv6
            results = await asyncio.wait_for(
                asyncio.to_thread(
                    socket.getaddrinfo,
                    hostname,
                    None,
                    socket.AF_UNSPEC,   # Both IPv4 and IPv6
                    socket.SOCK_STREAM,
                ),
                timeout=self.timeout,
            )

            # Extract unique IP addresses from results
            ip_addresses = list({r[4][0] for r in results})

            # Attempt reverse DNS lookup on the first IP
            reverse_hostname = ""
            if ip_addresses:
                try:
                    reverse_hostname = await asyncio.wait_for(
                        asyncio.to_thread(
                            socket.gethostbyaddr,
                            ip_addresses[0],
                        ),
                        timeout=self.timeout,
                    )
                    reverse_hostname = reverse_hostname[0]
                except (socket.herror, socket.gaierror, OSError):
                    reverse_hostname = ""
                except asyncio.TimeoutError:
                    reverse_hostname = ""

            finding = {
                "hostname":         hostname,
                "prefix":           prefix,
                "ip_addresses":     ip_addresses,
                "reverse_hostname": reverse_hostname,
            }

            ip_str = ", ".join(ip_addresses)
            reverse_str = f" (reverse: {reverse_hostname})" if reverse_hostname else ""
            log.warning(f"  Found: {hostname}  →  {ip_str}{reverse_str}")

            return finding

        except (socket.gaierror, OSError):
            # Subdomain does not exist — expected for most entries
            log.debug(f"  Not found: {hostname}")
            return None
        except asyncio.TimeoutError:
            log.debug(f"  Timeout: {hostname}")
            return None
        except Exception as exc:
            log.debug(f"  Error resolving {hostname}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target_domain: str,
        report: Optional[ReportManager] = None,
    ) -> list[dict]:
        """
        Run subdomain enumeration against a target domain.

        Args:
            target_domain: Root domain to enumerate (e.g. "example.com").
            report:        Optional ReportManager to record findings.

        Returns:
            Sorted list of finding dicts for discovered subdomains.
            Each dict: {hostname, prefix, ip_addresses, reverse_hostname}
        """
        # Normalise — strip any leading wildcard or dot
        domain = target_domain.lstrip("*.").lower().strip()

        log.info(
            f"Starting subdomain enumeration on '{domain}' "
            f"({len(self.wordlist)} candidates)..."
        )

        # ------------------------------------------------------------------
        # Wildcard DNS check
        # ------------------------------------------------------------------
        log.info("Checking for wildcard DNS configuration...")
        wildcard_detected = await self._check_wildcard(domain)

        if wildcard_detected:
            if self.force:
                log.warning(
                    "Wildcard DNS detected but --force is set. "
                    "Continuing — expect false positives."
                )
            else:
                log.warning(
                    "Subdomain scan aborted due to wildcard DNS. "
                    "Use --force to scan anyway (results will include false positives)."
                )
                return []
        else:
            log.info("No wildcard DNS detected — proceeding with enumeration.")

        # ------------------------------------------------------------------
        # Resolution
        # ------------------------------------------------------------------
        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded_resolve(prefix: str) -> Optional[dict]:
            async with semaphore:
                return await self.resolve_subdomain(domain, prefix)

        tasks = [
            asyncio.create_task(bounded_resolve(prefix))
            for prefix in self.wordlist
        ]

        try:
            results = await asyncio.gather(*tasks)
        except Exception as exc:
            log.error(f"Subdomain enumeration encountered a fatal error: {exc}")
            return []

        # Filter out None results and sort by hostname
        found = sorted(
            [r for r in results if r is not None],
            key=lambda x: x["hostname"],
        )

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            if found:
                report.add_section("Discovered Subdomains", found)
            else:
                report.add_section(
                    "Subdomain Enumeration",
                    [f"No subdomains discovered for '{domain}'."],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        log.info(
            f"Subdomain enumeration complete. "
            f"Candidates tested: {len(self.wordlist)} | "
            f"Discovered: {len(found)}"
        )

        if found:
            log.warning(f"Discovered {len(found)} subdomain(s):")
            for sub in found:
                ip_str = ", ".join(sub["ip_addresses"])
                log.warning(f"  {sub['hostname']:<40}  {ip_str}")

        return found
