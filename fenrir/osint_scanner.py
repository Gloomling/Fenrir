# fenrir/modules/osint_scanner.py
#
# OSINT (Open Source Intelligence) gathering module.
#
# Design:
#   - Gathers publicly available information about a target domain through
#     multiple passive reconnaissance techniques.
#   - Sources:
#       1. DuckDuckGo HTML search — email address harvesting, document discovery
#       2. Bing search (fallback/supplement) — alternative search engine
#       3. theHarvester integration — shells out to theHarvester if installed,
#          providing comprehensive email/subdomain/hostname harvesting
#       4. crt.sh certificate transparency — discovers subdomains via SSL
#          certificate records (highly reliable, no scraping fragility)
#       5. HaveIBeenPwned (HIBP) — checks if discovered emails appear in
#          known data breaches (no API key required for domain search)
#   - Known limitation: search engine scraping is inherently fragile.
#     DDG and Bing change their HTML structure without notice. When scraping
#     produces no results, an explicit note is logged explaining this may be
#     a scraping limitation rather than a true negative.
#   - crt.sh is the most reliable source as it queries a structured API.
#   - All findings are deduplicated before reporting.
#   - All findings are added to the ReportManager.
#
# theHarvester:
#   Optional external tool. If installed ('pip install theHarvester' or via
#   apt), it is called as a subprocess. Results are parsed from its output.
#   Skip gracefully if not found in PATH.

import asyncio
import json
import re
import shutil
import warnings
from typing import Optional

import httpx
from bs4 import BeautifulSoup

from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex for email address extraction
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# Common document file extensions to search for
DOCUMENT_FILETYPES: list[str] = [
    "pdf", "docx", "doc", "xlsx", "xls",
    "pptx", "ppt", "txt", "csv", "xml",
]

# Request headers to mimic a real browser (reduces bot detection)
BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


class OsintScanner:
    """
    Performs passive OSINT gathering for a target domain.

    Sources used:
      - DuckDuckGo HTML (email + document search)
      - Bing HTML (supplement/fallback for emails)
      - crt.sh certificate transparency logs (subdomain discovery)
      - theHarvester (if installed)
      - HaveIBeenPwned domain search (breach exposure)

    Args:
        timeout (float): HTTP request timeout in seconds. Default 15.0.
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self.harvester_path = shutil.which("theHarvester")
        log.debug(
            f"OsintScanner initialised. "
            f"Timeout: {timeout}s | "
            f"theHarvester: {'found' if self.harvester_path else 'not installed'}"
        )

    # ------------------------------------------------------------------
    # Source 1: DuckDuckGo — email harvesting
    # ------------------------------------------------------------------

    async def _search_ddg(
        self,
        client: httpx.AsyncClient,
        query: str,
    ) -> str:
        """
        Submit a query to DuckDuckGo HTML and return the page text.

        Args:
            client: Shared httpx.AsyncClient.
            query:  Search query string.

        Returns:
            Page HTML as string, or empty string on failure.
        """
        try:
            response = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query},
                headers=BROWSER_HEADERS,
                timeout=self.timeout,
                follow_redirects=True,
            )
            if response.status_code == 200:
                return response.text
            log.debug(
                f"DDG returned status {response.status_code} "
                f"for query '{query[:50]}'."
            )
        except httpx.RequestError as exc:
            log.debug(f"DDG request error for query '{query[:50]}': {exc}")
        except Exception as exc:
            log.debug(f"DDG unexpected error: {exc}")
        return ""

    async def _search_bing(
        self,
        client: httpx.AsyncClient,
        query: str,
    ) -> str:
        """
        Submit a query to Bing and return the page text.

        Args:
            client: Shared httpx.AsyncClient.
            query:  Search query string.

        Returns:
            Page HTML as string, or empty string on failure.
        """
        try:
            response = await client.get(
                "https://www.bing.com/search",
                params={"q": query},
                headers=BROWSER_HEADERS,
                timeout=self.timeout,
                follow_redirects=True,
            )
            if response.status_code == 200:
                return response.text
            log.debug(
                f"Bing returned status {response.status_code} "
                f"for query '{query[:50]}'."
            )
        except httpx.RequestError as exc:
            log.debug(f"Bing request error for query '{query[:50]}': {exc}")
        except Exception as exc:
            log.debug(f"Bing unexpected error: {exc}")
        return ""

    async def find_emails(
        self,
        client: httpx.AsyncClient,
        domain: str,
    ) -> set[str]:
        """
        Search for email addresses associated with the target domain.

        Queries both DuckDuckGo and Bing, extracts emails from the combined
        HTML, and filters to only those belonging to the target domain.

        Args:
            client: Shared httpx.AsyncClient.
            domain: Target domain (e.g. "example.com").

        Returns:
            Set of discovered email address strings.
        """
        log.info(f"Searching for email addresses @{domain}...")

        query = f'"@{domain}" email'
        ddg_html  = await self._search_ddg(client, query)
        bing_html = await self._search_bing(client, query)

        combined_html = ddg_html + bing_html
        found_emails: set[str] = set()

        if combined_html:
            all_emails = set(EMAIL_REGEX.findall(combined_html))
            # Filter to target domain only, exclude common noise
            found_emails = {
                email.lower() for email in all_emails
                if email.lower().endswith(f"@{domain.lower()}")
                and "example" not in email.lower()
            }

        if found_emails:
            log.warning(
                f"Found {len(found_emails)} potential email address(es) "
                f"for @{domain}:"
            )
            for email in sorted(found_emails):
                log.warning(f"  {email}")
        else:
            log.info(
                f"No email addresses found for @{domain} via search engines. "
                "Note: search engine scraping may be blocked or rate-limited — "
                "a negative result does not guarantee no emails exist."
            )

        return found_emails

    # ------------------------------------------------------------------
    # Source 2: Document discovery
    # ------------------------------------------------------------------

    async def find_documents(
        self,
        client: httpx.AsyncClient,
        domain: str,
    ) -> set[str]:
        """
        Search for publicly exposed documents related to the domain.

        Uses filetype: operators in DDG/Bing to find indexed documents.
        Attempts to extract direct URLs from search result links.

        Args:
            client: Shared httpx.AsyncClient.
            domain: Target domain.

        Returns:
            Set of discovered document URL strings.
        """
        log.info(f"Searching for exposed documents for '{domain}'...")

        document_urls: set[str] = set()
        ft_query = " OR ".join(f"filetype:{ft}" for ft in DOCUMENT_FILETYPES)
        query = f"site:{domain} ({ft_query})"

        ddg_html  = await self._search_ddg(client, query)
        bing_html = await self._search_bing(client, query)

        for html_content in [ddg_html, bing_html]:
            if not html_content:
                continue

            soup = BeautifulSoup(html_content, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = tag["href"]

                # DDG wraps result URLs in redirects like:
                # //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc.pdf
                # We need to decode these
                if "uddg=" in href:
                    try:
                        from urllib.parse import unquote, urlparse, parse_qs
                        parsed = urlparse(href)
                        params = parse_qs(parsed.query)
                        if "uddg" in params:
                            href = unquote(params["uddg"][0])
                    except Exception:
                        pass

                # Filter for actual document URLs
                href_lower = href.lower()
                if (
                    domain.lower() in href_lower
                    and any(
                        href_lower.endswith(f".{ft}")
                        or f".{ft}?" in href_lower
                        for ft in DOCUMENT_FILETYPES
                    )
                    and href.startswith("http")
                ):
                    document_urls.add(href)

        if document_urls:
            log.warning(
                f"Found {len(document_urls)} potentially exposed document(s):"
            )
            for doc in sorted(document_urls):
                log.warning(f"  {doc}")
        else:
            log.info(
                f"No exposed documents found for '{domain}' via search engines. "
                "Note: DDG redirect wrapping and rate limiting may cause "
                "false negatives — manually verify with Google dorks if needed."
            )

        return document_urls

    # ------------------------------------------------------------------
    # Source 3: crt.sh certificate transparency
    # ------------------------------------------------------------------

    async def search_crtsh(
        self,
        client: httpx.AsyncClient,
        domain: str,
    ) -> set[str]:
        """
        Query crt.sh for subdomains via SSL certificate transparency logs.

        crt.sh indexes all publicly trusted SSL certificates, which often
        reveal internal subdomains, staging environments, and infrastructure
        hostnames that wouldn't appear in DNS enumeration.

        This is the most reliable OSINT source as it queries a structured
        JSON API rather than scraping search engine HTML.

        Args:
            client: Shared httpx.AsyncClient.
            domain: Target domain.

        Returns:
            Set of discovered hostnames from certificate records.
        """
        log.info(f"Querying crt.sh for SSL certificate records on '{domain}'...")

        subdomains: set[str] = set()

        try:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
                timeout=self.timeout,
                follow_redirects=True,
            )

            if response.status_code != 200:
                log.warning(
                    f"crt.sh returned HTTP {response.status_code} "
                    f"for '{domain}'."
                )
                return subdomains

            try:
                records = response.json()
            except json.JSONDecodeError as exc:
                log.warning(f"crt.sh returned invalid JSON for '{domain}': {exc}")
                return subdomains

            for record in records:
                # name_value may contain multiple names separated by newlines
                name_value = record.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Filter out wildcards and non-subdomain entries
                    if (
                        name
                        and name.endswith(f".{domain.lower()}")
                        and "*" not in name
                        and name != domain.lower()
                    ):
                        subdomains.add(name)

            if subdomains:
                log.warning(
                    f"crt.sh: found {len(subdomains)} subdomain(s) in "
                    "certificate transparency logs:"
                )
                for sub in sorted(subdomains):
                    log.warning(f"  {sub}")
            else:
                log.info(
                    f"crt.sh: no subdomain certificates found for '{domain}'."
                )

        except httpx.TimeoutException:
            log.warning(
                f"crt.sh query timed out for '{domain}'. "
                "The service may be temporarily unavailable."
            )
        except httpx.RequestError as exc:
            log.warning(f"crt.sh request error for '{domain}': {exc}")
        except Exception as exc:
            log.error(f"crt.sh unexpected error for '{domain}': {exc}")

        return subdomains

    # ------------------------------------------------------------------
    # Source 4: theHarvester
    # ------------------------------------------------------------------

    async def run_theharvester(self, domain: str) -> dict:
        """
        Run theHarvester against the target domain if it is installed.

        theHarvester aggregates results from multiple sources including
        Google, Bing, LinkedIn, Shodan, and others.

        Args:
            domain: Target domain.

        Returns:
            Dict with keys: emails (list), hosts (list), ips (list).
            All empty if theHarvester is not installed or fails.
        """
        results = {"emails": [], "hosts": [], "ips": []}

        if not self.harvester_path:
            log.info(
                "theHarvester not found in PATH — skipping. "
                "Install with: pip install theHarvester"
            )
            return results

        log.info(f"Running theHarvester against '{domain}'...")

        command = [
            self.harvester_path,
            "-d", domain,
            "-b", "bing,duckduckgo,crtsh",  # Sources that don't require API keys
            "-f", "/tmp/fenrir_harvester_output",  # Output file
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=120,  # theHarvester can be slow
                )
            except asyncio.TimeoutError:
                process.kill()
                log.warning("theHarvester timed out after 120s — killing process.")
                return results

            output = stdout.decode("utf-8", errors="replace")

            # Parse emails from output
            emails_found = set(EMAIL_REGEX.findall(output))
            results["emails"] = sorted(
                e for e in emails_found
                if e.lower().endswith(f"@{domain.lower()}")
            )

            # Parse hosts/IPs — look for lines containing the domain
            host_pattern = re.compile(
                r"([\w\-\.]+\." + re.escape(domain) + r")",
                re.IGNORECASE,
            )
            ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

            hosts_found = set(host_pattern.findall(output))
            ips_found   = set(ip_pattern.findall(output))

            results["hosts"] = sorted(hosts_found)
            results["ips"]   = sorted(ips_found)

            if any(results.values()):
                log.warning("theHarvester results:")
                if results["emails"]:
                    log.warning(
                        f"  Emails  : {len(results['emails'])} found"
                    )
                if results["hosts"]:
                    log.warning(
                        f"  Hosts   : {len(results['hosts'])} found"
                    )
                if results["ips"]:
                    log.warning(
                        f"  IPs     : {len(results['ips'])} found"
                    )
            else:
                log.info("theHarvester returned no results.")

        except FileNotFoundError:
            log.warning(
                "theHarvester binary not found at expected path. "
                "Ensure it is installed and in PATH."
            )
        except Exception as exc:
            log.error(f"theHarvester encountered an error: {exc}")

        return results

    # ------------------------------------------------------------------
    # Source 5: HaveIBeenPwned domain search
    # ------------------------------------------------------------------

    async def check_hibp(
        self,
        client: httpx.AsyncClient,
        domain: str,
    ) -> list[dict]:
        """
        Check HaveIBeenPwned for breach exposure related to the domain.

        Uses the HIBP v3 API domain search endpoint. No API key required
        for this endpoint (as of the current API version).

        Args:
            client: Shared httpx.AsyncClient.
            domain: Target domain.

        Returns:
            List of breach dicts: {name, date, count, description}.
        """
        log.info(f"Checking HaveIBeenPwned for breaches related to '{domain}'...")

        breaches = []
        try:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                params={"domain": domain},
                headers={
                    **BROWSER_HEADERS,
                    "hibp-api-key": "",   # Placeholder — domain search is free
                },
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                for breach in data:
                    breaches.append({
                        "name":          breach.get("Name", ""),
                        "domain":        breach.get("Domain", ""),
                        "breach_date":   breach.get("BreachDate", ""),
                        "pwn_count":     breach.get("PwnCount", 0),
                        "description":   BeautifulSoup(
                            breach.get("Description", ""), "html.parser"
                        ).get_text()[:200],
                        "data_classes":  breach.get("DataClasses", []),
                    })

                if breaches:
                    log.warning(
                        f"HIBP: '{domain}' appears in "
                        f"{len(breaches)} known breach(es)!"
                    )
                    for b in breaches:
                        log.warning(
                            f"  [{b['breach_date']}] {b['name']}  "
                            f"— {b['pwn_count']:,} accounts compromised"
                        )
                        if b["data_classes"]:
                            log.warning(
                                f"    Data types: "
                                f"{', '.join(b['data_classes'][:5])}"
                            )
                else:
                    log.info(
                        f"HIBP: no breaches found for domain '{domain}'."
                    )

            elif response.status_code == 404:
                log.info(
                    f"HIBP: no breaches found for domain '{domain}'."
                )
            elif response.status_code == 429:
                log.warning(
                    "HIBP: rate limited. Wait a moment before retrying."
                )
            else:
                log.warning(
                    f"HIBP returned HTTP {response.status_code} "
                    f"for domain '{domain}'."
                )

        except httpx.RequestError as exc:
            log.warning(f"HIBP request error: {exc}")
        except Exception as exc:
            log.error(f"HIBP unexpected error: {exc}")

        return breaches

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target_domain: str,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run all OSINT gathering techniques against the target domain.

        Args:
            target_domain: Root domain to investigate (e.g. "example.com").
            report:        Optional ReportManager to record findings.

        Returns:
            Dict with keys:
              emails      (set[str])   — discovered email addresses
              documents   (set[str])   — discovered document URLs
              crtsh_subs  (set[str])   — subdomains from cert transparency
              harvester   (dict)       — theHarvester results
              breaches    (list[dict]) — HIBP breach records
        """
        domain = target_domain.strip().lower()

        log.info(f"Starting OSINT scan for '{domain}'...")
        log.info(
            "Note: OSINT sources include search engine scraping which may "
            "be rate-limited or blocked. Negative results should be "
            "manually verified."
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
            ) as client:

                # Run all HTTP-based sources concurrently
                (
                    emails,
                    documents,
                    crtsh_subs,
                    breaches,
                ) = await asyncio.gather(
                    self.find_emails(client, domain),
                    self.find_documents(client, domain),
                    self.search_crtsh(client, domain),
                    self.check_hibp(client, domain),
                )

        # theHarvester runs as a subprocess — separately from the HTTP client
        harvester_results = await self.run_theharvester(domain)

        # Merge emails from all sources
        all_emails = emails.copy()
        if harvester_results.get("emails"):
            harvester_emails = {
                e for e in harvester_results["emails"]
                if e.lower().endswith(f"@{domain}")
            }
            new_emails = harvester_emails - all_emails
            if new_emails:
                log.warning(
                    f"theHarvester found {len(new_emails)} additional email(s):"
                )
                for e in sorted(new_emails):
                    log.warning(f"  {e}")
            all_emails.update(harvester_emails)

        # Merge subdomains from crt.sh and theHarvester
        all_subdomains = crtsh_subs.copy()
        if harvester_results.get("hosts"):
            all_subdomains.update(harvester_results["hosts"])

        results = {
            "emails":     all_emails,
            "documents":  documents,
            "crtsh_subs": crtsh_subs,
            "harvester":  harvester_results,
            "breaches":   breaches,
        }

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            if all_emails:
                report.add_section(
                    "OSINT — Email Addresses",
                    sorted(all_emails),
                )
            if documents:
                report.add_section(
                    "OSINT — Exposed Documents",
                    sorted(documents),
                )
            if all_subdomains:
                report.add_section(
                    "OSINT — Certificate Transparency Subdomains",
                    sorted(all_subdomains),
                )
            if breaches:
                report.add_section(
                    "OSINT — Data Breach Exposure (HIBP)",
                    breaches,
                )
            if harvester_results.get("ips"):
                report.add_section(
                    "OSINT — IP Addresses (theHarvester)",
                    harvester_results["ips"],
                )

            # Always add a summary section
            report.add_section(
                "OSINT — Summary",
                [{
                    "emails_found":      len(all_emails),
                    "documents_found":   len(documents),
                    "crtsh_subdomains":  len(crtsh_subs),
                    "hibp_breaches":     len(breaches),
                    "harvester_emails":  len(harvester_results.get("emails", [])),
                    "harvester_hosts":   len(harvester_results.get("hosts", [])),
                }],
            )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        log.info("OSINT scan complete.")
        log.info(f"  Email addresses  : {len(all_emails)}")
        log.info(f"  Documents        : {len(documents)}")
        log.info(f"  CT subdomains    : {len(crtsh_subs)}")
        log.info(f"  HIBP breaches    : {len(breaches)}")

        return results
