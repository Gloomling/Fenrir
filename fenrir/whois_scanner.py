# fenrir/modules/whois_scanner.py
#
# WHOIS lookup module.
#
# Design:
#   - Performs WHOIS lookups for domains and IP addresses.
#   - For domains: retrieves registrar, dates, nameservers, registrant info.
#   - For IP addresses: retrieves ASN, network range, organisation, country.
#   - Uses python-whois (whois) library, which is synchronous — all calls
#     are offloaded to a thread via asyncio.to_thread().
#   - Structured fields are extracted and logged individually when present.
#   - Raw WHOIS text is included as a fallback when structured fields are
#     absent or incomplete (e.g. privacy-protected domains, ccTLDs with
#     non-standard WHOIS formats).
#   - Expiry date proximity check: warns if the domain expires within
#     90 days — relevant for takeover or social engineering opportunities.
#   - Privacy protection detection: flags domains using WHOIS privacy
#     services (e.g. Domains By Proxy, WhoisGuard, PrivacyProtect).
#   - All findings are added to the ReportManager.
#
# Note on IP WHOIS:
#   python-whois handles IP lookups differently from domain lookups.
#   For IPs we fall back to the raw text output since structured parsing
#   is unreliable across RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC).

import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import Optional, Union

import whois

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Warn if domain expires within this many days
EXPIRY_WARNING_DAYS = 90

# Known WHOIS privacy service keywords — presence in registrant fields
# indicates the domain owner is hidden behind a privacy proxy
PRIVACY_KEYWORDS: list[str] = [
    "whoisguard", "privacyprotect", "domains by proxy", "perfect privacy",
    "contact privacy", "withheld for privacy", "data protected",
    "redacted for privacy", "identity protect", "private registration",
    "proxy protection", "anonymous speech", "namecheap", "cloudflare",
    "gdpr masked", "privacy service",
]


class WhoisScanner:
    """
    Performs WHOIS lookups for domains and IP addresses.

    Args:
        timeout (float): Timeout for the WHOIS query in seconds. Default 15.0.
                         WHOIS servers can be slow — a generous timeout avoids
                         false failures.
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        log.debug(f"WhoisScanner initialised. Timeout: {timeout}s")

    # ------------------------------------------------------------------
    # Target type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ip_address(target: str) -> bool:
        """
        Return True if target is a valid IPv4 or IPv6 address.

        Args:
            target: String to test.

        Returns:
            True if valid IP, False if domain or invalid.
        """
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Domain WHOIS
    # ------------------------------------------------------------------

    async def lookup_domain(self, domain: str) -> dict:
        """
        Perform a WHOIS lookup for a domain name.

        Args:
            domain: Domain name (e.g. "example.com").

        Returns:
            Dict containing structured WHOIS fields and raw text fallback.
        """
        log.info(f"Performing domain WHOIS lookup for '{domain}'...")

        def _query() -> Optional[whois.WhoisEntry]:
            try:
                return whois.whois(domain)
            except Exception as exc:
                log.debug(f"WHOIS query exception for '{domain}': {exc}")
                return None

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_query),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            log.error(
                f"WHOIS lookup timed out for '{domain}' "
                f"after {self.timeout}s."
            )
            return {"target": domain, "error": "timeout", "raw": ""}
        except Exception as exc:
            log.error(f"Unexpected error during WHOIS lookup for '{domain}': {exc}")
            return {"target": domain, "error": str(exc), "raw": ""}

        if result is None:
            log.warning(f"WHOIS returned no data for '{domain}'.")
            return {"target": domain, "error": "no_data", "raw": ""}

        # ------------------------------------------------------------------
        # Extract structured fields
        # ------------------------------------------------------------------
        finding = {
            "target":       domain,
            "type":         "domain",
            "registrar":    _safe_str(result.registrar),
            "created":      _safe_date(result.creation_date),
            "expires":      _safe_date(result.expiration_date),
            "updated":      _safe_date(result.updated_date),
            "status":       _safe_list(result.status),
            "name_servers": _safe_list(result.name_servers),
            "emails":       _safe_list(result.emails),
            "registrant":   _safe_str(getattr(result, "registrant", None)),
            "org":          _safe_str(getattr(result, "org", None)),
            "country":      _safe_str(getattr(result, "country", None)),
            "dnssec":       _safe_str(getattr(result, "dnssec", None)),
            "privacy":      False,
            "raw":          _safe_str(result.text) if hasattr(result, "text") else "",
        }

        # ------------------------------------------------------------------
        # Log structured fields
        # ------------------------------------------------------------------
        log.info("WHOIS results:")

        if finding["registrar"]:
            log.info(f"  Registrar     : {finding['registrar']}")
        if finding["created"]:
            log.info(f"  Created       : {finding['created']}")
        if finding["expires"]:
            log.info(f"  Expires       : {finding['expires']}")
        if finding["updated"]:
            log.info(f"  Updated       : {finding['updated']}")
        if finding["registrant"]:
            log.info(f"  Registrant    : {finding['registrant']}")
        if finding["org"]:
            log.info(f"  Organisation  : {finding['org']}")
        if finding["country"]:
            log.info(f"  Country       : {finding['country']}")
        if finding["dnssec"]:
            log.info(f"  DNSSEC        : {finding['dnssec']}")
        if finding["name_servers"]:
            log.info(f"  Name Servers  : {', '.join(finding['name_servers'])}")
        if finding["emails"]:
            log.warning(f"  Emails found  : {', '.join(finding['emails'])}")
        if finding["status"]:
            log.info(f"  Status        : {', '.join(finding['status'][:3])}")

        # ------------------------------------------------------------------
        # Expiry proximity warning
        # ------------------------------------------------------------------
        expiry_str = finding.get("expires", "")
        if expiry_str and expiry_str != "N/A":
            try:
                # Handle both date and datetime objects
                expiry_dt = result.expiration_date
                if isinstance(expiry_dt, list):
                    expiry_dt = expiry_dt[0]
                if isinstance(expiry_dt, datetime):
                    # Make timezone-aware if naive
                    if expiry_dt.tzinfo is None:
                        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (expiry_dt - now).days
                    if days_remaining < 0:
                        log.warning(
                            f"  [EXPIRED] Domain '{domain}' expired "
                            f"{abs(days_remaining)} day(s) ago!"
                        )
                        finding["expiry_warning"] = "EXPIRED"
                    elif days_remaining <= EXPIRY_WARNING_DAYS:
                        log.warning(
                            f"  [EXPIRY WARNING] Domain '{domain}' expires "
                            f"in {days_remaining} day(s). "
                            "Potential domain takeover opportunity."
                        )
                        finding["expiry_warning"] = f"expires_in_{days_remaining}_days"
            except Exception as exc:
                log.debug(f"Expiry date calculation failed: {exc}")

        # ------------------------------------------------------------------
        # Privacy protection detection
        # ------------------------------------------------------------------
        privacy_check_fields = [
            finding.get("registrant", ""),
            finding.get("org", ""),
            finding.get("registrar", ""),
            " ".join(finding.get("emails", [])),
        ]
        combined = " ".join(str(f) for f in privacy_check_fields).lower()

        if any(kw in combined for kw in PRIVACY_KEYWORDS):
            log.warning(
                f"  [PRIVACY PROTECTED] Domain '{domain}' appears to use "
                "a WHOIS privacy service. Registrant details are masked."
            )
            finding["privacy"] = True

        # ------------------------------------------------------------------
        # Raw text fallback
        # ------------------------------------------------------------------
        # Log raw text if structured fields are mostly empty
        structured_fields = [
            finding["registrar"], finding["created"],
            finding["expires"], finding["registrant"],
        ]
        has_structured = any(
            f and f != "N/A" for f in structured_fields
        )

        if not has_structured:
            log.warning(
                f"Structured WHOIS data unavailable for '{domain}'. "
                "Falling back to raw WHOIS text:"
            )
            if finding["raw"]:
                # Log first 50 lines of raw text
                raw_lines = finding["raw"].splitlines()
                for line in raw_lines[:50]:
                    if line.strip():
                        log.info(f"  {line}")
                if len(raw_lines) > 50:
                    log.info(
                        f"  ... ({len(raw_lines) - 50} more lines — "
                        "see report for full output)"
                    )
            else:
                log.warning("  No raw WHOIS text available.")

        return finding

    # ------------------------------------------------------------------
    # IP WHOIS
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip_address: str) -> dict:
        """
        Perform a WHOIS lookup for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict containing raw WHOIS text and any extractable fields.
        """
        log.info(f"Performing IP WHOIS lookup for '{ip_address}'...")

        def _query() -> Optional[whois.WhoisEntry]:
            try:
                return whois.whois(ip_address)
            except Exception as exc:
                log.debug(f"IP WHOIS query exception for '{ip_address}': {exc}")
                return None

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_query),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            log.error(
                f"IP WHOIS lookup timed out for '{ip_address}' "
                f"after {self.timeout}s."
            )
            return {"target": ip_address, "error": "timeout", "raw": ""}
        except Exception as exc:
            log.error(
                f"Unexpected error during IP WHOIS for '{ip_address}': {exc}"
            )
            return {"target": ip_address, "error": str(exc), "raw": ""}

        if result is None:
            log.warning(f"IP WHOIS returned no data for '{ip_address}'.")
            return {"target": ip_address, "error": "no_data", "raw": ""}

        # For IP WHOIS, structured field availability varies widely by RIR.
        # We extract what we can and always include raw text.
        finding = {
            "target":       ip_address,
            "type":         "ip",
            "org":          _safe_str(getattr(result, "org", None)),
            "country":      _safe_str(getattr(result, "country", None)),
            "nets":         _safe_list(getattr(result, "nets", None)),
            "asn":          _safe_str(getattr(result, "asn", None)),
            "asn_cidr":     _safe_str(getattr(result, "asn_cidr", None)),
            "asn_country":  _safe_str(getattr(result, "asn_country_code", None)),
            "asn_registry": _safe_str(getattr(result, "asn_registry", None)),
            "raw":          _safe_str(result.text) if hasattr(result, "text") else "",
        }

        log.info("IP WHOIS results:")
        if finding["org"]:
            log.warning(f"  Organisation  : {finding['org']}")
        if finding["country"]:
            log.info(f"  Country       : {finding['country']}")
        if finding["asn"]:
            log.info(f"  ASN           : {finding['asn']}")
        if finding["asn_cidr"]:
            log.info(f"  CIDR          : {finding['asn_cidr']}")
        if finding["asn_registry"]:
            log.info(f"  Registry (RIR): {finding['asn_registry']}")

        # Always log raw text for IP WHOIS (structured parsing is unreliable)
        if finding["raw"]:
            log.info("  Raw WHOIS output:")
            raw_lines = finding["raw"].splitlines()
            for line in raw_lines[:40]:
                if line.strip() and not line.strip().startswith("%"):
                    log.info(f"    {line}")
            if len(raw_lines) > 40:
                log.info(
                    f"    ... ({len(raw_lines) - 40} more lines in report)"
                )
        else:
            # Try raw text fallback if structured also failed
            log.warning(
                f"No WHOIS data found for '{ip_address}'. "
                "The IP may be private, reserved, or the WHOIS server "
                "may be unreachable."
            )

        return finding

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run a WHOIS lookup for a domain or IP address.

        Automatically detects whether the target is an IP address or domain
        and routes to the appropriate lookup method.

        Args:
            target: Domain name or IP address to look up.
            report: Optional ReportManager to record findings.

        Returns:
            Finding dict (see lookup_domain / lookup_ip return values).
        """
        log.info(f"Starting WHOIS lookup for '{target}'...")

        if self._is_ip_address(target):
            finding = await self.lookup_ip(target)
        else:
            finding = await self.lookup_domain(target)

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            if finding.get("error"):
                report.add_section(
                    "WHOIS Lookup",
                    [f"WHOIS lookup failed for '{target}': {finding['error']}"],
                )
            else:
                # Store a clean copy without the (potentially huge) raw field
                # in the primary section, then add raw as a separate section
                summary = {
                    k: v for k, v in finding.items()
                    if k != "raw"
                }
                report.add_section("WHOIS Information", [summary])

                if finding.get("raw"):
                    report.add_section(
                        "WHOIS Raw Text",
                        [finding["raw"]],
                    )

        log.info("WHOIS lookup finished.")
        return finding


# ---------------------------------------------------------------------------
# Safe extraction helpers
# ---------------------------------------------------------------------------

def _safe_str(value) -> str:
    """
    Safely convert a value to a string.

    Handles None, lists (takes first element), and datetime objects.
    Returns "N/A" for None or empty values.
    """
    if value is None:
        return "N/A"
    if isinstance(value, list):
        if not value:
            return "N/A"
        value = value[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    result = str(value).strip()
    return result if result else "N/A"


def _safe_date(value) -> str:
    """
    Safely convert a date/datetime value (or list of them) to a string.

    python-whois sometimes returns a list of datetime objects for fields
    like creation_date when multiple dates are present in the WHOIS record.
    We take the first non-None value.
    """
    if value is None:
        return "N/A"
    if isinstance(value, list):
        # Filter out None values and take the first
        valid = [v for v in value if v is not None]
        if not valid:
            return "N/A"
        value = valid[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value).strip() or "N/A"


def _safe_list(value) -> list[str]:
    """
    Safely convert a value to a list of strings.

    Handles None, single values, and existing lists.
    Deduplicates and lowercases for consistency (useful for name_servers).
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        seen = set()
        result = []
        for item in value:
            if item is None:
                continue
            s = str(item).strip().lower()
            if s and s not in seen:
                seen.add(s)
                result.append(str(item).strip())
        return result
    return [str(value).strip()]
