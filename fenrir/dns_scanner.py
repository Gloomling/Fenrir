# fenrir/modules/dns_scanner.py
#
# DNS enumeration module.
#
# Design:
#   - Queries multiple DNS record types concurrently for a target domain.
#   - Record types covered:
#       A      — IPv4 addresses
#       AAAA   — IPv6 addresses
#       MX     — Mail exchange servers
#       TXT    — Text records (SPF, DKIM, DMARC, verification tokens)
#       NS     — Authoritative name servers
#       CNAME  — Canonical name aliases
#       SOA    — Start of Authority (zone info, serial, refresh intervals)
#       PTR    — Reverse DNS pointer (derived from A record IPs)
#   - Each record type has a dedicated handler that correctly parses the
#     aiodns-specific result object structure for that type.
#   - PTR lookups are performed on each IP found in A records — the target
#     domain is not used directly for PTR queries (PTR requires the reversed
#     IP in in-addr.arpa format).
#   - Zone transfer (AXFR) is attempted against each discovered NS server.
#     A successful zone transfer is a critical misconfiguration finding.
#   - All findings are added to the ReportManager in structured dict format.
#   - DNS errors (NXDOMAIN, SERVFAIL, REFUSED, etc.) are handled per-type
#     and do not abort the overall scan.
#
# aiodns result object attributes by record type:
#   A/AAAA:  result[i].host
#   MX:      result[i].host, result[i].priority
#   TXT:     result[i].text  (list of bytes — joined and decoded)
#   NS:      result[i].host
#   CNAME:   result.cname    (single result, not a list)
#   SOA:     result.nsname, result.hostmaster, result.serial,
#            result.refresh, result.retry, result.expires, result.minttl

import asyncio
import ipaddress
import socket
import struct
from typing import Optional

import aiodns

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# DNS error codes from aiodns / c-ares
# We suppress these expected "no records" errors at DEBUG level only
_NO_RECORD_ERRORS = {
    aiodns.error.ARES_ENODATA,      # No data (record type doesn't exist)
    aiodns.error.ARES_ENOTFOUND,    # Domain not found (NXDOMAIN)
    aiodns.error.ARES_ENOTIMP,      # Not implemented (record type not supported)
    aiodns.error.ARES_EREFUSED,     # Query refused by server
}


class DnsScanner:
    """
    Performs comprehensive DNS record enumeration for a target domain.

    Args:
        nameservers (list[str] | None):
            Custom DNS resolvers to use (e.g. ["8.8.8.8", "1.1.1.1"]).
            If None, the system default resolver is used.
        timeout (float):
            Per-query timeout in seconds. Default 5.0.
    """

    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        timeout: float = 5.0,
    ) -> None:
        self.timeout = timeout

        resolver_kwargs = {}
        if nameservers:
            resolver_kwargs["nameservers"] = nameservers

        self.resolver = aiodns.DNSResolver(**resolver_kwargs)
        log.debug(
            f"DnsScanner initialised. "
            f"Resolvers: {nameservers or 'system default'} | "
            f"Timeout: {timeout}s"
        )

    # ------------------------------------------------------------------
    # Record type handlers
    # ------------------------------------------------------------------

    async def _query_a(self, domain: str) -> list[dict]:
        """Query A records (IPv4 addresses)."""
        try:
            results = await asyncio.wait_for(
                self.resolver.query(domain, "A"),
                timeout=self.timeout,
            )
            records = []
            for r in results:
                log.warning(f"  [A]      {domain}  ->  {r.host}")
                records.append({"type": "A", "domain": domain, "value": r.host})
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("A", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.warning(f"  [A]      {domain}  ->  query timed out")
            return []

    async def _query_aaaa(self, domain: str) -> list[dict]:
        """Query AAAA records (IPv6 addresses)."""
        try:
            results = await asyncio.wait_for(
                self.resolver.query(domain, "AAAA"),
                timeout=self.timeout,
            )
            records = []
            for r in results:
                log.info(f"  [AAAA]   {domain}  ->  {r.host}")
                records.append({"type": "AAAA", "domain": domain, "value": r.host})
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("AAAA", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [AAAA]   {domain}  ->  query timed out")
            return []

    async def _query_mx(self, domain: str) -> list[dict]:
        """Query MX records (mail exchange servers)."""
        try:
            results = await asyncio.wait_for(
                self.resolver.query(domain, "MX"),
                timeout=self.timeout,
            )
            records = []
            for r in sorted(results, key=lambda x: x.priority):
                value = f"{r.host} (priority {r.priority})"
                log.warning(f"  [MX]     {domain}  ->  {value}")
                records.append({
                    "type":     "MX",
                    "domain":   domain,
                    "host":     r.host,
                    "priority": r.priority,
                    "value":    value,
                })
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("MX", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [MX]     {domain}  ->  query timed out")
            return []

    async def _query_txt(self, domain: str) -> list[dict]:
        """
        Query TXT records.

        TXT records are used for SPF, DKIM, DMARC, domain verification
        tokens, and other arbitrary text data. Each record may contain
        multiple strings which are joined.
        """
        try:
            results = await asyncio.wait_for(
                self.resolver.query(domain, "TXT"),
                timeout=self.timeout,
            )
            records = []
            for r in results:
                # r.text is a list of bytes objects -- decode and join
                try:
                    if isinstance(r.text, (list, tuple)):
                        value = " ".join(
                            t.decode("utf-8", errors="replace")
                            if isinstance(t, bytes) else str(t)
                            for t in r.text
                        )
                    else:
                        value = (
                            r.text.decode("utf-8", errors="replace")
                            if isinstance(r.text, bytes) else str(r.text)
                        )
                except Exception:
                    value = str(r.text)

                note = _classify_txt_record(value)
                display = f"{value}  [{note}]" if note else value

                log.warning(f"  [TXT]    {domain}  ->  {display}")
                records.append({
                    "type":   "TXT",
                    "domain": domain,
                    "value":  value,
                    "note":   note,
                })
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("TXT", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [TXT]    {domain}  ->  query timed out")
            return []

    async def _query_ns(self, domain: str) -> list[dict]:
        """Query NS records (authoritative name servers)."""
        try:
            results = await asyncio.wait_for(
                self.resolver.query(domain, "NS"),
                timeout=self.timeout,
            )
            records = []
            for r in results:
                log.warning(f"  [NS]     {domain}  ->  {r.host}")
                records.append({"type": "NS", "domain": domain, "value": r.host})
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("NS", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [NS]     {domain}  ->  query timed out")
            return []

    async def _query_cname(self, domain: str) -> list[dict]:
        """
        Query CNAME records.

        Note: A domain with a CNAME record cannot have other record types
        at the same label (per RFC 1912). aiodns returns a single result
        for CNAME, not a list.
        """
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, "CNAME"),
                timeout=self.timeout,
            )
            value = result.cname if hasattr(result, "cname") else str(result)
            log.info(f"  [CNAME]  {domain}  ->  {value}")
            return [{"type": "CNAME", "domain": domain, "value": value}]
        except aiodns.error.DNSError as exc:
            _log_dns_error("CNAME", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [CNAME]  {domain}  ->  query timed out")
            return []

    async def _query_soa(self, domain: str) -> list[dict]:
        """
        Query SOA record (Start of Authority).

        Returns zone administration information including:
        - Primary nameserver
        - Responsible party email (hostmaster)
        - Zone serial number
        - Refresh, retry, expire intervals
        - Minimum TTL
        """
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, "SOA"),
                timeout=self.timeout,
            )
            nsname     = getattr(result, "nsname",     "unknown")
            hostmaster = getattr(result, "hostmaster", "unknown")
            serial     = getattr(result, "serial",     "unknown")
            refresh    = getattr(result, "refresh",    "unknown")
            retry      = getattr(result, "retry",      "unknown")
            expires    = getattr(result, "expires",    "unknown")
            minttl     = getattr(result, "minttl",     "unknown")

            log.info(f"  [SOA]    {domain}:")
            log.info(f"             Primary NS  : {nsname}")
            log.info(f"             Hostmaster  : {hostmaster}")
            log.info(f"             Serial      : {serial}")
            log.info(f"             Refresh     : {refresh}s")
            log.info(f"             Retry       : {retry}s")
            log.info(f"             Expires     : {expires}s")
            log.info(f"             Min TTL     : {minttl}s")

            return [{
                "type":       "SOA",
                "domain":     domain,
                "nsname":     str(nsname),
                "hostmaster": str(hostmaster),
                "serial":     str(serial),
                "refresh":    str(refresh),
                "retry":      str(retry),
                "expires":    str(expires),
                "minttl":     str(minttl),
                "value":      f"ns={nsname} hostmaster={hostmaster} serial={serial}",
            }]
        except aiodns.error.DNSError as exc:
            _log_dns_error("SOA", domain, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [SOA]    {domain}  ->  query timed out")
            return []

    async def _query_ptr(self, ip_address: str) -> list[dict]:
        """
        Query PTR record for an IP address (reverse DNS lookup).

        PTR queries require the IP to be converted to reverse notation:
          192.168.1.10  ->  10.1.168.192.in-addr.arpa
          IPv6 address  ->  reversed nibble notation .ip6.arpa

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            List of PTR finding dicts.
        """
        try:
            reverse_name = _ip_to_reverse(ip_address)
            if not reverse_name:
                log.debug(f"  [PTR]    Could not build reverse for {ip_address}")
                return []

            results = await asyncio.wait_for(
                self.resolver.query(reverse_name, "PTR"),
                timeout=self.timeout,
            )
            records = []
            for r in results:
                value = r.host if hasattr(r, "host") else str(r)
                log.warning(f"  [PTR]    {ip_address}  ->  {value}")
                records.append({
                    "type":    "PTR",
                    "ip":      ip_address,
                    "reverse": reverse_name,
                    "value":   value,
                    "domain":  ip_address,
                })
            return records
        except aiodns.error.DNSError as exc:
            _log_dns_error("PTR", ip_address, exc)
            return []
        except asyncio.TimeoutError:
            log.debug(f"  [PTR]    {ip_address}  ->  query timed out")
            return []

    # ------------------------------------------------------------------
    # Zone transfer attempt
    # ------------------------------------------------------------------

    async def _attempt_zone_transfer(
        self,
        domain: str,
        nameserver: str,
    ) -> Optional[dict]:
        """
        Attempt a DNS zone transfer (AXFR) against a nameserver.

        A successful zone transfer reveals all DNS records for the zone --
        a critical misconfiguration. Uses raw TCP DNS since aiodns does
        not support AXFR.

        Args:
            domain:      Zone to request (e.g. "example.com").
            nameserver:  NS hostname to query.

        Returns:
            Finding dict if transfer succeeds, None otherwise.
        """
        log.info(f"  Attempting zone transfer: {domain} from {nameserver}...")

        def _axfr_attempt() -> Optional[dict]:
            """Synchronous AXFR attempt via raw DNS/TCP -- runs in a thread."""
            try:
                ns_ip = socket.gethostbyname(nameserver)

                def encode_name(name: str) -> bytes:
                    encoded = b""
                    for label in name.rstrip(".").split("."):
                        encoded += bytes([len(label)]) + label.encode()
                    return encoded + b"\x00"

                query_id = 1
                flags    = 0x0100
                question = encode_name(domain) + b"\x00\xfc\x00\x01"
                header   = struct.pack(">HHHHHH", query_id, flags, 1, 0, 0, 0)
                message  = header + question
                tcp_msg  = struct.pack(">H", len(message)) + message

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect((ns_ip, 53))
                    s.sendall(tcp_msg)
                    response = s.recv(4096)

                if len(response) > 12:
                    return {
                        "type":       "zone_transfer",
                        "domain":     domain,
                        "nameserver": nameserver,
                        "ns_ip":      ns_ip,
                        "severity":   "CRITICAL",
                        "note": (
                            f"Zone transfer (AXFR) succeeded from {nameserver} ({ns_ip})! "
                            "This exposes all DNS records for the zone. "
                            "Restrict AXFR to authorised secondary nameservers only."
                        ),
                    }
                return None

            except (socket.error, OSError, struct.error):
                return None
            except Exception:
                return None

        result = await asyncio.to_thread(_axfr_attempt)

        if result:
            log.warning(f"  [CRITICAL] Zone transfer SUCCEEDED from {nameserver}!")
            log.warning(f"             All DNS records for '{domain}' may be exposed.")

        return result

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target_domain: str,
        report: Optional[ReportManager] = None,
    ) -> dict[str, list[dict]]:
        """
        Run full DNS enumeration for the target domain.

        Queries A, AAAA, MX, TXT, NS, CNAME, SOA records concurrently,
        then performs PTR lookups on discovered IPs, and attempts zone
        transfers against each discovered NS.

        Args:
            target_domain: Domain to enumerate (e.g. "example.com").
            report:        Optional ReportManager to record findings.

        Returns:
            Dict mapping record type -> list of finding dicts.
            e.g. {"A": [...], "MX": [...], "PTR": [...], ...}
        """
        domain = target_domain.lower().strip()

        log.info(f"Starting DNS enumeration for '{domain}'...")
        log.info("Querying record types: A, AAAA, MX, TXT, NS, CNAME, SOA")

        # ------------------------------------------------------------------
        # Phase 1: Standard record queries (concurrent)
        # ------------------------------------------------------------------
        phase1_tasks = {
            "A":     asyncio.create_task(self._query_a(domain)),
            "AAAA":  asyncio.create_task(self._query_aaaa(domain)),
            "MX":    asyncio.create_task(self._query_mx(domain)),
            "TXT":   asyncio.create_task(self._query_txt(domain)),
            "NS":    asyncio.create_task(self._query_ns(domain)),
            "CNAME": asyncio.create_task(self._query_cname(domain)),
            "SOA":   asyncio.create_task(self._query_soa(domain)),
        }

        phase1_results: dict[str, list[dict]] = {}
        for record_type, task in phase1_tasks.items():
            try:
                phase1_results[record_type] = await task
            except Exception as exc:
                log.error(
                    f"Unexpected error querying {record_type} for {domain}: {exc}"
                )
                phase1_results[record_type] = []

        # ------------------------------------------------------------------
        # Phase 2: PTR lookups on discovered A record IPs
        # ------------------------------------------------------------------
        a_records = phase1_results.get("A", [])
        ptr_results: list[dict] = []

        if a_records:
            log.info(f"Performing PTR lookups on {len(a_records)} discovered IP(s)...")
            ptr_tasks = [
                asyncio.create_task(self._query_ptr(r["value"]))
                for r in a_records
            ]
            try:
                ptr_batches = await asyncio.gather(*ptr_tasks)
                ptr_results = [r for batch in ptr_batches for r in batch]
            except Exception as exc:
                log.error(f"PTR lookup phase encountered an error: {exc}")

        phase1_results["PTR"] = ptr_results

        # ------------------------------------------------------------------
        # Phase 3: Zone transfer attempts against NS servers
        # ------------------------------------------------------------------
        ns_records = phase1_results.get("NS", [])
        zt_results: list[dict] = []

        if ns_records:
            log.info(
                f"Attempting zone transfers against {len(ns_records)} nameserver(s)..."
            )
            zt_tasks = [
                asyncio.create_task(
                    self._attempt_zone_transfer(domain, r["value"])
                )
                for r in ns_records
            ]
            try:
                zt_attempts = await asyncio.gather(*zt_tasks)
                zt_results = [r for r in zt_attempts if r is not None]
            except Exception as exc:
                log.error(f"Zone transfer phase encountered an error: {exc}")

        if zt_results:
            phase1_results["ZONE_TRANSFER"] = zt_results

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            all_records = [
                record
                for record_type, records in phase1_results.items()
                for record in records
            ]
            if all_records:
                report.add_section("DNS Records", all_records)
                if zt_results:
                    report.add_section(
                        "DNS -- CRITICAL: Zone Transfer Succeeded",
                        zt_results,
                    )
            else:
                report.add_section(
                    "DNS Enumeration",
                    [f"No DNS records found for '{domain}'."],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        total_records = sum(len(v) for v in phase1_results.values())
        log.info(
            f"DNS enumeration complete for '{domain}'. "
            f"Total records found: {total_records}"
        )

        if zt_results:
            log.warning(
                f"CRITICAL: Zone transfer succeeded against "
                f"{len(zt_results)} nameserver(s)! See report for details."
            )

        return phase1_results


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _ip_to_reverse(ip_address: str) -> Optional[str]:
    """
    Convert an IP address to its reverse DNS lookup hostname.

    IPv4: "192.168.1.10"  ->  "10.1.168.192.in-addr.arpa"
    IPv6: "2001:db8::1"   ->  nibble-reversed .ip6.arpa format

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        Reverse hostname string, or None if the IP cannot be parsed.
    """
    try:
        addr = ipaddress.ip_address(ip_address)

        if isinstance(addr, ipaddress.IPv4Address):
            octets = ip_address.split(".")
            return ".".join(reversed(octets)) + ".in-addr.arpa"

        elif isinstance(addr, ipaddress.IPv6Address):
            full = addr.exploded.replace(":", "")
            return ".".join(reversed(full)) + ".ip6.arpa"

    except ValueError:
        pass

    return None


def _classify_txt_record(value: str) -> str:
    """
    Classify a TXT record value and return a short descriptor.

    Args:
        value: TXT record value string.

    Returns:
        Short classification string, or empty string if unrecognised.
    """
    v = value.lower()

    if v.startswith("v=spf1"):
        return "SPF"
    if "v=dkim1" in v:
        return "DKIM"
    if v.startswith("v=dmarc1"):
        return "DMARC"
    if "google-site-verification" in v:
        return "Google Verification"
    if "ms=" in v and "microsoft" in v:
        return "Microsoft Verification"
    if "docusign" in v:
        return "DocuSign Verification"
    if "atlassian-domain-verification" in v:
        return "Atlassian Verification"
    if "facebook-domain-verification" in v:
        return "Facebook Verification"
    if "have-i-been-pwned-verification" in v:
        return "HaveIBeenPwned Verification"

    return ""


def _log_dns_error(
    record_type: str,
    domain: str,
    exc: aiodns.error.DNSError,
) -> None:
    """
    Log a DNS query error at the appropriate level.

    Expected "no records" errors are suppressed at DEBUG level.
    Unexpected errors (SERVFAIL, REFUSED, etc.) are logged at WARNING.

    Args:
        record_type: The DNS record type that was queried.
        domain:      The domain that was queried.
        exc:         The DNSError exception.
    """
    error_code = exc.args[0] if exc.args else None

    if error_code in _NO_RECORD_ERRORS:
        log.debug(
            f"  [{record_type:<6}]  {domain}  ->  no records (code {error_code})"
        )
    else:
        log.warning(
            f"  [{record_type:<6}]  {domain}  ->  DNS error: {exc} "
            f"(code {error_code})"
        )
