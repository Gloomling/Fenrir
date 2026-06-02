# fenrir/modules/dns_scanner.py
#
# DNS enumeration module.
#
# Design:
#   - Queries multiple DNS record types concurrently for a target domain.
#   - Record types covered:
#       A       — IPv4 address records
#       AAAA    — IPv6 address records
#       MX      — Mail exchange records
#       TXT     — Text records (SPF, DKIM, DMARC, verification tokens)
#       NS      — Authoritative nameserver records
#       CNAME   — Canonical name (alias) records
#       SOA     — Start of Authority (zone metadata, serial, TTL policy)
#       PTR     — Reverse DNS lookup (IP -> hostname)
#   - Uses aiodns for fully async DNS resolution.
#   - Each record type has its own parser to handle unique response structures.
#   - Errors per record type are handled individually — a failed CNAME query
#     does not prevent A or MX results from being returned.
#   - Security-relevant TXT records (SPF, DMARC, DKIM) are identified and
#     flagged at WARNING level as they reveal email security posture.
#   - Zone transfer (AXFR) attempt is included as an optional check —
#     a successful zone transfer is a critical finding.
#   - All findings are added to the ReportManager.
#
# PTR record notes:
#   PTR queries require a reverse-format hostname:
#     IPv4: 1.2.3.4  -> 4.3.2.1.in-addr.arpa
#     IPv6: requires nibble-reversed .ip6.arpa format
#   The helper _to_ptr_name() handles this conversion.

import asyncio
import ipaddress
import socket
from typing import Optional

import aiodns

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# Record type definitions
# ---------------------------------------------------------------------------

# All standard record types to query
RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

# TXT record prefixes that indicate security-relevant configurations
SECURITY_TXT_PREFIXES: list[str] = [
    "v=spf1",       # SPF — controls which servers can send email for the domain
    "v=DMARC1",     # DMARC — email authentication policy
    "v=DKIM1",      # DKIM — email signing key
]


class DnsScanner:
    """
    Performs comprehensive DNS enumeration for a target domain.

    Queries A, AAAA, MX, TXT, NS, CNAME, SOA, and PTR records concurrently.
    Optionally attempts a zone transfer (AXFR).

    Args:
        nameserver (str | None):
            Custom DNS resolver IP to use. If None, uses the system default.
            Useful for querying the target's own authoritative nameserver.
        timeout (float):
            Timeout per DNS query in seconds. Default 5.0.
    """

    def __init__(
        self,
        nameserver: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.timeout = timeout
        self.nameserver = nameserver

        # Configure aiodns resolver
        resolver_kwargs: dict = {"timeout": timeout}
        if nameserver:
            resolver_kwargs["nameservers"] = [nameserver]
            log.debug(f"DnsScanner: using custom nameserver {nameserver}")

        self.resolver = aiodns.DNSResolver(**resolver_kwargs)
        log.debug(
            f"DnsScanner initialised. "
            f"Nameserver: {nameserver or 'system default'} | "
            f"Timeout: {timeout}s"
        )

    # ------------------------------------------------------------------
    # Record parsers
    # ------------------------------------------------------------------

    async def _query_a(self, domain: str) -> list[dict]:
        """Query A records (IPv4 addresses)."""
        results = []
        try:
            records = await self.resolver.query(domain, "A")
            for r in records:
                results.append({"type": "A", "value": r.host, "domain": domain})
                log.info(f"  A     {domain:<40}  {r.host}")
        except aiodns.error.DNSError as e:
            log.debug(f"  A record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying A for {domain}: {e}")
        return results

    async def _query_aaaa(self, domain: str) -> list[dict]:
        """Query AAAA records (IPv6 addresses)."""
        results = []
        try:
            records = await self.resolver.query(domain, "AAAA")
            for r in records:
                results.append({"type": "AAAA", "value": r.host, "domain": domain})
                log.info(f"  AAAA  {domain:<40}  {r.host}")
        except aiodns.error.DNSError as e:
            log.debug(f"  AAAA record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying AAAA for {domain}: {e}")
        return results

    async def _query_mx(self, domain: str) -> list[dict]:
        """Query MX records (mail exchange)."""
        results = []
        try:
            records = await self.resolver.query(domain, "MX")
            # Sort by priority (lower = higher priority)
            sorted_records = sorted(records, key=lambda r: r.priority)
            for r in sorted_records:
                results.append({
                    "type":     "MX",
                    "value":    r.host,
                    "priority": r.priority,
                    "domain":   domain,
                })
                log.info(
                    f"  MX    {domain:<40}  "
                    f"priority={r.priority:<5} {r.host}"
                )
        except aiodns.error.DNSError as e:
            log.debug(f"  MX record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying MX for {domain}: {e}")
        return results

    async def _query_txt(self, domain: str) -> list[dict]:
        """
        Query TXT records.

        TXT records often contain security-relevant data:
        SPF, DMARC, DKIM, domain ownership verification tokens.
        Security-relevant records are flagged at WARNING level.
        """
        results = []
        try:
            records = await self.resolver.query(domain, "TXT")
            for r in records:
                # TXT records are lists of byte strings — decode and join
                try:
                    if isinstance(r.text, (list, tuple)):
                        value = " ".join(
                            t.decode("utf-8", errors="replace")
                            if isinstance(t, bytes) else str(t)
                            for t in r.text
                        )
                    elif isinstance(r.text, bytes):
                        value = r.text.decode("utf-8", errors="replace")
                    else:
                        value = str(r.text)
                except Exception:
                    value = str(r.text)

                # Identify security-relevant records
                is_security = any(
                    value.lower().startswith(prefix.lower())
                    for prefix in SECURITY_TXT_PREFIXES
                )

                record = {
                    "type":        "TXT",
                    "value":       value,
                    "domain":      domain,
                    "is_security": is_security,
                }
                results.append(record)

                if is_security:
                    log.warning(f"  TXT   {domain:<40}  [SECURITY] {value[:120]}")
                else:
                    log.info(f"  TXT   {domain:<40}  {value[:120]}")

        except aiodns.error.DNSError as e:
            log.debug(f"  TXT record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying TXT for {domain}: {e}")
        return results

    async def _query_ns(self, domain: str) -> list[dict]:
        """Query NS records (authoritative nameservers)."""
        results = []
        try:
            records = await self.resolver.query(domain, "NS")
            for r in records:
                results.append({"type": "NS", "value": r.host, "domain": domain})
                log.info(f"  NS    {domain:<40}  {r.host}")
        except aiodns.error.DNSError as e:
            log.debug(f"  NS record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying NS for {domain}: {e}")
        return results

    async def _query_cname(self, domain: str) -> list[dict]:
        """Query CNAME records (canonical name aliases)."""
        results = []
        try:
            records = await self.resolver.query(domain, "CNAME")
            # CNAME returns a single record
            if hasattr(records, "cname"):
                cname_value = records.cname
            elif isinstance(records, list) and records:
                cname_value = getattr(records[0], "cname", str(records[0]))
            else:
                cname_value = str(records)

            results.append({
                "type":   "CNAME",
                "value":  cname_value,
                "domain": domain,
            })
            log.info(f"  CNAME {domain:<40}  → {cname_value}")

        except aiodns.error.DNSError as e:
            # CNAME queries commonly return NXDOMAIN — this is expected
            log.debug(f"  CNAME record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying CNAME for {domain}: {e}")
        return results

    async def _query_soa(self, domain: str) -> list[dict]:
        """
        Query SOA record (Start of Authority).

        SOA contains:
          - Primary nameserver (nsname)
          - Responsible party email (hostmaster)
          - Zone serial number
          - Refresh / retry / expire / minimum TTL values
        """
        results = []
        try:
            record = await self.resolver.query(domain, "SOA")

            # aiodns returns a single SOA object
            nsname     = getattr(record, "nsname",     "")
            hostmaster = getattr(record, "hostmaster", "")
            serial     = getattr(record, "serial",     "")
            refresh    = getattr(record, "refresh",    "")
            retry      = getattr(record, "retry",      "")
            expires    = getattr(record, "expires",    "")
            minttl     = getattr(record, "minttl",     "")

            soa_record = {
                "type":       "SOA",
                "domain":     domain,
                "nsname":     str(nsname),
                "hostmaster": str(hostmaster),
                "serial":     str(serial),
                "refresh":    str(refresh),
                "retry":      str(retry),
                "expires":    str(expires),
                "minttl":     str(minttl),
            }
            results.append(soa_record)

            log.info(f"  SOA   {domain}")
            log.info(f"        Primary NS   : {nsname}")
            log.info(f"        Hostmaster   : {hostmaster}")
            log.info(f"        Serial       : {serial}")
            log.info(f"        Refresh/Retry: {refresh}s / {retry}s")
            log.info(f"        Expire/MinTTL: {expires}s / {minttl}s")

        except aiodns.error.DNSError as e:
            log.debug(f"  SOA record query failed for {domain}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying SOA for {domain}: {e}")
        return results

    async def _query_ptr(self, ip_address: str) -> list[dict]:
        """
        Query PTR record for a given IP address (reverse DNS lookup).

        Converts the IP to its reverse-format DNS name before querying:
          IPv4: 192.168.1.10 -> 10.1.168.192.in-addr.arpa
          IPv6: uses nibble-reversed .ip6.arpa format

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            List with one finding dict, or empty list on failure.
        """
        results = []
        try:
            ptr_name = _to_ptr_name(ip_address)
            if not ptr_name:
                log.warning(f"  PTR: could not convert '{ip_address}' to PTR format.")
                return []

            records = await self.resolver.query(ptr_name, "PTR")

            for r in records:
                hostname = getattr(r, "name", str(r))
                results.append({
                    "type":      "PTR",
                    "ip":        ip_address,
                    "ptr_name":  ptr_name,
                    "hostname":  hostname,
                })
                log.info(f"  PTR   {ip_address:<40}  → {hostname}")

        except aiodns.error.DNSError as e:
            log.debug(f"  PTR record query failed for {ip_address}: {e}")
        except Exception as e:
            log.error(f"  Unexpected error querying PTR for {ip_address}: {e}")
        return results

    # ------------------------------------------------------------------
    # Zone transfer attempt
    # ------------------------------------------------------------------

    async def _attempt_zone_transfer(
        self,
        domain: str,
        nameservers: list[str],
    ) -> list[dict]:
        """
        Attempt a DNS zone transfer (AXFR) against each nameserver.

        A successful zone transfer is a CRITICAL finding — it exposes the
        entire DNS zone including all subdomains, internal hostnames, and
        IP addresses.

        Zone transfers use TCP (port 53) and are performed synchronously
        via the socket module in a thread (aiodns does not support AXFR).

        Args:
            domain:      Target domain.
            nameservers: List of NS hostnames to attempt transfer against.

        Returns:
            List of finding dicts if transfer succeeds, empty list otherwise.
        """
        findings = []

        for ns in nameservers:
            log.info(f"  Attempting zone transfer from {ns}...")

            def _axfr_attempt(ns_host: str) -> Optional[str]:
                """
                Send a raw AXFR request via TCP.
                Returns raw response bytes as hex string on success, None on failure.
                """
                try:
                    # Resolve NS hostname to IP
                    ns_ip = socket.gethostbyname(ns_host)

                    # Build minimal AXFR DNS query packet
                    # Transaction ID: 0x0001
                    # Flags: standard query (0x0000)
                    # Questions: 1, Answers/Auth/Additional: 0
                    txid    = b"\x00\x01"
                    flags   = b"\x00\x00"
                    qdcount = b"\x00\x01"
                    ancount = b"\x00\x00"
                    nscount = b"\x00\x00"
                    arcount = b"\x00\x00"
                    header  = txid + flags + qdcount + ancount + nscount + arcount

                    # Encode domain name as DNS labels
                    qname = b""
                    for label in domain.rstrip(".").split("."):
                        encoded = label.encode("ascii")
                        qname += bytes([len(encoded)]) + encoded
                    qname += b"\x00"

                    qtype  = b"\x00\xfc"   # AXFR
                    qclass = b"\x00\x01"   # IN
                    question = qname + qtype + qclass

                    query = header + question

                    # AXFR uses TCP — prefix message with 2-byte length
                    tcp_query = len(query).to_bytes(2, "big") + query

                    with socket.create_connection((ns_ip, 53), timeout=5) as sock:
                        sock.sendall(tcp_query)
                        # Read the first 2 bytes (response length)
                        length_bytes = sock.recv(2)
                        if len(length_bytes) < 2:
                            return None
                        resp_len = int.from_bytes(length_bytes, "big")
                        # Read the full response
                        response = b""
                        while len(response) < resp_len:
                            chunk = sock.recv(resp_len - len(response))
                            if not chunk:
                                break
                            response += chunk

                    # Check RCODE in response flags (byte 3, lower 4 bits)
                    if len(response) >= 4:
                        rcode = response[3] & 0x0F
                        if rcode == 0:
                            return response.hex()

                    return None

                except (socket.error, OSError, ConnectionRefusedError):
                    return None
                except Exception:
                    return None

            result = await asyncio.to_thread(_axfr_attempt, ns)

            if result is not None:
                log.warning(
                    f"  [CRITICAL] Zone transfer SUCCEEDED from {ns}! "
                    f"The nameserver {ns} allows unauthenticated AXFR requests. "
                    "This exposes the entire DNS zone."
                )
                findings.append({
                    "type":        "zone_transfer",
                    "nameserver":  ns,
                    "domain":      domain,
                    "severity":    "CRITICAL",
                    "note":        (
                        f"Nameserver {ns} allows unauthenticated zone transfers (AXFR). "
                        "Restrict zone transfers to authorised secondary nameservers only."
                    ),
                })
            else:
                log.info(f"  Zone transfer refused by {ns} (expected).")

        return findings

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def run(
        self,
        target_domain: str,
        target_ip: Optional[str] = None,
        attempt_zone_transfer: bool = True,
        report: Optional[ReportManager] = None,
    ) -> dict[str, list[dict]]:
        """
        Run full DNS enumeration for a target domain.

        Args:
            target_domain:         Domain to enumerate (e.g. "example.com").
            target_ip:             Optional IP address for PTR lookup.
                                   If not provided, PTR is skipped unless an
                                   A record is found.
            attempt_zone_transfer: Whether to attempt AXFR. Default True.
            report:                Optional ReportManager to record findings.

        Returns:
            Dict mapping record type -> list of finding dicts.
            Keys: "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA",
                  "PTR", "ZONE_TRANSFER"
        """
        domain = target_domain.strip().lower()

        log.info(f"Starting DNS enumeration for '{domain}'...")

        # ------------------------------------------------------------------
        # Run all standard record type queries concurrently
        # ------------------------------------------------------------------
        log.info("Querying DNS records...")

        record_tasks = {
            "A":     asyncio.create_task(self._query_a(domain)),
            "AAAA":  asyncio.create_task(self._query_aaaa(domain)),
            "MX":    asyncio.create_task(self._query_mx(domain)),
            "TXT":   asyncio.create_task(self._query_txt(domain)),
            "NS":    asyncio.create_task(self._query_ns(domain)),
            "CNAME": asyncio.create_task(self._query_cname(domain)),
            "SOA":   asyncio.create_task(self._query_soa(domain)),
        }

        record_results: dict[str, list[dict]] = {}
        for rtype, task in record_tasks.items():
            try:
                record_results[rtype] = await task
            except Exception as exc:
                log.error(f"DNS query task for {rtype} failed unexpectedly: {exc}")
                record_results[rtype] = []

        # ------------------------------------------------------------------
        # PTR lookup
        # ------------------------------------------------------------------
        # Use the provided IP, or fall back to the first A record result
        ptr_ip = target_ip
        if not ptr_ip and record_results.get("A"):
            ptr_ip = record_results["A"][0]["value"]

        if ptr_ip:
            log.info(f"Querying PTR record for {ptr_ip}...")
            record_results["PTR"] = await self._query_ptr(ptr_ip)
        else:
            log.debug("PTR lookup skipped — no IP address available.")
            record_results["PTR"] = []

        # ------------------------------------------------------------------
        # Zone transfer attempt
        # ------------------------------------------------------------------
        record_results["ZONE_TRANSFER"] = []
        if attempt_zone_transfer:
            ns_records = record_results.get("NS", [])
            nameservers = [r["value"] for r in ns_records]

            if nameservers:
                log.info(
                    f"Attempting zone transfer against "
                    f"{len(nameservers)} nameserver(s)..."
                )
                record_results["ZONE_TRANSFER"] = (
                    await self._attempt_zone_transfer(domain, nameservers)
                )
            else:
                log.debug(
                    "Zone transfer skipped — no NS records found to target."
                )

        # ------------------------------------------------------------------
        # Report
        # ------------------------------------------------------------------
        if report:
            # Flatten all records into a single section per type
            for rtype, records in record_results.items():
                if records:
                    section_title = f"DNS — {rtype} Records"
                    report.add_section(section_title, records)

            if record_results.get("ZONE_TRANSFER"):
                report.add_section(
                    "DNS — Zone Transfer (CRITICAL)",
                    record_results["ZONE_TRANSFER"],
                )

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        total_records = sum(
            len(v) for k, v in record_results.items()
            if k != "ZONE_TRANSFER"
        )

        log.info(
            f"DNS enumeration complete. "
            f"Total records found: {total_records}"
        )

        # Highlight security-relevant TXT records
        security_txt = [
            r for r in record_results.get("TXT", [])
            if r.get("is_security")
        ]
        if security_txt:
            log.warning(
                f"Security-relevant TXT records found ({len(security_txt)}):"
            )
            for r in security_txt:
                log.warning(f"  {r['value'][:120]}")

        # Highlight zone transfer success
        if record_results.get("ZONE_TRANSFER"):
            log.warning(
                "CRITICAL: One or more nameservers allowed zone transfers!"
            )

        return record_results


# ---------------------------------------------------------------------------
# PTR name conversion helper
# ---------------------------------------------------------------------------

def _to_ptr_name(ip_address: str) -> Optional[str]:
    """
    Convert an IP address to its PTR record query name.

    IPv4: 192.168.1.10  ->  10.1.168.192.in-addr.arpa
    IPv6: 2001:db8::1   ->  1.0.0.0...0.8.b.d.1.0.0.2.ip6.arpa

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        PTR query name string, or None if the address is invalid.
    """
    try:
        addr = ipaddress.ip_address(ip_address)

        if isinstance(addr, ipaddress.IPv4Address):
            # Reverse the octets and append in-addr.arpa
            octets = ip_address.split(".")
            return ".".join(reversed(octets)) + ".in-addr.arpa"

        elif isinstance(addr, ipaddress.IPv6Address):
            # Expand to full form, remove colons, reverse nibbles, append ip6.arpa
            expanded = addr.exploded.replace(":", "")
            reversed_nibbles = ".".join(reversed(expanded))
            return reversed_nibbles + ".ip6.arpa"

    except ValueError:
        log.debug(f"_to_ptr_name: invalid IP address '{ip_address}'")
        return None

    return None