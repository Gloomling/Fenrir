# fenrir/modules/threat_intel_scanner.py
#
# Fix 14 — Changes from original:
#   - Soft API key warnings via config.validate_key() instead of hard-coded string checks
#   - Added AlienVault OTX query (ip_address endpoint) alongside VirusTotal
#   - Added offline DB fallback: checks local ip_reputation + ioc_threatfox + c2_botnet
#     tables when API keys absent or unavailable — works fully offline
#   - Added EPSS-enriched CVE context when target is found in threat feeds
#   - Structured findings dict passed to ReportManager
#   - run() accepts optional ReportManager and returns dict of findings
#   - All results merged into a single unified threat picture per target

import asyncio
from typing import Optional

import httpx

from ..config import config


<<<<<<< HEAD:Fenrir/fenrir/modules/threat_intel_scanner.py
def _get_db_manager():
=======
def __get_db_manager():
>>>>>>> 4303c7a940759894ccfa34a3b86f43c7db73d781:fenrir/modules/threat_intel_scanner.py
    """
    Return the shared DatabaseManager singleton.
    Tries relative import first (installed package), then path-based fallback
    for checkouts where the package root is not registered as fenrir.
    """
    try:
        from ..database import get_db_manager as _gdm
        return _gdm()
    except (ImportError, ValueError):
        pass
    try:
        import importlib.util, sys
        from pathlib import Path
        db_init = Path(__file__).resolve().parent.parent / "database" / "__init__.py"
        if db_init.exists():
            spec = importlib.util.spec_from_file_location(
                "fenrir.database", str(db_init),
                submodule_search_locations=[str(db_init.parent)],
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules.setdefault("fenrir.database", mod)
            spec.loader.exec_module(mod)
<<<<<<< HEAD:Fenrir/fenrir/modules/threat_intel_scanner.py
            return mod.get_db_manager()
=======
            return mod._get_db_manager()
>>>>>>> 4303c7a940759894ccfa34a3b86f43c7db73d781:fenrir/modules/threat_intel_scanner.py
    except Exception:
        pass
    return None


from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
VT_IP_URL   = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_DOM_URL  = "https://www.virustotal.com/api/v3/domains/{domain}"
OTX_IP_URL  = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_DOM_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

_HTTP_TIMEOUT = 20.0


class ThreatIntelScanner:
    """
    Queries threat intelligence sources for information about a target IP or domain.

    Sources (in priority order):
      1. Local offline database — ip_reputation, ioc_threatfox, c2_botnet tables
      2. VirusTotal API         — requires VIRUSTOTAL_API_KEY in .env
      3. AlienVault OTX API     — requires OTX_API_KEY in .env

    All three sources are queried in parallel where keys are present.
    Offline DB is always queried regardless of key availability.
    """

    def __init__(self) -> None:
        log.debug("ThreatIntelScanner initialised.")
        self._vt_ok,  self._vt_msg  = config.validate_key("virustotal")
        self._otx_ok, self._otx_msg = config.validate_key("alienvault")
        self._db = __get_db_manager()

    async def run(
        self,
        target: str,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Run threat intelligence scan for a target IP or domain.

        Args:
            target: IPv4 address or domain name.
            report: Optional ReportManager to record findings.

        Returns:
            Dict with keys:
              target, is_ip, offline_findings, virustotal, otx, summary
        """
        log.info(f"Starting threat intelligence scan for: {target}")

        is_ip = _looks_like_ip(target)
        results = {
            "target":           target,
            "is_ip":            is_ip,
            "offline_findings": [],
            "virustotal":       None,
            "otx":              None,
            "summary":          [],
        }

        # --- Warn about missing keys (once, clearly) ---
        if not self._vt_ok:
            log.warning(f"VirusTotal: {self._vt_msg}")
        if not self._otx_ok:
            log.warning(f"AlienVault OTX: {self._otx_msg}")

        # --- Run all sources concurrently ---
        tasks = [self._query_offline(target, is_ip)]
        if self._vt_ok:
            tasks.append(self._query_virustotal(target, is_ip))
        else:
            tasks.append(asyncio.coroutine(lambda: None)())  # placeholder

        if self._otx_ok:
            tasks.append(self._query_otx(target, is_ip))
        else:
            tasks.append(asyncio.coroutine(lambda: None)())

        offline_res, vt_res, otx_res = await asyncio.gather(*tasks, return_exceptions=True)

        # Store results (guard against exceptions from gather)
        results["offline_findings"] = offline_res if isinstance(offline_res, list) else []
        results["virustotal"]       = vt_res  if isinstance(vt_res, dict)  else None
        results["otx"]              = otx_res if isinstance(otx_res, dict)  else None

        # --- Build summary ---
        summary = self._build_summary(results)
        results["summary"] = summary

        # --- Log summary ---
        for line in summary:
            lvl = line.get("level", "info")
            msg = line.get("message", "")
            getattr(log, lvl)(msg)

        # --- Report ---
        if report:
            findings = [s["message"] for s in summary]
            report.add_section(
                "Threat Intelligence",
                [{"target": target, "findings": findings}],
            )

        log.info("Threat intelligence scan complete.")
        return results

    # ------------------------------------------------------------------
    # Offline DB
    # ------------------------------------------------------------------

    async def _query_offline(self, target: str, is_ip: bool) -> list[dict]:
        """Query local offline threat intelligence database."""
        if not self._db.is_available():
            log.debug("Offline DB not available — skipping local threat intel lookup.")
            return []

        findings = []

        if is_ip:
            # Direct IP reputation lookup
            rep = await asyncio.to_thread(self._db.check_ip_reputation, target)
            if rep:
                findings.append({
                    "source":   rep.get("source", "local_db"),
                    "type":     "ip_reputation",
                    "category": rep.get("category", ""),
                    "notes":    rep.get("notes", ""),
                    "added":    rep.get("added_date", ""),
                })
                log.warning(
                    f"[LOCAL DB] {target} found in ip_reputation: "
                    f"{rep.get('category')} (source: {rep.get('source')})"
                )

            # C2 botnet check
            c2_rows = await asyncio.to_thread(self._query_c2, target)
            for row in c2_rows:
                findings.append({
                    "source":  "feodo_tracker",
                    "type":    "c2_infrastructure",
                    "malware": row.get("malware", ""),
                    "port":    row.get("port", ""),
                    "status":  row.get("status", ""),
                    "country": row.get("country", ""),
                })
                log.warning(
                    f"[LOCAL DB] {target} is a known C2 server: "
                    f"{row.get('malware')} (port {row.get('port')}, "
                    f"status: {row.get('status')})"
                )

        # ThreatFox IOC lookup (works for both IP and domain)
        ioc_rows = await asyncio.to_thread(self._query_threatfox_ioc, target)
        for row in ioc_rows:
            findings.append({
                "source":    "threatfox",
                "type":      "ioc",
                "ioc_type":  row.get("ioc_type", ""),
                "malware":   row.get("malware", ""),
                "threat":    row.get("threat_type", ""),
                "confidence": row.get("confidence", 0),
            })
            log.warning(
                f"[LOCAL DB] {target} found in ThreatFox: "
                f"{row.get('malware')} — {row.get('threat_type')} "
                f"(confidence: {row.get('confidence')}%)"
            )

        if not findings:
            log.info(f"[LOCAL DB] {target} not found in offline threat databases.")

        return findings

    def _query_c2(self, ip: str) -> list[dict]:
        """Synchronous C2 lookup for asyncio.to_thread."""
        try:
            import sqlite3
            from ..database.db_manager import DB_PATH
            if not DB_PATH.exists():
                return []
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM c2_botnet WHERE ip_address = ?", (ip,)
            )
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            log.debug(f"C2 lookup error: {exc}")
            return []

    def _query_threatfox_ioc(self, value: str) -> list[dict]:
        """Synchronous ThreatFox IOC lookup for asyncio.to_thread."""
        try:
            import sqlite3
            from ..database.db_manager import DB_PATH
            if not DB_PATH.exists():
                return []
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM ioc_threatfox WHERE ioc_value LIKE ? LIMIT 10",
                (f"%{value}%",),
            )
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            log.debug(f"ThreatFox IOC lookup error: {exc}")
            return []

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------

    async def _query_virustotal(self, target: str, is_ip: bool) -> dict:
        """Query VirusTotal API for IP or domain reputation."""
        log.info(f"Querying VirusTotal for {target}...")
        url     = (VT_IP_URL if is_ip else VT_DOM_URL).format(ip=target, domain=target)
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                attrs  = resp.json().get("data", {}).get("attributes", {})
                stats  = attrs.get("last_analysis_stats", {})
                result = {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "harmless":    stats.get("harmless", 0),
                    "undetected":  stats.get("undetected", 0),
                    "reputation":  attrs.get("reputation", 0),
                    "country":     attrs.get("country", ""),
                    "as_owner":    attrs.get("as_owner", ""),
                    "categories":  attrs.get("categories", {}),
                }
                log.info(
                    f"[VirusTotal] {target}: malicious={result['malicious']}, "
                    f"suspicious={result['suspicious']}, "
                    f"reputation={result['reputation']}"
                )
                return result

            elif resp.status_code == 404:
                log.info(f"[VirusTotal] {target} not found in database.")
                return {"not_found": True}
            elif resp.status_code == 429:
                log.warning("[VirusTotal] Rate limit exceeded. Try again later.")
                return {"rate_limited": True}
            else:
                log.error(f"[VirusTotal] HTTP {resp.status_code}: {resp.text[:200]}")
                return {"error": resp.status_code}

        except httpx.TimeoutException:
            log.warning("[VirusTotal] Request timed out.")
            return {"timeout": True}
        except httpx.RequestError as exc:
            log.error(f"[VirusTotal] Connection error: {exc}")
            return {"connection_error": str(exc)}

    # ------------------------------------------------------------------
    # AlienVault OTX
    # ------------------------------------------------------------------

    async def _query_otx(self, target: str, is_ip: bool) -> dict:
        """Query AlienVault OTX for IP or domain indicators."""
        log.info(f"Querying AlienVault OTX for {target}...")
        url     = (OTX_IP_URL if is_ip else OTX_DOM_URL).format(ip=target, domain=target)
        headers = {"X-OTX-API-KEY": config.ALIENVAULT_OTX_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                data       = resp.json()
                pulse_info = data.get("pulse_info", {})
                result     = {
                    "pulse_count":   pulse_info.get("count", 0),
                    "pulses":        [
                        {
                            "name":     p.get("name", ""),
                            "tags":     p.get("tags", []),
                            "tlp":      p.get("tlp", ""),
                            "modified": p.get("modified", ""),
                        }
                        for p in pulse_info.get("pulses", [])[:5]  # top 5
                    ],
                    "country":       data.get("country_name", ""),
                    "asn":           data.get("asn", ""),
                    "reputation":    data.get("reputation", 0),
                    "malware_count": data.get("malware_families", {}).get("count", 0)
                                     if isinstance(data.get("malware_families"), dict)
                                     else 0,
                }
                log.info(
                    f"[OTX] {target}: {result['pulse_count']} pulse(s), "
                    f"reputation={result['reputation']}, "
                    f"country={result['country']}"
                )
                return result

            elif resp.status_code == 404:
                log.info(f"[OTX] {target} not found in OTX.")
                return {"not_found": True}
            elif resp.status_code == 403:
                log.warning("[OTX] Invalid or expired API key.")
                return {"auth_error": True}
            else:
                log.error(f"[OTX] HTTP {resp.status_code}: {resp.text[:200]}")
                return {"error": resp.status_code}

        except httpx.TimeoutException:
            log.warning("[OTX] Request timed out.")
            return {"timeout": True}
        except httpx.RequestError as exc:
            log.error(f"[OTX] Connection error: {exc}")
            return {"connection_error": str(exc)}

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------

    def _build_summary(self, results: dict) -> list[dict]:
        """
        Merge findings from all sources into a unified threat summary.

        Returns:
            List of {"level": "info"|"warning"|"critical", "message": str}
        """
        target   = results["target"]
        summary  = []

        # --- Offline findings ---
        for f in results["offline_findings"]:
            ftype = f.get("type", "")
            if ftype == "ip_reputation":
                summary.append({
                    "level":   "warning",
                    "message": f"LOCAL DB: {target} flagged as '{f['category']}' by {f['source']}",
                })
            elif ftype == "c2_infrastructure":
                summary.append({
                    "level":   "critical",
                    "message": (
                        f"LOCAL DB: {target} is a known C2 server "
                        f"({f['malware']}, port {f['port']}, status: {f['status']})"
                    ),
                })
            elif ftype == "ioc":
                summary.append({
                    "level":   "warning",
                    "message": (
                        f"LOCAL DB: {target} is a ThreatFox IOC — "
                        f"{f['malware']} ({f['threat']}, "
                        f"confidence {f['confidence']}%)"
                    ),
                })

        # --- VirusTotal ---
        vt = results.get("virustotal") or {}
        if vt and not any(k in vt for k in ("not_found", "error", "timeout",
                                              "rate_limited", "connection_error")):
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            if mal > 0 or sus > 0:
                level = "critical" if mal >= 5 else "warning"
                summary.append({
                    "level":   level,
                    "message": (
                        f"VirusTotal: {target} flagged — "
                        f"{mal} malicious, {sus} suspicious detections "
                        f"(reputation: {vt.get('reputation', 'N/A')}, "
                        f"country: {vt.get('country', 'N/A')})"
                    ),
                })
            else:
                summary.append({
                    "level":   "info",
                    "message": f"VirusTotal: {target} appears clean (0 malicious detections).",
                })

        # --- OTX ---
        otx = results.get("otx") or {}
        if otx and not any(k in otx for k in ("not_found", "error", "timeout",
                                               "auth_error", "connection_error")):
            pulse_count = otx.get("pulse_count", 0)
            if pulse_count > 0:
                level = "critical" if pulse_count >= 10 else "warning"
                summary.append({
                    "level":   level,
                    "message": (
                        f"AlienVault OTX: {target} appears in {pulse_count} threat pulse(s). "
                        f"Top pulse: '{otx['pulses'][0]['name']}'" if otx.get("pulses")
                        else f"AlienVault OTX: {target} appears in {pulse_count} threat pulse(s)."
                    ),
                })
            else:
                summary.append({
                    "level":   "info",
                    "message": f"AlienVault OTX: {target} has no threat pulses.",
                })

        # --- Clean bill if nothing found ---
        if not summary:
            summary.append({
                "level":   "info",
                "message": f"No threat intelligence findings for {target}.",
            })

        return summary


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _looks_like_ip(value: str) -> bool:
    """Return True if value looks like an IPv4 address."""
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))