# fenrir/epss_client.py
"""
EPSS (Exploit Prediction Scoring System) client.

Fetches probability scores from the FIRST.org EPSS API v3:
  https://api.first.org/data/1.0/epss?cve=CVE-2021-44228

EPSS score: 0.0–1.0  — probability of exploitation in the wild in next 30 days.
Percentile:  0.0–1.0  — how this score compares to all scored CVEs.

Results are cached in memory for the session to avoid re-requesting the same CVEs.
Rate limit: FIRST.org allows ~100 req/min unauthenticated.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

log = logging.getLogger("fenrir")

_EPSS_API = "https://api.first.org/data/1.0/epss"
_CACHE: dict[str, dict] = {}   # cve_id → {"score": float, "percentile": float, "ts": float}
_CACHE_TTL = 3600              # 1 hour


async def get_epss(cve_ids: list[str],
                   timeout: float = 8.0) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.

    Returns dict: {cve_id: {"score": float, "percentile": float}}
    Missing / unknown CVEs are omitted from the result.
    Falls back gracefully if network is unavailable.
    """
    if not cve_ids:
        return {}

    now     = time.monotonic()
    needed  = [c for c in cve_ids
               if c not in _CACHE or (now - _CACHE[c].get("ts", 0)) > _CACHE_TTL]
    result  = {c: _CACHE[c] for c in cve_ids if c in _CACHE}

    if not needed:
        return result

    # Batch: FIRST API accepts up to 30 CVEs per request
    BATCH = 30
    for i in range(0, len(needed), BATCH):
        batch = needed[i: i + BATCH]
        try:
            data = await _fetch_batch(batch, timeout)
            for entry in data:
                cve = entry.get("cve", "")
                if not cve:
                    continue
                item = {
                    "score":      float(entry.get("epss", 0)),
                    "percentile": float(entry.get("percentile", 0)),
                    "ts":         time.monotonic(),
                }
                _CACHE[cve] = item
                result[cve] = item
        except Exception as exc:
            log.debug(f"[epss] batch fetch failed ({batch[:2]}…): {exc}")

    return result


async def _fetch_batch(cve_ids: list[str], timeout: float) -> list[dict]:
    """Perform one HTTP GET to the EPSS API for up to 30 CVEs."""
    import urllib.request, urllib.parse, json as _json
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    url    = f"{_EPSS_API}?{params}"
    log.debug(f"[epss] GET {url[:120]}")

    def _do_get():
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _json.loads(resp.read().decode())

    data = await asyncio.to_thread(_do_get)
    return data.get("data", [])


def enrich_cves_with_epss(cves: list[dict],
                           epss_data: dict[str, dict]) -> list[dict]:
    """
    Attach EPSS score and percentile to each CVE dict in-place.
    Also computes a composite risk_score = cvss * epss (0–10 * 0–1).
    Returns the same list (mutated).
    """
    for cve in cves:
        cid   = cve.get("id") or cve.get("cve_id", "")
        entry = epss_data.get(cid)
        if entry:
            cve["epss_score"]      = round(entry["score"], 4)
            cve["epss_percentile"] = round(entry["percentile"] * 100, 1)
            cvss = float(cve.get("score") or cve.get("cvss_score") or 0)
            cve["risk_score"]      = round(cvss * entry["score"], 3)
        else:
            cve.setdefault("epss_score",      None)
            cve.setdefault("epss_percentile", None)
            cve.setdefault("risk_score",      None)
    return cves