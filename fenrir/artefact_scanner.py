# fenrir/artefact_scanner.py
"""
Offline Artefact & Hash Intelligence Scanner

Analyses files and hash values against the entire Fenrir offline database:
  - artefact_hashes  (OTX + MalwareBazaar merged)
  - hash_reputation  (MalwareBazaar daily feed)
  - ioc_threatfox    (ThreatFox hash IOCs)
  - otx_indicators   (AlienVault OTX hash indicators)
  - OTX pulse metadata → malware family, ATT&CK techniques, tags
  - ATT&CK technique lookup → full TTP chain for a malware sample
  - Sigma rule matching → detection rules relevant to the threat actor/malware
  - YARA scanning     → pattern matching against local YARA rules (optional)

All queries are 100% offline — no network calls are made.

API:
    scanner = ArtefactScanner()

    # Analyse a file
    result = await scanner.scan_file("/tmp/suspicious.exe")

    # Check a known hash
    result = await scanner.scan_hash("d41d8cd98f00b204e9800998ecf8427e")

    # Query an OTX indicator (IP, domain, URL, hash)
    result = await scanner.query_indicator("192.168.1.1")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fenrir.logging_config import get_logger

log = get_logger()

# ── YARA support (optional) ────────────────────────────────────────────────────
try:
    import yara as _yara
    YARA_OK = True
except ImportError:
    YARA_OK = False

# ── ssdeep fuzzy hashing (optional) ───────────────────────────────────────────
try:
    import ssdeep as _ssdeep
    SSDEEP_OK = True
except ImportError:
    SSDEEP_OK = False

# ── Built-in YARA rules for common malware patterns ───────────────────────────
_BUILTIN_YARA_RULES = r"""
rule Suspicious_PE_Import {
    meta:
        description = "PE file importing suspicious functions"
        category    = "malware"
    strings:
        $virt    = "VirtualAlloc" nocase
        $inject  = "WriteProcessMemory" nocase
        $thread  = "CreateRemoteThread" nocase
        $shell   = "ShellExecute" nocase wide
    condition:
        2 of ($virt, $inject, $thread, $shell)
}

rule Possible_Packed_PE {
    meta:
        description = "Possibly packed PE (common packer sections)"
        category    = "packer"
    strings:
        $upx0  = "UPX0"
        $upx1  = "UPX1"
        $aspack = ".aspack"
        $nsp   = ".nsp0"
        $mpress = "MPRESS"
    condition:
        any of them
}

rule PowerShell_Encoded {
    meta:
        description = "PowerShell encoded command"
        category    = "fileless"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "powershell -e " nocase
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        any of ($enc1, $enc2, $enc3) and $b64
}

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool strings"
        category    = "credential_access"
        attack_id   = "T1003"
    strings:
        $s1 = "sekurlsa::" nocase
        $s2 = "lsadump::" nocase
        $s3 = "mimikatz" nocase
        $s4 = "wdigest.dll" nocase
        $s5 = "kerberos::" nocase
    condition:
        2 of them
}

rule Meterpreter_Shellcode {
    meta:
        description = "Meterpreter shellcode patterns"
        category    = "c2"
        attack_id   = "T1059"
    strings:
        $stage = { FC E8 8? 00 00 00 }
        $winapi = { 60 89 E5 31 D2 64 8B 52 30 }
        $rev_tcp = "reverse_tcp" nocase
        $bind    = "bind_tcp" nocase
    condition:
        $stage or $winapi or any of ($rev_tcp, $bind)
}

rule Ransomware_Indicators {
    meta:
        description = "Common ransomware indicators"
        category    = "ransomware"
        attack_id   = "T1486"
    strings:
        $note1 = "your files have been encrypted" nocase wide
        $note2 = "bitcoin" nocase wide
        $note3 = "decrypt" nocase wide
        $note4 = "README" nocase
        $ext1  = ".locked" nocase
        $ext2  = ".crypt" nocase
        $ext3  = ".encrypted" nocase
        $cry   = "CryptEncrypt" nocase
        $cry2  = "CryptGenKey" nocase
    condition:
        (2 of ($note1,$note2,$note3,$note4)) or
        (any of ($ext1,$ext2,$ext3) and any of ($cry,$cry2))
}

rule Webshell_PHP {
    meta:
        description = "PHP webshell indicators"
        category    = "webshell"
        attack_id   = "T1505.003"
    strings:
        $eval1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)/ nocase
        $sys   = /\$_(GET|POST|REQUEST|COOKIE)\[.{1,30}\].*system\s*\(/ nocase
        $cmd   = "passthru" nocase
        $exec  = "shell_exec" nocase
        $upload = "move_uploaded_file" nocase
    condition:
        2 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike beacon patterns"
        category    = "c2"
        attack_id   = "T1059"
    strings:
        $magic1 = { 4D 5A 90 00 03 00 00 00 }
        $cs1    = "ReflectivLoader" nocase
        $cs2    = "beacon.dll" nocase
        $cs3    = "cobaltstrike" nocase
        $sleep  = "sleep_mask" nocase
    condition:
        $magic1 at 0 and any of ($cs1,$cs2,$cs3,$sleep)
}
"""


@dataclass
class ArtefactResult:
    """Result of analysing a file or hash."""
    # Input
    input_type:     str = ""        # "file" | "hash" | "indicator"
    input_value:    str = ""        # path or hash value

    # File metadata (only if input_type == "file")
    file_name:      str = ""
    file_size:      int = 0
    file_type:      str = ""

    # Computed hashes
    hash_md5:       str = ""
    hash_sha1:      str = ""
    hash_sha256:    str = ""
    hash_ssdeep:    str = ""

    # Verdict
    found:          bool = False
    verdict:        str = "unknown"     # clean|suspicious|malicious|unknown
    threat_score:   int = 0             # 0–100
    malware_family: str = ""
    malware_type:   str = ""

    # Intel sources that matched
    sources:        list = field(default_factory=list)
    details:        list = field(default_factory=list)

    # OTX pulse data
    pulse_names:    list = field(default_factory=list)
    pulse_ids:      list = field(default_factory=list)

    # ATT&CK enrichment
    attack_ids:     list = field(default_factory=list)
    attack_details: list = field(default_factory=list)  # full technique records

    # Sigma detections
    sigma_rules:    list = field(default_factory=list)  # matching sigma rule titles

    # YARA results
    yara_matches:   list = field(default_factory=list)  # rule names that matched

    # Tags / references
    tags:           list = field(default_factory=list)
    references:     list = field(default_factory=list)

    # Related IOCs (from same OTX pulses)
    related_ips:    list = field(default_factory=list)
    related_domains: list = field(default_factory=list)
    related_urls:   list = field(default_factory=list)

    # Error
    error:          str = ""


class ArtefactScanner:
    """
    Offline artefact and hash intelligence scanner.

    Queries the entire Fenrir offline DB with no network calls.
    Works with:
      - File paths  (computes hashes, runs YARA, queries DB)
      - Hash values (MD5/SHA1/SHA256)
      - OTX-style indicators (IP, domain, URL, CVE)
    """

    def __init__(self) -> None:
        log.debug("ArtefactScanner initialised.")
        self._db = self._load_db()
        self._yara_rules = self._compile_yara()

    def _load_db(self):
        try:
            from fenrir.database import get_db_manager
            return get_db_manager()
        except Exception as exc:
            log.warning(f"[artefact] DB not available: {exc}")
            return None

    def _compile_yara(self):
        if not YARA_OK:
            return None
        try:
            return _yara.compile(source=_BUILTIN_YARA_RULES)
        except Exception as exc:
            log.debug(f"[artefact] YARA compile error: {exc}")
            return None

    # ── Public API ─────────────────────────────────────────────────────────────

    async def scan_file(self, file_path: str) -> ArtefactResult:
        """
        Analyse a file:
          1. Compute MD5, SHA1, SHA256, ssdeep
          2. Detect file type
          3. Run YARA rules against file content
          4. Query all offline DB sources
          5. Enrich with ATT&CK techniques and Sigma rules
        """
        path = Path(file_path)
        result = ArtefactResult(input_type="file", input_value=str(path))

        if not path.exists():
            result.error = f"File not found: {path}"
            return result

        result.file_name = path.name
        result.file_size = path.stat().st_size
        log.info(f"[artefact] Scanning file: {path.name} "
                 f"({result.file_size:,} bytes)")

        # Compute hashes
        try:
            result.hash_md5, result.hash_sha1, result.hash_sha256 = \
                await asyncio.to_thread(self._compute_hashes, path)
            log.info(f"[artefact] SHA256: {result.hash_sha256}")
            log.info(f"[artefact] MD5:    {result.hash_md5}")
        except Exception as exc:
            result.error = f"Hash computation failed: {exc}"
            return result

        # ssdeep fuzzy hash
        if SSDEEP_OK:
            try:
                result.hash_ssdeep = await asyncio.to_thread(
                    _ssdeep.hash_from_file, str(path))
            except Exception:
                pass

        # File type detection
        result.file_type = await asyncio.to_thread(self._detect_file_type, path)

        # YARA scan
        if self._yara_rules:
            result.yara_matches = await asyncio.to_thread(
                self._run_yara, path)

        # DB lookups
        if result.hash_sha256:
            db_result = await asyncio.to_thread(
                self._query_db, result.hash_sha256)
            self._merge_db_result(result, db_result)

        # ATT&CK + Sigma enrichment
        await self._enrich_attack(result)
        await self._find_sigma_rules(result)

        # Pull related IOCs from matching pulses
        await self._pull_related_iocs(result)

        self._compute_final_verdict(result)
        self._log_summary(result)
        return result

    async def scan_hash(self, hash_value: str) -> ArtefactResult:
        """Query a hash (MD5/SHA1/SHA256) against all offline sources."""
        h = hash_value.strip().lower()
        result = ArtefactResult(input_type="hash", input_value=h)

        col_len = len(h)
        if col_len == 32:
            result.hash_md5    = h
        elif col_len == 40:
            result.hash_sha1   = h
        elif col_len == 64:
            result.hash_sha256 = h
        else:
            result.error = f"Unrecognised hash length {col_len}. Expected MD5(32), SHA1(40), SHA256(64)."
            return result

        log.info(f"[artefact] Hash query: {h[:16]}…")
        db_result = await asyncio.to_thread(self._query_db, h)
        self._merge_db_result(result, db_result)
        await self._enrich_attack(result)
        await self._find_sigma_rules(result)
        await self._pull_related_iocs(result)
        self._compute_final_verdict(result)
        self._log_summary(result)
        return result

    async def query_indicator(self, value: str) -> ArtefactResult:
        """
        Query any OTX-style indicator (IP, domain, URL, CVE, hash).
        Routes to the appropriate DB query.
        """
        v = value.strip()
        result = ArtefactResult(input_type="indicator", input_value=v)

        if not self._db or not self._db._available:
            result.error = "Offline database not available. Run --db-build first."
            return result

        try:
            conn = self._db._connect()

            # Check OTX indicators table
            rows = conn.execute(
                """SELECT oi.*, op.name as pulse_name, op.description as pulse_desc,
                          op.attack_ids, op.tags as pulse_tags
                   FROM otx_indicators oi
                   LEFT JOIN otx_pulses op ON oi.pulse_id = op.pulse_id
                   WHERE oi.indicator_value = ?
                   ORDER BY oi.created_date DESC
                   LIMIT 50""",
                (v,)
            ).fetchall()

            for row in rows:
                d = dict(row)
                result.found = True
                result.sources.append("otx_indicators")
                result.details.append(d)
                if d.get("malware_family"):
                    result.malware_family = d["malware_family"]
                if d.get("pulse_name") and d["pulse_name"] not in result.pulse_names:
                    result.pulse_names.append(d["pulse_name"])
                    result.pulse_ids.append(d.get("pulse_id",""))
                # ATT&CK from pulse
                try:
                    ids = json.loads(d.get("attack_ids") or "[]")
                    result.attack_ids.extend(
                        x for x in ids if x not in result.attack_ids)
                except Exception:
                    pass
                try:
                    tags = json.loads(d.get("pulse_tags") or "[]")
                    result.tags.extend(x for x in tags if x not in result.tags)
                except Exception:
                    pass

            # Also check ip_reputation if it looks like an IP
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                ip_rows = conn.execute(
                    "SELECT * FROM ip_reputation WHERE ip_address = ? LIMIT 10",
                    (v,)
                ).fetchall()
                for row in ip_rows:
                    d = dict(row)
                    result.found = True
                    result.sources.append("ip_reputation")
                    result.details.append(d)
                    if result.threat_score < (d.get("score") or 0):
                        result.threat_score = d.get("score", 50)

            conn.close()

            if result.found:
                result.verdict = "malicious"
            await self._enrich_attack(result)
            await self._find_sigma_rules(result)
            self._log_summary(result)

        except Exception as exc:
            result.error = str(exc)
            log.error(f"[artefact] indicator query error: {exc}")

        return result

    # ── File analysis helpers ──────────────────────────────────────────────────

    @staticmethod
    def _compute_hashes(path: Path) -> tuple[str, str, str]:
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    @staticmethod
    def _detect_file_type(path: Path) -> str:
        """Lightweight magic-byte file type detection."""
        MAGIC = {
            b"MZ":                           "PE (Windows Executable)",
            b"\x7fELF":                      "ELF (Linux Executable)",
            b"PK\x03\x04":                   "ZIP Archive",
            b"\x1f\x8b":                     "GZIP",
            b"Rar!":                          "RAR Archive",
            b"\xca\xfe\xba\xbe":             "Java Class",
            b"\xfe\xed\xfa\xce":             "Mach-O 32-bit",
            b"\xce\xfa\xed\xfe":             "Mach-O 32-bit (reversed)",
            b"\xfe\xed\xfa\xcf":             "Mach-O 64-bit",
            b"\xcf\xfa\xed\xfe":             "Mach-O 64-bit (reversed)",
            b"%PDF":                          "PDF Document",
            b"<?php":                         "PHP Script",
            b"#!/":                           "Shell Script",
            b"\x89PNG":                       "PNG Image",
            b"\xff\xd8\xff":                  "JPEG Image",
            b"GIF87a":                        "GIF Image",
            b"GIF89a":                        "GIF Image",
            b"RIFF":                          "RIFF (WAV/AVI)",
            b"\x00\x00\x01\x00":             "ICO File",
            b"MSCFd":                         "Microsoft Cabinet",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a": "Microsoft OLE (Office)",
            b"OggS":                          "OGG Media",
            b"7z\xbc\xaf'":                  "7-Zip Archive",
        }
        try:
            with open(path, "rb") as fh:
                header = fh.read(16)
            for magic, name in MAGIC.items():
                if header[:len(magic)] == magic:
                    return name
            # Check extension as fallback
            ext = path.suffix.lower()
            ext_map = {
                ".ps1": "PowerShell Script", ".bat": "Batch Script",
                ".vbs": "VBScript",          ".js":  "JavaScript",
                ".py":  "Python Script",     ".sh":  "Shell Script",
                ".dll": "DLL",               ".sys": "Kernel Driver",
                ".doc": "Word Document",     ".xls": "Excel Spreadsheet",
                ".docx":"Word Document",     ".xlsx":"Excel Spreadsheet",
                ".pdf": "PDF Document",      ".jar": "Java Archive",
                ".apk": "Android Package",   ".ipa": "iOS Package",
            }
            return ext_map.get(ext, f"Unknown ({ext})")
        except Exception:
            return "Unknown"

    def _run_yara(self, path: Path) -> list[str]:
        """Run compiled YARA rules against the file. Returns list of matching rule names."""
        if not self._yara_rules:
            return []
        try:
            matches = self._yara_rules.match(str(path))
            results = []
            for m in matches:
                meta    = m.meta or {}
                attack  = meta.get("attack_id", "")
                cat     = meta.get("category", "")
                label   = f"{m.rule}"
                if cat:     label += f" [{cat}]"
                if attack:  label += f" ({attack})"
                results.append(label)
            return results
        except Exception as exc:
            log.debug(f"[yara] {exc}")
            return []

    # ── DB query ───────────────────────────────────────────────────────────────

    def _query_db(self, hash_value: str) -> dict:
        """Synchronous multi-source hash lookup — call via asyncio.to_thread."""
        if not self._db or not self._db._available:
            return {"found": False, "verdict": "unknown", "threat_score": 0,
                    "sources": [], "details": [], "attack_ids": [],
                    "pulse_names": [], "pulse_ids": [], "malware_family": "", "tags": []}
        return self._db.query_hash_all_sources(hash_value)

    def _merge_db_result(self, result: ArtefactResult, db: dict) -> None:
        if db.get("found"):
            result.found          = True
            result.verdict        = db.get("verdict", "malicious")
            result.threat_score   = db.get("threat_score", 70)
            result.malware_family = db.get("malware_family", "")
            result.sources.extend(db.get("sources", []))
            result.details.extend(db.get("details", []))
            result.attack_ids.extend(
                x for x in db.get("attack_ids", [])
                if x not in result.attack_ids)
            result.pulse_names.extend(
                x for x in db.get("pulse_names", [])
                if x not in result.pulse_names)
            result.tags.extend(
                x for x in db.get("tags", [])
                if x not in result.tags)

    # ── ATT&CK enrichment ─────────────────────────────────────────────────────

    async def _enrich_attack(self, result: ArtefactResult) -> None:
        """Look up full ATT&CK technique records for all technique IDs found."""
        if not result.attack_ids or not self._db or not self._db._available:
            return
        try:
            def _lookup():
                details = []
                conn = self._db._connect()
                for tid in result.attack_ids[:20]:
                    row = conn.execute(
                        "SELECT * FROM attack_techniques WHERE technique_id = ?",
                        (tid.upper(),)
                    ).fetchone()
                    if row:
                        details.append(dict(row))
                    # Also search by tag in case it's a sub-technique
                    if not row:
                        rows = conn.execute(
                            "SELECT * FROM attack_techniques WHERE technique_id LIKE ?",
                            (f"{tid}%",)
                        ).fetchall()
                        details.extend(dict(r) for r in rows[:3])
                conn.close()
                return details
            result.attack_details = await asyncio.to_thread(_lookup)
        except Exception as exc:
            log.debug(f"[artefact] ATT&CK enrichment: {exc}")

    # ── Sigma rule matching ────────────────────────────────────────────────────

    async def _find_sigma_rules(self, result: ArtefactResult) -> None:
        """Find Sigma detection rules relevant to this threat."""
        if not self._db or not self._db._available:
            return
        search_terms = []
        if result.malware_family:
            search_terms.append(result.malware_family)
        for tech in result.attack_ids[:5]:
            search_terms.append(f"attack.{tech.lower()}")
        if not search_terms:
            return
        try:
            def _search():
                matches = []
                conn = self._db._connect()
                for term in search_terms[:3]:
                    rows = conn.execute(
                        """SELECT rule_id, title, level, category, tags
                           FROM sigma_rules
                           WHERE title LIKE ? OR tags LIKE ? OR description LIKE ?
                           LIMIT 5""",
                        (f"%{term}%", f"%{term}%", f"%{term}%")
                    ).fetchall()
                    for r in rows:
                        d = dict(r)
                        label = f"{d.get('title','')} [{d.get('level','')}]"
                        if label not in matches:
                            matches.append(label)
                conn.close()
                return matches
            result.sigma_rules = await asyncio.to_thread(_search)
        except Exception as exc:
            log.debug(f"[artefact] Sigma search: {exc}")

    # ── Related IOCs ───────────────────────────────────────────────────────────

    async def _pull_related_iocs(self, result: ArtefactResult) -> None:
        """Pull related IPs, domains, URLs from the same OTX pulses."""
        if not result.pulse_ids or not self._db or not self._db._available:
            return
        try:
            def _pull():
                ips, domains, urls = [], [], []
                conn = self._db._connect()
                for pid in result.pulse_ids[:5]:
                    rows = conn.execute(
                        """SELECT indicator_type, indicator_value
                           FROM otx_indicators WHERE pulse_id = ?
                           LIMIT 30""",
                        (pid,)
                    ).fetchall()
                    for r in rows:
                        t, v = r["indicator_type"], r["indicator_value"]
                        if "IPv4" in t and v not in ips:
                            ips.append(v)
                        elif "domain" in t.lower() and v not in domains:
                            domains.append(v)
                        elif "URL" in t and v not in urls:
                            urls.append(v)
                conn.close()
                return ips[:20], domains[:20], urls[:10]
            result.related_ips, result.related_domains, result.related_urls = \
                await asyncio.to_thread(_pull)
        except Exception as exc:
            log.debug(f"[artefact] related IOC pull: {exc}")

    # ── Verdict ────────────────────────────────────────────────────────────────

    def _compute_final_verdict(self, result: ArtefactResult) -> None:
        # YARA hits boost score
        if result.yara_matches:
            result.threat_score = max(result.threat_score, 60)
            if result.verdict == "unknown":
                result.verdict = "suspicious"

        # Multiple sources → higher confidence
        if len(result.sources) >= 2 and result.found:
            result.verdict = "malicious"
            result.threat_score = max(result.threat_score, 85)

        # Clamp score
        result.threat_score = max(0, min(100, result.threat_score))

    def _log_summary(self, result: ArtefactResult) -> None:
        v_icons = {"malicious":"🔴","suspicious":"🟡","clean":"🟢","unknown":"⚪"}
        icon    = v_icons.get(result.verdict, "⚪")
        log.info(f"[artefact] {icon} {result.input_value[:40]} → "
                 f"verdict={result.verdict} score={result.threat_score} "
                 f"sources={result.sources} family={result.malware_family or '-'}")
        if result.yara_matches:
            log.info(f"[artefact]   YARA: {result.yara_matches}")
        if result.attack_ids:
            log.info(f"[artefact]   ATT&CK: {result.attack_ids}")

    def to_report_dict(self, result: ArtefactResult) -> dict:
        """Convert an ArtefactResult to a serialisable dict for report_manager."""
        return {
            "title":        f"Artefact Analysis: {result.file_name or result.input_value[:40]}",
            "input_type":   result.input_type,
            "input_value":  result.input_value,
            "file_name":    result.file_name,
            "file_size":    result.file_size,
            "file_type":    result.file_type,
            "hash_md5":     result.hash_md5,
            "hash_sha1":    result.hash_sha1,
            "hash_sha256":  result.hash_sha256,
            "hash_ssdeep":  result.hash_ssdeep,
            "verdict":      result.verdict,
            "threat_score": result.threat_score,
            "malware_family": result.malware_family,
            "found":        result.found,
            "sources":      result.sources,
            "yara_matches": result.yara_matches,
            "attack_ids":   result.attack_ids,
            "attack_details": result.attack_details,
            "sigma_rules":  result.sigma_rules,
            "pulse_names":  result.pulse_names,
            "related_ips":  result.related_ips,
            "related_domains": result.related_domains,
            "tags":         result.tags,
            "error":        result.error,
        }
