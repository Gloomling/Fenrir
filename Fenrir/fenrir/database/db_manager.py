# fenrir/database/db_manager.py
#
# Query interface for the Fenrir offline intelligence database.
#
# Design:
#   - All scanner modules use this class instead of live API calls.
#   - Uses SQLite with WAL mode for safe concurrent reads during scans.
#   - All query methods are synchronous — callers wrap in asyncio.to_thread()
#     if called from async contexts (see examples in each method's docstring).
#   - Returns structured dicts matching the format previously returned by
#     nvdlib and searchsploit so scanner modules require minimal changes.
#   - Gracefully handles a missing or empty database — returns empty results
#     with a warning rather than crashing. This allows the tool to run in
#     online-only mode if the database has not been built yet.
#
# Thread safety:
#   - SQLite in WAL mode supports concurrent readers.
#   - Each public method opens and closes its own connection from a pool.
#   - A threading.Lock guards write operations (used by DatabaseBuilder).

import json
import os
import shutil
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from ..logging_config import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

# Resolve paths relative to this file's location
_MODULE_DIR   = Path(__file__).resolve().parent
_PROJECT_ROOT = _MODULE_DIR.parent.parent
DB_DIR        = _PROJECT_ROOT / "data" / "db"
DB_PATH       = DB_DIR / "fenrir.db"
EXPLOITS_DIR  = DB_DIR / "exploits"


class DatabaseManager:
    """
    Query interface for the Fenrir offline intelligence database.

    Args:
        db_path (Path | str | None):
            Path to the SQLite database file.
            Defaults to <project_root>/data/db/fenrir.db.

    Usage in async scanner modules:
        from fenrir.database import get_db_manager
        db = get_db_manager()

        # Wrap in asyncio.to_thread for async contexts:
        results = await asyncio.to_thread(db.search_cves, "Apache 2.4.51")
    """

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self.db_path = Path(db_path) if db_path else DB_PATH
        self._lock = threading.Lock()
        self._available = self._check_availability()

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def _check_availability(self) -> bool:
        """
        Check whether the database file exists and has been populated.

        Returns:
            True if the database is usable, False otherwise.
        """
        if not self.db_path.exists():
            log.warning(
                f"Offline database not found at '{self.db_path}'. "
                "Run 'fenrir --db-build' to build it. "
                "Some modules will fall back to live API calls if configured."
            )
            return False

        try:
            conn = self._connect()
            cursor = conn.execute(
                "SELECT value FROM db_meta WHERE key = 'schema_version'"
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                log.debug(
                    f"Offline database available at '{self.db_path}'. "
                    f"Schema version: {row[0]}"
                )
                return True
            else:
                log.warning(
                    "Database exists but appears empty or uninitialised. "
                    "Run 'fenrir --db-build' to populate it."
                )
                return False
        except sqlite3.Error as exc:
            log.warning(f"Database check failed: {exc}")
            return False

    def is_available(self) -> bool:
        """Return True if the database is available and usable."""
        return self._available

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """
        Open a SQLite connection with optimal settings for read performance.

        Returns:
            sqlite3.Connection with WAL mode and row factory set.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn

    # ------------------------------------------------------------------
    # CVE queries
    # ------------------------------------------------------------------

    def search_cves(
        self,
        keyword: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 5,
        year_from: Optional[int] = None,
    ) -> tuple[list[dict], bool]:
        """
        Search the local CVE database.

        Searches are performed in priority order:
          1. CPE-based lookup (most precise) — if product + version given
          2. Full-text search on description (if keyword given)
          3. Combined filter on severity/score

        Args:
            keyword:   Free-text search string (e.g. "Apache httpd 2.4.51").
            product:   Product name for CPE matching (e.g. "apache").
            version:   Version string for CPE matching (e.g. "2.4.51").
            severity:  Filter by severity: "CRITICAL", "HIGH", "MEDIUM", "LOW".
            min_score: Filter by minimum CVSS v3 score (0.0 - 10.0).
            limit:     Maximum results to return. Default 5.
            year_from: Only return CVEs published from this year onwards.

        Returns:
            Tuple of (results, has_more):
              results  — list of CVE dicts (see _row_to_cve_dict)
              has_more — True if more results exist beyond the limit

        Usage:
            results, has_more = await asyncio.to_thread(
                db.search_cves, keyword="Apache 2.4.51", limit=5
            )
        """
        if not self._available:
            log.warning("CVE search skipped — offline database not available.")
            return [], False

        try:
            conn = self._connect()
            fetch_count = limit + 1  # Fetch one extra to detect overflow

            rows = []

            # --- Strategy 1: CPE-based lookup ---
            if product and version:
                rows = self._search_by_cpe(conn, product, version, fetch_count)

            # --- Strategy 2: FTS keyword search ---
            if not rows and keyword:
                rows = self._search_by_fts(conn, keyword, fetch_count)

            # --- Strategy 3: Keyword LIKE fallback ---
            # FTS may miss short keywords; LIKE is a reliable fallback
            if not rows and keyword:
                rows = self._search_by_like(conn, keyword, fetch_count)

            conn.close()

            # Apply post-filters
            results = [self._row_to_cve_dict(r) for r in rows]

            if severity:
                results = [
                    r for r in results
                    if r.get("cvss_v3_severity", "").upper() == severity.upper()
                ]
            if min_score is not None:
                results = [
                    r for r in results
                    if (r.get("cvss_v3_score") or 0) >= min_score
                ]
            if year_from:
                results = [
                    r for r in results
                    if _extract_year(r.get("published", "")) >= year_from
                ]

            # Sort by CVSS score descending
            results.sort(
                key=lambda x: x.get("cvss_v3_score") or 0,
                reverse=True,
            )

            has_more = len(results) > limit
            return results[:limit], has_more

        except sqlite3.Error as exc:
            log.error(f"CVE search error: {exc}")
            return [], False

    def _search_by_cpe(
        self,
        conn: sqlite3.Connection,
        product: str,
        version: str,
        limit: int,
    ) -> list[sqlite3.Row]:
        """Search CVEs via CPE product/version matching."""
        # Build a CPE pattern — NVD CPE format: cpe:2.3:a:vendor:product:version:...
        cpe_pattern = f"%:{product.lower()}:%:{version}:%"
        cursor = conn.execute(
            """
            SELECT DISTINCT c.*
            FROM cves c
            JOIN cpe_matches m ON c.cve_id = m.cve_id
            WHERE m.cpe_string LIKE ?
              AND m.vulnerable = 1
            ORDER BY c.cvss_v3_score DESC NULLS LAST
            LIMIT ?
            """,
            (cpe_pattern, limit),
        )
        return cursor.fetchall()

    def _search_by_fts(
        self,
        conn: sqlite3.Connection,
        keyword: str,
        limit: int,
    ) -> list[sqlite3.Row]:
        """Search CVEs using the full-text search index."""
        try:
            cursor = conn.execute(
                """
                SELECT c.*
                FROM cves c
                JOIN cves_fts f ON c.rowid = f.rowid
                WHERE cves_fts MATCH ?
                ORDER BY c.cvss_v3_score DESC NULLS LAST
                LIMIT ?
                """,
                (keyword, limit),
            )
            return cursor.fetchall()
        except sqlite3.OperationalError:
            # FTS table may not exist in older databases
            return []

    def _search_by_like(
        self,
        conn: sqlite3.Connection,
        keyword: str,
        limit: int,
    ) -> list[sqlite3.Row]:
        """Search CVEs using LIKE pattern matching on description."""
        pattern = f"%{keyword}%"
        cursor = conn.execute(
            """
            SELECT *
            FROM cves
            WHERE description LIKE ?
               OR cve_id LIKE ?
            ORDER BY cvss_v3_score DESC NULLS LAST
            LIMIT ?
            """,
            (pattern, pattern, limit),
        )
        return cursor.fetchall()

    def get_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """
        Retrieve a single CVE record by its ID.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2021-44228").

        Returns:
            CVE dict or None if not found.
        """
        if not self._available:
            return None
        try:
            conn = self._connect()
            cursor = conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?",
                (cve_id.upper(),),
            )
            row = cursor.fetchone()
            conn.close()
            return self._row_to_cve_dict(row) if row else None
        except sqlite3.Error as exc:
            log.error(f"get_cve_by_id error: {exc}")
            return None

    @staticmethod
    def _row_to_cve_dict(row: sqlite3.Row) -> dict:
        """Convert a SQLite Row from the cves table to a dict."""
        d = dict(row)
        # Deserialise JSON fields
        for field in ("cpe_matches", "references"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
            else:
                d[field] = []
        return d

    # ------------------------------------------------------------------
    # Exploit queries
    # ------------------------------------------------------------------

    def search_exploits(
        self,
        query: str,
        platform: Optional[str] = None,
        exploit_type: Optional[str] = None,
        verified_only: bool = False,
        limit: int = 20,
    ) -> list[dict]:
        """
        Search the local Exploit-DB for matching exploits.

        Args:
            query:         Search string (e.g. "Apache 2.4.51", "CVE-2021-41773").
            platform:      Filter by platform (e.g. "linux", "windows", "php").
            exploit_type:  Filter by type (e.g. "remote", "local", "webapps").
            verified_only: Only return exploits marked as verified. Default False.
            limit:         Maximum results. Default 20.

        Returns:
            List of exploit dicts, each containing:
            exploit_id, title, file_path, type, platform, date_published,
            author, verified, cve_ids, edb_url, local_file_path (full path).

        Usage:
            exploits = await asyncio.to_thread(
                db.search_exploits, "Apache 2.4.51 path traversal"
            )
        """
        if not self._available:
            log.warning("Exploit search skipped — offline database not available.")
            return []

        try:
            conn = self._connect()
            results = []

            # --- FTS search first ---
            try:
                cursor = conn.execute(
                    """
                    SELECT e.*
                    FROM exploits e
                    JOIN exploits_fts f ON e.rowid = f.rowid
                    WHERE exploits_fts MATCH ?
                    ORDER BY e.verified DESC, e.date_published DESC
                    LIMIT ?
                    """,
                    (query, limit * 2),  # Fetch extra for post-filtering
                )
                results = cursor.fetchall()
            except sqlite3.OperationalError:
                pass

            # --- LIKE fallback ---
            if not results:
                pattern = f"%{query}%"
                cursor = conn.execute(
                    """
                    SELECT *
                    FROM exploits
                    WHERE title LIKE ?
                       OR description LIKE ?
                       OR cve_ids LIKE ?
                    ORDER BY verified DESC, date_published DESC
                    LIMIT ?
                    """,
                    (pattern, pattern, pattern, limit * 2),
                )
                results = cursor.fetchall()

            conn.close()

            # Convert to dicts and post-filter
            exploit_list = [self._row_to_exploit_dict(r) for r in results]

            if platform:
                exploit_list = [
                    e for e in exploit_list
                    if platform.lower() in (e.get("platform") or "").lower()
                ]
            if exploit_type:
                exploit_list = [
                    e for e in exploit_list
                    if exploit_type.lower() in (e.get("type") or "").lower()
                ]
            if verified_only:
                exploit_list = [
                    e for e in exploit_list
                    if e.get("verified") == 1
                ]

            return exploit_list[:limit]

        except sqlite3.Error as exc:
            log.error(f"Exploit search error: {exc}")
            return []

    def get_exploit_file_path(self, exploit_id: int) -> Optional[Path]:
        """
        Get the full local file path for an exploit.

        Args:
            exploit_id: Exploit-DB ID number.

        Returns:
            Path to the exploit file on disk, or None if not found.
        """
        if not self._available:
            return None
        try:
            conn = self._connect()
            cursor = conn.execute(
                "SELECT file_path FROM exploits WHERE exploit_id = ?",
                (exploit_id,),
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            full_path = EXPLOITS_DIR / row["file_path"].lstrip("/")
            return full_path if full_path.exists() else None

        except sqlite3.Error as exc:
            log.error(f"get_exploit_file_path error: {exc}")
            return None

    def copy_exploit_to_workdir(
        self,
        exploit_id: int,
        dest_dir: Optional[Path | str] = None,
    ) -> Optional[Path]:
        """
        Copy an exploit file to the working directory (like searchsploit --mirror).

        Args:
            exploit_id: Exploit-DB ID number.
            dest_dir:   Destination directory. Defaults to current working dir.

        Returns:
            Path to the copied file, or None if the source file is not found.
        """
        src_path = self.get_exploit_file_path(exploit_id)
        if not src_path:
            log.warning(
                f"Exploit {exploit_id}: source file not found in local database. "
                "The exploit index entry exists but the file was not downloaded."
            )
            return None

        dest_dir = Path(dest_dir) if dest_dir else Path.cwd()
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / src_path.name

        try:
            shutil.copy2(src_path, dest_path)
            log.info(f"Exploit {exploit_id} copied to: {dest_path}")
            return dest_path
        except OSError as exc:
            log.error(
                f"Failed to copy exploit {exploit_id} to '{dest_path}': {exc}"
            )
            return None

    def _row_to_exploit_dict(self, row: sqlite3.Row) -> dict:
        """Convert a SQLite Row from the exploits table to a dict."""
        d = dict(row)
        # Deserialise CVE IDs JSON field
        if d.get("cve_ids"):
            try:
                d["cve_ids"] = json.loads(d["cve_ids"])
            except (json.JSONDecodeError, TypeError):
                d["cve_ids"] = []
        else:
            d["cve_ids"] = []

        # Add full local file path
        if d.get("file_path"):
            full_path = EXPLOITS_DIR / d["file_path"].lstrip("/")
            d["local_file_path"] = str(full_path) if full_path.exists() else None
        else:
            d["local_file_path"] = None

        return d

    # ------------------------------------------------------------------
    # IP reputation queries
    # ------------------------------------------------------------------

    def check_ip_reputation(self, ip_address: str) -> Optional[dict]:
        """
        Check an IP address against the local threat intelligence feeds.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Reputation dict if the IP is known malicious:
            {ip_address, category, source, added_date, notes}
            None if the IP is not in the local database (clean or unknown).

        Usage:
            result = await asyncio.to_thread(db.check_ip_reputation, "1.2.3.4")
            if result:
                log.warning(f"Known malicious IP: {result['category']}")
        """
        if not self._available:
            return None
        try:
            conn = self._connect()
            cursor = conn.execute(
                "SELECT * FROM ip_reputation WHERE ip_address = ?",
                (ip_address,),
            )
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None
        except sqlite3.Error as exc:
            log.error(f"IP reputation check error: {exc}")
            return None

    def check_ip_range_reputation(self, ip_address: str) -> list[dict]:
        """
        Check if an IP falls within any known malicious CIDR ranges.

        Uses a simple prefix search rather than full CIDR parsing for
        performance. Checks /8, /16, and /24 prefixes.

        Args:
            ip_address: IPv4 address string.

        Returns:
            List of reputation dicts for matching ranges.
        """
        if not self._available:
            return []

        results = []
        try:
            parts = ip_address.split(".")
            if len(parts) != 4:
                return []

            prefixes = [
                f"{parts[0]}.",
                f"{parts[0]}.{parts[1]}.",
                f"{parts[0]}.{parts[1]}.{parts[2]}.",
            ]

            conn = self._connect()
            for prefix in prefixes:
                cursor = conn.execute(
                    "SELECT * FROM ip_reputation WHERE ip_address LIKE ?",
                    (f"{prefix}%",),
                )
                rows = cursor.fetchall()
                results.extend([dict(r) for r in rows])
            conn.close()
        except sqlite3.Error as exc:
            log.error(f"IP range reputation check error: {exc}")

        return results

    # ------------------------------------------------------------------
    # Hash reputation queries
    # ------------------------------------------------------------------

    def check_hash(
        self,
        hash_value: str,
        hash_type: str = "sha256",
    ) -> Optional[dict]:
        """
        Check a file hash against the local malware hash database.

        Args:
            hash_value: Hash string to check.
            hash_type:  Hash algorithm: "sha256", "md5", or "sha1". Default "sha256".

        Returns:
            Hash reputation dict if found:
            {hash_sha256, hash_md5, malware_family, malware_type, source,
             added_date, signature}
            None if hash is not in the database.

        Usage:
            result = await asyncio.to_thread(
                db.check_hash, sha256_hash, "sha256"
            )
        """
        if not self._available:
            return None

        column_map = {
            "sha256": "hash_sha256",
            "md5":    "hash_md5",
            "sha1":   "hash_sha1",
        }
        column = column_map.get(hash_type.lower())
        if not column:
            log.warning(f"Unknown hash type '{hash_type}'. Use sha256, md5, or sha1.")
            return None

        try:
            conn = self._connect()
            cursor = conn.execute(
                f"SELECT * FROM hash_reputation WHERE {column} = ?",
                (hash_value.lower(),),
            )
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None
        except sqlite3.Error as exc:
            log.error(f"Hash reputation check error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Database status
    # ------------------------------------------------------------------

    def get_db_status(self) -> dict:
        """
        Return a summary of the database build status and record counts.

        Returns:
            Dict with keys:
              available       (bool)   — whether the database is usable
              schema_version  (str)    — current schema version
              nvd_last_updated (str)   — NVD build/update timestamp
              nvd_build_type  (str)    — "full" or "lite"
              nvd_cve_count   (int)    — number of CVE records
              exploitdb_last_updated (str) — Exploit-DB build timestamp
              exploitdb_exploit_count (int) — number of exploit records
              threat_feeds_last_updated (str) — threat feeds timestamp
              ip_reputation_count (int) — number of IP reputation records
              hash_reputation_count (int) — number of hash records
              db_size_mb      (float)  — database file size in MB
        """
        status = {
            "available":       self._available,
            "schema_version":  "N/A",
            "nvd_last_updated": "Never",
            "nvd_build_type":  "N/A",
            "nvd_cve_count":   0,
            "exploitdb_last_updated": "Never",
            "exploitdb_exploit_count": 0,
            "threat_feeds_last_updated": "Never",
            "ip_reputation_count": 0,
            "hash_reputation_count": 0,
            "db_size_mb": 0.0,
        }

        if not self._available:
            return status

        try:
            conn = self._connect()

            # Fetch all meta values
            cursor = conn.execute("SELECT key, value FROM db_meta")
            meta = {row["key"]: row["value"] for row in cursor.fetchall()}

            # Get record counts
            for table, key in [
                ("cves",           "nvd_cve_count"),
                ("exploits",       "exploitdb_exploit_count"),
                ("ip_reputation",  "ip_reputation_count"),
                ("hash_reputation","hash_reputation_count"),
            ]:
                try:
                    cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                    status[key] = cursor.fetchone()[0]
                except sqlite3.Error:
                    pass

            conn.close()

            # Populate from meta
            status["schema_version"]  = meta.get("schema_version", "N/A")
            status["nvd_last_updated"] = meta.get("nvd_last_updated", "Never")
            status["nvd_build_type"]  = meta.get("nvd_build_type", "N/A")
            status["exploitdb_last_updated"] = meta.get(
                "exploitdb_last_updated", "Never"
            )
            status["threat_feeds_last_updated"] = meta.get(
                "threat_feeds_last_updated", "Never"
            )

            # Database file size
            if self.db_path.exists():
                status["db_size_mb"] = round(
                    self.db_path.stat().st_size / (1024 * 1024), 2
                )

        except sqlite3.Error as exc:
            log.error(f"get_db_status error: {exc}")

        return status

    def print_db_status(self) -> None:
        """Print a formatted database status summary to the log."""
        status = self.get_db_status()

        log.info("=" * 50)
        log.info("  Fenrir Offline Database Status")
        log.info("=" * 50)

        if not status["available"]:
            log.warning("  Database: NOT BUILT")
            log.warning("  Run 'fenrir --db-build' to build the database.")
            log.info("=" * 50)
            return

        log.info(f"  Schema Version  : {status['schema_version']}")
        log.info(f"  Database Size   : {status['db_size_mb']} MB")
        log.info("")
        log.info("  NVD (CVE Database):")
        log.info(f"    Build Type    : {status['nvd_build_type']}")
        log.info(f"    CVE Records   : {status['nvd_cve_count']:,}")
        log.info(f"    Last Updated  : {status['nvd_last_updated']}")
        log.info("")
        log.info("  Exploit-DB:")
        log.info(f"    Exploit Records: {status['exploitdb_exploit_count']:,}")
        log.info(f"    Last Updated  : {status['exploitdb_last_updated']}")
        log.info("")
        log.info("  Threat Intelligence Feeds:")
        log.info(f"    IP Reputation : {status['ip_reputation_count']:,} entries")
        log.info(f"    Hash Reputation: {status['hash_reputation_count']:,} entries")
        log.info(f"    Last Updated  : {status['threat_feeds_last_updated']}")
        log.info("=" * 50)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _extract_year(date_str: str) -> int:
    """Extract year from an ISO date string. Returns 0 on failure."""
    try:
        return int(date_str[:4])
    except (ValueError, TypeError, IndexError):
        return 0
