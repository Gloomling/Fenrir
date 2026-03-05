# fenrir/scan_history.py
#
# Scan history database — stores every scan result in a local SQLite database.
# Supports: listing past scans, loading full results, diff between two scans,
# EPSS score enrichment, and scheduled scan management.

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

log = logging.getLogger("fenrir")

# Default history DB lives alongside the results folder
_HISTORY_DB: Optional[Path] = None


def _get_history_path() -> Path:
    global _HISTORY_DB
    if _HISTORY_DB:
        return _HISTORY_DB
    from .fenrir_paths import RESULTS_DIR
    path = RESULTS_DIR / "scan_history.db"
    _HISTORY_DB = path
    return path


def set_history_path(path: Path) -> None:
    global _HISTORY_DB
    _HISTORY_DB = Path(path)


# =============================================================================
# Schema
# =============================================================================

_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    target      TEXT NOT NULL,
    scan_type   TEXT NOT NULL DEFAULT 'single',   -- 'single' | 'network'
    modules     TEXT,                              -- JSON list
    result_dir  TEXT,
    summary     TEXT,                              -- JSON summary dict
    report_json TEXT                               -- full JSON report
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    target       TEXT NOT NULL,
    scan_type    TEXT NOT NULL DEFAULT 'single',
    modules      TEXT,
    interval_h   REAL NOT NULL DEFAULT 24,         -- hours between runs
    next_run_at  TEXT NOT NULL,
    last_run_at  TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1
);
"""


class ScanHistory:
    """Thread-safe scan history store."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = db_path or _get_history_path()
        self._lock = threading.Lock()
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_schema(self) -> None:
        try:
            with self._lock:
                conn = self._connect()
                conn.executescript(_DDL)
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error(f"[history] Schema init error: {exc}")

    # ------------------------------------------------------------------
    # Scan recording
    # ------------------------------------------------------------------

    def begin_scan(self, target: str, scan_type: str = "single",
                   modules: Optional[list] = None) -> int:
        """Record a scan start. Returns the scan row id."""
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.execute(
                    "INSERT INTO scans (started_at, target, scan_type, modules) "
                    "VALUES (?, ?, ?, ?)",
                    (datetime.now().isoformat(), target, scan_type,
                     json.dumps(modules or []))
                )
                scan_id = cur.lastrowid
                conn.commit()
                conn.close()
                return scan_id
        except Exception as exc:
            log.error(f"[history] begin_scan error: {exc}")
            return -1

    def finish_scan(self, scan_id: int, result_dir: str,
                    summary: dict, report_json: dict) -> None:
        """Update the scan record with results."""
        if scan_id < 0:
            return
        try:
            with self._lock:
                conn = self._connect()
                conn.execute(
                    "UPDATE scans SET finished_at=?, result_dir=?, "
                    "summary=?, report_json=? WHERE id=?",
                    (datetime.now().isoformat(), result_dir,
                     json.dumps(summary), json.dumps(report_json), scan_id)
                )
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error(f"[history] finish_scan error: {exc}")

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_scans(self, limit: int = 200) -> list[dict]:
        """Return recent scans, newest first, without full report JSON."""
        try:
            with self._lock:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT id, started_at, finished_at, target, scan_type, "
                    "modules, result_dir, summary "
                    "FROM scans ORDER BY started_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                conn.close()
            result = []
            for r in rows:
                d = dict(r)
                d["summary"] = _safe_json(d.get("summary"))
                d["modules"] = _safe_json(d.get("modules"))
                result.append(d)
            return result
        except Exception as exc:
            log.error(f"[history] list_scans error: {exc}")
            return []

    def get_scan(self, scan_id: int) -> Optional[dict]:
        """Load full scan record including report JSON."""
        try:
            with self._lock:
                conn = self._connect()
                row = conn.execute(
                    "SELECT * FROM scans WHERE id=?", (scan_id,)
                ).fetchone()
                conn.close()
            if not row:
                return None
            d = dict(row)
            d["summary"]     = _safe_json(d.get("summary"))
            d["modules"]     = _safe_json(d.get("modules"))
            d["report_json"] = _safe_json(d.get("report_json"))
            return d
        except Exception as exc:
            log.error(f"[history] get_scan error: {exc}")
            return None

    def delete_scan(self, scan_id: int) -> None:
        try:
            with self._lock:
                conn = self._connect()
                conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error(f"[history] delete_scan error: {exc}")

    # ------------------------------------------------------------------
    # Diff: compare two scans for the same target
    # ------------------------------------------------------------------

    def diff_scans(self, scan_id_a: int, scan_id_b: int) -> dict:
        """
        Compare two scans.  Returns:
          new_ports, closed_ports, new_cves, resolved_cves,
          new_exploits, os_changed (bool), duration_delta
        """
        a = self.get_scan(scan_id_a)
        b = self.get_scan(scan_id_b)
        if not a or not b:
            return {"error": "One or both scan IDs not found"}

        def _extract(scan: dict):
            report = scan.get("report_json") or {}
            ports, cves, exploits = set(), set(), set()
            for section in (report if isinstance(report, list)
                            else report.get("sections", [])):
                title = (section.get("title", "") or "").lower()
                findings = section.get("findings", []) or []
                for f in findings:
                    if isinstance(f, dict):
                        if "port" in title:
                            ports.add(str(f.get("port", "")))
                        if "cve" in title or "vuln" in title:
                            cves.add(f.get("id") or f.get("cve_id", ""))
                        if "exploit" in title:
                            exploits.add(str(f.get("id", "")))
            summary = scan.get("summary") or {}
            os_name = summary.get("os_name", "")
            return ports, cves, exploits, os_name

        ports_a, cves_a, expl_a, os_a = _extract(a)
        ports_b, cves_b, expl_b, os_b = _extract(b)

        return {
            "scan_a":         {"id": scan_id_a, "target": a.get("target"),
                               "started": a.get("started_at")},
            "scan_b":         {"id": scan_id_b, "target": b.get("target"),
                               "started": b.get("started_at")},
            "new_ports":      sorted(ports_b - ports_a),
            "closed_ports":   sorted(ports_a - ports_b),
            "new_cves":       sorted(cves_b - cves_a),
            "resolved_cves":  sorted(cves_a - cves_b),
            "new_exploits":   sorted(expl_b - expl_a),
            "os_changed":     os_a != os_b,
            "os_before":      os_a,
            "os_after":       os_b,
        }

    # ------------------------------------------------------------------
    # Scheduled scans
    # ------------------------------------------------------------------

    def add_schedule(self, name: str, target: str, scan_type: str = "single",
                     modules: Optional[list] = None,
                     interval_h: float = 24.0) -> int:
        try:
            with self._lock:
                conn = self._connect()
                next_run = (datetime.now() + timedelta(hours=interval_h)).isoformat()
                cur = conn.execute(
                    "INSERT INTO scheduled_scans "
                    "(name, target, scan_type, modules, interval_h, next_run_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (name, target, scan_type,
                     json.dumps(modules or []), interval_h, next_run)
                )
                sid = cur.lastrowid
                conn.commit()
                conn.close()
                return sid
        except Exception as exc:
            log.error(f"[history] add_schedule error: {exc}")
            return -1

    def list_schedules(self) -> list[dict]:
        try:
            with self._lock:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT * FROM scheduled_scans ORDER BY next_run_at"
                ).fetchall()
                conn.close()
            result = []
            for r in rows:
                d = dict(r)
                d["modules"] = _safe_json(d.get("modules"))
                result.append(d)
            return result
        except Exception as exc:
            log.error(f"[history] list_schedules error: {exc}")
            return []

    def delete_schedule(self, schedule_id: int) -> None:
        try:
            with self._lock:
                conn = self._connect()
                conn.execute("DELETE FROM scheduled_scans WHERE id=?", (schedule_id,))
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error(f"[history] delete_schedule error: {exc}")

    def get_due_schedules(self) -> list[dict]:
        """Return schedules whose next_run_at is in the past."""
        now = datetime.now().isoformat()
        try:
            with self._lock:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT * FROM scheduled_scans "
                    "WHERE enabled=1 AND next_run_at <= ?",
                    (now,)
                ).fetchall()
                conn.close()
            result = []
            for r in rows:
                d = dict(r)
                d["modules"] = _safe_json(d.get("modules"))
                result.append(d)
            return result
        except Exception as exc:
            log.error(f"[history] get_due_schedules error: {exc}")
            return []

    def update_schedule_run(self, schedule_id: int, interval_h: float) -> None:
        next_run = (datetime.now() + timedelta(hours=interval_h)).isoformat()
        now      = datetime.now().isoformat()
        try:
            with self._lock:
                conn = self._connect()
                conn.execute(
                    "UPDATE scheduled_scans SET last_run_at=?, next_run_at=? WHERE id=?",
                    (now, next_run, schedule_id)
                )
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error(f"[history] update_schedule_run error: {exc}")


def _safe_json(val):
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return val


# Module-level singleton
_instance: Optional[ScanHistory] = None


def get_scan_history() -> ScanHistory:
    global _instance
    if _instance is None:
        _instance = ScanHistory()
    return _instance