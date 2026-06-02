# fenrir/report_manager.py
#
# Handles the creation, population, and finalisation of scan reports.
#
# Design:
#   - Each scan session creates one ReportManager instance.
#   - All findings are stored in memory as structured data during the scan.
#   - On finalize(), two output files are written simultaneously:
#       1. A human-readable plain-text report  (.txt)
#       2. A structured JSON report             (.json)
#   - Individual modules call add_section() to contribute their findings.
#   - The ReportManager is passed into each module by the CLI/GUI orchestrator
#     so all modules write to the same session report.
#   - Thread-safe: add_section() uses a threading.Lock so it is safe to call
#     from concurrent async tasks running in threads.
#
# Report structure (JSON):
#   {
#     "meta": {
#       "target":     "192.168.1.10",
#       "started_at": "2025-08-01T14:32:00",
#       "finished_at": "2025-08-01T14:45:12",
#       "duration_seconds": 792,
#       "fenrir_version": "2.0.0"
#     },
#     "sections": [
#       {
#         "title": "Open Ports",
#         "findings": ["80", "443", "8080"],
#         "finding_count": 3
#       },
#       ...
#     ]
#   }

import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Union

from .logging_config import get_logger
from .config import config

log = get_logger()


class ReportManager:
    """
    Creates and manages a scan report for a single Fenrir session.

    Args:
        output_dir (str | Path): Directory where report files will be written.
        target (str):            The scan target (IP, domain, or file path).

    Usage:
        report = ReportManager(output_dir="/home/user/reports", target="192.168.1.10")
        report.add_section("Open Ports", ["80", "443", "8080"])
        report.add_section("CVEs Found", [{"id": "CVE-2021-44228", "score": 10.0}])
        report.finalize()
    """

    def __init__(self, output_dir: Union[str, Path], target: str) -> None:
        self.target = target
        self.output_dir = Path(output_dir)
        self.start_time = datetime.now()
        self._lock = threading.Lock()

        # In-memory store: list of {"title": str, "findings": list, "finding_count": int}
        self._sections: list[dict] = []

        # Derive output file paths from target and timestamp
        safe_target = target.replace("/", "_").replace(":", "_").replace("\\", "_")
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        base_name = f"fenrir_report_{safe_target}_{timestamp}"

        self.txt_path = self.output_dir / f"{base_name}.txt"
        self.json_path = self.output_dir / f"{base_name}.json"

        # Ensure the output directory exists
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.error(
                f"Could not create output directory '{self.output_dir}': {exc}. "
                "Reports will not be saved."
            )

        log.info(f"Report session started. Target: {self.target}")
        log.info(f"  TXT report : {self.txt_path}")
        log.info(f"  JSON report: {self.json_path}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_section(
        self,
        title: str,
        findings: list[Union[str, dict]],
    ) -> None:
        """
        Add a findings section to the report.

        Thread-safe — safe to call from concurrent module tasks.

        Args:
            title (str):
                Section heading, e.g. "Open Ports", "CVEs Found".

            findings (list[str | dict]):
                The findings for this section. Each item may be either:
                  - A plain string  (e.g. "Port 80 open")
                  - A dict          (e.g. {"id": "CVE-2021-44228", "score": 10.0})
                Mixed lists are accepted.
                Empty lists are silently ignored — no empty section is written.

        Example:
            report.add_section("Open Ports", ["80", "443"])
            report.add_section("CVEs", [{"id": "CVE-2021-44228", "score": 10.0,
                                          "severity": "CRITICAL",
                                          "description": "Log4Shell"}])
        """
        if not findings:
            log.debug(f"add_section('{title}'): no findings — section skipped.")
            return

        section = {
            "title": title,
            "findings": findings,
            "finding_count": len(findings),
        }

        with self._lock:
            self._sections.append(section)

        log.debug(f"Report section added: '{title}' ({len(findings)} finding(s)).")

    def finalize(self) -> None:
        """
        Finalise the report and write both output files.

        Should be called once, after all modules have completed.
        Calling finalize() more than once will overwrite the previous output —
        this is intentional to allow a partial report if the scan is interrupted.

        Writes:
            <output_dir>/fenrir_report_<target>_<timestamp>.txt
            <output_dir>/fenrir_report_<target>_<timestamp>.json
        """
        end_time = datetime.now()
        duration = end_time - self.start_time
        duration_seconds = int(duration.total_seconds())

        log.info("Finalising scan report...")

        self._write_txt(end_time, duration_seconds)
        self._write_json(end_time, duration_seconds)

        log.info(f"Reports saved:")
        log.info(f"  TXT  → {self.txt_path}")
        log.info(f"  JSON → {self.json_path}")

    def get_section_count(self) -> int:
        """Return the number of sections currently in the report."""
        with self._lock:
            return len(self._sections)

    def get_sections(self) -> list[dict]:
        """Return a snapshot of all report sections (thread-safe copy)."""
        with self._lock:
            return list(self._sections)

    def get_total_finding_count(self) -> int:
        """Return the total number of individual findings across all sections."""
        with self._lock:
            return sum(s["finding_count"] for s in self._sections)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_txt(self, end_time: datetime, duration_seconds: int) -> None:
        """Write the human-readable plain-text report."""
        try:
            with open(self.txt_path, "w", encoding="utf-8") as f:

                # ---- Header ----
                f.write("=" * 64 + "\n")
                f.write("  FENRIR SECURITY SCAN REPORT\n")
                f.write("=" * 64 + "\n")
                f.write(f"  Target          : {self.target}\n")
                f.write(f"  Scan Started    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Scan Finished   : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Duration        : {self._format_duration(duration_seconds)}\n")
                f.write(f"  Fenrir Version  : {config.APP_VERSION}\n")
                f.write(f"  Total Findings  : {self.get_total_finding_count()}\n")
                f.write("=" * 64 + "\n\n")

                # ---- Sections ----
                if not self._sections:
                    f.write("  No findings recorded for this scan.\n")
                else:
                    for section in self._sections:
                        title = section["title"].upper()
                        count = section["finding_count"]
                        f.write(f"--- {title} ({count} finding(s)) ---\n")

                        for finding in section["findings"]:
                            if isinstance(finding, dict):
                                # Pretty-print dicts as indented key: value pairs
                                for key, value in finding.items():
                                    f.write(f"    {key}: {value}\n")
                                f.write("\n")
                            else:
                                f.write(f"  - {finding}\n")

                        f.write("\n")

                # ---- Footer ----
                f.write("=" * 64 + "\n")
                f.write("  END OF REPORT\n")
                f.write("=" * 64 + "\n")

        except OSError as exc:
            log.error(f"Failed to write TXT report to '{self.txt_path}': {exc}")

    def _write_json(self, end_time: datetime, duration_seconds: int) -> None:
        """Write the structured JSON report."""
        report_data = {
            "meta": {
                "target":           self.target,
                "started_at":       self.start_time.isoformat(),
                "finished_at":      end_time.isoformat(),
                "duration_seconds": duration_seconds,
                "duration_human":   self._format_duration(duration_seconds),
                "fenrir_version":   config.APP_VERSION,
                "total_findings":   self.get_total_finding_count(),
            },
            "sections": self._sections,
        }

        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)
                # default=str handles any non-serialisable types (e.g. datetime
                # objects that slipped through) by converting them to strings.
        except OSError as exc:
            log.error(f"Failed to write JSON report to '{self.json_path}': {exc}")

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """
        Convert a duration in seconds to a human-readable string.

        Examples:
            45  -> "45s"
            90  -> "1m 30s"
            3661 -> "1h 1m 1s"
        """
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)

        parts = []
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")

        return " ".join(parts)
