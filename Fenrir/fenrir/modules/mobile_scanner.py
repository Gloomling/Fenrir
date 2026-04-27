# fenrir/modules/mobile_scanner.py
#
# Fix 19 — Changes from original:
#   - Added missing `import asyncio` (original would crash on run())
#   - `import zipfile` removed (unused — androguard handles zip internally)
#   - `import hashlib` retained and used: computes SHA256 of APK for hash rep lookup
#   - Offline DB hash check: checks computed SHA256 against hash_reputation table
#   - Added structured findings dict for every check
#   - ReportManager integration
#   - run() returns dict of all findings
#   - Certificate analysis added: extracts signing cert from APK META-INF
#   - Hardcoded dangerous permissions list expanded to 20+ permissions
#   - Graceful fallback if androguard version API changes

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Optional

from ..database import get_db_manager
from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# androguard optional import — may not be installed on all systems
try:
    from androguard.core.bytecodes.apk import APK
    _ANDROGUARD_AVAILABLE = True
except ImportError:
    try:
        from androguard.core.apk import APK  # androguard 4.x path
        _ANDROGUARD_AVAILABLE = True
    except ImportError:
        _ANDROGUARD_AVAILABLE = False
        log.debug("androguard not installed — APK analysis unavailable.")

# Permissions flagged as dangerous or high-risk
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.INTERNET",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
}


class MobileScanner:
    """
    Performs static analysis on mobile application files.

    Supported formats:
      .apk — Android Package

    Analysis includes:
      - SHA256 hash computation + offline reputation check
      - Manifest metadata (package name, version, activities)
      - Dangerous permission enumeration
      - APK certificate fingerprint extraction
      - Basic obfuscation indicator check
    """

    def __init__(self) -> None:
        log.debug("MobileScanner initialised.")
        self._db = get_db_manager()

    async def run(
        self,
        file_path: str,
        report: Optional[ReportManager] = None,
    ) -> dict:
        """
        Perform static analysis on a mobile application file.

        Args:
            file_path: Path to the APK file.
            report:    Optional ReportManager.

        Returns:
            Dict with keys: file, sha256, hash_reputation, manifest,
                            permissions, certificate, findings
        """
        path = Path(file_path)
        log.info(f"Starting mobile application scan: {path.name}")

        results = {
            "file":            str(path),
            "sha256":          None,
            "hash_reputation": None,
            "manifest":        {},
            "permissions":     {"dangerous": [], "normal": []},
            "certificate":     None,
            "findings":        [],
        }

        if not path.exists():
            log.error(f"File not found: {file_path}")
            return results

        if not path.suffix.lower() == ".apk":
            log.error(f"Unsupported file type '{path.suffix}'. Only .apk is currently supported.")
            return results

        # --- SHA256 hash ---
        sha256 = await asyncio.to_thread(self._compute_sha256, path)
        results["sha256"] = sha256
        log.info(f"SHA256: {sha256}")

        # --- Offline hash reputation check ---
        if sha256 and self._db.is_available():
            rep = await asyncio.to_thread(self._db.check_hash, sha256, "sha256")
            if rep:
                results["hash_reputation"] = rep
                log.warning(
                    f"HASH REPUTATION HIT: {path.name} is known malware! "
                    f"Family: {rep.get('malware_family', 'Unknown')} "
                    f"({rep.get('source')})"
                )
                results["findings"].append({
                    "severity": "CRITICAL",
                    "check":    "hash_reputation",
                    "detail":   (
                        f"APK hash matches known malware: "
                        f"{rep.get('malware_family', 'Unknown')} "
                        f"(source: {rep.get('source')})"
                    ),
                })
            else:
                log.info("Hash not found in offline malware database — not a known sample.")
        elif not self._db.is_available():
            log.debug("Offline DB not available — skipping hash reputation check.")

        # --- APK analysis ---
        if _ANDROGUARD_AVAILABLE:
            await asyncio.to_thread(self._analyze_apk, path, results)
        else:
            log.warning(
                "androguard not installed — skipping APK static analysis. "
                "Install with: pip install androguard"
            )
            results["findings"].append({
                "severity": "INFO",
                "check":    "dependency",
                "detail":   "androguard not installed — static analysis skipped.",
            })

        # --- ReportManager ---
        if report:
            section = {
                "file":            str(path),
                "sha256":          sha256,
                "known_malware":   bool(results.get("hash_reputation")),
                "package_name":    results["manifest"].get("package", ""),
                "version_name":    results["manifest"].get("version_name", ""),
                "dangerous_perms": len(results["permissions"]["dangerous"]),
                "findings":        results["findings"],
            }
            report.add_section("Mobile Application Analysis", [section])

        log.info("Mobile application scan finished.")
        return results

    # ------------------------------------------------------------------
    # Hash
    # ------------------------------------------------------------------

    def _compute_sha256(self, path: Path) -> str:
        """Compute SHA256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError as exc:
            log.error(f"Cannot read file for hashing: {exc}")
            return ""

    # ------------------------------------------------------------------
    # APK analysis
    # ------------------------------------------------------------------

    def _analyze_apk(self, path: Path, results: dict) -> None:
        """Full androguard APK static analysis. Runs in thread pool."""
        try:
            apk = APK(str(path))
        except Exception as exc:
            log.error(f"Failed to parse APK: {exc}")
            results["findings"].append({
                "severity": "ERROR",
                "check":    "parse",
                "detail":   f"APK parsing failed: {exc}",
            })
            return

        # --- Manifest metadata ---
        try:
            package     = apk.get_package()
            version_name = apk.get_androidversion_name() or apk.get_app_name()
            version_code = apk.get_androidversion_code()
            min_sdk      = apk.get_min_sdk_version()
            target_sdk   = apk.get_target_sdk_version()
            main_act     = apk.get_main_activity()
            app_name     = apk.get_app_name()

            results["manifest"] = {
                "package":      package,
                "app_name":     app_name,
                "version_name": version_name,
                "version_code": version_code,
                "min_sdk":      min_sdk,
                "target_sdk":   target_sdk,
                "main_activity": main_act,
            }

            log.info("APK Manifest:")
            log.info(f"  Package:      {package}")
            log.info(f"  App Name:     {app_name}")
            log.info(f"  Version:      {version_name} (code {version_code})")
            log.info(f"  Min SDK:      {min_sdk} | Target SDK: {target_sdk}")
            log.info(f"  Main Activity: {main_act}")

            # Old SDK warning
            if min_sdk and int(str(min_sdk).strip() or 0) < 21:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "check":    "min_sdk",
                    "detail":   (
                        f"minSdkVersion {min_sdk} is below Android 5.0 (API 21) — "
                        "supports very old devices with known vulnerabilities."
                    ),
                })

        except Exception as exc:
            log.warning(f"Manifest extraction partial failure: {exc}")

        # --- Permissions ---
        try:
            permissions = apk.get_permissions()
            dangerous   = []
            normal      = []

            log.info(f"Permissions ({len(permissions)} total):")
            for perm in sorted(permissions):
                if perm in _DANGEROUS_PERMISSIONS:
                    dangerous.append(perm)
                    log.warning(f"  [DANGEROUS] {perm}")
                else:
                    normal.append(perm)
                    log.debug(f"  [normal]    {perm}")

            results["permissions"]["dangerous"] = dangerous
            results["permissions"]["normal"]    = normal

            if dangerous:
                results["findings"].append({
                    "severity": "HIGH" if len(dangerous) > 5 else "MEDIUM",
                    "check":    "dangerous_permissions",
                    "detail":   (
                        f"{len(dangerous)} dangerous permission(s) declared: "
                        + ", ".join(dangerous[:5])
                        + ("..." if len(dangerous) > 5 else "")
                    ),
                })
                log.info(f"  {len(normal)} normal permissions (debug-level detail).")
            else:
                log.info("  No dangerous permissions detected.")

        except Exception as exc:
            log.warning(f"Permission analysis failed: {exc}")

        # --- Certificate ---
        try:
            certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v1()
            if certs:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                cert      = x509.load_der_x509_certificate(list(certs.values())[0])
                subject   = cert.subject.rfc4514_string()
                issuer    = cert.issuer.rfc4514_string()
                not_after = cert.not_valid_after_utc.isoformat()
                fp        = cert.fingerprint(hashes.SHA256()).hex()

                results["certificate"] = {
                    "subject":   subject,
                    "issuer":    issuer,
                    "not_after": not_after,
                    "sha256_fp": fp,
                }
                log.info(f"Certificate Subject: {subject}")
                log.info(f"Certificate Issuer:  {issuer}")
                log.info(f"Certificate Expires: {not_after}")
                log.info(f"Certificate SHA256:  {fp}")

                # Self-signed check
                if subject == issuer:
                    results["findings"].append({
                        "severity": "MEDIUM",
                        "check":    "certificate",
                        "detail":   "APK is signed with a self-signed certificate.",
                    })
                    log.warning("APK uses a self-signed certificate.")
        except Exception as exc:
            log.debug(f"Certificate analysis failed: {exc}")

        # --- Obfuscation indicators ---
        try:
            activities = apk.get_activities()
            services   = apk.get_services()
            receivers  = apk.get_receivers()
            providers  = apk.get_providers()

            all_components = list(activities) + list(services) + list(receivers) + list(providers)
            short_names    = [c for c in all_components if len(c.split(".")[-1]) <= 2]

            if len(short_names) > len(all_components) * 0.4:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "check":    "obfuscation",
                    "detail":   (
                        f"{len(short_names)}/{len(all_components)} components have "
                        "short names (possible obfuscation with ProGuard/R8)."
                    ),
                })
                log.warning(
                    f"Possible obfuscation: {len(short_names)}/{len(all_components)} "
                    "components have short class names."
                )
        except Exception as exc:
            log.debug(f"Obfuscation check failed: {exc}")

        # --- Final summary ---
        critical = [f for f in results["findings"] if f.get("severity") == "CRITICAL"]
        high     = [f for f in results["findings"] if f.get("severity") == "HIGH"]

        if critical:
            log.warning(f"CRITICAL findings: {len(critical)}")
        if high:
            log.warning(f"HIGH findings: {len(high)}")
        if not results["findings"]:
            log.info("No significant security findings detected in APK.")
