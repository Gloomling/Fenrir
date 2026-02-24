# File: fenrir/modules/mobile_scanner.py
import os
import zipfile
import hashlib
from androguard.core.bytecodes.apk import APK
from ..logging_config import log

class MobileScanner:
    """Performs static analysis on mobile application files (APKs)."""
    def __init__(self):
        log.debug("Mobile Scanner module initialized.")

    def analyze_apk(self, file_path: str):
        """Analyzes a single Android APK file."""
        try:
            log.info(f"Analyzing APK: {os.path.basename(file_path)}")
            a = APK(file_path)
            
            if not a.is_valid_apk():
                log.error("Invalid APK file provided.")
                return

            log.info("Basic APK Information:")
            log.info(f"  - Package Name: {a.get_package()}")
            log.info(f"  - Main Activity: {a.get_main_activity()}")
            log.info(f"  - App Name: {a.get_app_name()}")
            
            permissions = a.get_permissions()
            log.info(f"Found {len(permissions)} permission(s):")
            # Check for potentially dangerous permissions
            dangerous_perms = [
                "android.permission.READ_SMS", "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"
            ]
            for perm in sorted(permissions):
                if any(dp in perm for dp in dangerous_perms):
                    log.warning(f"  - {perm} (Potentially Dangerous)")
                else:
                    log.info(f"  - {perm}")

        except Exception as e:
            log.error(f"Failed to analyze APK {file_path}. Is it a valid file? Error: {e}")

    async def run(self, file_path: str):
        """Runs the mobile application scan."""
        log.info(f"Starting mobile application scan on {file_path}...")
        
        if not os.path.exists(file_path):
            log.error(f"File not found: {file_path}")
            return

        if file_path.lower().endswith(".apk"):
            # Run synchronous analysis in a thread
            await asyncio.to_thread(self.analyze_apk, file_path)
        else:
            log.error("Unsupported file type. This module currently only supports .apk files.")
            
        log.info("Mobile application scan finished.")
```python
