# fenrir/modules/rf_scanner.py
import asyncio
import shutil
import re
import csv
import os
from ..logging_config import log

class RfScanner:
    """
    Scans for RF signals by integrating with the 'rtl_power' command-line tool.
    This requires an RTL-SDR dongle and the rtl-sdr package to be installed.
    """
    def __init__(self):
        log.debug("RF Scanner module initialized.")
        self.rtl_power_path = shutil.which("rtl_power")
        # Regex to find significant power peaks in rtl_power output
        self.peak_regex = re.compile(r"(\d+\.\d+)\s+dB")

    async def run(self, duration: int = 20, freq_range: str = "24M:1.7G"):
        """
        Runs the RF scan using rtl_power.

        Args:
            duration: The time in seconds to scan (e.g., 20s).
            freq_range: The frequency range to scan (e.g., "24M:1.7G").
        """
        log.info(f"Starting RF scan for {duration} seconds...")

        if not self.rtl_power_path:
            log.error("`rtl_power` is not installed or not in your system's PATH.")
            log.error("Please install it (e.g., 'sudo apt install rtl-sdr') to use this feature.")
            return

        output_csv_path = "rf_scan_results.csv"
        command = [
            self.rtl_power_path,
            "-f", freq_range,
            "-i", "10",      # Integration interval
            "-g", "30",      # Tuner gain
            "-e", f"{duration}s", # Exit timer
            output_csv_path
        ]

        try:
            log.info(f"Executing command: {' '.join(command)}")
            log.info("This will take the full duration to complete...")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_output = stderr.decode().strip()
                if "No supported devices found" in error_output:
                    log.error("No RTL-SDR dongle found. Please ensure it is connected.")
                else:
                    log.error(f"rtl_power exited with an error: {error_output}")
                return

            log.info("RF scan complete. Analyzing results...")
            self.analyze_results(output_csv_path)

        except FileNotFoundError:
            log.error("rtl_power command not found. Is rtl-sdr installed?")
        except Exception as e:
            log.error(f"An unexpected error occurred during RF scan: {e}")
        finally:
            # Clean up the output file
            if os.path.exists(output_csv_path):
                os.remove(output_csv_path)

        log.info("RF scan finished.")

    def analyze_results(self, file_path: str):
        """Parses the CSV output from rtl_power to find signal peaks."""
        if not os.path.exists(file_path):
            log.warning("Scan result file not found.")
            return

        found_peaks = []
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                # Format: Date, Time, Freq_Low, Freq_High, Step, Samples, dBm_1, dBm_2, ...
                if len(row) < 7:
                    continue
                
                freq_low = float(row[2])
                freq_high = float(row[3])
                
                # Find the maximum power level in the row's dBm readings
                power_levels = [float(val) for val in row[6:]]
                max_power = max(power_levels)

                # A simple threshold to identify a "peak"
                # This could be made more sophisticated (e.g., signal-to-noise ratio)
                if max_power > -20: # -20 dBm is a reasonably strong signal
                    center_freq_mhz = ((freq_low + freq_high) / 2) / 1_000_000
                    found_peaks.append((center_freq_mhz, max_power))

        if found_peaks:
            log.warning(f"Found {len(found_peaks)} significant RF signal(s):")
            for freq, power in sorted(found_peaks):
                log.warning(f"  - Peak detected at ~{freq:.2f} MHz (Power: {power:.2f} dBm)")
        else:
            log.info("No significant signal peaks detected in the specified range.")

